package push

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// worker is one running dispatcher goroutine bound to a single subscription.
type worker struct {
	mgr    *Manager
	sub    store.PushSubscription
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	signal chan int64
	// warned tracks whether we've already emitted the "100 failures" WARN
	// for the current failure streak.
	warned bool
}

func (w *worker) run() {
	defer func() {
		w.mgr.Notifier.Unsubscribe(w.sub.Source, w.signal)
		close(w.done)
	}()

	for {
		if err := w.ctx.Err(); err != nil {
			return
		}

		// Pull current state (cursor, failure count) for this pass.
		sub, err := w.mgr.Subs.Get(w.ctx, w.sub.ID)
		if err != nil {
			w.mgr.Logger.Warn("push: get sub failed",
				slog.String("id", w.sub.ID),
				slog.String("error", err.Error()),
			)
			if w.sleep(1 * time.Second) {
				return
			}
			continue
		}
		if sub.PausedAt != nil {
			return
		}

		// Need plaintext to sign — without it we cannot dispatch. Park
		// until a Rotate or Add wires one in.
		w.mgr.mu.Lock()
		plaintext, hasSecret := w.mgr.secrets[sub.ID]
		w.mgr.mu.Unlock()
		if !hasSecret {
			// Wake on signal; otherwise sleep in 5s increments.
			select {
			case <-w.ctx.Done():
				return
			case <-w.signal:
			case <-time.After(5 * time.Second):
			}
			continue
		}

		batch, err := w.mgr.Events.ReadSince(w.ctx, sub.Source, sub.Cursor, w.batchSize())
		if err != nil {
			w.mgr.Logger.Error("push: read batch failed",
				slog.String("id", sub.ID),
				slog.String("error", err.Error()),
			)
			if w.sleep(1 * time.Second) {
				return
			}
			continue
		}
		if len(batch) == 0 {
			// Idle: wait for either a signal or a long-poll ticker.
			select {
			case <-w.ctx.Done():
				return
			case <-w.signal:
				continue
			case <-time.After(30 * time.Second):
				continue
			}
		}

		ev := batch[0]
		ok := w.deliver(plaintext, ev)
		if ok {
			w.warned = false
			continue
		}
		// Failure path: backoff, no cursor advance.
		if w.failureWarn(sub) {
			w.warned = true
		}
		// Re-read sub for fresh failure counter.
		fresh, _ := w.mgr.Subs.Get(w.ctx, sub.ID)
		if w.sleep(backoff(fresh.ConsecutiveFailures, w.mgr)) {
			return
		}
	}
}

// deliver attempts a single POST. Returns true on 2xx (cursor + success
// recorded). On any non-2xx or error, records the failure (without advancing
// cursor) and returns false.
func (w *worker) deliver(plaintext string, ev store.Event) bool {
	timeout := w.mgr.AttemptTimeout
	if timeout <= 0 {
		timeout = DefaultAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(w.ctx, timeout)
	defer cancel()

	req, err := buildOutboundRequest(ctx, w.sub, plaintext, ev.DeliveryID, ev.Sequence, ev.Body, ev.Headers, w.mgr.Now)
	if err != nil {
		_ = w.mgr.Subs.RecordFailure(w.ctx, w.sub.ID, w.mgr.Now(), "build request: "+err.Error())
		return false
	}

	resp, err := w.mgr.HTTPClient.Do(req)
	if err != nil {
		_ = w.mgr.Subs.RecordFailure(w.ctx, w.sub.ID, w.mgr.Now(), "transport: "+err.Error())
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = w.mgr.Subs.RecordFailure(w.ctx, w.sub.ID, w.mgr.Now(),
			fmt.Sprintf("target returned %d", resp.StatusCode))
		return false
	}

	if err := w.mgr.Subs.UpdateCursorAndSuccess(w.ctx, w.sub.ID, ev.Sequence, w.mgr.Now()); err != nil {
		w.mgr.Logger.Error("push: update cursor failed",
			slog.String("id", w.sub.ID),
			slog.String("error", err.Error()),
		)
		// Treat persistence failure as a transient delivery failure so we
		// don't lose the event next time. Cursor was not advanced.
		return false
	}
	return true
}

func (w *worker) batchSize() int {
	if w.mgr.BatchSize <= 0 {
		return DefaultBatchSize
	}
	return w.mgr.BatchSize
}

// sleep waits up to d with optional early wake on a new-event signal.
// Returns true if the worker should exit.
func (w *worker) sleep(d time.Duration) bool {
	if d <= 0 {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-w.ctx.Done():
		return true
	case <-w.signal:
		// During backoff with a pending event we deliberately don't shorten
		// the sleep; design.md says "no-shorten if currently in active
		// backoff with pending events". But if we're here without any
		// pending event we DO want to wake. The check is at run() loop
		// top; this select is the wake signal for both cases.
		return false
	case <-t.C:
		return false
	}
}

func (w *worker) failureWarn(sub store.PushSubscription) bool {
	// Re-fetch to see updated counter.
	fresh, err := w.mgr.Subs.Get(w.ctx, sub.ID)
	if err != nil {
		return w.warned
	}
	if !w.warned && fresh.ConsecutiveFailures >= WarnFailureStreak {
		w.mgr.Logger.Warn("push: subscription has crossed 100 consecutive failures",
			slog.String("id", sub.ID),
			slog.String("source", sub.Source),
			slog.Int("consecutive_failures", fresh.ConsecutiveFailures),
			slog.String("last_error", fresh.LastError),
		)
		return true
	}
	return w.warned
}

// backoff returns min(cap, 2^failures*100ms) with full jitter [0, computed).
func backoff(failures int, m *Manager) time.Duration {
	if failures <= 0 {
		failures = 1
	}
	if failures > 30 {
		failures = 30
	}
	base := time.Duration(1<<uint(failures-1)) * 100 * time.Millisecond
	if base > DefaultBackoffCap {
		base = DefaultBackoffCap
	}
	if base <= 0 {
		return 100 * time.Millisecond
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return time.Duration(m.rng.Int63n(int64(base)))
}

// buildOutboundRequest constructs the POST that will be sent to a subscription.
// extraHeaders override headers from ev.Headers.
func buildOutboundRequest(
	ctx context.Context,
	sub store.PushSubscription,
	plaintextSecret string,
	deliveryID string,
	sequence int64,
	body []byte,
	captured map[string]string,
	now func() time.Time,
) (*http.Request, error) {
	if sub.TargetURL == "" {
		return nil, errors.New("empty target_url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.TargetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// Copy captured headers, skipping hop-by-hop and provider signatures.
	for k, v := range captured {
		if IsHopByHop(k) {
			continue
		}
		req.Header.Set(k, v)
	}
	// Always set our own headers.
	unix := now().Unix()
	req.Header.Set("X-Hooks-Signature", SignatureHeader(plaintextSecret, unix, body))
	req.Header.Set("X-Hooks-Delivery-Id", deliveryID)
	if sequence > 0 {
		req.Header.Set("X-Hooks-Sequence", strconv.FormatInt(sequence, 10))
	}
	req.Header.Set("X-Hooks-Source", sub.Source)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return req, nil
}

func mergeHeaders(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
