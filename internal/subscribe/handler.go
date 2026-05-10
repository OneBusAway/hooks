// Package subscribe implements the GET /subscribe/<source> SSE endpoint.
//
// Stream layout:
//
//	id:<seq>
//	event:<source>
//	data:<json>
//	\n
//
// data is a single line of JSON containing delivery_id, provider_timestamp,
// received_at, headers, and a base64-encoded body. Bytes round-trip verbatim.
//
// The handler runs an initial-backfill drain (read from the store in batches
// of ≤1000 until caught up to the current latest sequence) followed by a
// live loop (select on the per-source notifier channel + a 30s keepalive
// ticker). On any signal the live loop drains all newer events from the
// store, so a dropped notify channel signal still lands the affected events.
//
// Initial-backfill stale-event filter: events whose provider_timestamp is
// older than the source's effective skew window (the per-source value from
// hooks.yaml, falling back to the verifier's 5-minute default — the same
// effective_skew ingest already enforces) are skipped during the initial
// drain. The cursor advances past skipped events so reconnects with
// `?since=<seq>` start past them and the live drain does not re-emit them.
// Live tail (notifier-triggered or keepalive-triggered drains) is
// unfiltered. The trade-off is documented in
// docs/superpowers/specs/2026-05-09-subscribe-stale-backfill-filter-design.md.
package subscribe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// Defaults documented in design.md.
const (
	DefaultKeepalive  = 30 * time.Second
	DefaultBatchLimit = 1000
)

// Handler serves /subscribe/<source>.
//
// Sources maps each allowed source name to its effective skew window — the
// per-source value from hooks.yaml, or the verifier default if zero/unset.
// Source membership is determined by key presence (`d, ok := h.Sources[s]`),
// not value: zero is a legitimate duration and must not be conflated with
// "unknown source". Resolution to a non-zero default happens upstream in
// internal/server.Build so the handler itself never sees zero.
type Handler struct {
	Store      store.EventStore
	Notifier   *pubsub.Notifier
	Auth       *tokens.Authenticator
	Sources    map[string]time.Duration
	Logger     *slog.Logger
	Keepalive  time.Duration
	BatchLimit int

	// Now is the clock used by the initial-backfill stale-event filter.
	// Tests inject a fixed clock; production leaves it nil and falls back
	// to time.Now.
	Now func() time.Time
}

// New constructs a Handler with sensible defaults. sources maps each allowed
// source name to its already-resolved effective skew window (caller must not
// pass zero — see Handler.Sources).
func New(st store.EventStore, n *pubsub.Notifier, auth *tokens.Authenticator, sources map[string]time.Duration, logger *slog.Logger) *Handler {
	srcSet := make(map[string]time.Duration, len(sources))
	for s, d := range sources {
		srcSet[s] = d
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		Store:      st,
		Notifier:   n,
		Auth:       auth,
		Sources:    srcSet,
		Logger:     logger,
		Keepalive:  DefaultKeepalive,
		BatchLimit: DefaultBatchLimit,
	}
}

// ServeHTTP handles GET /subscribe/<source>.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	source := lastPathSegment(r.URL.Path)
	if _, ok := h.Sources[source]; !ok {
		http.Error(w, "unknown source", http.StatusNotFound)
		return
	}

	if _, err := h.Auth.AuthorizeSource(r, source); err != nil {
		tokens.WriteAuthError(w, err)
		return
	}

	cursor, err := parseCursor(r, h.Store, source)
	if err != nil {
		http.Error(w, "invalid cursor: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Configure SSE response.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	if err := h.stream(r.Context(), w, flusher, source, cursor); err != nil {
		// Errors here are typically client disconnects; log at debug.
		h.Logger.Debug("subscribe: stream ended", slog.String("source", source), slog.String("error", err.Error()))
	}
}

func (h *Handler) stream(ctx context.Context, w io.Writer, flusher http.Flusher, source string, cursor int64) error {
	batchLimit := h.BatchLimit
	if batchLimit <= 0 {
		batchLimit = DefaultBatchLimit
	}
	keepalive := h.Keepalive
	if keepalive <= 0 {
		keepalive = DefaultKeepalive
	}

	// Subscribe to live signals BEFORE replaying so we don't miss anything
	// that arrives during replay.
	ch := h.Notifier.Subscribe(source)
	defer h.Notifier.Unsubscribe(source, ch)

	// Initial backfill — filters stale events by age. See package doc.
	cursor, err := h.initialDrain(ctx, w, flusher, source, cursor, batchLimit)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-ch:
			if !ok {
				return errors.New("notifier closed")
			}
			cursor, err = h.liveDrain(ctx, w, flusher, source, cursor, batchLimit)
			if err != nil {
				return err
			}
		case <-ticker.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return err
			}
			flusher.Flush()
			// Belt-and-suspenders: if we missed a signal, drain anyway.
			cursor, err = h.liveDrain(ctx, w, flusher, source, cursor, batchLimit)
			if err != nil {
				return err
			}
		}
	}
}

// initialDrain reads from the store and emits events to the wire, filtering
// out events older than the source's effective skew window. Cursor advances
// on every event whether emitted or skipped: if it didn't, the unfiltered
// liveDrain that runs next would re-pick the same skipped events from the
// store and re-emit them on the wire.
func (h *Handler) initialDrain(ctx context.Context, w io.Writer, flusher http.Flusher, source string, cursor int64, batchLimit int) (int64, error) {
	skew := h.Sources[source]
	now := h.now()
	cutoff := now.Add(-skew)
	return h.readBatchAndEmit(ctx, w, flusher, source, cursor, batchLimit, func(ev store.Event) bool {
		// Forward-compat: a missing/zero ProviderTimestamp passes. A
		// raw time.Time{} round-trips through the store's nanosecond
		// encoding into a pre-epoch wraparound value (year 1754), so
		// IsZero() doesn't catch it. The "at or before unix epoch"
		// sentinel covers both that wraparound and any pre-1970
		// garbage; real provider timestamps are post-2000.
		if ev.ProviderTimestamp.Unix() <= 0 {
			return true
		}
		if ev.ProviderTimestamp.Before(cutoff) {
			h.Logger.Debug("subscribe: skipping stale event on initial backfill",
				slog.String("source", source),
				slog.Int64("seq", ev.Sequence),
				slog.String("delivery_id", ev.DeliveryID),
				slog.Duration("age", now.Sub(ev.ProviderTimestamp)),
				slog.Duration("skew_window", skew),
			)
			return false
		}
		return true
	})
}

// liveDrain reads from the store and emits every event unconditionally.
// Live ingest events are fresh by definition (they just passed the same
// effective_skew check at ingest), and the inspector "Replay to listeners"
// path uses Notifier.Publish to wake currently-connected SSE subscribers —
// that path stays open even for stale events.
func (h *Handler) liveDrain(ctx context.Context, w io.Writer, flusher http.Flusher, source string, cursor int64, batchLimit int) (int64, error) {
	return h.readBatchAndEmit(ctx, w, flusher, source, cursor, batchLimit, nil)
}

// readBatchAndEmit reads ≤batchLimit events at a time starting after cursor
// and emits each to the wire. If keep is non-nil, an event is written only
// when keep(ev) is true; cursor advances on every event regardless.
func (h *Handler) readBatchAndEmit(ctx context.Context, w io.Writer, flusher http.Flusher, source string, cursor int64, batchLimit int, keep func(store.Event) bool) (int64, error) {
	for {
		batch, err := h.Store.ReadSince(ctx, source, cursor, batchLimit)
		if err != nil {
			return cursor, err
		}
		if len(batch) == 0 {
			return cursor, nil
		}
		var wrote bool
		for _, ev := range batch {
			cursor = ev.Sequence
			if keep != nil && !keep(ev) {
				continue
			}
			if err := writeEvent(w, ev); err != nil {
				return cursor, err
			}
			wrote = true
		}
		if wrote {
			flusher.Flush()
		}
	}
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// writeEvent renders an Event as a single SSE message.
func writeEvent(w io.Writer, ev store.Event) error {
	payload := ssePayload{
		DeliveryID:        ev.DeliveryID,
		ProviderTimestamp: ev.ProviderTimestamp,
		ReceivedAt:        ev.ReceivedAt,
		Headers:           ev.Headers,
		Body:              base64.StdEncoding.EncodeToString(ev.Body),
		BodySHA256:        ev.BodySHA256,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := fmt.Fprintf(w, "id:%d\nevent:%s\ndata:", ev.Sequence, ev.Source); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\n\n"); err != nil {
		return err
	}
	return nil
}

type ssePayload struct {
	DeliveryID        string            `json:"delivery_id"`
	ProviderTimestamp time.Time         `json:"provider_timestamp"`
	ReceivedAt        time.Time         `json:"received_at"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	BodySHA256        string            `json:"body_sha256"`
}

// parseCursor resolves the effective starting sequence from `since` and
// `Last-Event-ID`. The maximum of the two wins so browser auto-reconnect
// cannot regress.
func parseCursor(r *http.Request, st store.EventStore, source string) (int64, error) {
	cursor := int64(0)

	if v := r.URL.Query().Get("since"); v != "" {
		if v == "latest" {
			latest, err := st.LatestSequence(r.Context(), source)
			if err != nil {
				return 0, err
			}
			cursor = latest
		} else {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("since: %w", err)
			}
			if n < 0 {
				return 0, fmt.Errorf("since: must be non-negative")
			}
			cursor = n
		}
	}

	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("Last-Event-ID: %w", err)
		}
		if n > cursor {
			cursor = n
		}
	}
	return cursor, nil
}

func lastPathSegment(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
