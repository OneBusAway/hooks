// Package push delivers stored events to registered HTTP subscribers.
//
// One worker goroutine runs per non-paused subscription. Each worker:
//
//  1. Reads up to BatchSize events with sequence > cursor from the store.
//  2. POSTs the first event to the subscription's target URL, signed with
//     X-Hooks-Signature.
//  3. On 2xx → atomically advance cursor, record success, reset failure
//     counter; loop.
//  4. On non-2xx, network error, or per-attempt timeout → record failure
//     (without advancing cursor) and sleep min(60s, 2^failures*100ms) with
//     full jitter.
//  5. Wakes early on a Notifier signal IF currently idle (cursor == latest).
//
// The dispatcher requires the subscription's plaintext signing secret to be
// supplied at registration (Add) or rotation (Rotate). After a process
// restart, plaintexts are not on disk; the operator must rotate-secret to
// re-supply them. This is the design trade-off documented in design.md.
package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/store"
)

// Defaults documented in design.md.
const (
	DefaultAttemptTimeout = 30 * time.Second
	DefaultBackoffCap     = 60 * time.Second
	DefaultBatchSize      = 100
	WarnFailureStreak     = 100
)

// Manager runs one worker per active subscription and exposes lifecycle
// methods called by the push API handlers.
type Manager struct {
	Events     store.EventStore
	Subs       store.PushSubscriptionStore
	Notifier   *pubsub.Notifier
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time

	// AttemptTimeout is the per-attempt HTTP timeout. Zero falls back to
	// DefaultAttemptTimeout.
	AttemptTimeout time.Duration

	// BatchSize is the cap on events read per dispatcher pass. Zero falls
	// back to DefaultBatchSize. Workers always send the *first* of each
	// batch; the next sequence is fetched after the cursor advances.
	BatchSize int

	mu      sync.Mutex
	workers map[string]*worker // id → worker
	secrets map[string]string  // id → plaintext signing secret
	// rng is owned by the manager but only read by workers under mu, so a
	// shared instance is fine here.
	rng *rand.Rand
}

// New constructs a Manager. Workers do not run until Start or Add is called.
func New(events store.EventStore, subs store.PushSubscriptionStore, n *pubsub.Notifier, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		Events:         events,
		Subs:           subs,
		Notifier:       n,
		HTTPClient:     &http.Client{Timeout: 0}, // we apply per-attempt timeout via context
		Logger:         logger,
		Now:            time.Now,
		AttemptTimeout: DefaultAttemptTimeout,
		BatchSize:      DefaultBatchSize,
		workers:        map[string]*worker{},
		secrets:        map[string]string{},
		rng:            rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Start hydrates the manager from persisted subscriptions. Workers are
// created but only run if a plaintext secret is present (registered via Add
// or Rotate in this process).
func (m *Manager) Start(ctx context.Context) error {
	subs, err := m.Subs.List(ctx, true)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if sub.PausedAt != nil {
			continue
		}
		// Persisted-only: no plaintext yet. We still create a worker shell
		// so SeedSecret/Add can wire one in later, but the worker only
		// dispatches once secret is set.
		m.ensureWorker(sub)
	}
	return nil
}

// Stop signals every worker to exit and waits for them.
func (m *Manager) Stop() {
	m.mu.Lock()
	workers := make([]*worker, 0, len(m.workers))
	for _, w := range m.workers {
		workers = append(workers, w)
	}
	m.workers = map[string]*worker{}
	m.mu.Unlock()
	for _, w := range workers {
		w.cancel()
	}
	for _, w := range workers {
		<-w.done
	}
}

// Add registers a new subscription's plaintext secret and starts (or
// re-starts) its worker.
func (m *Manager) Add(sub store.PushSubscription, plaintextSecret string) {
	m.mu.Lock()
	m.secrets[sub.ID] = plaintextSecret
	m.mu.Unlock()
	m.ensureWorker(sub)
}

// Rotate updates the plaintext secret used by the worker. Takes effect on
// the very next attempt.
func (m *Manager) Rotate(id, plaintextSecret string) {
	m.mu.Lock()
	m.secrets[id] = plaintextSecret
	m.mu.Unlock()
}

// Pause stops a worker without touching state.
func (m *Manager) Pause(id string) {
	m.mu.Lock()
	w := m.workers[id]
	delete(m.workers, id)
	m.mu.Unlock()
	if w != nil {
		w.cancel()
	}
}

// Resume re-starts a worker after a Pause. Caller must already have
// persisted paused_at = NULL on the row.
func (m *Manager) Resume(ctx context.Context, id string) error {
	sub, err := m.Subs.Get(ctx, id)
	if err != nil {
		return err
	}
	m.ensureWorker(sub)
	return nil
}

// Remove tears down a worker (used after Delete). Plaintext is forgotten.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	w := m.workers[id]
	delete(m.workers, id)
	delete(m.secrets, id)
	m.mu.Unlock()
	if w != nil {
		w.cancel()
	}
}

// Test sends a synthetic ping event without advancing the cursor. Used by
// `hooksctl push test` and the inspector "Test" button.
func (m *Manager) Test(ctx context.Context, id string) error {
	sub, err := m.Subs.Get(ctx, id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	plaintext, ok := m.secrets[id]
	m.mu.Unlock()
	if !ok {
		return errors.New("no plaintext signing secret in memory; rotate-secret first")
	}
	body := []byte(`{"test":true}`)
	deliveryID := "test-" + strconv.FormatInt(m.Now().UnixNano(), 36)
	req, err := buildOutboundRequest(ctx, sub, plaintext, deliveryID, 0, body, map[string]string{
		"Content-Type": "application/json",
		"X-Hooks-Test": "1",
	}, m.Now)
	if err != nil {
		return err
	}
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("test target returned %d", resp.StatusCode)
	}
	return nil
}

// ReplayOne delivers a single existing event one-shot to all matching
// non-paused push subscriptions, with X-Hooks-Replay: 1, WITHOUT advancing
// any cursor. Used by the inspector "Replay to listeners" action.
func (m *Manager) ReplayOne(ctx context.Context, ev store.Event) {
	subs, err := m.Subs.ListBySource(ctx, ev.Source, false)
	if err != nil {
		m.Logger.Warn("push: replay list failed", slog.String("error", err.Error()))
		return
	}
	for _, sub := range subs {
		m.mu.Lock()
		plaintext, ok := m.secrets[sub.ID]
		m.mu.Unlock()
		if !ok {
			m.Logger.Warn("push: replay skipped (no plaintext)", slog.String("id", sub.ID))
			continue
		}
		extra := map[string]string{"X-Hooks-Replay": "1"}
		req, err := buildOutboundRequest(ctx, sub, plaintext, ev.DeliveryID, ev.Sequence, ev.Body, mergeHeaders(ev.Headers, extra), m.Now)
		if err != nil {
			m.Logger.Warn("push: build replay request", slog.String("id", sub.ID), slog.String("error", err.Error()))
			continue
		}
		resp, err := m.HTTPClient.Do(req)
		if err != nil {
			m.Logger.Warn("push: replay deliver failed", slog.String("id", sub.ID), slog.String("error", err.Error()))
			continue
		}
		_ = resp.Body.Close()
	}
}

func (m *Manager) ensureWorker(sub store.PushSubscription) {
	m.mu.Lock()
	if _, exists := m.workers[sub.ID]; exists {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{
		mgr:    m,
		sub:    sub,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
		signal: m.Notifier.Subscribe(sub.Source),
	}
	m.workers[sub.ID] = w
	m.mu.Unlock()

	go w.run()
}
