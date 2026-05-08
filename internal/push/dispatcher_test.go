package push

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/store"
)

func setupManager(t *testing.T) (*Manager, *store.SQLite, *pubsub.Notifier) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	notifier := pubsub.New()
	logger := slog.New(slog.DiscardHandler)
	m := New(st.Events(), st.PushSubscriptions(), notifier, logger)
	m.AttemptTimeout = 2 * time.Second
	t.Cleanup(m.Stop)
	return m, st, notifier
}

func newSub(t *testing.T, st *store.SQLite, source, target string) (store.PushSubscription, string) {
	t.Helper()
	const secret = "test-signing-secret"
	sub := store.PushSubscription{
		ID:                "sub-" + source,
		Source:            source,
		TargetURL:         target,
		SigningSecretHash: "argon2id$dummy",
		Cursor:            0,
		CreatedAt:         time.Now().UTC(),
	}
	if err := st.PushSubscriptions().Insert(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	return sub, secret
}

func appendEv(t *testing.T, st *store.SQLite, source, deliveryID string, body []byte) store.Event {
	t.Helper()
	ev, err := st.Append(context.Background(), store.AppendInput{
		Source:            source,
		DeliveryID:        deliveryID,
		ProviderTimestamp: time.Now(),
		Headers: map[string]string{
			"Content-Type":             "application/json",
			"Connection":               "keep-alive",
			"Render-Webhook-Signature": "t=1,v1=ab",
			"Render-Webhook-Id":        deliveryID,
		},
		Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

type recordedRequest struct {
	URL     string
	Method  string
	Body    []byte
	Headers http.Header
}

func recordingTarget(t *testing.T, status func() int, recorded *[]recordedRequest, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*recorded = append(*recorded, recordedRequest{
			URL:     r.URL.String(),
			Method:  r.Method,
			Body:    body,
			Headers: r.Header.Clone(),
		})
		mu.Unlock()
		w.WriteHeader(status())
	}))
}

func TestDispatcherAdvancesCursorOn2xx(t *testing.T) {
	m, st, notifier := setupManager(t)
	var (
		got []recordedRequest
		mu  sync.Mutex
	)
	srv := recordingTarget(t, func() int { return 200 }, &got, &mu)
	t.Cleanup(srv.Close)

	sub, secret := newSub(t, st, "render", srv.URL)
	m.Add(sub, secret)

	for i := 0; i < 3; i++ {
		ev := appendEv(t, st, "render", fmt.Sprintf("d-%d", i), []byte(fmt.Sprintf("body-%d", i)))
		notifier.Publish("render", ev.Sequence)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("got %d requests", len(got))
	}
	// In-order delivery.
	for i, r := range got {
		want := fmt.Sprintf("body-%d", i)
		if string(r.Body) != want {
			t.Fatalf("got[%d].Body = %q, want %q", i, r.Body, want)
		}
		if r.Headers.Get("Connection") != "" {
			t.Fatalf("hop-by-hop Connection header forwarded")
		}
		if r.Headers.Get("X-Hooks-Source") != "render" {
			t.Fatalf("X-Hooks-Source missing")
		}
		if r.Headers.Get("X-Hooks-Delivery-Id") == "" {
			t.Fatalf("X-Hooks-Delivery-Id missing")
		}
		if r.Headers.Get("Render-Webhook-Signature") == "" {
			t.Fatalf("provider Render-Webhook-Signature was stripped (spec says only hop-by-hop)")
		}
		if r.Headers.Get("Render-Webhook-Id") == "" {
			t.Fatalf("provider Render-Webhook-Id was stripped (spec says only hop-by-hop)")
		}
	}

	updated, _ := st.PushSubscriptions().Get(context.Background(), sub.ID)
	if updated.Cursor != 3 {
		t.Fatalf("cursor = %d, want 3", updated.Cursor)
	}
	if updated.ConsecutiveFailures != 0 {
		t.Fatalf("failures = %d", updated.ConsecutiveFailures)
	}
}

func TestDispatcherDoesNotAdvanceOnNon2xx(t *testing.T) {
	m, st, notifier := setupManager(t)
	var status atomic.Int32
	status.Store(500)
	var (
		got []recordedRequest
		mu  sync.Mutex
	)
	srv := recordingTarget(t, func() int { return int(status.Load()) }, &got, &mu)
	t.Cleanup(srv.Close)

	sub, secret := newSub(t, st, "render", srv.URL)
	m.Add(sub, secret)

	ev := appendEv(t, st, "render", "d-0", []byte("body"))
	notifier.Publish("render", ev.Sequence)

	// Wait for at least one attempt.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fresh, _ := st.PushSubscriptions().Get(context.Background(), sub.ID)
		if fresh.ConsecutiveFailures >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	fresh, _ := st.PushSubscriptions().Get(context.Background(), sub.ID)
	if fresh.Cursor != 0 {
		t.Fatalf("cursor = %d, want 0", fresh.Cursor)
	}
	if fresh.ConsecutiveFailures < 1 {
		t.Fatalf("expected at least 1 failure, got %d", fresh.ConsecutiveFailures)
	}
	if !strings.Contains(fresh.LastError, "500") {
		t.Fatalf("last_error = %q", fresh.LastError)
	}

	// Recovery resets counter.
	status.Store(200)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fresh, _ = st.PushSubscriptions().Get(context.Background(), sub.ID)
		if fresh.Cursor == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if fresh.Cursor != 1 || fresh.ConsecutiveFailures != 0 {
		t.Fatalf("after recovery: %+v", fresh)
	}
}

func TestSignatureMatchesConsumerVerification(t *testing.T) {
	m, st, _ := setupManager(t)
	const secret = "consumer-secret"
	var captured recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = recordedRequest{Body: body, Headers: r.Header.Clone()}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	sub := store.PushSubscription{
		ID: "x", Source: "render", TargetURL: srv.URL,
		SigningSecretHash: "argon2id$dummy", CreatedAt: time.Now().UTC(),
	}
	if err := st.PushSubscriptions().Insert(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	m.Add(sub, secret)

	body := []byte(`{"hello":"world"}`)
	ev := appendEv(t, st, "render", "d-1", body)
	m.Notifier.Publish("render", ev.Sequence)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if captured.Headers != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if captured.Headers == nil {
		t.Fatal("no request received")
	}

	header := captured.Headers.Get("X-Hooks-Signature")
	parts := strings.Split(header, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		t.Fatalf("bad signature header: %q", header)
	}
	tsRaw := strings.TrimPrefix(parts[0], "t=")
	gotV1 := strings.TrimPrefix(parts[1], "v1=")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(captured.Body)
	wantV1 := hex.EncodeToString(mac.Sum(nil))
	if gotV1 != wantV1 {
		t.Fatalf("v1 mismatch: got %s want %s", gotV1, wantV1)
	}
	if _, err := strconv.ParseInt(tsRaw, 10, 64); err != nil {
		t.Fatalf("t not numeric: %v", err)
	}
}

func TestRotateTakesEffectOnNextAttempt(t *testing.T) {
	m, st, notifier := setupManager(t)

	signatureCh := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		signatureCh <- r.Header.Get("X-Hooks-Signature")
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	sub, secret := newSub(t, st, "render", srv.URL)
	m.Add(sub, secret)

	ev1 := appendEv(t, st, "render", "d-0", []byte("a"))
	notifier.Publish("render", ev1.Sequence)
	first := <-signatureCh

	// Rotate secret.
	m.Rotate(sub.ID, "new-secret")
	ev2 := appendEv(t, st, "render", "d-1", []byte("b"))
	notifier.Publish("render", ev2.Sequence)
	second := <-signatureCh

	if first == second {
		t.Fatalf("signatures identical after rotate")
	}
}

func TestPauseStopsDispatch(t *testing.T) {
	m, st, notifier := setupManager(t)
	var (
		got []recordedRequest
		mu  sync.Mutex
	)
	srv := recordingTarget(t, func() int { return 200 }, &got, &mu)
	t.Cleanup(srv.Close)

	sub, secret := newSub(t, st, "render", srv.URL)
	m.Add(sub, secret)

	if err := st.PushSubscriptions().Pause(context.Background(), sub.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	m.Pause(sub.ID)

	for i := 0; i < 3; i++ {
		ev := appendEv(t, st, "render", fmt.Sprintf("d-%d", i), []byte("x"))
		notifier.Publish("render", ev.Sequence)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("paused sub got %d requests", len(got))
	}
}

func TestReplayDoesNotAdvanceCursor(t *testing.T) {
	m, st, _ := setupManager(t)
	var (
		got []recordedRequest
		mu  sync.Mutex
	)
	srv := recordingTarget(t, func() int { return 200 }, &got, &mu)
	t.Cleanup(srv.Close)

	// Register the sub with a high cursor so the worker never picks up our
	// test event via live delivery — we want only the explicit ReplayOne
	// call to land at the target.
	const cursorAhead = int64(999)
	sub := store.PushSubscription{
		ID:                "sub-replay",
		Source:            "render",
		TargetURL:         srv.URL,
		SigningSecretHash: "argon2id$dummy",
		Cursor:            cursorAhead,
		CreatedAt:         time.Now().UTC(),
	}
	if err := st.PushSubscriptions().Insert(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	const secret = "test-secret"
	m.Add(sub, secret)

	ev := appendEv(t, st, "render", "d-0", []byte("body-0"))

	m.ReplayOne(context.Background(), ev)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if got[0].Headers.Get("X-Hooks-Replay") != "1" {
		t.Fatalf("missing X-Hooks-Replay")
	}
	fresh, _ := st.PushSubscriptions().Get(context.Background(), sub.ID)
	if fresh.Cursor != cursorAhead {
		t.Fatalf("cursor moved during replay: %d -> %d", cursorAhead, fresh.Cursor)
	}
	_ = ev
}

func TestTestDoesNotAdvanceCursor(t *testing.T) {
	m, st, _ := setupManager(t)
	var (
		got []recordedRequest
		mu  sync.Mutex
	)
	srv := recordingTarget(t, func() int { return 200 }, &got, &mu)
	t.Cleanup(srv.Close)

	sub, secret := newSub(t, st, "render", srv.URL)
	m.Add(sub, secret)

	if err := m.Test(context.Background(), sub.ID); err != nil {
		t.Fatalf("Test: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Headers.Get("X-Hooks-Test") != "1" {
		t.Fatalf("missing X-Hooks-Test")
	}
	fresh, _ := st.PushSubscriptions().Get(context.Background(), sub.ID)
	if fresh.Cursor != 0 {
		t.Fatalf("cursor changed: %d", fresh.Cursor)
	}
}

func TestBackoffBounded(t *testing.T) {
	m, _, _ := setupManager(t)
	if got := backoff(50, m); got > DefaultBackoffCap {
		t.Fatalf("backoff exceeds cap: %v", got)
	}
	for i := 0; i < 50; i++ {
		if got := backoff(1, m); got < 0 || got >= 100*time.Millisecond {
			t.Fatalf("low-failures backoff out of bounds: %v", got)
		}
	}
}
