package devicepair

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// writeFailingWriter records WriteHeader and refuses to Write the body.
// Stand-in for a TCP connection that drops mid-response.
type writeFailingWriter struct {
	headers http.Header
	code    int
}

func (w *writeFailingWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = http.Header{}
	}
	return w.headers
}
func (w *writeFailingWriter) WriteHeader(code int) { w.code = code }
func (w *writeFailingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("simulated connection reset")
}

func insertApprovedUnfetched(t *testing.T, s *store.SQLite, deviceCode, userCode string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.Insert(context.Background(), store.Token{
		ID: "tok-" + deviceCode, Name: "device-pairing",
		Scopes: []string{"render"}, SecretHash: "$argon2id$placeholder",
		CreatedAt: now, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	plaintext := "plaintext-pat-" + deviceCode
	tokenID := "tok-" + deviceCode
	if err := s.InsertDevicePairing(context.Background(), store.DevicePairing{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		Status:          store.DevicePairingStatusApprovedUnfetched,
		CreatedAt:       now,
		ExpiresAt:       now.Add(15 * time.Minute),
		RequestedScopes: []string{"render"},
		PlaintextToken:  &plaintext,
		TokenID:         &tokenID,
	}); err != nil {
		t.Fatalf("seed pairing: %v", err)
	}
}

// TestPoll_ResponseWriteFails_DoesNotMarkFetched is the regression test for
// the design.md invariant: "Do not bind the `done` transition to TCP-write
// success. If the response write fails, the row stays approved_unfetched
// and the next poll succeeds."
func TestPoll_ResponseWriteFails_DoesNotMarkFetched(t *testing.T) {
	s := newTest(t)
	insertApprovedUnfetched(t, s, "dc-writefail", "WRITE-FAIL")

	api := NewAPI(s, fakeAuth{}, nil, "")
	body, _ := json.Marshal(pollRequest{DeviceCode: "dc-writefail"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/poll", bytes.NewReader(body))
	fw := &writeFailingWriter{}
	api.Poll(fw, req)

	// Give any (incorrectly-spawned) goroutine ample time to run.
	time.Sleep(100 * time.Millisecond)

	got, err := s.GetDevicePairingByDeviceCode(context.Background(), "dc-writefail")
	if err != nil {
		t.Fatalf("GetDevicePairingByDeviceCode: %v", err)
	}
	if got.Status != store.DevicePairingStatusApprovedUnfetched {
		t.Errorf("status mutated despite write failure: got %q, want %q",
			got.Status, store.DevicePairingStatusApprovedUnfetched)
	}
	if got.PlaintextToken == nil {
		t.Error("plaintext_token was NULLed despite write failure")
	}
}

// markFetchedFailingStore wraps a real DevicePairingStore but errors out
// of MarkFetched. Used to verify the new logger emits a warn line.
type markFetchedFailingStore struct {
	store.DevicePairingStore
	called atomic.Int32
}

func (m *markFetchedFailingStore) MarkFetched(ctx context.Context, deviceCode string) error {
	m.called.Add(1)
	return errors.New("simulated mark-fetched failure")
}

// TestPoll_MarkFetchedFailure_LogsWarn verifies the new (Tier 1, fix #1)
// logging behavior: a failing MarkFetched is observable instead of silent.
func TestPoll_MarkFetchedFailure_LogsWarn(t *testing.T) {
	s := newTest(t)
	insertApprovedUnfetched(t, s, "dc-markfail", "MARK-FAIL")

	api := NewAPI(s, fakeAuth{}, nil, "")
	wrap := &markFetchedFailingStore{DevicePairingStore: api.Pairings}
	api.Pairings = wrap
	// The deferred MarkFetched goroutine writes to the buffer concurrently
	// with the test's polling reads; bytes.Buffer is not goroutine-safe, so
	// serialize through a mutex-wrapped writer.
	logBuf := newSyncBuffer()
	api.Logger = slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(pollRequest{DeviceCode: "dc-markfail"})
	resp, err := http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll: %d", resp.StatusCode)
	}

	// Wait for goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if wrap.called.Load() > 0 && logBuf.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if wrap.called.Load() == 0 {
		t.Fatal("MarkFetched was never called on a successful poll")
	}
	if !strings.Contains(logBuf.String(), "mark-fetched") {
		t.Errorf("expected mark-fetched-failure warn log, got: %q", logBuf.String())
	}
}

// syncBuffer is a goroutine-safe bytes.Buffer wrapper for tests that
// observe slog output written from a background goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSyncBuffer() *syncBuffer { return &syncBuffer{} }

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
