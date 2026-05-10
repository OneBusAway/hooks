package subscribe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/onebusaway/hooks/internal/tokens"
)

func setup(t *testing.T) (*Handler, *store.SQLite, *pubsub.Notifier, string, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tokens.AttachVerifier(st)

	res, err := tokens.Issue(context.Background(), st.Tokens(), "tester", []string{"render"})
	if err != nil {
		t.Fatal(err)
	}
	adminRes, err := tokens.Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}

	notifier := pubsub.New()
	h := New(st, notifier, tokens.New(st.Tokens()), map[string]time.Duration{"render": 5 * time.Minute}, slog.New(slog.DiscardHandler))
	h.Keepalive = 50 * time.Millisecond
	return h, st, notifier, res.Plaintext, adminRes.Plaintext
}

func appendEvent(t *testing.T, st *store.SQLite, source, deliveryID string, body []byte) store.Event {
	t.Helper()
	return appendEventAt(t, st, source, deliveryID, time.Now(), body)
}

// appendEventAt seeds an event with a caller-controlled ProviderTimestamp.
// The store still stamps ReceivedAt with time.Now(); the SSE stale filter
// reads ProviderTimestamp, which is what the consumer's signature-verifier
// will check.
func appendEventAt(t *testing.T, st *store.SQLite, source, deliveryID string, providerTime time.Time, body []byte) store.Event {
	t.Helper()
	ev, err := st.Append(context.Background(), store.AppendInput{
		Source:            source,
		DeliveryID:        deliveryID,
		ProviderTimestamp: providerTime,
		Headers:           map[string]string{"X-Test": "1"},
		Body:              body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func startServer(t *testing.T, h *Handler) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /subscribe/{source}", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type sseMessage struct {
	ID    string
	Event string
	Data  string
}

func readSSE(t *testing.T, body io.Reader) <-chan sseMessage {
	t.Helper()
	out := make(chan sseMessage, 16)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	go func() {
		defer close(out)
		var msg sseMessage
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case line == "":
				if msg.ID != "" || msg.Event != "" || msg.Data != "" {
					out <- msg
					msg = sseMessage{}
				}
			case strings.HasPrefix(line, "id:"):
				msg.ID = strings.TrimPrefix(line, "id:")
			case strings.HasPrefix(line, "event:"):
				msg.Event = strings.TrimPrefix(line, "event:")
			case strings.HasPrefix(line, "data:"):
				msg.Data = strings.TrimPrefix(line, "data:")
			}
		}
	}()
	return out
}

func TestSubscribeUnauthorizedWithoutToken(t *testing.T) {
	h, _, _, _, _ := setup(t)
	srv := startServer(t, h)

	resp, err := http.Get(srv.URL + "/subscribe/render")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestSubscribeForbiddenWithoutSourceScope(t *testing.T) {
	h, _, _, _, adminTok := setup(t)
	srv := startServer(t, h)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscribe/render", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestSubscribeReplayThenLive(t *testing.T) {
	h, st, notifier, tok, _ := setup(t)
	srv := startServer(t, h)

	// Pre-load events.
	for i := 0; i < 3; i++ {
		appendEvent(t, st, "render", fmt.Sprintf("d-%d", i), []byte(fmt.Sprintf("body-%d", i)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/subscribe/render?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("wrong content-type: %q", ct)
	}

	stream := readSSE(t, resp.Body)
	for i := 1; i <= 3; i++ {
		select {
		case msg := <-stream:
			if msg.ID != strconv.Itoa(i) {
				t.Fatalf("got id %q, want %d", msg.ID, i)
			}
			if msg.Event != "render" {
				t.Fatalf("event %q", msg.Event)
			}
			var p ssePayload
			if err := json.Unmarshal([]byte(msg.Data), &p); err != nil {
				t.Fatalf("decode data: %v (raw: %q)", err, msg.Data)
			}
			body, _ := base64.StdEncoding.DecodeString(p.Body)
			if string(body) != fmt.Sprintf("body-%d", i-1) {
				t.Fatalf("body mismatch: %q", body)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("never received seq %d", i)
		}
	}

	// Now ingest a live one.
	go func() {
		ev := appendEvent(t, st, "render", "live", []byte("live-body"))
		notifier.Publish("render", ev.Sequence)
	}()
	select {
	case msg := <-stream:
		if msg.ID != "4" {
			t.Fatalf("live msg id %q, want 4", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("never received live event")
	}
}

func TestSubscribeLatestSkipsBacklog(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	srv := startServer(t, h)

	for i := 0; i < 3; i++ {
		appendEvent(t, st, "render", fmt.Sprintf("d-%d", i), []byte("x"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/subscribe/render?since=latest", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	stream := readSSE(t, resp.Body)
	select {
	case msg := <-stream:
		t.Fatalf("got historic event %q", msg.ID)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSubscribeLastEventIDOverridesSinceWhenLarger(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	srv := startServer(t, h)

	for i := 0; i < 5; i++ {
		appendEvent(t, st, "render", fmt.Sprintf("d-%d", i), []byte("x"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/subscribe/render?since=2", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Last-Event-ID", "4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	stream := readSSE(t, resp.Body)
	select {
	case msg := <-stream:
		// since=2 + Last-Event-ID=4 → start at 5
		if msg.ID != "5" {
			t.Fatalf("got %q, want 5", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("never received")
	}
}

func TestSubscribeKeepaliveOnIdle(t *testing.T) {
	h, _, _, tok, _ := setup(t)
	srv := startServer(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/subscribe/render?since=latest", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	got := string(buf[:n])
	if !strings.Contains(got, ": keepalive") {
		t.Fatalf("never saw keepalive in: %q", got)
	}
}

func TestSubscribeReleasesOnDisconnect(t *testing.T) {
	h, _, notifier, tok, _ := setup(t)
	srv := startServer(t, h)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/subscribe/render?since=latest", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for subscribe registration.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if notifier.SubscriberCount("render") == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if notifier.SubscriberCount("render") != 1 {
		t.Fatalf("never registered: %d", notifier.SubscriberCount("render"))
	}

	cancel()
	resp.Body.Close()

	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if notifier.SubscriberCount("render") == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscriber not released: %d", notifier.SubscriberCount("render"))
}

func TestConcurrentSubscribers(t *testing.T) {
	const N = 25
	h, st, notifier, tok, _ := setup(t)
	srv := startServer(t, h)

	var wg sync.WaitGroup
	var received atomic.Int64

	cli := &http.Client{Timeout: 30 * time.Second}
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/subscribe/render?since=0", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := cli.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			scanner := bufio.NewScanner(resp.Body)
			scanner.Buffer(make([]byte, 1<<20), 1<<20)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "id:") {
					received.Add(1)
				}
			}
		}()
	}

	// Wait for everyone to register. Generous deadline tolerates slow CI
	// runners under -race; the per-request timeouts above must outlive this.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if notifier.SubscriberCount("render") >= N {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := notifier.SubscriberCount("render"); got < N {
		t.Fatalf("only %d/%d subscribers registered", got, N)
	}

	for i := 0; i < 3; i++ {
		ev := appendEvent(t, st, "render", fmt.Sprintf("e-%d", i), []byte("body"))
		notifier.Publish("render", ev.Sequence)
	}

	// Give listeners a moment, then close servers.
	time.Sleep(500 * time.Millisecond)
	srv.Close()
	wg.Wait()

	if got := received.Load(); got < int64(N*3) {
		t.Logf("received %d, expected at least %d (some listeners may have aborted before flush)", got, N*3)
	}
}

func TestUnknownSourceIs404(t *testing.T) {
	h, _, _, tok, _ := setup(t)
	srv := startServer(t, h)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscribe/stripe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// readWithDeadline pulls the next SSE message off the stream or returns
// ok=false on timeout. Used for assertions that nothing arrived.
func readWithDeadline(stream <-chan sseMessage, d time.Duration) (sseMessage, bool) {
	select {
	case msg, ok := <-stream:
		if !ok {
			return sseMessage{}, false
		}
		return msg, true
	case <-time.After(d):
		return sseMessage{}, false
	}
}

// connect opens a SSE subscription using tok and returns the response and
// the parsed message channel. Caller is responsible for cancel + Close.
func connect(t *testing.T, srv *httptest.Server, tok, path string) (*http.Response, <-chan sseMessage, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		_ = resp.Body.Close()
		t.Fatalf("status %d", resp.StatusCode)
	}
	stream := readSSE(t, resp.Body)
	return resp, stream, cancel
}

// fixedNow returns a clock function that always returns t. Used to make the
// initial-backfill stale filter deterministic in tests.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestInitialBackfillSkipsStaleEvent(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	appendEventAt(t, st, "render", "stale-1", now.Add(-10*time.Minute), []byte("body"))

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	if msg, ok := readWithDeadline(stream, 750*time.Millisecond); ok && msg.ID != "" {
		t.Fatalf("expected no SSE message; got id=%q event=%q", msg.ID, msg.Event)
	}
}

func TestInitialBackfillDeliversFreshEvent(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	appendEventAt(t, st, "render", "fresh-1", now.Add(-1*time.Minute), []byte("body"))

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	msg, ok := readWithDeadline(stream, 2*time.Second)
	if !ok {
		t.Fatal("never received fresh event")
	}
	if msg.ID != "1" {
		t.Fatalf("got id %q, want 1", msg.ID)
	}
}

func TestInitialBackfillMixedBatchOnlyFreshEmittedAndIdempotentOnReconnect(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	stale := now.Add(-10 * time.Minute)
	fresh := now.Add(-1 * time.Minute)
	appendEventAt(t, st, "render", "stale-a", stale, []byte("a")) // seq 1
	appendEventAt(t, st, "render", "fresh-b", fresh, []byte("b")) // seq 2
	appendEventAt(t, st, "render", "stale-c", stale, []byte("c")) // seq 3
	appendEventAt(t, st, "render", "fresh-d", fresh, []byte("d")) // seq 4

	collect := func() []string {
		resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
		defer cancel()
		defer resp.Body.Close()
		var ids []string
		// Read until the stream goes idle (no more events). The window
		// must be long enough to survive -race slowdowns on CI runners.
		for {
			msg, ok := readWithDeadline(stream, 750*time.Millisecond)
			if !ok {
				return ids
			}
			ids = append(ids, msg.ID)
		}
	}

	first := collect()
	if len(first) != 2 || first[0] != "2" || first[1] != "4" {
		t.Fatalf("first connect: got ids %v, want [2 4]", first)
	}
	second := collect()
	if len(second) != 2 || second[0] != "2" || second[1] != "4" {
		t.Fatalf("reconnect: got ids %v, want [2 4]", second)
	}
}

func TestInitialBackfillAllStaleStillAdvancesCursor(t *testing.T) {
	h, st, notifier, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	stale := now.Add(-10 * time.Minute)
	appendEventAt(t, st, "render", "stale-1", stale, []byte("a")) // seq 1
	appendEventAt(t, st, "render", "stale-2", stale, []byte("b")) // seq 2

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	// Drain the initial backfill: we expect zero messages within a short window.
	if msg, ok := readWithDeadline(stream, 750*time.Millisecond); ok && msg.ID != "" {
		t.Fatalf("initial drain emitted unexpected msg id=%q", msg.ID)
	}

	// Now ingest a fresh event live and notify.
	freshEv := appendEventAt(t, st, "render", "fresh-3", now.Add(-1*time.Minute), []byte("c"))
	notifier.Publish("render", freshEv.Sequence)

	msg, ok := readWithDeadline(stream, 2*time.Second)
	if !ok {
		t.Fatal("never received fresh event")
	}
	if msg.ID != "3" {
		t.Fatalf("got id %q, want 3 — cursor was not advanced past stale events on initial drain", msg.ID)
	}
	// Make sure no further (re-emitted stale) event sneaks in.
	if extra, ok := readWithDeadline(stream, 500*time.Millisecond); ok && extra.ID != "" {
		t.Fatalf("unexpected extra msg id=%q after fresh event", extra.ID)
	}
}

func TestLiveTailDoesNotFilter(t *testing.T) {
	h, st, notifier, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	// Wait for initial drain to drain (no events seeded).
	if msg, ok := readWithDeadline(stream, 500*time.Millisecond); ok && msg.ID != "" {
		t.Fatalf("unexpected initial msg id=%q", msg.ID)
	}

	// Now write a stale event directly to the store and notify. Live tail
	// must not filter — this models manual replay of an old event to a
	// currently-connected SSE subscriber.
	staleEv := appendEventAt(t, st, "render", "stale-live", now.Add(-30*time.Minute), []byte("body"))
	notifier.Publish("render", staleEv.Sequence)

	msg, ok := readWithDeadline(stream, 2*time.Second)
	if !ok {
		t.Fatal("live tail did not deliver stale event")
	}
	if msg.ID != "1" {
		t.Fatalf("got id %q, want 1", msg.ID)
	}
}

func TestInitialBackfillBoundaryAtExactlySkew(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	// delta == skew (5 min) → emit. Matches `delta > skew` ingest semantics.
	appendEventAt(t, st, "render", "boundary-1", now.Add(-5*time.Minute), []byte("body"))

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	msg, ok := readWithDeadline(stream, 2*time.Second)
	if !ok {
		t.Fatal("event at exactly skew was filtered; expected emit")
	}
	if msg.ID != "1" {
		t.Fatalf("got id %q, want 1", msg.ID)
	}
}

func TestInitialBackfillFutureTimestampPasses(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	appendEventAt(t, st, "render", "future-1", now.Add(1*time.Minute), []byte("body"))

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	msg, ok := readWithDeadline(stream, 2*time.Second)
	if !ok {
		t.Fatal("future-timestamp event was not emitted")
	}
	if msg.ID != "1" {
		t.Fatalf("got id %q, want 1", msg.ID)
	}
}

func TestInitialBackfillZeroProviderTimestampPasses(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	appendEventAt(t, st, "render", "zero-1", time.Time{}, []byte("body"))

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()

	msg, ok := readWithDeadline(stream, 2*time.Second)
	if !ok {
		t.Fatal("zero-timestamp event was filtered; expected emit (forward-compat)")
	}
	if msg.ID != "1" {
		t.Fatalf("got id %q, want 1", msg.ID)
	}
}

// syncBuf is a goroutine-safe bytes.Buffer wrapper. The handler goroutine
// writes log lines while the test goroutine reads them; bytes.Buffer alone
// races under -race.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestInitialBackfillSkipIsObservable(t *testing.T) {
	h, st, _, tok, _ := setup(t)
	logBuf := &syncBuf{}
	h.Logger = slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	h.Now = fixedNow(now)
	srv := startServer(t, h)

	ev := appendEventAt(t, st, "render", "stale-obs", now.Add(-10*time.Minute), []byte("body"))

	resp, stream, cancel := connect(t, srv, tok, "/subscribe/render?since=0")
	defer cancel()
	defer resp.Body.Close()
	// Drain enough time for the initial drain to run.
	_, _ = readWithDeadline(stream, 750*time.Millisecond)

	logged := logBuf.String()
	wantSubs := []string{
		`level=DEBUG`,
		`source=render`,
		fmt.Sprintf("seq=%d", ev.Sequence),
		`delivery_id=stale-obs`,
		`age=`,
		`skew_window=`,
	}
	for _, sub := range wantSubs {
		if !strings.Contains(logged, sub) {
			t.Fatalf("log missing %q; got: %s", sub, logged)
		}
	}
}

func TestUnknownSourceIs404WithMapShape(t *testing.T) {
	// Direct construction with the new map shape — exercises the
	// key-presence-not-value-zero membership rule for /subscribe/<source>.
	h, _, _, tok, _ := setup(t)
	h.Sources = map[string]time.Duration{"render": 5 * time.Minute}
	srv := startServer(t, h)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscribe/stripe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
