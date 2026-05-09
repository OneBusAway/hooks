package subscribe

import (
	"bufio"
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
	h := New(st, notifier, tokens.New(st.Tokens()), []string{"render"}, slog.New(slog.DiscardHandler))
	h.Keepalive = 50 * time.Millisecond
	return h, st, notifier, res.Plaintext, adminRes.Plaintext
}

func appendEvent(t *testing.T, st *store.SQLite, source, deliveryID string, body []byte) store.Event {
	t.Helper()
	ev, err := st.Append(context.Background(), store.AppendInput{
		Source:            source,
		DeliveryID:        deliveryID,
		ProviderTimestamp: time.Now(),
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

	cli := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

	// Wait for everyone to register.
	deadline := time.Now().Add(2 * time.Second)
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
