package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/onebusaway/hooks/internal/tui"
)

// --- parseEventPayload ---

func TestParseEventPayload(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	t.Run("happy path", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"delivery_id": "d1",
			"headers":     map[string]string{"Content-Type": "application/json"},
			"body":        encode(`{"event":"test"}`),
		})
		p, err := parseEventPayload(map[string]string{"data": string(raw), "id": "42"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.DeliveryID != "d1" {
			t.Errorf("DeliveryID = %q; want d1", p.DeliveryID)
		}
		if string(p.Body) != `{"event":"test"}` {
			t.Errorf("Body = %q; want {\"event\":\"test\"}", p.Body)
		}
		if p.Headers["Content-Type"] != "application/json" {
			t.Errorf("Headers[Content-Type] = %q", p.Headers["Content-Type"])
		}
	})

	t.Run("malformed JSON returns errSkipEvent", func(t *testing.T) {
		_, err := parseEventPayload(map[string]string{"data": "not-json", "id": "1"})
		if !errors.Is(err, errSkipEvent) {
			t.Errorf("want errSkipEvent, got %v", err)
		}
	})

	t.Run("invalid base64 body returns errSkipEvent", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"delivery_id": "d3",
			"headers":     map[string]string{},
			"body":        "not!!valid!!base64",
		})
		_, err := parseEventPayload(map[string]string{"data": string(raw), "id": "3"})
		if !errors.Is(err, errSkipEvent) {
			t.Errorf("want errSkipEvent, got %v", err)
		}
	})

	t.Run("missing delivery_id falls back to SSE id", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"headers": map[string]string{},
			"body":    encode("body"),
		})
		p, err := parseEventPayload(map[string]string{"data": string(raw), "id": "99"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.DeliveryID != "99" {
			t.Errorf("DeliveryID fallback = %q; want 99", p.DeliveryID)
		}
	})
}

// --- tokenFingerprint ---

func TestTokenFingerprint(t *testing.T) {
	tests := []struct {
		token      string
		wantPrefix string
		wantSuffix string
	}{
		{"abcdefghij1234567890", "abcdef", "890"}, // > 9 runes
		{"abcde", "abc", "cde"},                   // > 3, <= 9 runes
		{"abc", "abc", ""},                        // exactly 3: full token, empty suffix
		{"ab", "ab", ""},                          // <= 3 runes
		{"", "", ""},                              // empty
	}
	for _, tc := range tests {
		prefix, suffix := tokenFingerprint(tc.token)
		if prefix != tc.wantPrefix || suffix != tc.wantSuffix {
			t.Errorf("tokenFingerprint(%q) = (%q, %q); want (%q, %q)",
				tc.token, prefix, suffix, tc.wantPrefix, tc.wantSuffix)
		}
	}
}

// --- streamFromCursorWith errSkipEvent handling ---

func TestStreamFromCursorWith_SkipsErrSkipEvent(t *testing.T) {
	// SSE server: first event triggers errSkipEvent from handle, second is valid.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Event id=1: handle will return errSkipEvent for this one.
		fmt.Fprint(w, "id: 1\nevent: render\ndata: bad\n\n")
		// Event id=2: handled normally.
		fmt.Fprint(w, "id: 2\nevent: render\ndata: good\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(srv.Close)

	var handled []string
	cursor := int64(0)
	cursorPath := filepath.Join(t.TempDir(), "cursor")
	g := globals{Server: srv.URL}

	_ = streamFromCursorWith(context.Background(), g, "tok", "render", &cursor, cursorPath,
		func(_ context.Context, msg map[string]string) error {
			if msg["id"] == "1" {
				return errSkipEvent
			}
			handled = append(handled, msg["id"])
			return nil
		})

	if len(handled) != 1 || handled[0] != "2" {
		t.Errorf("handled = %v; want [2] (event 1 should be skipped)", handled)
	}
	if cursor != 2 {
		t.Errorf("cursor = %d; want 2 (advanced past both events)", cursor)
	}
}

// --- forwardOneTUI ---

// tuiCapture accumulates TUI messages sent by forwardOneTUI via a headless
// tea.Program (WithoutRenderer + WithInput(nil)).
type tuiCapture struct {
	received  []tui.DeliveryReceivedMsg
	completed []tui.DeliveryCompletedMsg
}

type captureProgModel struct{ c *tuiCapture }

func (m captureProgModel) Init() tea.Cmd { return nil }
func (m captureProgModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tui.QuitMsg:
		return m, tea.Quit
	case tui.DeliveryReceivedMsg:
		m.c.received = append(m.c.received, msg)
	case tui.DeliveryCompletedMsg:
		m.c.completed = append(m.c.completed, msg)
	}
	return m, nil
}
func (m captureProgModel) View() tea.View { return tea.NewView("") }

func newCaptureProg(c *tuiCapture) *tea.Program {
	return tea.NewProgram(captureProgModel{c: c},
		tea.WithoutRenderer(),
		tea.WithInput(nil),
	)
}

// runCaptureProg starts the program in a goroutine and returns a channel that
// closes when prog.Run() returns.
func runCaptureProg(prog *tea.Program) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = prog.Run()
	}()
	return done
}

func TestForwardOneTUI_MalformedPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("target must not be reached for a malformed event")
	}))
	defer target.Close()

	capt := &tuiCapture{}
	prog := newCaptureProg(capt)
	done := runCaptureProg(prog)

	msg := map[string]string{
		"id":    "42",
		"event": "render",
		"data":  "not-valid-json",
	}
	err := forwardOneTUI(ctx, prog, &http.Client{Timeout: time.Second}, target.URL, msg, "render", false)
	prog.Send(tui.QuitMsg{})
	<-done

	if !errors.Is(err, errSkipEvent) {
		t.Fatalf("want errSkipEvent, got %v", err)
	}
	if len(capt.received) != 1 {
		t.Fatalf("want 1 DeliveryReceivedMsg, got %d", len(capt.received))
	}
	if capt.received[0].Delivery.Suffix != deliverySuffixMalformed {
		t.Errorf("want Suffix %q, got %q", deliverySuffixMalformed, capt.received[0].Delivery.Suffix)
	}
	if !strings.HasSuffix(capt.received[0].Delivery.Path, "/render") {
		t.Errorf("want Path ending in /render, got %q", capt.received[0].Delivery.Path)
	}
	if len(capt.completed) != 0 {
		t.Errorf("want 0 DeliveryCompletedMsg for malformed, got %d", len(capt.completed))
	}
}

func TestForwardOneTUI_RetryOnNonSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var attempts atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer target.Close()

	body, _ := json.Marshal(map[string]any{
		"delivery_id": "d1",
		"headers":     map[string]string{},
		"body":        base64.StdEncoding.EncodeToString([]byte(`{}`)),
	})
	msg := map[string]string{
		"id":    "1",
		"event": "render",
		"data":  string(body),
	}

	capt := &tuiCapture{}
	prog := newCaptureProg(capt)
	done := runCaptureProg(prog)

	err := forwardOneTUI(ctx, prog, &http.Client{Timeout: 5 * time.Second}, target.URL, msg, "render", false)
	prog.Send(tui.QuitMsg{})
	<-done

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must have at least one DeliveryReceivedMsg (initial in-flight).
	if len(capt.received) < 1 {
		t.Fatalf("want at least 1 DeliveryReceivedMsg, got %d", len(capt.received))
	}

	// Must have an intermediate "retrying" completion for the 503.
	hasRetrying := false
	for _, c := range capt.completed {
		if c.Suffix == deliverySuffixRetrying && c.Status == http.StatusServiceUnavailable {
			hasRetrying = true
		}
	}
	if !hasRetrying {
		t.Errorf("want intermediate DeliveryCompletedMsg with Suffix=%q and Status=503", deliverySuffixRetrying)
	}

	// Final completion must be 200 with no error suffix.
	if len(capt.completed) == 0 {
		t.Fatal("want at least 1 DeliveryCompletedMsg")
	}
	final := capt.completed[len(capt.completed)-1]
	if final.Status != http.StatusOK {
		t.Errorf("want final status 200, got %d", final.Status)
	}
	if final.Suffix != "" {
		t.Errorf("want final suffix '', got %q", final.Suffix)
	}
}

func TestForwardOneTUI_RetryOnTransportError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First request: hijack the connection and close it to simulate a transport error.
	// Subsequent requests: respond with 200.
	var attempts atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("server does not support hijacking")
				return
			}
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	body, _ := json.Marshal(map[string]any{
		"delivery_id": "d1",
		"headers":     map[string]string{},
		"body":        base64.StdEncoding.EncodeToString([]byte(`{}`)),
	})
	msg := map[string]string{
		"id":    "1",
		"event": "render",
		"data":  string(body),
	}

	capt := &tuiCapture{}
	prog := newCaptureProg(capt)
	done := runCaptureProg(prog)

	err := forwardOneTUI(ctx, prog, &http.Client{Timeout: 5 * time.Second}, target.URL, msg, "render", false)
	prog.Send(tui.QuitMsg{})
	<-done

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasTransportErr := false
	for _, c := range capt.completed {
		if c.Suffix == deliverySuffixTransportErr {
			hasTransportErr = true
		}
	}
	if !hasTransportErr {
		t.Errorf("want intermediate DeliveryCompletedMsg with Suffix=%q", deliverySuffixTransportErr)
	}

	final := capt.completed[len(capt.completed)-1]
	if final.Status != http.StatusOK {
		t.Errorf("want final status 200, got %d", final.Status)
	}
	if final.Suffix != "" {
		t.Errorf("want final suffix '', got %q", final.Suffix)
	}
}
