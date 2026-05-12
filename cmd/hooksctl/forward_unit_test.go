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
	"testing"
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
