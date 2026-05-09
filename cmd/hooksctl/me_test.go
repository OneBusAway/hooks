package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeMeServer is a minimal in-memory stand-in for /api/me/* endpoints.
// Each call records the path, method, and body so tests can assert wire
// shape without booting the full server.
type fakeMeServer struct {
	srv *httptest.Server

	mu     sync.Mutex
	calls  []fakeMeCall
	tokens []map[string]any // tokens fixture used by ListTokens
	subs   []map[string]any // subscriptions fixture used by ListSubs
}

type fakeMeCall struct {
	method string
	path   string
	auth   string
	body   string
}

func newFakeMeServer(t *testing.T) *fakeMeServer {
	t.Helper()
	f := &fakeMeServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeMeServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, fakeMeCall{
		method: r.Method,
		path:   r.URL.RequestURI(),
		auth:   r.Header.Get("Authorization"),
		body:   string(body),
	})
	tokens := f.tokens
	subs := f.subs
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/me/tokens":
		if tokens == nil {
			tokens = []map[string]any{}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
	case r.Method == http.MethodPost && r.URL.Path == "/api/me/tokens":
		writeFakeJSON(w, http.StatusCreated, map[string]any{
			"id":         "tok-new",
			"name":       "ci",
			"scopes":     []string{"render"},
			"kind":       "pat",
			"plaintext":  "secret-shown-once",
			"created_at": "2026-01-01T00:00:00Z",
		})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/me/tokens/") && strings.HasSuffix(r.URL.Path, "/revoke"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/api/me/subscriptions":
		if subs == nil {
			subs = []map[string]any{}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"subscriptions": subs})
	case r.Method == http.MethodPost && r.URL.Path == "/api/me/subscriptions":
		writeFakeJSON(w, http.StatusCreated, map[string]any{
			"subscription": map[string]any{
				"id":         "sub-new",
				"source":     "render",
				"target_url": "https://example.test/hook",
				"cursor":     0,
				"created_at": "2026-01-01T00:00:00Z",
			},
			"signing_secret": "rotated-secret",
		})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/me/subscriptions/"):
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"id":         "sub-1",
			"source":     "render",
			"target_url": "https://example.test/hook",
			"cursor":     7,
			"created_at": "2026-01-01T00:00:00Z",
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/me/subscriptions/"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pause"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/resume"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rotate-secret"):
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"id":             "sub-1",
			"signing_secret": "rotated-secret",
		})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/test"):
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeFakeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeMeServer) lastCall(t *testing.T) fakeMeCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("no requests recorded")
	}
	return f.calls[len(f.calls)-1]
}

// ---------- me token ----------

func TestMeTokenAdd_PostsExpectedBody(t *testing.T) {
	f := newFakeMeServer(t)
	out, code := captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"},
			[]string{"token", "add", "--name", "ci", "--scopes", "render"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; out=%s", code, out)
	}
	c := f.lastCall(t)
	if c.method != http.MethodPost || c.path != "/api/me/tokens" {
		t.Fatalf("method/path = %s %s", c.method, c.path)
	}
	if c.auth != "Bearer pat-xyz" {
		t.Fatalf("auth = %q", c.auth)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(c.body), &got); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, c.body)
	}
	if got["name"] != "ci" {
		t.Errorf("name = %v", got["name"])
	}
	scopes, _ := got["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "render" {
		t.Errorf("scopes = %v", got["scopes"])
	}
	if got["kind"] != "pat" {
		t.Errorf("kind = %v, want pat (default)", got["kind"])
	}
	if !strings.Contains(out, "secret-shown-once") {
		t.Errorf("stdout missing plaintext: %q", out)
	}
}

func TestMeTokenAdd_KindListenerEphemeralExpiresIn(t *testing.T) {
	f := newFakeMeServer(t)
	out, code := captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"},
			[]string{"token", "add", "--name", "fwd", "--scopes", "render,stripe",
				"--kind", "listener", "--ephemeral", "--expires-in", "30m"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(f.lastCall(t).body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["kind"] != "listener" {
		t.Errorf("kind = %v", got["kind"])
	}
	if got["ephemeral"] != true {
		t.Errorf("ephemeral = %v", got["ephemeral"])
	}
	scopes, _ := got["scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "render" || scopes[1] != "stripe" {
		t.Errorf("scopes = %v", got["scopes"])
	}
	want := float64(30 * 60) // JSON numbers decode to float64
	if got["expires_in_seconds"] != want {
		t.Errorf("expires_in_seconds = %v, want %v", got["expires_in_seconds"], want)
	}
}

func TestMeTokenAdd_RejectsUnparseableExpiresIn(t *testing.T) {
	f := newFakeMeServer(t)
	code := cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"},
		[]string{"token", "add", "--name", "x", "--scopes", "render", "--expires-in", "tomorrow"})
	if code == 0 {
		t.Fatal("expected non-zero exit on bad --expires-in")
	}
}

func TestMeTokenList_PrintsTable(t *testing.T) {
	f := newFakeMeServer(t)
	f.tokens = []map[string]any{
		{"id": "tok-1", "name": "ci", "scopes": []string{"render"}, "kind": "pat"},
		{"id": "tok-2", "name": "fwd", "scopes": []string{"render"}, "kind": "listener", "ephemeral": true},
	}
	out, code := captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, []string{"token", "list"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	for _, want := range []string{"tok-1", "tok-2", "ci", "fwd", "listener"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestMeTokenList_IncludeRevokedFlag(t *testing.T) {
	f := newFakeMeServer(t)
	_, _ = captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, []string{"token", "list", "--include-revoked"})
	})
	if !strings.Contains(f.lastCall(t).path, "include_revoked=1") {
		t.Errorf("path missing include_revoked=1: %s", f.lastCall(t).path)
	}
}

func TestMeTokenRevoke_HitsRevokeEndpoint(t *testing.T) {
	f := newFakeMeServer(t)
	out, code := captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, []string{"token", "revoke", "tok-1"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	c := f.lastCall(t)
	if c.method != http.MethodPost || c.path != "/api/me/tokens/tok-1/revoke" {
		t.Fatalf("method/path = %s %s", c.method, c.path)
	}
}

// ---------- me sub ----------

func TestMeSubAdd_PostsExpectedBody(t *testing.T) {
	f := newFakeMeServer(t)
	out, code := captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"},
			[]string{"sub", "add", "--source", "render", "--to", "https://example.test/hook", "--name", "lab"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	c := f.lastCall(t)
	if c.method != http.MethodPost || c.path != "/api/me/subscriptions" {
		t.Fatalf("method/path = %s %s", c.method, c.path)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(c.body), &got); err != nil {
		t.Fatalf("body decode: %v", err)
	}
	if got["source"] != "render" || got["target_url"] != "https://example.test/hook" || got["name"] != "lab" {
		t.Errorf("payload = %v", got)
	}
	if !strings.Contains(out, "rotated-secret") {
		t.Errorf("stdout missing signing secret: %q", out)
	}
}

func TestMeSubList_IncludePausedFlag(t *testing.T) {
	f := newFakeMeServer(t)
	_, _ = captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, []string{"sub", "list", "--include-paused"})
	})
	if !strings.Contains(f.lastCall(t).path, "include_paused=1") {
		t.Errorf("path missing include_paused=1: %s", f.lastCall(t).path)
	}
}

func TestMeSubList_PrintsTable(t *testing.T) {
	f := newFakeMeServer(t)
	f.subs = []map[string]any{
		{"id": "sub-1", "source": "render", "target_url": "https://example.test/hook", "cursor": 12},
	}
	out, code := captureStdout(t, func() int {
		return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, []string{"sub", "list"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	for _, want := range []string{"sub-1", "render", "https://example.test/hook"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestMeSubAction_HitsCorrectEndpoint(t *testing.T) {
	cases := []struct {
		args   []string
		method string
		path   string
	}{
		{[]string{"sub", "pause", "sub-1"}, http.MethodPost, "/api/me/subscriptions/sub-1/pause"},
		{[]string{"sub", "resume", "sub-1"}, http.MethodPost, "/api/me/subscriptions/sub-1/resume"},
		{[]string{"sub", "rotate-secret", "sub-1"}, http.MethodPost, "/api/me/subscriptions/sub-1/rotate-secret"},
		{[]string{"sub", "test", "sub-1"}, http.MethodPost, "/api/me/subscriptions/sub-1/test"},
		{[]string{"sub", "rm", "sub-1"}, http.MethodDelete, "/api/me/subscriptions/sub-1"},
		{[]string{"sub", "get", "sub-1"}, http.MethodGet, "/api/me/subscriptions/sub-1"},
	}
	for _, tc := range cases {
		t.Run(tc.args[1], func(t *testing.T) {
			f := newFakeMeServer(t)
			_, code := captureStdout(t, func() int {
				return cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, tc.args)
			})
			if code != 0 {
				t.Fatalf("exit = %d", code)
			}
			c := f.lastCall(t)
			if c.method != tc.method || c.path != tc.path {
				t.Fatalf("got %s %s, want %s %s", c.method, c.path, tc.method, tc.path)
			}
		})
	}
}

func TestMe_UnknownSubcommand_Errors(t *testing.T) {
	f := newFakeMeServer(t)
	code := cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, []string{"bogus"})
	if code == 0 {
		t.Fatal("expected non-zero exit on unknown subcommand")
	}
}

func TestMe_NoArgs_Errors(t *testing.T) {
	f := newFakeMeServer(t)
	code := cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"}, nil)
	if code == 0 {
		t.Fatal("expected non-zero exit when no subcommand provided")
	}
}

func TestMeTokenAdd_RequiresName(t *testing.T) {
	f := newFakeMeServer(t)
	code := cmdMe(globals{Server: f.srv.URL, Token: "pat-xyz"},
		[]string{"token", "add", "--scopes", "render"})
	if code == 0 {
		t.Fatal("expected non-zero exit when --name is missing")
	}
}
