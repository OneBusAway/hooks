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

// fakeInviteServer is a minimal stand-in for /api/invites that records
// each request so tests can assert wire shape without booting the server.
type fakeInviteServer struct {
	srv *httptest.Server

	mu      sync.Mutex
	calls   []fakeMeCall
	invites []map[string]any
}

func newFakeInviteServer(t *testing.T) *fakeInviteServer {
	t.Helper()
	f := &fakeInviteServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeInviteServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, fakeMeCall{
		method: r.Method,
		path:   r.URL.RequestURI(),
		auth:   r.Header.Get("Authorization"),
		body:   string(body),
	})
	invites := f.invites
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/invites":
		writeFakeJSON(w, http.StatusCreated, map[string]any{
			"code":           "ABCD2EFGH3JK4MNP",
			"role":           "user",
			"default_scopes": []string{"render"},
			"bootstrap":      false,
			"created_at":     "2026-05-09T00:00:00Z",
			"expires_at":     "2026-05-16T00:00:00Z",
		})
	case r.Method == http.MethodGet && r.URL.Path == "/api/invites":
		if invites == nil {
			invites = []map[string]any{}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"invites": invites})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/invites/"):
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeInviteServer) lastCall(t *testing.T) fakeMeCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("no requests recorded")
	}
	return f.calls[len(f.calls)-1]
}

func TestInviteCreate_DefaultsToUserRoleNoTTL(t *testing.T) {
	f := newFakeInviteServer(t)
	out, code := captureStdout(t, func() int {
		return cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"},
			[]string{"create"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	c := f.lastCall(t)
	if c.method != http.MethodPost || c.path != "/api/invites" {
		t.Fatalf("method/path = %s %s", c.method, c.path)
	}
	if c.auth != "Bearer admin-pat" {
		t.Fatalf("auth = %q", c.auth)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(c.body), &got); err != nil {
		t.Fatalf("body decode: %v (%s)", err, c.body)
	}
	if got["role"] != "user" {
		t.Errorf("role = %v, want user (default)", got["role"])
	}
	if _, has := got["ttl_seconds"]; has {
		t.Errorf("ttl_seconds should be omitted when --ttl unset, got %v", got["ttl_seconds"])
	}
	if _, has := got["default_scopes"]; has {
		t.Errorf("default_scopes should be omitted when --scopes unset, got %v", got["default_scopes"])
	}
	if !strings.Contains(out, "ABCD2EFGH3JK4MNP") {
		t.Errorf("output missing code: %s", out)
	}
	if !strings.Contains(out, "/signup?code=ABCD2EFGH3JK4MNP") {
		t.Errorf("output missing signup URL: %s", out)
	}
}

func TestInviteCreate_AdminRoleScopesTTL(t *testing.T) {
	f := newFakeInviteServer(t)
	out, code := captureStdout(t, func() int {
		return cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"},
			[]string{"create", "--role", "admin", "--scopes", "render,stripe", "--ttl", "30d"})
	})
	if code != 0 {
		t.Fatalf("exit = %d; out=%s", code, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(f.lastCall(t).body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["role"] != "admin" {
		t.Errorf("role = %v", got["role"])
	}
	scopes, _ := got["default_scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "render" || scopes[1] != "stripe" {
		t.Errorf("default_scopes = %v", got["default_scopes"])
	}
	want := float64(30 * 24 * 3600)
	if got["ttl_seconds"] != want {
		t.Errorf("ttl_seconds = %v, want %v", got["ttl_seconds"], want)
	}
}

func TestInviteCreate_RejectsBadTTL(t *testing.T) {
	f := newFakeInviteServer(t)
	code := cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"},
		[]string{"create", "--ttl", "tomorrow"})
	if code == 0 {
		t.Fatal("expected non-zero exit on bad --ttl")
	}
}

func TestInviteCreate_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"role must be admin or user"}`))
	}))
	t.Cleanup(srv.Close)
	code := cmdInvite(globals{Server: srv.URL, Token: "admin-pat"},
		[]string{"create", "--role", "owner"})
	if code == 0 {
		t.Fatal("expected non-zero exit when server rejects role")
	}
}

func TestInviteList_DefaultExcludesConsumed(t *testing.T) {
	f := newFakeInviteServer(t)
	_, code := captureStdout(t, func() int {
		return cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"}, []string{"list"})
	})
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	if !strings.Contains(f.lastCall(t).path, "consumed=false") {
		t.Errorf("default list should pass consumed=false: %s", f.lastCall(t).path)
	}
}

func TestInviteList_IncludeConsumedDropsFilter(t *testing.T) {
	f := newFakeInviteServer(t)
	_, _ = captureStdout(t, func() int {
		return cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"},
			[]string{"list", "--include-consumed"})
	})
	if strings.Contains(f.lastCall(t).path, "consumed=") {
		t.Errorf("--include-consumed should drop consumed= filter: %s", f.lastCall(t).path)
	}
}

func TestInviteList_PrintsTable(t *testing.T) {
	f := newFakeInviteServer(t)
	f.invites = []map[string]any{
		{"code": "AAAA1111", "role": "user", "expires_at": "2026-06-01T00:00:00Z"},
		{"code": "BBBB2222", "role": "admin", "consumed_at": "2026-05-10T00:00:00Z"},
	}
	out, code := captureStdout(t, func() int {
		return cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"},
			[]string{"list", "--include-consumed"})
	})
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"AAAA1111", "BBBB2222", "user", "admin"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestInviteRevoke_DeletesByCode(t *testing.T) {
	f := newFakeInviteServer(t)
	_, code := captureStdout(t, func() int {
		return cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"},
			[]string{"revoke", "AAAA1111"})
	})
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	c := f.lastCall(t)
	if c.method != http.MethodDelete || c.path != "/api/invites/AAAA1111" {
		t.Fatalf("method/path = %s %s", c.method, c.path)
	}
}

func TestInviteRevoke_RequiresCode(t *testing.T) {
	f := newFakeInviteServer(t)
	code := cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"}, []string{"revoke"})
	if code == 0 {
		t.Fatal("expected non-zero exit when code missing")
	}
}

func TestInviteRevoke_409Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"invite already consumed"}`))
	}))
	t.Cleanup(srv.Close)
	code := cmdInvite(globals{Server: srv.URL, Token: "admin-pat"},
		[]string{"revoke", "AAAA1111"})
	if code == 0 {
		t.Fatal("expected non-zero exit on 409")
	}
}

func TestInvite_NoArgs_Errors(t *testing.T) {
	f := newFakeInviteServer(t)
	code := cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"}, nil)
	if code == 0 {
		t.Fatal("expected non-zero exit with no subcommand")
	}
}

func TestInvite_UnknownSubcommand_Errors(t *testing.T) {
	f := newFakeInviteServer(t)
	code := cmdInvite(globals{Server: f.srv.URL, Token: "admin-pat"}, []string{"bogus"})
	if code == 0 {
		t.Fatal("expected non-zero exit on unknown subcommand")
	}
}
