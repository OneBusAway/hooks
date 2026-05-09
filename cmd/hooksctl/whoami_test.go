package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWhoami_PrintsProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/me" {
			t.Errorf("path = %q, want /api/me", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pat-xyz" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":        "u1",
			"email":          "alice@example.com",
			"name":           "Alice",
			"role":           "user",
			"default_scopes": []string{"render"},
		})
	}))
	defer srv.Close()

	out, code := captureStdout(t, func() int {
		return cmdWhoami(globals{Server: srv.URL, Token: "pat-xyz"}, nil)
	})
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "alice@example.com") {
		t.Errorf("stdout missing email: %q", out)
	}
	if !strings.Contains(out, "user") {
		t.Errorf("stdout missing role: %q", out)
	}
	if !strings.Contains(out, srv.URL) {
		t.Errorf("stdout missing server URL: %q", out)
	}
}

func TestWhoami_AnonymousReturns401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	code := cmdWhoami(globals{Server: srv.URL, Token: "bad"}, nil)
	if code == 0 {
		t.Errorf("expected non-zero exit on 401, got 0")
	}
}

func TestWhoami_NoTokenAndNoProfile_Errors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	code := cmdWhoami(globals{Server: "http://x"}, nil)
	if code == 0 {
		t.Errorf("expected non-zero exit when unauthenticated, got 0")
	}
}
