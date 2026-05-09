package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLogout_RevokesPATAndDeletesProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := saveProfile("default", profile{
		ServerURL: "http://example",
		Token:     "tok",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	var revokeCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/me/tokens/self/revoke" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		revokeCalled.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	_, code := captureStdout(t, func() int {
		return cmdLogout(globals{Server: srv.URL, Token: "tok", Profile: "default"}, nil)
	})
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !revokeCalled.Load() {
		t.Errorf("revoke not called")
	}
	if _, err := loadProfile("default"); err == nil {
		t.Errorf("expected profile deleted")
	}
}

func TestLogout_RevokeFails_StillDeletesAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := saveProfile("default", profile{
		ServerURL: "http://x", Token: "tok",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oops"}`))
	}))
	defer srv.Close()

	_, code := captureStdout(t, func() int {
		return cmdLogout(globals{Server: srv.URL, Token: "tok", Profile: "default"}, nil)
	})
	if code == 0 {
		t.Errorf("expected non-zero exit on revoke failure")
	}
	if _, err := loadProfile("default"); err == nil {
		t.Errorf("expected profile deleted even on revoke failure")
	}
}

func TestLogout_NoProfile_NoCrash(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// No HOOKS_TOKEN, no profile — exit cleanly with no work to do.
	_, code := captureStdout(t, func() int {
		return cmdLogout(globals{}, nil)
	})
	if code != 0 {
		t.Errorf("exit = %d, want 0 (nothing to do)", code)
	}
}

func TestLogout_404FromServerIsNotAFailure(t *testing.T) {
	// A 404 from /api/me/tokens/self/revoke means the bearer doesn't own
	// the resolved token (system token, or already-revoked). That's not
	// a logout failure — the credential is effectively gone server-side.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := saveProfile("default", profile{
		ServerURL: "http://x", Token: "tok",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()

	_, code := captureStdout(t, func() int {
		return cmdLogout(globals{Server: srv.URL, Token: "tok", Profile: "default"}, nil)
	})
	if code != 0 {
		t.Errorf("exit = %d, want 0 on 404", code)
	}
	if _, err := loadProfile("default"); err == nil {
		t.Errorf("expected profile deleted")
	}
}
