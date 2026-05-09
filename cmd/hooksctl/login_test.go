package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startTestDevicePairServer stands up a fake /api/auth/device/{start,poll}
// pair. The poll handler returns 202 (pending) the first `pendingCount`
// calls, then 200 with the supplied token + scopes. Interval is set to
// 1 so the test runs fast.
type devicePairTestServer struct {
	srv   *httptest.Server
	polls *atomic.Int32
}

func startTestDevicePairServer(t *testing.T, pendingCount int32, token string, scopes []string) *devicePairTestServer {
	t.Helper()
	r := &devicePairTestServer{polls: new(atomic.Int32)}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/device/start", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev-abc",
			"user_code":        "ABCD-WXYZ",
			"verification_uri": "https://example.com/device",
			"interval":         1,
			"expires_in":       900,
		})
	})
	mux.HandleFunc("/api/auth/device/poll", func(w http.ResponseWriter, _ *http.Request) {
		n := r.polls.Add(1)
		if n <= pendingCount {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":  token,
			"name":   "device-pairing",
			"scopes": scopes,
		})
	})
	r.srv = httptest.NewServer(mux)
	return r
}

func TestLogin_Success_WritesProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	d := startTestDevicePairServer(t, 1, "tok-greatsecret", []string{"render"})
	defer d.srv.Close()

	loginTestClient = d.srv.Client()
	defer func() { loginTestClient = nil }()

	out, code := captureStdout(t, func() int {
		return cmdLogin(globals{
			Server:  d.srv.URL,
			Profile: "default",
		}, nil)
	})
	if code != 0 {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if got := d.polls.Load(); got < 2 {
		t.Errorf("polls = %d, want >= 2", got)
	}
	if !strings.Contains(out, "ABCD-WXYZ") {
		t.Errorf("stdout missing user_code: %q", out)
	}
	p, err := loadProfile("default")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if p.Token != "tok-greatsecret" {
		t.Errorf("profile.Token = %q", p.Token)
	}
	if p.ServerURL != d.srv.URL {
		t.Errorf("profile.ServerURL = %q", p.ServerURL)
	}
}

func TestLogin_Denied_ReturnsNonZero(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/device/start", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "x",
			"user_code":        "X-X",
			"verification_uri": "x",
			"interval":         1,
			"expires_in":       900,
		})
	})
	mux.HandleFunc("/api/auth/device/poll", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"denied"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	loginTestClient = srv.Client()
	defer func() { loginTestClient = nil }()
	_, code := captureStdout(t, func() int {
		return cmdLogin(globals{Server: srv.URL, Profile: "default"}, nil)
	})
	if code == 0 {
		t.Errorf("expected non-zero exit on denied")
	}
	if _, err := loadProfile("default"); err == nil {
		t.Errorf("expected no profile written on denied")
	}
}

func TestLogin_Expired_ReturnsNonZero(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/device/start", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "x", "user_code": "X-X",
			"verification_uri": "x", "interval": 1, "expires_in": 900,
		})
	})
	mux.HandleFunc("/api/auth/device/poll", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"error":"expired"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	loginTestClient = srv.Client()
	defer func() { loginTestClient = nil }()
	_, code := captureStdout(t, func() int {
		return cmdLogin(globals{Server: srv.URL, Profile: "default"}, nil)
	})
	if code == 0 {
		t.Errorf("expected non-zero exit on expired")
	}
}

func TestLogin_PassesScopesAndAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	var got struct {
		Scopes []string
		Admin  bool
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/device/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "x", "user_code": "X-X",
			"verification_uri": "x", "interval": 1, "expires_in": 900,
		})
	})
	mux.HandleFunc("/api/auth/device/poll", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":  "tok",
			"name":   "x",
			"scopes": []string{"render", "admin"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	loginTestClient = srv.Client()
	defer func() { loginTestClient = nil }()
	_, code := captureStdout(t, func() int {
		return cmdLogin(globals{Server: srv.URL, Profile: "default"},
			[]string{"--scopes", "render,stripe", "--admin"})
	})
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "render" || got.Scopes[1] != "stripe" {
		t.Errorf("scopes = %v", got.Scopes)
	}
	if !got.Admin {
		t.Errorf("admin = false, want true")
	}
}

// TestLoginPollHardCap_IsHonored verifies the 15-minute cap exists. We
// trigger the cap by setting a tiny client deadline via a server that
// sleeps longer than the test timeout: simpler is to validate the
// constant directly.
func TestLoginPollHardCap_Is15Minutes(t *testing.T) {
	if loginPollHardCap != 15*time.Minute {
		t.Errorf("loginPollHardCap = %v, want 15m", loginPollHardCap)
	}
}
