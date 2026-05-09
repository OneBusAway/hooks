package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/onebusaway/hooks/internal/auth"
)

func mux(t *testing.T) *http.ServeMux {
	t.Helper()
	m := http.NewServeMux()
	m.Handle("POST /protected", Middleware(CSRFConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	return m
}

func newPost(srv *httptest.Server, csrfCookie, csrfToken, origin string) *http.Request {
	body := strings.NewReader("csrf_token=" + csrfToken)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/protected", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "session"})
	if csrfCookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookie, Value: csrfCookie})
	}
	return req
}

func TestCSRF_HappyPath(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req := newPost(srv, "tok123", "tok123", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCSRF_MissingOrigin_403(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req := newPost(srv, "tok", "tok", "")
	// Strip the Referer too so we hit the missing-origin branch.
	req.Header.Del("Referer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCSRF_MismatchedOrigin_403(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req := newPost(srv, "tok", "tok", "https://attacker.example/")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCSRF_OriginNull_403(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req := newPost(srv, "tok", "tok", "null")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCSRF_MissingCookie_403(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req := newPost(srv, "", "tok", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCSRF_MismatchedToken_403(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req := newPost(srv, "expected", "different", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCSRF_BearerOnly_Bypasses(t *testing.T) {
	srv := httptest.NewServer(mux(t))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/protected", bytes.NewReader(nil))
	// No cookies; bearer-only.
	req.Header.Set("Authorization", "Bearer xyz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer-only should bypass: %d", resp.StatusCode)
	}
}

// TestCSRF_LegacyBearerInCookie_Bypasses covers §16.9: the legacy
// inspector path stuffs a raw bearer token into a cookie. server.Build
// is expected to install a SkipFunc that recognizes that format and
// bypasses CSRF for those callers. This test exercises the SkipFunc
// branch specifically — distinct from TestCSRF_BearerOnly_Bypasses,
// which fires on the "no hooks_session cookie at all" branch. We send
// a request that carries BOTH a non-empty hooks_session AND the legacy
// cookie, so without the SkipFunc the request would proceed into
// Origin/CSRF-token checks and fail.
func TestCSRF_LegacyBearerInCookie_Bypasses(t *testing.T) {
	const legacyCookie = "hooks_token"
	skipCalls := 0
	cfg := CSRFConfig{
		SkipFunc: func(r *http.Request) bool {
			skipCalls++
			c, err := r.Cookie(legacyCookie)
			return err == nil && c.Value != ""
		},
	}
	m := http.NewServeMux()
	m.Handle("POST /protected", Middleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/protected", bytes.NewReader(nil))
	// Crucial: a non-empty hooks_session means the empty-value bypass
	// branch (csrf.go:65) does NOT fire. Only a SkipFunc that recognizes
	// the legacy hooks_token can let the request through; without it,
	// Origin enforcement would 403.
	req.AddCookie(&http.Cookie{Name: "hooks_session", Value: "anything-not-empty"})
	req.AddCookie(&http.Cookie{Name: legacyCookie, Value: "legacy-bearer-plaintext"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy raw-bearer cookie should bypass CSRF via SkipFunc: %d", resp.StatusCode)
	}
	if skipCalls == 0 {
		t.Errorf("SkipFunc was never invoked — middleware bypassed via a different branch (test masks the legacy path)")
	}

	// Negative half: same shape without the legacy cookie — SkipFunc
	// returns false, the request continues into CSRF enforcement and
	// gets a 403 (no Origin, no csrf cookie/token).
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/protected", bytes.NewReader(nil))
	req2.AddCookie(&http.Cookie{Name: "hooks_session", Value: "anything-not-empty"})
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatalf("without legacy cookie the request must NOT bypass CSRF; got 200")
	}
}

func TestCSRF_SafeMethod_Bypasses(t *testing.T) {
	m := http.NewServeMux()
	m.Handle("GET /probe", Middleware(CSRFConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/probe")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}
