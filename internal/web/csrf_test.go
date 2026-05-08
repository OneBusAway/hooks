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
