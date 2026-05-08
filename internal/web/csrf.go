// Package web provides HTTP-layer middleware shared between the auth API,
// the inspector, and the user-facing /api/me surface. Today it carries
// CSRF + Origin enforcement; design-doc CSRF strategy is described in
// docs/security.md.
package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/secret"
)

// CSRFTokenFormField is the form field / JSON key the middleware looks at.
const CSRFTokenFormField = "csrf_token"

// CSRFTokenHeader is an alternate transport for SPAs sending JSON.
const CSRFTokenHeader = "X-Hooks-CSRF"

// CSRFConfig configures the middleware. ExpectedHost defaults to the
// request's r.Host, but operators behind ingress controllers may need to
// pin a single canonical host so a relayed Origin still matches.
type CSRFConfig struct {
	ExpectedHost string
	// SkipFunc, if non-nil, returns true for requests that should bypass
	// the middleware entirely. Bearer-only API calls (no hooks_session
	// cookie) and the legacy raw-bearer-in-cookie path return true here.
	SkipFunc func(r *http.Request) bool
}

// Errors surfaced by the middleware in 403 responses (logged, not echoed
// to clients beyond a generic message).
var (
	errMissingOrigin   = errors.New("csrf: missing Origin and Referer")
	errOriginMismatch  = errors.New("csrf: Origin/Referer host mismatch")
	errOriginNull      = errors.New("csrf: Origin is null")
	errMissingCSRF     = errors.New("csrf: missing csrf cookie")
	errMissingTok      = errors.New("csrf: missing csrf token in form/header")
	errMismatchedToken = errors.New("csrf: token mismatch")
)

// Middleware returns an http.Handler that protects mutating cookie-
// authenticated requests. design.md §"CSRF and request-origin defenses"
// describes the contract:
//
//   - Origin header must match the request host. Origin: null is rejected.
//   - hooks_csrf cookie value must equal the form/JSON csrf_token field.
//   - Comparison is constant-time.
//   - Bearer-only requests (no hooks_session cookie) bypass the check.
//   - Safe methods (GET/HEAD/OPTIONS) bypass.
func Middleware(cfg CSRFConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if cfg.SkipFunc != nil && cfg.SkipFunc(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer-only requests: no hooks_session cookie at all -> bypass.
		if c, err := r.Cookie(auth.SessionCookie); err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		if err := checkOrigin(r, cfg.ExpectedHost); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if err := checkToken(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func checkOrigin(r *http.Request, expectedHost string) error {
	origin := r.Header.Get("Origin")
	if origin == "null" {
		return errOriginNull
	}
	wantHost := expectedHost
	if wantHost == "" {
		wantHost = r.Host
	}
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return errOriginMismatch
		}
		if !hostsMatch(u.Host, wantHost) {
			return errOriginMismatch
		}
		return nil
	}
	// Origin missing -> fall back to Referer.
	ref := r.Header.Get("Referer")
	if ref == "" {
		return errMissingOrigin
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		return errMissingOrigin
	}
	if !hostsMatch(u.Host, wantHost) {
		return errOriginMismatch
	}
	return nil
}

func hostsMatch(a, b string) bool {
	// Strip default ports if either side has one explicitly.
	a = strings.TrimSuffix(a, ":80")
	a = strings.TrimSuffix(a, ":443")
	b = strings.TrimSuffix(b, ":80")
	b = strings.TrimSuffix(b, ":443")
	return strings.EqualFold(a, b)
}

func checkToken(r *http.Request) error {
	cookie, err := r.Cookie(auth.CSRFCookie)
	if err != nil || cookie.Value == "" {
		return errMissingCSRF
	}
	tok := r.Header.Get(CSRFTokenHeader)
	if tok == "" {
		// Form / multipart parsed lazily; ParseForm fills r.Form for
		// application/x-www-form-urlencoded automatically. For JSON
		// bodies callers should use the header transport.
		_ = r.ParseForm()
		tok = r.Form.Get(CSRFTokenFormField)
	}
	if tok == "" {
		return errMissingTok
	}
	if !secret.EqualString(tok, cookie.Value) {
		return errMismatchedToken
	}
	return nil
}
