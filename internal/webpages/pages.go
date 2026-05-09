// Package webpages serves the unauthenticated, server-rendered HTML pages
// that complement the JSON auth API: /login, /signup, and (in a follow-up)
// /device.
//
// The forms post back to themselves rather than to /api/auth/login. On
// success the handler issues the same hooks_session and hooks_csrf
// cookies the JSON /api/auth/login endpoint would, then redirects with a
// 303 See Other so a refresh does not re-submit.
//
// CSRF here is a pre-session double-submit. The general-purpose CSRF
// middleware in internal/web only fires for cookie-authenticated
// (hooks_session-bearing) requests, so login and signup are out of its
// scope. To still defend against cross-origin form submission, GET seeds
// a hooks_csrf_pre cookie and embeds the same value in the form's hidden
// csrf_token field; POST verifies the two with a constant-time compare.
package webpages

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/invites"
	"github.com/onebusaway/hooks/internal/ratelimit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
)

//go:embed templates/*.tmpl.html
var templatesFS embed.FS

// PreSessionCSRFCookie is the cookie name used to seed a CSRF token for
// pre-session forms (login, signup, device-pairing). It is distinct from
// hooks_csrf (which is the per-session token rotated on login) so that a
// fresh login can replace it without colliding with a stale unauthenticated
// token. The cookie is HttpOnly=false (the form needs the value) and
// SameSite=Lax just like the post-session CSRF cookie.
const PreSessionCSRFCookie = "hooks_csrf_pre"

// SignupFunc validates an invite, hashes the password, and inserts the
// user atomically. It returns the inserted user on success, or a typed
// error mapped to a user-visible message on failure.
type SignupFunc func(ctx context.Context, code, email, name string, password secret.String, now time.Time) (store.User, error)

// Pages is the handler set for /login and /signup.
type Pages struct {
	Auth   *auth.Manager
	Signup SignupFunc
	Logger *slog.Logger
	Now    func() time.Time

	tpls *template.Template
}

// New constructs a Pages handler. Templates are parsed once at
// construction; both /login and /signup share the same set. The Pages
// handler reads auth.Manager.Cookies.TrustProxyHeaders to mirror the
// post-session cookie's Secure flag policy on the pre-session CSRF cookie.
func New(authMgr *auth.Manager, signup SignupFunc, logger *slog.Logger) (*Pages, error) {
	tpls, err := template.New("").ParseFS(templatesFS, "templates/*.tmpl.html")
	if err != nil {
		return nil, fmt.Errorf("parse webpages templates: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Pages{
		Auth:   authMgr,
		Signup: signup,
		Logger: logger,
		Now:    time.Now,
		tpls:   tpls,
	}, nil
}

// Register mounts /login and /signup on mux. Callers should not wrap
// these in the CSRF middleware: the page handlers manage their own
// pre-session CSRF cookie and verify it inline.
func (p *Pages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", p.LoginGET)
	mux.HandleFunc("POST /login", p.LoginPOST)
	mux.HandleFunc("GET /signup", p.SignupGET)
	mux.HandleFunc("POST /signup", p.SignupPOST)
}

// LoginGET renders the login form, seeding a pre-session CSRF cookie if
// not already present.
func (p *Pages) LoginGET(w http.ResponseWriter, r *http.Request) {
	csrf := p.ensurePreSessionCSRF(w, r)
	if csrf == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	p.render(w, "login", map[string]any{
		"CSRFToken": csrf,
		"Email":     "",
		"Error":     "",
		"Next":      next,
	})
}

// LoginPOST handles form submission, verifies password via auth.Manager,
// issues session + CSRF cookies, and redirects on success.
func (p *Pages) LoginPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !p.checkPreSessionCSRF(r) {
		http.Error(w, "csrf token mismatch", http.StatusForbidden)
		return
	}

	email := strings.TrimSpace(r.Form.Get("email"))
	password := r.Form.Get("password")
	next := safeNext(r.URL.Query().Get("next"))
	renderLoginErr := func(msg string) {
		csrf := p.ensurePreSessionCSRF(w, r)
		p.render(w, "login", map[string]any{
			"CSRFToken": csrf, "Email": email, "Error": msg, "Next": next,
		})
	}

	if email == "" || password == "" {
		renderLoginErr("Email and password are required.")
		return
	}

	u, err := p.Auth.Authenticate(r.Context(), email, secret.String(password))
	if errors.Is(err, auth.ErrBadCredentials) {
		renderLoginErr("Invalid email or password.")
		return
	}
	if errors.Is(err, auth.ErrDeactivated) {
		renderLoginErr("Account deactivated.")
		return
	}
	if err != nil {
		p.warn(r.Context(), "webpages: login authenticate failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cookieValue, _, err := p.Auth.CreateSession(r.Context(), u.ID, r.UserAgent(), clientIP(r))
	if err != nil {
		p.warn(r.Context(), "webpages: login create session failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := p.Auth.SetCookies(w, r, cookieValue); err != nil {
		p.warn(r.Context(), "webpages: login set cookies failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.clearPreSessionCSRF(w, r)
	p.recordAudit(r.Context(), u.ID, audit.ActionSessionCreate, "user", u.ID, nil)

	dest := next
	if dest == "" {
		dest = "/inspector"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// SignupGET renders the signup form. Expects ?code= query parameter; if
// absent the form prompts for the code via a separate input. (Empty code
// at submit time is rejected by the underlying signup function.)
func (p *Pages) SignupGET(w http.ResponseWriter, r *http.Request) {
	csrf := p.ensurePreSessionCSRF(w, r)
	if csrf == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	p.render(w, "signup", map[string]any{
		"CSRFToken": csrf,
		"Code":      code,
		"Email":     "",
		"Name":      "",
		"Error":     "",
	})
}

// SignupPOST handles form submission for signup.
func (p *Pages) SignupPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !p.checkPreSessionCSRF(r) {
		http.Error(w, "csrf token mismatch", http.StatusForbidden)
		return
	}

	code := strings.TrimSpace(r.Form.Get("code"))
	email := strings.TrimSpace(r.Form.Get("email"))
	name := strings.TrimSpace(r.Form.Get("name"))
	password := r.Form.Get("password")

	renderErr := func(msg string) {
		csrf := p.ensurePreSessionCSRF(w, r)
		p.render(w, "signup", map[string]any{
			"CSRFToken": csrf, "Code": code, "Email": email, "Name": name, "Error": msg,
		})
	}

	if code == "" || email == "" || name == "" || password == "" {
		renderErr("All fields are required.")
		return
	}

	if _, err := p.Signup(r.Context(), code, email, name, secret.String(password), p.Now().UTC()); err != nil {
		renderErr(signupErrorMessage(err))
		return
	}

	p.clearPreSessionCSRF(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ensurePreSessionCSRF reads the pre-session CSRF cookie. If absent, it
// generates a fresh value and writes the cookie. Returns the value so it
// can be embedded in the rendered form. On entropy failure it logs and
// returns an empty string; callers should treat that as a 500 condition
// rather than render a form whose token will never validate.
func (p *Pages) ensurePreSessionCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(PreSessionCSRFCookie); err == nil && c.Value != "" {
		return c.Value
	}
	val, err := secret.NewRandom()
	if err != nil {
		p.warn(r.Context(), "webpages: csrf seed failed", slog.Any("err", err))
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     PreSessionCSRFCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: false,
		Secure:   p.requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Hour / time.Second),
	})
	return val
}

func (p *Pages) checkPreSessionCSRF(r *http.Request) bool {
	c, err := r.Cookie(PreSessionCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	tok := r.Form.Get("csrf_token")
	if tok == "" {
		return false
	}
	return secret.EqualString(tok, c.Value)
}

func (p *Pages) clearPreSessionCSRF(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     PreSessionCSRFCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   p.requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// signupErrorMessage maps an invites.Provision error to a user-visible
// string. The raw error is logged separately before display.
func signupErrorMessage(err error) string {
	switch {
	case errors.Is(err, invites.ErrSignupInviteNotFound):
		return "Invite not found."
	case errors.Is(err, invites.ErrSignupInviteConsumed):
		return "Invite already used."
	case errors.Is(err, invites.ErrSignupInviteExpired):
		return "Invite has expired."
	case errors.Is(err, invites.ErrSignupBadPassword):
		return "Password must be at least 12 characters and not contain your email."
	case errors.Is(err, invites.ErrSignupEmailInUse):
		return "An account with that email already exists."
	default:
		return "Could not create account. Please try again."
	}
}

// DefaultSignupFunc returns a SignupFunc backed by invites.Provision, the
// shared core that also serves /api/auth/signup. server.Build wires this
// in.
func DefaultSignupFunc(invStore store.InviteStore, uStore store.UserStore, rec audit.Recorder) SignupFunc {
	return func(ctx context.Context, code, email, name string, password secret.String, now time.Time) (store.User, error) {
		return invites.Provision(ctx, invStore, uStore, rec, code, email, name, password, now)
	}
}

func (p *Pages) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.tpls.ExecuteTemplate(w, name, data); err != nil {
		p.warn(context.Background(), "webpages: render", slog.String("name", name), slog.Any("err", err))
	}
}

func (p *Pages) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	if p.Logger == nil {
		return
	}
	p.Logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

func (p *Pages) recordAudit(ctx context.Context, actor, action, targetType, targetID string, meta map[string]any) {
	if p.Auth == nil || p.Auth.Audit == nil {
		return
	}
	a := actor
	p.Auth.Audit.Record(ctx, store.AuditEvent{
		ActorUserID: &a,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    meta,
	})
}

// safeNext sanitizes the ?next= query parameter so a redirect cannot be
// hijacked to a foreign host. Only paths starting with a single "/" and
// not "//" (protocol-relative) are accepted.
func safeNext(s string) string {
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return ""
	}
	// Reject anything that contains \ or other URL-foolery.
	if u, err := url.Parse(s); err != nil || u.Host != "" || u.Scheme != "" {
		return ""
	}
	return s
}

// clientIP delegates to ratelimit.KeyByIP, which net.SplitHostPorts the
// RemoteAddr and handles bracketed IPv6 correctly. Tier-3 task 17.4
// consolidated client-IP extraction onto that helper.
func clientIP(r *http.Request) string {
	return ratelimit.KeyByIP(r)
}

// requestIsHTTPS mirrors auth.Manager's policy: r.TLS is the canonical
// signal; X-Forwarded-Proto is honored only when the operator opted in
// via web.trust_proxy_headers (auth.Manager.Cookies.TrustProxyHeaders).
func (p *Pages) requestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if p.Auth != nil && p.Auth.Cookies.TrustProxyHeaders {
		if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
			return true
		}
	}
	return false
}
