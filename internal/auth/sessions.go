// Package auth implements the cookie-based session login flow described in
// add-developer-accounts. It owns:
//
//   - POST /api/auth/login: verify password, create user_sessions row, set
//     hooks_session and hooks_csrf cookies.
//   - POST /api/auth/logout: delete session, clear cookies, audit.
//   - Session middleware: parse cookie, lookup, SHA-256 verify, slide
//     expiry, attach (*User, *Session) to context.
//   - Background sweeper: periodically delete expired user_sessions.
//
// Plaintext password material always flows through internal/secret.String at
// boundaries; password hashing happens in internal/users (the store package
// never imports argon2 — design.md §"Storage layer" preserves that).
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
)

// Cookie names used by the session/CSRF flow. These are referenced by the
// inspector's HTML rendering and the CSRF middleware so they're public.
const (
	SessionCookie = "hooks_session"
	CSRFCookie    = "hooks_csrf"
)

// DefaultSessionTTL is the sliding-expiry window for a session cookie.
// design.md §"Cookie session storage" pegs it at 30 days; configurable
// via web.session_ttl in hooks.yaml when wired through Build.
const DefaultSessionTTL = 30 * 24 * time.Hour

// MinSlideInterval is the granularity at which a touched session is
// re-extended in the database. Touching every request burns writes; we
// only persist a new expires_at when last_used_at is more than this old.
const MinSlideInterval = time.Hour

// CookieOptions configures the cookie attributes set on login.
type CookieOptions struct {
	// TTL is the sliding-expiry window. Zero -> DefaultSessionTTL.
	TTL time.Duration
	// TrustProxyHeaders, when true, sets Secure on the cookie if the
	// X-Forwarded-Proto request header is "https". Default false.
	TrustProxyHeaders bool
}

// Manager is the session-management surface used by handlers and the
// inspector. It is safe for concurrent use. Construct via NewManager;
// fields are unexported so a zero-value Manager{} with nil deps is a
// compile-time error rather than a first-call panic.
type Manager struct {
	sessions store.SessionStore
	users    store.UserStore
	audit    audit.Recorder
	logger   *slog.Logger
	now      func() time.Time
	cookies  CookieOptions
}

// NewManager constructs a Manager with sensible defaults.
func NewManager(s store.SessionStore, u store.UserStore, a audit.Recorder, opts CookieOptions) *Manager {
	if opts.TTL == 0 {
		opts.TTL = DefaultSessionTTL
	}
	return &Manager{
		sessions: s,
		users:    u,
		audit:    a,
		now:      time.Now,
		cookies:  opts,
	}
}

// SetLogger attaches an *slog.Logger to the manager. Used by server.Build
// after construction (the logger is shared across the wiring root) and by
// tests to silence output. A nil logger is treated as "no logging" by the
// internal warn helpers.
func (m *Manager) SetLogger(l *slog.Logger) { m.logger = l }

// Auditor returns the audit recorder the manager was constructed with.
// Exposed because internal/webpages records its own audit events through
// the same recorder rather than carrying a separate dependency.
func (m *Manager) Auditor() audit.Recorder { return m.audit }

// TrustProxyHeaders reports whether the manager was constructed to honor
// X-Forwarded-Proto when deciding cookie Secure flags. Used by
// internal/webpages so its pre-session cookies follow the same policy.
func (m *Manager) TrustProxyHeaders() bool { return m.cookies.TrustProxyHeaders }

// CreateSession inserts a new user_sessions row backing a fresh login,
// returning the cookie plaintext (id.secret) the caller should set on the
// response. The session secret is 32 random bytes; we store its SHA-256
// digest, NOT Argon2id (design.md §"Authentication: web sessions"), since
// the input space is high-entropy and per-request Argon2 is pure cost.
func (m *Manager) CreateSession(ctx context.Context, userID, userAgent, ip string) (cookie string, sess store.Session, err error) {
	plaintext, err := secret.NewRandom()
	if err != nil {
		return "", store.Session{}, err
	}
	id := uuid.NewString()
	now := m.now().UTC()
	sess = store.Session{
		ID:         id,
		UserID:     userID,
		SecretHash: hashSessionSecret(plaintext),
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(m.cookies.TTL),
		UserAgent:  truncate(userAgent, 256),
		IP:         truncate(ip, 64),
	}
	if err := m.sessions.Insert(ctx, sess); err != nil {
		return "", store.Session{}, err
	}
	return id + "." + plaintext, sess, nil
}

// Lookup parses the cookie value, looks the row up by id, runs a constant-
// time SHA-256 verify against the supplied plaintext, slides the expiry
// when warranted, and returns the (User, Session). If anything fails it
// returns ErrInvalid and the caller should clear the cookie.
func (m *Manager) Lookup(ctx context.Context, cookieValue string) (store.User, store.Session, error) {
	id, plaintext, ok := strings.Cut(cookieValue, ".")
	if !ok || id == "" || plaintext == "" {
		return store.User{}, store.Session{}, ErrInvalid
	}
	sess, err := m.sessions.LookupByID(ctx, id)
	if err != nil {
		return store.User{}, store.Session{}, ErrInvalid
	}
	want := hashSessionSecret(plaintext)
	if !secret.EqualString(want, sess.SecretHash) {
		return store.User{}, store.Session{}, ErrInvalid
	}
	now := m.now().UTC()
	if now.After(sess.ExpiresAt) {
		// Best-effort cleanup of the now-expired row.
		_ = m.sessions.Delete(ctx, sess.ID)
		return store.User{}, store.Session{}, ErrExpired
	}
	user, err := m.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return store.User{}, store.Session{}, ErrInvalid
	}
	if user.DeactivatedAt != nil {
		_ = m.sessions.Delete(ctx, sess.ID)
		return store.User{}, store.Session{}, ErrInvalid
	}

	// Slide the expiry only when the persisted last_used_at is "stale enough".
	// This keeps writes off the hot path under sustained inspector use.
	if now.Sub(sess.LastUsedAt) >= MinSlideInterval {
		newExp := now.Add(m.cookies.TTL)
		if err := m.sessions.Touch(ctx, sess.ID, now, newExp); err != nil {
			// Touching is best-effort; do not fail auth on a write hiccup.
			_ = err
		} else {
			sess.LastUsedAt = now
			sess.ExpiresAt = newExp
		}
	}
	return user, sess, nil
}

// DeleteSession revokes the row backing the cookie. Verifies the secret
// half of the cookie value (constant-time SHA-256 compare) BEFORE issuing
// the DELETE so an attacker holding only the session id cannot force-
// logout a victim. Returns ErrInvalid for malformed cookies, missing
// rows, or hash mismatches; the row remains untouched on any of these
// paths. The caller should clear browser cookies on the response
// regardless of the outcome.
func (m *Manager) DeleteSession(ctx context.Context, cookieValue string) (string, error) {
	id, plaintext, ok := strings.Cut(cookieValue, ".")
	if !ok || id == "" || plaintext == "" {
		return "", ErrInvalid
	}
	sess, err := m.sessions.LookupByID(ctx, id)
	if err != nil {
		return "", ErrInvalid
	}
	want := hashSessionSecret(plaintext)
	if !secret.EqualString(want, sess.SecretHash) {
		return "", ErrInvalid
	}
	if err := m.sessions.Delete(ctx, id); err != nil {
		return id, err
	}
	return id, nil
}

// DeleteSessionsByUser invalidates every active session for userID.
// Used by admin password-reset flows so a rotated password takes effect
// immediately for any browser that already had a cookie. Returns
// nil-on-empty (no rows) rather than ErrInvalid; callers do not need
// to know whether the user had any live sessions.
func (m *Manager) DeleteSessionsByUser(ctx context.Context, userID string) error {
	return m.sessions.DeleteByUser(ctx, userID)
}

// SetCookies writes the hooks_session and hooks_csrf cookies onto w.
// SetCookies is shared between login and the CSRF cookie rotation that
// happens on session creation: every call generates a fresh hooks_csrf
// value via secret.NewRandom, so a prior session's CSRF token cannot
// authenticate a freshly created session.
func (m *Manager) SetCookies(w http.ResponseWriter, r *http.Request, cookieValue string) (csrfToken string, err error) {
	csrf, err := secret.NewRandom()
	if err != nil {
		return "", err
	}
	secure := requestIsHTTPS(r, m.cookies.TrustProxyHeaders)
	maxAge := int(m.cookies.TTL / time.Second)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	return csrf, nil
}

// ClearCookies expires both cookies on w. Used by logout and on any
// validation failure so a cookie that no longer authenticates is also
// removed from the browser.
func (m *Manager) ClearCookies(w http.ResponseWriter, r *http.Request) {
	secure := requestIsHTTPS(r, m.cookies.TrustProxyHeaders)
	for _, name := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: name == SessionCookie,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

// hashSessionSecret returns sha256-hex of plaintext, lower-cased. Cheap
// per-request CPU; constant-time compare via secret.EqualString.
func hashSessionSecret(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func requestIsHTTPS(r *http.Request, trustProxy bool) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if trustProxy {
		if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
