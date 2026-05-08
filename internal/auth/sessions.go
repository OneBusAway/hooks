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
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
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
// inspector. It is safe for concurrent use.
type Manager struct {
	Sessions store.SessionStore
	Users    store.UserStore
	Audit    store.AuditStore
	Now      func() time.Time
	Cookies  CookieOptions
}

// NewManager constructs a Manager with sensible defaults.
func NewManager(s store.SessionStore, u store.UserStore, a store.AuditStore, opts CookieOptions) *Manager {
	if opts.TTL == 0 {
		opts.TTL = DefaultSessionTTL
	}
	return &Manager{
		Sessions: s,
		Users:    u,
		Audit:    a,
		Now:      time.Now,
		Cookies:  opts,
	}
}

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
	now := m.Now().UTC()
	sess = store.Session{
		ID:         id,
		UserID:     userID,
		SecretHash: hashSessionSecret(plaintext),
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(m.Cookies.TTL),
		UserAgent:  truncate(userAgent, 256),
		IP:         truncate(ip, 64),
	}
	if err := m.Sessions.Insert(ctx, sess); err != nil {
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
	sess, err := m.Sessions.LookupByID(ctx, id)
	if err != nil {
		return store.User{}, store.Session{}, ErrInvalid
	}
	want := hashSessionSecret(plaintext)
	if !secret.EqualString(want, sess.SecretHash) {
		return store.User{}, store.Session{}, ErrInvalid
	}
	now := m.Now().UTC()
	if now.After(sess.ExpiresAt) {
		// Best-effort cleanup of the now-expired row.
		_ = m.Sessions.Delete(ctx, sess.ID)
		return store.User{}, store.Session{}, ErrExpired
	}
	user, err := m.Users.GetByID(ctx, sess.UserID)
	if err != nil {
		return store.User{}, store.Session{}, ErrInvalid
	}
	if user.DeactivatedAt != nil {
		_ = m.Sessions.Delete(ctx, sess.ID)
		return store.User{}, store.Session{}, ErrInvalid
	}

	// Slide the expiry only when the persisted last_used_at is "stale enough".
	// This keeps writes off the hot path under sustained inspector use.
	if now.Sub(sess.LastUsedAt) >= MinSlideInterval {
		newExp := now.Add(m.Cookies.TTL)
		if err := m.Sessions.Touch(ctx, sess.ID, now, newExp); err != nil {
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
	sess, err := m.Sessions.LookupByID(ctx, id)
	if err != nil {
		return "", ErrInvalid
	}
	want := hashSessionSecret(plaintext)
	if !secret.EqualString(want, sess.SecretHash) {
		return "", ErrInvalid
	}
	if err := m.Sessions.Delete(ctx, id); err != nil {
		return id, err
	}
	return id, nil
}

// SetCookies writes the hooks_session and hooks_csrf cookies onto w.
// SetCookies is shared between login and the CSRF cookie rotation that
// happens on session creation.
func (m *Manager) SetCookies(w http.ResponseWriter, r *http.Request, cookieValue string) (csrfToken string, err error) {
	csrf, err := secret.NewRandom()
	if err != nil {
		return "", err
	}
	secure := requestIsHTTPS(r, m.Cookies.TrustProxyHeaders)
	maxAge := int(m.Cookies.TTL / time.Second)
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
	secure := requestIsHTTPS(r, m.Cookies.TrustProxyHeaders)
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
