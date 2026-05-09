package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/onebusaway/hooks/internal/store"
)

// ContextKey is the typed key under which Authenticate-derived state is
// stashed on a request's context. Use Manager.FromContext(ctx) to read it.
type ContextKey struct{ name string }

var sessionContextKey = ContextKey{name: "session"}

type sessionContext struct {
	User    store.User
	Session store.Session
}

// FromContext returns the (User, Session) attached by the session
// middleware, or (zero, false) if the request was not cookie-authenticated.
func (m *Manager) FromContext(ctx context.Context) (store.User, store.Session, bool) {
	sc, ok := ctx.Value(sessionContextKey).(*sessionContext)
	if !ok {
		return store.User{}, store.Session{}, false
	}
	return sc.User, sc.Session, true
}

// Middleware returns an http.Handler middleware that, when a hooks_session
// cookie is present, runs Lookup and stashes (User, Session) on the
// request context. Anonymous requests pass through unchanged. Validation
// failures clear the cookie and pass through anonymous so downstream
// authorization layers can decide whether to 401/403/redirect.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, sess, lookupErr := m.Lookup(r.Context(), c.Value)
		if lookupErr != nil {
			// Don't recurse into ClearCookies during the request that's
			// just probing /login; just pass anonymous and let the handler
			// re-issue cookies on a fresh login.
			if errors.Is(lookupErr, ErrExpired) || errors.Is(lookupErr, ErrInvalid) {
				m.ClearCookies(w, r)
			}
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey, &sessionContext{User: user, Session: sess})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
