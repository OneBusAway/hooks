package tokens

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// ContextKey is a private type for context keys to avoid collisions.
type ContextKey int

const (
	// ContextKeyToken stores the authenticated *store.Token on a request.
	ContextKeyToken ContextKey = iota
)

// TokenFrom returns the authenticated token attached to the request context,
// if any.
func TokenFrom(ctx context.Context) (store.Token, bool) {
	t, ok := ctx.Value(ContextKeyToken).(store.Token)
	return t, ok
}

// TouchInterval is the minimum gap between consecutive last_used_at writes
// for the same token. Without this debounce, every authenticated request
// becomes a SQLite write.
const TouchInterval = time.Minute

// Authenticator validates bearer tokens and attaches them to the request
// context. The required scope is supplied by RequireScope or RequireSourceOrAdmin.
type Authenticator struct {
	Tokens store.TokenStore
	Now    func() time.Time

	touchMu       sync.Mutex
	lastTouchedAt map[string]time.Time
}

// New returns an Authenticator using the real wall clock.
func New(ts store.TokenStore) *Authenticator {
	return &Authenticator{Tokens: ts, Now: time.Now, lastTouchedAt: map[string]time.Time{}}
}

// Resolve looks up the bearer token from r and returns it, or an error.
func (a *Authenticator) Resolve(r *http.Request) (store.Token, error) {
	plaintext, err := extractBearer(r)
	if err != nil {
		return store.Token{}, err
	}
	return a.ResolvePlaintext(r.Context(), plaintext)
}

// ResolvePlaintext is the variant used by callers (e.g. the inspector cookie
// flow) that already have the plaintext outside an Authorization header.
func (a *Authenticator) ResolvePlaintext(ctx context.Context, plaintext string) (store.Token, error) {
	if plaintext == "" {
		return store.Token{}, errMissingToken
	}
	tok, err := a.Tokens.LookupByPlaintext(ctx, plaintext)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Token{}, errInvalidToken
		}
		return store.Token{}, err
	}
	if tok.RevokedAt != nil {
		return store.Token{}, errInvalidToken
	}
	// Reject tokens whose absolute expires_at has elapsed. Treat as invalid
	// (401) rather than forbidden (403): the credential is no longer
	// authentic, not the request unauthorized.
	if tok.ExpiresAt != nil && a.Now().After(*tok.ExpiresAt) {
		return store.Token{}, errInvalidToken
	}
	a.maybeTouch(ctx, tok.ID)
	return tok, nil
}

// maybeTouch persists last_used_at at most once per TouchInterval per token,
// best-effort.
func (a *Authenticator) maybeTouch(ctx context.Context, id string) {
	now := a.Now()
	a.touchMu.Lock()
	if prev, ok := a.lastTouchedAt[id]; ok && now.Sub(prev) < TouchInterval {
		a.touchMu.Unlock()
		return
	}
	a.lastTouchedAt[id] = now
	a.touchMu.Unlock()
	_ = a.Tokens.TouchLastUsed(ctx, id, now)
}

// RequireScope returns a middleware that admits only requests whose token has
// the specified scope.
func (a *Authenticator) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := a.Resolve(r)
			if err != nil {
				writeAuthError(w, err)
				return
			}
			if !store.HasScope(tok.Scopes, scope) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), ContextKeyToken, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthorizeSource validates the bearer token and returns it if its scopes
// include source. Admin scope ALONE does not grant subscribe access.
// PAT-kind tokens are explicitly rejected per task 8.7: only listener-kind
// tokens (and legacy rows whose kind is empty) authorize /subscribe/<source>.
func (a *Authenticator) AuthorizeSource(r *http.Request, source string) (store.Token, error) {
	tok, err := a.Resolve(r)
	if err != nil {
		return store.Token{}, err
	}
	if tok.Kind == store.TokenKindPAT {
		return store.Token{}, errForbidden
	}
	if !store.HasScope(tok.Scopes, source) {
		return store.Token{}, errForbidden
	}
	return tok, nil
}

// AuthorizeAdmin validates the bearer token and requires the admin scope.
func (a *Authenticator) AuthorizeAdmin(r *http.Request) (store.Token, error) {
	tok, err := a.Resolve(r)
	if err != nil {
		return store.Token{}, err
	}
	if !store.HasScope(tok.Scopes, store.ScopeAdmin) {
		return store.Token{}, errForbidden
	}
	return tok, nil
}

var (
	errInvalidToken = errors.New("invalid bearer token")
	errMissingToken = errors.New("missing bearer token")
	errForbidden    = errors.New("forbidden")
)

// IsAuthError reports whether err originated from token resolution and should
// produce HTTP 401.
func IsAuthError(err error) bool {
	return errors.Is(err, errInvalidToken) || errors.Is(err, errMissingToken)
}

// IsForbidden reports whether err should produce HTTP 403.
func IsForbidden(err error) bool { return errors.Is(err, errForbidden) }

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case IsForbidden(err):
		http.Error(w, "forbidden", http.StatusForbidden)
	case IsAuthError(err):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// WriteAuthError writes the appropriate HTTP status based on err. Exposed so
// handlers that call AuthorizeSource/Admin directly can render consistent
// responses.
func WriteAuthError(w http.ResponseWriter, err error) { writeAuthError(w, err) }

func extractBearer(r *http.Request) (string, error) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if h == "" {
		// Allow ?access_token= for SSE convenience? No — every documented
		// path uses Authorization, and EventSource lacks header support but
		// hooksctl uses an HTTP client.
		return "", errMissingToken
	}
	if !strings.HasPrefix(h, prefix) {
		return "", errInvalidToken
	}
	return strings.TrimSpace(h[len(prefix):]), nil
}
