package me

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// SessionProvider is implemented by auth.Manager. It returns the session-
// authenticated user attached upstream by the session middleware, if any.
type SessionProvider interface {
	FromContext(ctx context.Context) (store.User, store.Session, bool)
}

// Caller is the resolved /api/me request actor. Token is non-nil only
// when the request was authenticated via bearer PAT.
type Caller struct {
	User  store.User
	Token *store.Token
}

// IsPAT reports whether the request came in via bearer token rather than
// session cookie.
func (c Caller) IsPAT() bool { return c.Token != nil }

// errors used internally; the handler maps them to HTTP statuses via writeAuthErr.
var (
	errAnonymous    = errors.New("me: unauthenticated")
	errKindMismatch = errors.New("me: listener tokens cannot reach /api/me")
	errOwnerless    = errors.New("me: token has no owning user")
	errDeactivated  = errors.New("me: account deactivated")
)

// resolveCaller extracts the calling user from r. Order:
//  1. session cookie (auth middleware attached state).
//  2. bearer token; reject anything other than kind='pat'.
//
// Returns errAnonymous if no credential was presented at all, so the
// caller can decide between 401 and a redirect.
func (a *API) resolveCaller(r *http.Request) (Caller, error) {
	if a.Auth != nil {
		if user, _, ok := a.Auth.FromContext(r.Context()); ok {
			return Caller{User: user}, nil
		}
	}
	if a.Bearer == nil {
		return Caller{}, errAnonymous
	}
	tok, err := a.Bearer.Resolve(r)
	if err != nil {
		return Caller{}, err
	}
	if tok.Kind != store.TokenKindPAT {
		return Caller{}, errKindMismatch
	}
	if tok.OwnerUserID == nil {
		return Caller{}, errOwnerless
	}
	user, err := a.Users.GetByID(r.Context(), *tok.OwnerUserID)
	if err != nil {
		// Token's owning user was deleted between revoke and the next call:
		// treat as ownerless rather than 500 so callers see a clean 403.
		if errors.Is(err, store.ErrNotFound) {
			return Caller{}, errOwnerless
		}
		// Genuine DB error — log so operators correlate, but still return
		// the error so writeAuthErr maps it to 500.
		a.warn(r.Context(), "me: bearer owner lookup failed",
			slog.String("token_id", tok.ID), slog.Any("err", err))
		return Caller{}, err
	}
	if user.DeactivatedAt != nil {
		return Caller{}, errDeactivated
	}
	return Caller{User: user, Token: &tok}, nil
}

// writeAuthErr maps internal errors to the right HTTP code + JSON body.
func writeAuthErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAnonymous), tokens.IsAuthError(err):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case errors.Is(err, errKindMismatch), errors.Is(err, errOwnerless), tokens.IsForbidden(err):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	case errors.Is(err, errDeactivated):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account deactivated"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}
