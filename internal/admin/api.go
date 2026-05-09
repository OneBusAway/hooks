// Package admin exposes admin-only HTTP surfaces:
//
//   - /api/users/{,id,id/deactivate,id/reactivate,id/reset-password}
//   - /api/audit (paginated read of audit_events)
//
// Authorization accepts EITHER a session cookie whose user has role=admin
// OR a bearer token whose scopes include admin. Cookie-only mutations are
// CSRF-checked at the server-Build layer, identically to the user-facing
// /api/me/* endpoints.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// SessionProvider is implemented by auth.Manager.
type SessionProvider interface {
	FromContext(ctx context.Context) (store.User, store.Session, bool)
}

// API exposes /api/users/* and /api/audit.
type API struct {
	Users         store.UserStore
	Sessions      store.SessionStore
	Tokens        store.TokenStore
	Subs          store.PushSubscriptionStore
	Audit         audit.Recorder
	AuditReader   store.AuditStore
	Cascader      Cascader
	HashPassword  func(plaintext string) (string, error)
	ValidatePolicy func(email, plaintext string) error

	Logger *slog.Logger
	Now    func() time.Time

	Auth   SessionProvider
	Bearer *tokens.Authenticator
}

// Cascader runs the deactivate-and-cascade transaction. Implemented by
// store.SQLite.DeactivateUserCascade.
type Cascader interface {
	DeactivateUserCascade(ctx context.Context, id string, when time.Time) (store.CascadeRevokeResult, error)
}

// Register mounts /api/users/* and /api/audit onto mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/users", a.ListUsers)
	mux.HandleFunc("GET /api/users/{id}", a.GetUser)
	mux.HandleFunc("PATCH /api/users/{id}", a.PatchUser)
	mux.HandleFunc("POST /api/users/{id}/deactivate", a.Deactivate)
	mux.HandleFunc("POST /api/users/{id}/reactivate", a.Reactivate)
	mux.HandleFunc("POST /api/users/{id}/reset-password", a.ResetPassword)

	mux.HandleFunc("GET /api/audit", a.ListAudit)
}

// adminCaller carries both the user identity and (when authenticated via
// bearer) the token id, so audit events can attribute actions to the
// specific PAT a privileged user was holding at the time.
type adminCaller struct {
	User    store.User
	TokenID *string
}

// requireAdmin returns the calling admin or writes a 401/403 and ok=false.
// Accepts either a session-cookie admin or a bearer token whose scopes
// include admin. A non-admin session cookie does NOT short-circuit the
// bearer fallback — callers commonly leave a stale browser session in the
// same context where they later use an admin PAT.
func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) (adminCaller, bool) {
	// Session cookie path.
	if a.Auth != nil {
		if user, _, ok := a.Auth.FromContext(r.Context()); ok {
			if user.Role == store.RoleAdmin {
				return adminCaller{User: user}, true
			}
			// Cookie present but non-admin: fall through to bearer in case
			// the request also carries an admin PAT.
		}
	}
	if a.Bearer != nil {
		tok, err := a.Bearer.AuthorizeAdmin(r)
		if err != nil {
			// If a non-admin session cookie was present and no bearer
			// matched, return 403 (admin required) rather than 401 — the
			// caller IS authenticated, just not with admin authority.
			if a.Auth != nil {
				if _, _, ok := a.Auth.FromContext(r.Context()); ok {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
					return adminCaller{}, false
				}
			}
			tokens.WriteAuthError(w, err)
			return adminCaller{}, false
		}
		// Bearer-admin: prefer the token's owning user as the actor; fall
		// back to a system identity when the token has no owner.
		caller := adminCaller{}
		tokID := tok.ID
		caller.TokenID = &tokID
		if tok.OwnerUserID != nil {
			u, err := a.Users.GetByID(r.Context(), *tok.OwnerUserID)
			if err == nil {
				caller.User = u
				return caller, true
			}
			// Owner row missing/transient-error: log and fall through to
			// system identity rather than silently dropping attribution.
			a.warn(r.Context(), "admin: bearer-admin owner lookup failed",
				slog.String("token_id", tok.ID), slog.Any("err", err))
		}
		caller.User = store.User{ID: "", Role: store.RoleAdmin, Name: "system"}
		return caller, true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	return adminCaller{}, false
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *API) recordAudit(ctx context.Context, caller adminCaller, action, targetType, targetID string, meta map[string]any) {
	if a.Audit == nil {
		return
	}
	ev := store.AuditEvent{
		Action:       action,
		TargetType:   targetType,
		TargetID:     targetID,
		Metadata:     meta,
		ActorTokenID: caller.TokenID,
	}
	if caller.User.ID != "" {
		uid := caller.User.ID
		ev.ActorUserID = &uid
	}
	a.Audit.Record(ctx, ev)
}

func (a *API) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	if a.Logger == nil {
		return
	}
	a.Logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// notFoundOr500 maps store.ErrNotFound → 404 and anything else → 500.
func (a *API) notFoundOr500(ctx context.Context, w http.ResponseWriter, msg string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	a.warn(ctx, msg, slog.Any("err", err))
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
}
