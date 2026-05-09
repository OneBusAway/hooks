package me

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// MaxTokenTTL caps the absolute expires_at requested by /api/me/tokens
// (1 year). Ephemeral tokens carry a separate 24h-idle policy
// enforced by the prune loop via
// store.SQLite.ExpireEphemeralTokensIdle.
const MaxTokenTTL = 365 * 24 * time.Hour

// API exposes /api/me/*. Caller resolution accepts either a session
// cookie (resolved by auth.Manager.Middleware) or a kind='pat' bearer
// token; listener tokens are rejected with 403.
type API struct {
	Users   store.UserStore
	Tokens  store.TokenStore
	Subs    store.PushSubscriptionStore
	Audit   audit.Recorder
	Logger  *slog.Logger
	Now     func() time.Time

	// Auth is the cookie-session provider; nil disables session-based auth.
	Auth SessionProvider
	// Bearer authenticates kind='pat' tokens; nil disables PAT-based auth.
	Bearer *tokens.Authenticator

	// PushManager applies side effects to the in-memory dispatcher when
	// subscriptions are added/paused/resumed/rotated/deleted.
	PushManager *push.Manager

	// HashSecret produces the at-rest hash for a push subscription
	// signing secret (Argon2id via internal/tokens.Hash).
	HashSecret func(string) (string, error)

	// ConfiguredSources is the set of source names from hooks.yaml.
	// Used to validate subscription source + token scope subset.
	ConfiguredSources map[string]bool
}

// Register mounts /api/me/* routes onto mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/me", a.GetMe)
	mux.HandleFunc("PATCH /api/me", a.PatchMe)

	mux.HandleFunc("GET /api/me/tokens", a.ListTokens)
	mux.HandleFunc("POST /api/me/tokens", a.CreateToken)
	mux.HandleFunc("POST /api/me/tokens/{id}/revoke", a.RevokeToken)

	mux.HandleFunc("GET /api/me/subscriptions", a.ListSubs)
	mux.HandleFunc("POST /api/me/subscriptions", a.CreateSub)
	mux.HandleFunc("GET /api/me/subscriptions/{id}", a.GetSub)
	mux.HandleFunc("DELETE /api/me/subscriptions/{id}", a.DeleteSub)
	mux.HandleFunc("POST /api/me/subscriptions/{id}/pause", a.PauseSub)
	mux.HandleFunc("POST /api/me/subscriptions/{id}/resume", a.ResumeSub)
	mux.HandleFunc("POST /api/me/subscriptions/{id}/rotate-secret", a.RotateSub)
	mux.HandleFunc("POST /api/me/subscriptions/{id}/test", a.TestSub)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *API) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	if a.Logger == nil {
		return
	}
	a.Logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

// recordAudit records an audit event attributed to caller. When caller is
// authenticated via a PAT bearer, ActorTokenID is populated alongside
// ActorUserID so the audit trail distinguishes between two PATs owned by
// the same user.
func (a *API) recordAudit(ctx context.Context, caller Caller, action audit.Action, targetType audit.TargetType, targetID string, meta map[string]any) {
	if a.Audit == nil {
		return
	}
	ev := store.AuditEvent{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   meta,
	}
	if caller.User.ID != "" {
		uid := caller.User.ID
		ev.ActorUserID = &uid
	}
	if caller.Token != nil {
		tid := caller.Token.ID
		ev.ActorTokenID = &tid
	}
	a.Audit.Record(ctx, ev)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
