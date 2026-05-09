package invites

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

// DefaultInviteTTL is the lifetime of a regular admin-issued invite.
// Bootstrap invites use a separate 24h TTL (see SQLite.EnsureBootstrapInvite).
const DefaultInviteTTL = 7 * 24 * time.Hour

// AdminContextProvider returns the (User, true) for cookie-authenticated
// requests, or (zero, false) for anonymous / bearer-token requests. The
// auth and tokens packages each implement this; the API takes one to stay
// transport-agnostic.
type AdminContextProvider interface {
	FromContext(ctx context.Context) (store.User, store.Session, bool)
}

// API exposes /api/invites (admin) and /api/auth/signup (unauthenticated).
type API struct {
	Invites store.InviteStore
	Users   store.UserStore
	Audit   audit.Recorder
	Auth    AdminContextProvider
	Logger  *slog.Logger
	Now     func() time.Time
}

// NewAPI constructs an API.
func NewAPI(inv store.InviteStore, u store.UserStore, rec audit.Recorder, auth AdminContextProvider) *API {
	return &API{
		Invites: inv,
		Users:   u,
		Audit:   rec,
		Auth:    auth,
		Now:     time.Now,
	}
}

// Register mounts the routes onto mux. CSRF and rate-limit middlewares
// are layered on by the caller (server.Build).
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/invites", a.Create)
	mux.HandleFunc("GET /api/invites", a.List)
	mux.HandleFunc("DELETE /api/invites/{code}", a.Delete)
	mux.HandleFunc("POST /api/auth/signup", a.Signup)
}

type createRequest struct {
	Role          string   `json:"role"`
	DefaultScopes []string `json:"default_scopes,omitempty"`
	TTLSeconds    int64    `json:"ttl_seconds,omitempty"`
}

type inviteResponse struct {
	Code             string    `json:"code"`
	Role             string    `json:"role"`
	DefaultScopes    []string  `json:"default_scopes"`
	Bootstrap        bool      `json:"bootstrap"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ConsumedAt       *time.Time `json:"consumed_at,omitempty"`
	ConsumedByUserID *string    `json:"consumed_by_user_id,omitempty"`
}

func (a *API) Create(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	role := store.Role(req.Role)
	if role != store.RoleAdmin && role != store.RoleUser {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be admin or user"})
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = DefaultInviteTTL
	}
	code, err := NewCode()
	if err != nil {
		a.warn(r.Context(), "invites: NewCode failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	now := a.Now().UTC()
	exp := now.Add(ttl)
	inv := store.Invite{
		Code:            code,
		Role:            role,
		DefaultScopes:   req.DefaultScopes,
		CreatedByUserID: &caller.ID,
		Bootstrap:       false,
		CreatedAt:       now,
		ExpiresAt:       &exp,
	}
	if err := a.Invites.Insert(r.Context(), inv); err != nil {
		a.warn(r.Context(), "invites: insert failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), &caller.ID, "invite.create", "invite", code, map[string]any{
		"role": string(role),
	})
	writeJSON(w, http.StatusCreated, toInviteResponse(inv))
}

func (a *API) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	var rows []store.Invite
	var err error
	switch r.URL.Query().Get("consumed") {
	case "true", "1":
		rows, err = a.Invites.ListByConsumed(r.Context(), true)
	case "false", "0":
		rows, err = a.Invites.ListByConsumed(r.Context(), false)
	default:
		rows, err = a.Invites.List(r.Context())
	}
	if err != nil {
		a.warn(r.Context(), "invites: list failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := make([]inviteResponse, 0, len(rows))
	for _, inv := range rows {
		out = append(out, toInviteResponse(inv))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (a *API) Delete(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	code := NormalizeCode(r.PathValue("code"))
	inv, err := a.Invites.GetByCode(r.Context(), code)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.warn(r.Context(), "invites: get-by-code failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if inv.ConsumedAt != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "invite already consumed"})
		return
	}
	if err := a.Invites.Delete(r.Context(), code); err != nil {
		a.warn(r.Context(), "invites: delete failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), &caller.ID, "invite.revoke", "invite", code, nil)
	w.WriteHeader(http.StatusNoContent)
}

type signupRequest struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type signupResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

func (a *API) Signup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	req.Code = NormalizeCode(req.Code)
	req.Email = strings.TrimSpace(req.Email)
	req.Name = strings.TrimSpace(req.Name)
	if req.Code == "" || req.Email == "" || req.Name == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code, email, name, password required"})
		return
	}

	// Validate the invite first (404/410/409 disambiguation).
	inv, err := a.Invites.GetByCode(r.Context(), req.Code)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite not found"})
		return
	}
	if err != nil {
		a.warn(r.Context(), "invites: signup get-by-code failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	now := a.Now().UTC()
	if inv.ConsumedAt != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "invite already consumed"})
		return
	}
	if inv.ExpiresAt != nil && inv.ExpiresAt.Before(now) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "invite expired"})
		return
	}

	// Password policy.
	if err := users.ValidatePassword(req.Email, secret.String(req.Password)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password does not meet policy"})
		return
	}

	hash, err := users.HashPassword(secret.String(req.Password))
	if err != nil {
		a.warn(r.Context(), "invites: signup hash failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	u := store.User{
		ID:            uuid.NewString(),
		Email:         req.Email,
		Name:          req.Name,
		Role:          inv.Role,
		PasswordHash:  hash,
		DefaultScopes: append([]string{}, inv.DefaultScopes...),
		CreatedAt:     now,
	}

	// Prefer the *SQLite atomic SignupTx when available; otherwise fall
	// back to a best-effort sequence (in-memory test stores).
	type signupTxer interface {
		SignupTx(ctx context.Context, code string, u store.User, now time.Time) error
	}
	if tx, ok := a.Invites.(signupTxer); ok {
		if err := tx.SignupTx(r.Context(), req.Code, u, now); err != nil {
			a.handleSignupErr(r.Context(), w, err)
			return
		}
	} else {
		// Fallback: best-effort sequence. Not safe under concurrent signup
		// races, but used only by tests with a mock store.
		if err := a.Users.Insert(r.Context(), u); err != nil {
			a.warn(r.Context(), "invites: signup user insert failed", slog.Any("err", err))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		if err := a.Invites.MarkConsumed(r.Context(), req.Code, u.ID, now); err != nil {
			a.warn(r.Context(), "invites: signup mark-consumed failed", slog.Any("err", err))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		_, _ = a.Invites.MarkBootstrapsConsumed(r.Context(), u.ID, now)
	}

	a.recordAudit(r.Context(), &u.ID, "user.create", "user", u.ID, map[string]any{
		"email": u.Email,
		"role":  string(u.Role),
	})
	a.recordAudit(r.Context(), &u.ID, "invite.consume", "invite", req.Code, nil)

	writeJSON(w, http.StatusCreated, signupResponse{UserID: u.ID, Email: u.Email, Role: string(u.Role)})
}

func (a *API) handleSignupErr(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInviteConsumed) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "invite already consumed"})
		return
	}
	if errors.Is(err, store.ErrEmailInUse) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "email already in use"})
		return
	}
	a.warn(ctx, "invites: signup tx failed", slog.Any("err", err))
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
}

func toInviteResponse(inv store.Invite) inviteResponse {
	return inviteResponse{
		Code:             inv.Code,
		Role:             string(inv.Role),
		DefaultScopes:    inv.DefaultScopes,
		Bootstrap:        inv.Bootstrap,
		CreatedAt:        inv.CreatedAt,
		ExpiresAt:        inv.ExpiresAt,
		ConsumedAt:       inv.ConsumedAt,
		ConsumedByUserID: inv.ConsumedByUserID,
	}
}

func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	if a.Auth == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return store.User{}, false
	}
	user, _, ok := a.Auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return store.User{}, false
	}
	if user.Role != store.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return store.User{}, false
	}
	return user, true
}

func (a *API) recordAudit(ctx context.Context, actor *string, action, targetType, targetID string, meta map[string]any) {
	if a.Audit == nil {
		return
	}
	a.Audit.Record(ctx, store.AuditEvent{
		ActorUserID: actor,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    meta,
	})
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
