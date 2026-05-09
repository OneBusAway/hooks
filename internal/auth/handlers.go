package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/onebusaway/hooks/internal/ratelimit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
)

// API exposes the /api/auth/* endpoints.
type API struct {
	Manager *Manager
}

// NewAPI constructs an API.
func NewAPI(m *Manager) *API { return &API{Manager: m} }

// Register mounts the auth routes onto mux. CSRF middleware is applied at
// the server.Build level so the auth API does not have to know about it.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/login", a.Login)
	mux.HandleFunc("POST /api/auth/logout", a.Logout)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CSRFToken string `json:"csrf_token"`
}

func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
		return
	}
	u, err := a.Manager.Authenticate(r.Context(), req.Email, secret.String(req.Password))
	if errors.Is(err, ErrBadCredentials) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
		return
	}
	if errors.Is(err, ErrDeactivated) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account deactivated"})
		return
	}
	if err != nil {
		a.warn(r.Context(), "auth: login authenticate failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	cookieValue, _, err := a.Manager.CreateSession(r.Context(), u.ID, r.UserAgent(), clientIP(r))
	if err != nil {
		a.warn(r.Context(), "auth: login create session failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	csrf, err := a.Manager.SetCookies(w, r, cookieValue)
	if err != nil {
		a.warn(r.Context(), "auth: login set cookies failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	a.recordAudit(r.Context(), u.ID, "session.create", "user", u.ID, nil)
	writeJSON(w, http.StatusOK, loginResponse{
		UserID:    u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Role:      string(u.Role),
		CSRFToken: csrf,
	})
}

func (a *API) Logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		// Idempotent: already logged out.
		a.Manager.ClearCookies(w, r)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Distinguish ErrInvalid (idempotent — clear cookie + 204) from a real
	// store error. Silently discarding the latter would leave the session
	// row alive server-side; a replay of the cookie still authenticates.
	id, delErr := a.Manager.DeleteSession(r.Context(), c.Value)
	a.Manager.ClearCookies(w, r)
	if delErr != nil && !errors.Is(delErr, ErrInvalid) {
		a.warn(r.Context(), "auth: logout delete session failed", slog.Any("err", delErr))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if id != "" {
		// Audit, attributing to the session's owner if we can find them.
		if user, _, ok := a.Manager.FromContext(r.Context()); ok {
			a.recordAudit(r.Context(), user.ID, "session.delete", "session", id, nil)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) recordAudit(ctx context.Context, actorUserID, action, targetType, targetID string, meta map[string]any) {
	if a.Manager.Audit == nil || actorUserID == "" {
		return
	}
	actorID := actorUserID
	a.Manager.Audit.Record(ctx, store.AuditEvent{
		ActorUserID: &actorID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    meta,
	})
}

func (a *API) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	if a.Manager == nil || a.Manager.Logger == nil {
		return
	}
	a.Manager.Logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// clientIP returns the request's best-effort client IP via the shared
// ratelimit.KeyByIP helper — net.SplitHostPort handles bracketed IPv6
// correctly. It does NOT honor X-Forwarded-For or any proxy headers;
// callers behind a trusted reverse proxy that need the original client IP
// must use a header-aware helper (not yet implemented).
func clientIP(r *http.Request) string {
	return ratelimit.KeyByIP(r)
}
