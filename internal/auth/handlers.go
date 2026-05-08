package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
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
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/logout", a.logout)
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

func (a *API) login(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	cookieValue, _, err := a.Manager.CreateSession(r.Context(), u.ID, r.UserAgent(), clientIP(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	csrf, err := a.Manager.SetCookies(w, r, cookieValue)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	a.recordAudit(r, u.ID, "session.create", "user", u.ID, nil)
	writeJSON(w, http.StatusOK, loginResponse{
		UserID:    u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Role:      string(u.Role),
		CSRFToken: csrf,
	})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		// Idempotent: already logged out.
		a.Manager.ClearCookies(w, r)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	id, _ := a.Manager.DeleteSession(r.Context(), c.Value)
	a.Manager.ClearCookies(w, r)
	if id != "" {
		// Audit, attributing to the session's owner if we can find them.
		if user, _, ok := a.Manager.FromContext(r.Context()); ok {
			a.recordAudit(r, user.ID, "session.delete", "session", id, nil)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) recordAudit(r *http.Request, actorUserID, action, targetType, targetID string, meta map[string]any) {
	if a.Manager.Audit == nil || actorUserID == "" {
		return
	}
	actorID := actorUserID
	_ = a.Manager.Audit.Insert(r.Context(), store.AuditEvent{
		ID:          uuid.NewString(),
		At:          a.Manager.Now().UTC(),
		ActorUserID: &actorID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    meta,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// clientIP returns the request's best-effort client IP. Trust the
// X-Forwarded-For header only when web.trust_proxy_headers is on; for now
// callers can extract that themselves and we just take RemoteAddr.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	addr := r.RemoteAddr
	// Strip :port if present.
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
