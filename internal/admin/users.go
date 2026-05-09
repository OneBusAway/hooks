package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/store"
)

type userView struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	Role          string     `json:"role"`
	DefaultScopes []string   `json:"default_scopes"`
	CreatedAt     time.Time  `json:"created_at"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty"`
}

func userToView(u store.User) userView {
	return userView{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Role:          string(u.Role),
		DefaultScopes: u.DefaultScopes,
		CreatedAt:     u.CreatedAt,
		DeactivatedAt: u.DeactivatedAt,
	}
}

func (a *API) ListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	role := store.Role(r.URL.Query().Get("role"))
	var rows []store.User
	var err error
	if role == store.RoleAdmin || role == store.RoleUser {
		rows, err = a.Users.ListByRole(r.Context(), role)
	} else {
		rows, err = a.Users.List(r.Context())
	}
	if err != nil {
		a.warn(r.Context(), "admin: list users failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := make([]userView, 0, len(rows))
	for _, u := range rows {
		out = append(out, userToView(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (a *API) GetUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	u, err := a.Users.GetByID(r.Context(), id)
	if err != nil {
		a.notFoundOr500(r.Context(), w, "admin: get user failed", err)
		return
	}
	writeJSON(w, http.StatusOK, userToView(u))
}

type patchUserRequest struct {
	Name          *string   `json:"name"`
	DefaultScopes *[]string `json:"default_scopes"`
}

func (a *API) PatchUser(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	target, err := a.Users.GetByID(r.Context(), id)
	if err != nil {
		a.notFoundOr500(r.Context(), w, "admin: patch user lookup failed", err)
		return
	}
	var req patchUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Name == nil && req.DefaultScopes == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no fields to update"})
		return
	}
	name := target.Name
	if req.Name != nil {
		nm := strings.TrimSpace(*req.Name)
		if nm == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be non-empty"})
			return
		}
		name = nm
	}
	scopes := target.DefaultScopes
	if req.DefaultScopes != nil {
		scopes = *req.DefaultScopes
	}
	if err := a.Users.UpdateProfile(r.Context(), id, name, scopes); err != nil {
		a.warn(r.Context(), "admin: update user failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), caller, audit.ActionUserUpdate, audit.TargetTypeUser, id, map[string]any{
		"name":           name,
		"default_scopes": scopes,
	})
	target.Name = name
	target.DefaultScopes = scopes
	writeJSON(w, http.StatusOK, userToView(target))
}

type deactivateRequest struct {
	Confirm string `json:"confirm"`
}

func (a *API) Deactivate(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	target, err := a.Users.GetByID(r.Context(), id)
	if err != nil {
		a.notFoundOr500(r.Context(), w, "admin: deactivate lookup failed", err)
		return
	}
	var req deactivateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if !strings.EqualFold(req.Confirm, target.Email) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "confirm must equal the target user's email"})
		return
	}
	if a.Cascader == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cascader not configured"})
		return
	}
	res, err := a.Cascader.DeactivateUserCascade(r.Context(), id, a.now())
	if errors.Is(err, store.ErrLastAdmin) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "would leave zero active admins"})
		return
	}
	if errors.Is(err, store.ErrAlreadyDeactivated) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already deactivated"})
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.warn(r.Context(), "admin: deactivate cascade failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), caller, audit.ActionUserDeactivate, audit.TargetTypeUser, id, map[string]any{
		"tokens_revoked":       res.TokensRevoked,
		"subscriptions_paused": res.SubscriptionsPaused,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens_revoked":       res.TokensRevoked,
		"subscriptions_paused": res.SubscriptionsPaused,
	})
}

func (a *API) Reactivate(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := a.Users.Reactivate(r.Context(), id); err != nil {
		a.notFoundOr500(r.Context(), w, "admin: reactivate failed", err)
		return
	}
	a.recordAudit(r.Context(), caller, audit.ActionUserReactivate, audit.TargetTypeUser, id, nil)
	w.WriteHeader(http.StatusNoContent)
}

type resetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

func (a *API) ResetPassword(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	target, err := a.Users.GetByID(r.Context(), id)
	if err != nil {
		a.notFoundOr500(r.Context(), w, "admin: reset-password lookup failed", err)
		return
	}
	var req resetPasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_password required"})
		return
	}
	if a.ValidatePolicy != nil {
		if err := a.ValidatePolicy(target.Email, req.NewPassword); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password does not meet policy"})
			return
		}
	}
	if a.HashPassword == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password hasher not configured"})
		return
	}
	hash, err := a.HashPassword(req.NewPassword)
	if err != nil {
		a.warn(r.Context(), "admin: reset-password hash failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if err := a.Users.SetPasswordHash(r.Context(), id, hash); err != nil {
		a.warn(r.Context(), "admin: reset-password set hash failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if a.Sessions != nil {
		// Failure here is security-relevant: the password hash has been
		// rotated but live sessions are not invalidated, so an attacker
		// who triggered the reset still holds a valid cookie. Fail loud
		// (500) and ask the operator to retry.
		if err := a.Sessions.DeleteByUser(r.Context(), id); err != nil {
			a.warn(r.Context(), "admin: reset-password sessions delete failed",
				slog.Any("err", err), slog.String("user_id", id))
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "password updated but session invalidation failed; retry to invalidate live sessions",
			})
			return
		}
	}
	a.recordAudit(r.Context(), caller, audit.ActionUserPasswordReset, audit.TargetTypeUser, id, nil)
	w.WriteHeader(http.StatusNoContent)
}

