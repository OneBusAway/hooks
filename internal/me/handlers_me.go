package me

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type meView struct {
	UserID        string    `json:"user_id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Role          string    `json:"role"`
	DefaultScopes []string  `json:"default_scopes"`
	CreatedAt     time.Time `json:"created_at"`
}

func (a *API) GetMe(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, meView{
		UserID:        caller.User.ID,
		Email:         caller.User.Email,
		Name:          caller.User.Name,
		Role:          string(caller.User.Role),
		DefaultScopes: caller.User.DefaultScopes,
		CreatedAt:     caller.User.CreatedAt,
	})
}

type patchMeRequest struct {
	Name *string `json:"name"`
}

func (a *API) PatchMe(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	var req patchMeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Name == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no fields to update"})
		return
	}
	name := strings.TrimSpace(*req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be non-empty"})
		return
	}
	if err := a.Users.UpdateProfile(r.Context(), caller.User.ID, name, caller.User.DefaultScopes); err != nil {
		a.warn(r.Context(), "me: update profile failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), caller, "user.update", "user", caller.User.ID, map[string]any{
		"name": name,
	})
	writeJSON(w, http.StatusOK, meView{
		UserID:        caller.User.ID,
		Email:         caller.User.Email,
		Name:          name,
		Role:          string(caller.User.Role),
		DefaultScopes: caller.User.DefaultScopes,
		CreatedAt:     caller.User.CreatedAt,
	})
}
