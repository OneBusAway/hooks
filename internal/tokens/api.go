package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// API exposes the token-management endpoints (admin-scope-required) used by
// both the inspector UI and `hooksctl token`.
type API struct {
	Store store.TokenStore
	Auth  *Authenticator
}

// NewAPI constructs an API.
func NewAPI(ts store.TokenStore, auth *Authenticator) *API {
	return &API{Store: ts, Auth: auth}
}

// Register mounts /api/tokens routes onto mux. Each route enforces admin scope.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tokens", a.list)
	mux.HandleFunc("POST /api/tokens", a.create)
	mux.HandleFunc("POST /api/tokens/{id}/revoke", a.revoke)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	includeRevoked := r.URL.Query().Get("include_revoked") == "1"
	tokens, err := a.Store.List(r.Context(), includeRevoked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]listEntry, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toListEntry(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	scopes := normalizeScopes(req.Scopes)
	if req.Name == "" || len(scopes) == 0 {
		http.Error(w, "name and scopes are required", http.StatusBadRequest)
		return
	}
	res, err := Issue(r.Context(), a.Store, req.Name, scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         res.ID,
		"name":       req.Name,
		"scopes":     scopes,
		"plaintext":  res.Plaintext,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *API) revoke(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := a.Store.Revoke(r.Context(), id, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if _, err := a.Auth.AuthorizeAdmin(r); err != nil {
		WriteAuthError(w, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func normalizeScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	// Accept either ["render","admin"] or ["render,admin"].
	flat := strings.Join(in, ",")
	return ParseScopes(flat)
}

type createReq struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type listEntry struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func toListEntry(t store.Token) listEntry {
	return listEntry{
		ID: t.ID, Name: t.Name, Scopes: t.Scopes,
		CreatedAt:  t.CreatedAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
	}
}

// silence unused
var _ = context.Background
