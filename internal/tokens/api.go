package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/store"
)

// API exposes the token-management endpoints (admin-scope-required) used by
// both the inspector UI and `hooksctl token`.
type API struct {
	Store store.TokenStore
	Auth  *Authenticator

	// Logger receives WarnContext entries on internal-error sites. nil-safe.
	Logger *slog.Logger
	// Audit records ownership-transfer events. nil-safe (skip recording).
	Audit audit.Recorder
}

// NewAPI constructs an API.
func NewAPI(ts store.TokenStore, auth *Authenticator) *API {
	return &API{Store: ts, Auth: auth}
}

// Register mounts /api/tokens routes onto mux. Each route enforces admin scope.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tokens", a.list)
	mux.HandleFunc("POST /api/tokens", a.create)
	mux.HandleFunc("PATCH /api/tokens/{id}", a.patch)
	mux.HandleFunc("POST /api/tokens/{id}/revoke", a.revoke)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	tok, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	_ = tok
	includeRevoked := r.URL.Query().Get("include_revoked") == "1"
	owner := r.URL.Query().Get("owner")
	kindFilter := store.TokenKind(r.URL.Query().Get("kind"))

	var rows []store.Token
	var err error
	switch owner {
	case "":
		rows, err = a.Store.List(r.Context(), includeRevoked)
	case "system":
		rows, err = a.Store.ListSystem(r.Context(), includeRevoked)
	default:
		rows, err = a.Store.ListByOwner(r.Context(), owner, includeRevoked)
	}
	if err != nil {
		a.warn(r.Context(), "tokens: list failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]listEntry, 0, len(rows))
	for _, t := range rows {
		if kindFilter != "" && t.Kind != kindFilter {
			continue
		}
		out = append(out, toListEntry(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// patchReq distinguishes "field omitted" from "field present with null/empty"
// by parsing through json.RawMessage. Without that, *string can't tell apart
// (a) `{}` — leave owner alone, (b) `{"owner_user_id": null}` — clear owner.
type patchReq struct {
	OwnerUserID json.RawMessage `json:"owner_user_id"`
}

// resolveOwner inspects raw to decide whether the patch sets, clears, or
// leaves the owner unchanged. Returns ok=false when the field is absent.
func resolveOwner(raw json.RawMessage) (newOwner *string, present bool, err error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if string(raw) == "null" {
		return nil, true, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false, err
	}
	if s == "" || s == "system" {
		return nil, true, nil
	}
	return &s, true, nil
}

func (a *API) patch(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	var req patchReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	newOwner, present, err := resolveOwner(req.OwnerUserID)
	if err != nil {
		http.Error(w, "owner_user_id: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !present {
		http.Error(w, "no fields to update", http.StatusBadRequest)
		return
	}
	if err := a.Store.UpdateOwner(r.Context(), id, newOwner); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		a.warn(r.Context(), "tokens: update owner failed", slog.Any("err", err), slog.String("id", id))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.recordTransfer(r.Context(), caller, id, newOwner)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
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
		a.warn(r.Context(), "tokens: issue failed", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
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
	if _, ok := a.requireAdmin(w, r); !ok {
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
		a.warn(r.Context(), "tokens: revoke failed", slog.Any("err", err), slog.String("id", id))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireAdmin returns the bearer token alongside the admin gate. The
// returned token's owner_user_id (if any) attributes audit trail entries
// to the operator behind the token.
func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) (store.Token, bool) {
	tok, err := a.Auth.AuthorizeAdmin(r)
	if err != nil {
		WriteAuthError(w, err)
		return store.Token{}, false
	}
	return tok, true
}

func (a *API) recordTransfer(ctx context.Context, caller store.Token, tokenID string, newOwner *string) {
	if a.Audit == nil {
		return
	}
	meta := map[string]any{}
	if newOwner != nil {
		meta["new_owner_user_id"] = *newOwner
	} else {
		meta["new_owner_user_id"] = nil
	}
	tokID := caller.ID
	a.Audit.Record(ctx, store.AuditEvent{
		ActorUserID:  caller.OwnerUserID,
		ActorTokenID: &tokID,
		Action:       audit.ActionTokenTransferOwner,
		TargetType:   "token",
		TargetID:     tokenID,
		Metadata:     meta,
	})
}

func (a *API) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	if a.Logger == nil {
		return
	}
	a.Logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
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
