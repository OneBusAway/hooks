package me

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

type tokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Kind       string     `json:"kind"`
	Ephemeral  bool       `json:"ephemeral,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func tokenToView(t store.Token) tokenView {
	return tokenView{
		ID:         t.ID,
		Name:       t.Name,
		Scopes:     t.Scopes,
		Kind:       string(t.Kind),
		Ephemeral:  t.Ephemeral,
		CreatedAt:  t.CreatedAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
		ExpiresAt:  t.ExpiresAt,
	}
}

func (a *API) ListTokens(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	includeRevoked := r.URL.Query().Get("include_revoked") == "1"
	kindFilter := store.TokenKind(r.URL.Query().Get("kind"))

	rows, err := a.Tokens.ListByOwner(r.Context(), caller.User.ID, includeRevoked)
	if err != nil {
		a.warn(r.Context(), "me: list tokens failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := make([]tokenView, 0, len(rows))
	for _, t := range rows {
		if kindFilter != "" && t.Kind != kindFilter {
			continue
		}
		out = append(out, tokenToView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

type createTokenRequest struct {
	Name             string   `json:"name"`
	Scopes           []string `json:"scopes"`
	Kind             string   `json:"kind"`
	Ephemeral        bool     `json:"ephemeral"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
}

type createTokenResponse struct {
	tokenView
	Plaintext string `json:"plaintext"`
}

func (a *API) CreateToken(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	var req createTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	kind := store.TokenKind(req.Kind)
	if kind == "" {
		kind = store.TokenKindPAT
	}
	if kind != store.TokenKindPAT && kind != store.TokenKindListener {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be pat or listener"})
		return
	}

	scopes := Normalize(req.Scopes)
	if kind == store.TokenKindPAT && len(scopes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scopes required for kind=pat"})
		return
	}
	if kind == store.TokenKindListener && len(scopes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scopes required for kind=listener"})
		return
	}
	held := HeldScopes(caller.User)
	if !SubsetOf(scopes, held) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requested scopes exceed caller's authority"})
		return
	}
	if kind == store.TokenKindPAT {
		scopes = EnsureAccount(scopes)
	}

	now := a.now()
	var expiresAt *time.Time
	if req.ExpiresInSeconds > 0 {
		ttl := time.Duration(req.ExpiresInSeconds) * time.Second
		if ttl > MaxTokenTTL {
			ttl = MaxTokenTTL
		}
		t := now.Add(ttl)
		expiresAt = &t
	}

	res, err := tokens.Generate(req.Name, scopes)
	if err != nil {
		a.warn(r.Context(), "me: token generate failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	owner := caller.User.ID
	tok := store.Token{
		ID:          res.ID,
		Name:        req.Name,
		Scopes:      scopes,
		SecretHash:  res.Hash,
		CreatedAt:   now,
		OwnerUserID: &owner,
		Kind:        kind,
		Ephemeral:   req.Ephemeral,
		ExpiresAt:   expiresAt,
	}
	if err := a.Tokens.Insert(r.Context(), tok); err != nil {
		a.warn(r.Context(), "me: token insert failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), caller, "token.create", "token", tok.ID, map[string]any{
		"kind":   string(kind),
		"scopes": scopes,
	})
	writeJSON(w, http.StatusCreated, createTokenResponse{
		tokenView: tokenToView(tok),
		Plaintext: res.Plaintext,
	})
}

func (a *API) RevokeToken(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "self" {
		if !caller.IsPAT() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "self alias requires bearer token"})
			return
		}
		id = caller.Token.ID
	}
	tok, err := a.Tokens.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.warn(r.Context(), "me: token get failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if tok.OwnerUserID == nil || *tok.OwnerUserID != caller.User.ID {
		// Hide cross-user tokens behind 404 so users can't probe IDs.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := a.Tokens.Revoke(r.Context(), id, a.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.warn(r.Context(), "me: token revoke failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.recordAudit(r.Context(), caller, "token.revoke", "token", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
