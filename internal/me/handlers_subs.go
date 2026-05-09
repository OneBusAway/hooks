package me

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
)

type subView struct {
	ID                  string     `json:"id"`
	Source              string     `json:"source"`
	TargetURL           string     `json:"target_url"`
	Name                string     `json:"name,omitempty"`
	Cursor              int64      `json:"cursor"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastError           string     `json:"last_error,omitempty"`
	LastAttemptAt       *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt       *time.Time `json:"last_success_at,omitempty"`
	PausedAt            *time.Time `json:"paused_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

func subToView(s store.PushSubscription) subView {
	return subView{
		ID: s.ID, Source: s.Source, TargetURL: s.TargetURL, Name: s.Name,
		Cursor:              s.Cursor,
		ConsecutiveFailures: s.ConsecutiveFailures,
		LastError:           s.LastError,
		LastAttemptAt:       s.LastAttemptAt,
		LastSuccessAt:       s.LastSuccessAt,
		PausedAt:            s.PausedAt,
		CreatedAt:           s.CreatedAt,
	}
}

func (a *API) ListSubs(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	includePaused := r.URL.Query().Get("include_paused") == "1"
	rows, err := a.Subs.ListByOwner(r.Context(), caller.User.ID, includePaused)
	if err != nil {
		a.warn(r.Context(), "me: list subs failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := make([]subView, 0, len(rows))
	for _, s := range rows {
		out = append(out, subToView(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

func (a *API) GetSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	sub, ok := a.requireOwnedSub(w, r, caller)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, subToView(sub))
}

type createSubRequest struct {
	Source    string `json:"source"`
	TargetURL string `json:"target_url"`
	Name      string `json:"name"`
	Since     string `json:"since"`
}

func (a *API) CreateSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	var req createSubRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	req.Source = strings.TrimSpace(req.Source)
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	if req.Source == "" || req.TargetURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source and target_url required"})
		return
	}
	if !a.ConfiguredSources[req.Source] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown source"})
		return
	}
	if u, err := url.Parse(req.TargetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_url must be http or https"})
		return
	}
	held := HeldScopes(caller.User)
	if !SubsetOf([]string{req.Source}, held) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "source not in held scopes"})
		return
	}

	cursor, err := a.resolveSince(r, req.Source, req.Since)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	plaintext, err := secret.NewRandom()
	if err != nil {
		a.warn(r.Context(), "me: subs random failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	hash, err := a.HashSecret(plaintext)
	if err != nil {
		a.warn(r.Context(), "me: subs hash failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	owner := caller.User.ID
	sub := store.PushSubscription{
		ID:                uuid.NewString(),
		Source:            req.Source,
		TargetURL:         req.TargetURL,
		SigningSecretHash: hash,
		Name:              req.Name,
		Cursor:            cursor,
		CreatedAt:         a.now(),
		OwnerUserID:       &owner,
	}
	if err := a.Subs.Insert(r.Context(), sub); err != nil {
		a.warn(r.Context(), "me: subs insert failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if a.PushManager != nil {
		a.PushManager.Add(sub, plaintext)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"subscription":   subToView(sub),
		"signing_secret": plaintext,
	})
}

func (a *API) DeleteSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	sub, ok := a.requireOwnedSub(w, r, caller)
	if !ok {
		return
	}
	if err := a.Subs.Delete(r.Context(), sub.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.warn(r.Context(), "me: subs delete failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if a.PushManager != nil {
		a.PushManager.Remove(sub.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) PauseSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	sub, ok := a.requireOwnedSub(w, r, caller)
	if !ok {
		return
	}
	if err := a.Subs.Pause(r.Context(), sub.ID, a.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.warn(r.Context(), "me: subs pause failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if a.PushManager != nil {
		a.PushManager.Pause(sub.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) ResumeSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	sub, ok := a.requireOwnedSub(w, r, caller)
	if !ok {
		return
	}
	if err := a.Subs.Resume(r.Context(), sub.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.warn(r.Context(), "me: subs resume failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if a.PushManager != nil {
		// DB resume succeeded; if the in-memory dispatcher fails to
		// reattach the worker, deliveries silently stop until the next
		// process restart. Surface so operators see the divergence.
		if err := a.PushManager.Resume(r.Context(), sub.ID); err != nil {
			a.warn(r.Context(), "me: dispatcher resume failed",
				slog.Any("err", err), slog.String("id", sub.ID))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) RotateSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	sub, ok := a.requireOwnedSub(w, r, caller)
	if !ok {
		return
	}
	plaintext, err := secret.NewRandom()
	if err != nil {
		a.warn(r.Context(), "me: subs rotate random failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	hash, err := a.HashSecret(plaintext)
	if err != nil {
		a.warn(r.Context(), "me: subs rotate hash failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if err := a.Subs.RotateSecret(r.Context(), sub.ID, hash); err != nil {
		a.warn(r.Context(), "me: subs rotate failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if a.PushManager != nil {
		a.PushManager.Rotate(sub.ID, plaintext)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             sub.ID,
		"signing_secret": plaintext,
	})
}

func (a *API) TestSub(w http.ResponseWriter, r *http.Request) {
	caller, err := a.resolveCaller(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	sub, ok := a.requireOwnedSub(w, r, caller)
	if !ok {
		return
	}
	if a.PushManager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "push manager unavailable"})
		return
	}
	if err := a.PushManager.Test(r.Context(), sub.ID); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireOwnedSub(w http.ResponseWriter, r *http.Request, caller Caller) (store.PushSubscription, bool) {
	id := r.PathValue("id")
	sub, err := a.Subs.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return store.PushSubscription{}, false
	}
	if err != nil {
		a.warn(r.Context(), "me: subs get failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return store.PushSubscription{}, false
	}
	if sub.OwnerUserID == nil || *sub.OwnerUserID != caller.User.ID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return store.PushSubscription{}, false
	}
	return sub, true
}

func (a *API) resolveSince(r *http.Request, source, raw string) (int64, error) {
	switch raw {
	case "", "latest":
		if a.PushManager == nil {
			return 0, nil
		}
		return a.PushManager.Events.LatestSequence(r.Context(), source)
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("since: must be a non-negative integer or `latest`")
	}
	return n, nil
}
