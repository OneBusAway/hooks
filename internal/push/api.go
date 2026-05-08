package push

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// API exposes /api/push-subscriptions endpoints. Every route requires the
// admin scope.
type API struct {
	Manager        *Manager
	Subs           store.PushSubscriptionStore
	Auth           *tokens.Authenticator
	Now            func() time.Time
	HashSecret     func(plaintext string) (string, error)
	ConfiguredSrcs map[string]bool
}

// NewAPI constructs an API. configuredSources is the set of source names from
// hooks.yaml; registration with an unknown source is rejected with HTTP 400.
func NewAPI(m *Manager, subs store.PushSubscriptionStore, auth *tokens.Authenticator, configured []string, hash func(string) (string, error)) *API {
	srcSet := map[string]bool{}
	for _, s := range configured {
		srcSet[s] = true
	}
	return &API{
		Manager:        m,
		Subs:           subs,
		Auth:           auth,
		Now:            time.Now,
		HashSecret:     hash,
		ConfiguredSrcs: srcSet,
	}
}

// Register mounts /api/push-subscriptions routes onto mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/push-subscriptions", a.create)
	mux.HandleFunc("GET /api/push-subscriptions", a.list)
	mux.HandleFunc("GET /api/push-subscriptions/{id}", a.get)
	mux.HandleFunc("DELETE /api/push-subscriptions/{id}", a.delete)
	mux.HandleFunc("POST /api/push-subscriptions/{id}/pause", a.pause)
	mux.HandleFunc("POST /api/push-subscriptions/{id}/resume", a.resume)
	mux.HandleFunc("POST /api/push-subscriptions/{id}/rotate-secret", a.rotateSecret)
	mux.HandleFunc("POST /api/push-subscriptions/{id}/test", a.test)
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	// Reject multi-source registration with a clearer message than "JSON
	// decode failed".
	rawBytes, err := readAll(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if hasField(rawBytes, "sources") {
		http.Error(w, "register one source per subscription (got `sources` array)", http.StatusBadRequest)
		return
	}

	var req createReq
	if err := json.Unmarshal(rawBytes, &req); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Source == "" {
		http.Error(w, "source is required", http.StatusBadRequest)
		return
	}
	if !a.ConfiguredSrcs[req.Source] {
		http.Error(w, fmt.Sprintf("unknown source %q", req.Source), http.StatusBadRequest)
		return
	}
	if req.TargetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}
	if u, err := url.Parse(req.TargetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "target_url must be http or https", http.StatusBadRequest)
		return
	}

	cursor, err := a.resolveSinceField(r.Context(), req.Source, req.Since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	plaintext, err := generatePlainSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := a.HashSecret(plaintext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sub := store.PushSubscription{
		ID:                uuid.NewString(),
		Source:            req.Source,
		TargetURL:         req.TargetURL,
		SigningSecretHash: hash,
		Name:              req.Name,
		Cursor:            cursor,
		CreatedAt:         a.Now().UTC(),
	}
	if err := a.Subs.Insert(r.Context(), sub); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.Manager.Add(sub, plaintext)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             sub.ID,
		"source":         sub.Source,
		"target_url":     sub.TargetURL,
		"name":           sub.Name,
		"cursor":         sub.Cursor,
		"signing_secret": plaintext,
		"created_at":     sub.CreatedAt.Format(time.RFC3339),
	})
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	includePaused := r.URL.Query().Get("include_paused") == "1"
	subs, err := a.Subs.List(r.Context(), includePaused)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]subView, 0, len(subs))
	for _, s := range subs {
		out = append(out, viewOf(r.Context(), s, a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	sub, err := a.Subs.Get(r.Context(), id)
	if err != nil {
		writeNotFoundOr500(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewOf(r.Context(), sub, a))
}

func (a *API) delete(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := a.Subs.Delete(r.Context(), id); err != nil {
		writeNotFoundOr500(w, err)
		return
	}
	a.Manager.Remove(id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) pause(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := a.Subs.Pause(r.Context(), id, a.Now().UTC()); err != nil {
		writeNotFoundOr500(w, err)
		return
	}
	a.Manager.Pause(id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) resume(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := a.Subs.Resume(r.Context(), id); err != nil {
		writeNotFoundOr500(w, err)
		return
	}
	if err := a.Manager.Resume(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) rotateSecret(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	plaintext, err := generatePlainSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := a.HashSecret(plaintext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.Subs.RotateSecret(r.Context(), id, hash); err != nil {
		writeNotFoundOr500(w, err)
		return
	}
	a.Manager.Rotate(id, plaintext)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             id,
		"signing_secret": plaintext,
	})
}

func (a *API) test(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := a.Manager.Test(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if _, err := a.Auth.AuthorizeAdmin(r); err != nil {
		tokens.WriteAuthError(w, err)
		return false
	}
	return true
}

func (a *API) resolveSinceField(ctx context.Context, source, raw string) (int64, error) {
	switch raw {
	case "", "latest":
		// Cold-start at latest by default per design.md.
		latest, err := a.Manager.Events.LatestSequence(ctx, source)
		if err != nil {
			return 0, err
		}
		return latest, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("since: must be an integer, `latest`, or omitted")
	}
	if n < 0 {
		return 0, errors.New("since: must be non-negative")
	}
	return n, nil
}

type createReq struct {
	Source    string `json:"source"`
	TargetURL string `json:"target_url"`
	Name      string `json:"name"`
	Since     string `json:"since"`
}

type subView struct {
	ID                  string     `json:"id"`
	Source              string     `json:"source"`
	TargetURL           string     `json:"target_url"`
	Name                string     `json:"name,omitempty"`
	Cursor              int64      `json:"cursor"`
	QueueDepth          int64      `json:"queue_depth"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastError           string     `json:"last_error,omitempty"`
	LastAttemptAt       *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt       *time.Time `json:"last_success_at,omitempty"`
	PausedAt            *time.Time `json:"paused_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

func viewOf(ctx context.Context, s store.PushSubscription, a *API) subView {
	latest, _ := a.Manager.Events.LatestSequence(ctx, s.Source)
	depth := latest - s.Cursor
	if depth < 0 {
		depth = 0
	}
	return subView{
		ID: s.ID, Source: s.Source, TargetURL: s.TargetURL, Name: s.Name,
		Cursor:              s.Cursor,
		QueueDepth:          depth,
		ConsecutiveFailures: s.ConsecutiveFailures,
		LastError:           s.LastError,
		LastAttemptAt:       s.LastAttemptAt,
		LastSuccessAt:       s.LastSuccessAt,
		PausedAt:            s.PausedAt,
		CreatedAt:           s.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeNotFoundOr500(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func generatePlainSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func readAll(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	const limit = 64 << 10
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	buf := make([]byte, 0, 1<<10)
	tmp := make([]byte, 1<<10)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if errors.Is(err, http.ErrAbortHandler) || err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

// hasField is a lightweight pre-decode check for fields we don't model in the
// canonical request type. Used to give a more helpful error when callers send
// `sources: [...]` instead of a single `source`.
func hasField(in []byte, name string) bool {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(in, &generic); err != nil {
		return false
	}
	_, ok := generic[name]
	return ok
}
