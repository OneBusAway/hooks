package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

type auditView struct {
	ID           string         `json:"id"`
	At           time.Time      `json:"at"`
	ActorUserID  *string        `json:"actor_user_id,omitempty"`
	ActorTokenID *string        `json:"actor_token_id,omitempty"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type"`
	TargetID     string         `json:"target_id"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

func auditToView(e store.AuditEvent) auditView {
	return auditView{
		ID: e.ID, At: e.At,
		ActorUserID:  e.ActorUserID,
		ActorTokenID: e.ActorTokenID,
		Action:       e.Action,
		TargetType:   e.TargetType,
		TargetID:     e.TargetID,
		Metadata:     e.Metadata,
	}
}

func (a *API) ListAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.AuditReader == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit reader not configured"})
		return
	}
	q := store.AuditQuery{}
	if v := r.URL.Query().Get("actor"); v != "" {
		actor := v
		q.ActorUserID = &actor
	}
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since: must be RFC3339"})
			return
		}
		q.Since = &t
	}
	if v := r.URL.Query().Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "until: must be RFC3339"})
			return
		}
		q.Until = &t
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit: must be a positive integer"})
			return
		}
		q.Limit = n
	}
	rows, err := a.AuditReader.List(r.Context(), q)
	if err != nil {
		a.warn(r.Context(), "admin: list audit failed", slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := make([]auditView, 0, len(rows))
	for _, e := range rows {
		out = append(out, auditToView(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
