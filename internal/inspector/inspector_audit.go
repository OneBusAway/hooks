package inspector

// /audit: admin-only HTML view of the
// audit_events log. Renders rows ordered by `at DESC` with the actor email
// resolved via UserStore (falling back to the raw user id when the user
// row is missing). Optional ?since= and ?until= RFC3339 query parameters
// narrow the time range; ?actor=<user_id> filters by actor; ?limit=
// caps the page size.

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// auditDefaultLimit caps the rendered list when no ?limit= is supplied so a
// long-running deployment doesn't spew thousands of rows into one HTML page.
// auditMaxLimit clamps an operator-supplied ?limit= to the same ceiling so a
// hand-crafted query can't bypass it.
const (
	auditDefaultLimit = 200
	auditMaxLimit     = 1000
)

// auditRow is one rendered row in the /audit table.
type auditRow struct {
	ID           string
	At           time.Time
	ActorLabel   string // resolved email, or raw id, or "system"
	ActorTokenID string // token id when set, else ""
	Action       string
	TargetType   string
	TargetID     string
	Metadata     map[string]any
}

// auditFilters mirrors the query-string controls so the form can re-render
// the user's most recent inputs verbatim. The string forms (Since/Until)
// preserve the original RFC3339 the operator typed; the parsed times go on
// the AuditQuery.
type auditFilters struct {
	Actor string
	Since string
	Until string
	Limit int
}

func (in *Inspector) auditList(w http.ResponseWriter, r *http.Request) {
	if !in.requireAdmin(w, r) {
		return
	}
	if in.AuditReader == nil {
		http.Error(w, "audit reader not configured", http.StatusServiceUnavailable)
		return
	}

	q, filters, err := parseAuditQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rows, err := in.AuditReader.List(r.Context(), q)
	if err != nil {
		in.Logger.Error("inspector: list audit failed", slog.String("error", err.Error()))
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}

	cache := map[string]string{}
	out := make([]auditRow, 0, len(rows))
	for _, e := range rows {
		out = append(out, auditRow{
			ID:           e.ID,
			At:           e.At,
			ActorLabel:   in.ownerLabel(r.Context(), e.ActorUserID, cache),
			ActorTokenID: derefString(e.ActorTokenID),
			Action:       string(e.Action),
			TargetType:   string(e.TargetType),
			TargetID:     e.TargetID,
			Metadata:     e.Metadata,
		})
	}

	in.render(w, "audit", map[string]any{
		"Title":   "Audit",
		"Events":  out,
		"Filters": filters,
	})
}

// parseAuditQuery extracts the AuditQuery + the original-string filters from
// r.URL.Query(). RFC3339 parse failures bubble up as 400s so the operator
// fixes the query string instead of getting an empty list.
func parseAuditQuery(r *http.Request) (store.AuditQuery, auditFilters, error) {
	var (
		q       store.AuditQuery
		filters auditFilters
	)
	values := r.URL.Query()

	if v := values.Get("actor"); v != "" {
		actor := v
		q.ActorUserID = &actor
		filters.Actor = v
	}
	if v := values.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return q, filters, &auditQueryError{Field: "since", Reason: "must be RFC3339"}
		}
		q.Since = &t
		filters.Since = v
	}
	if v := values.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return q, filters, &auditQueryError{Field: "until", Reason: "must be RFC3339"}
		}
		q.Until = &t
		filters.Until = v
	}
	if v := values.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return q, filters, &auditQueryError{Field: "limit", Reason: "must be a positive integer"}
		}
		if n > auditMaxLimit {
			n = auditMaxLimit
		}
		q.Limit = n
		filters.Limit = n
	} else {
		q.Limit = auditDefaultLimit
		filters.Limit = auditDefaultLimit
	}
	return q, filters, nil
}

// auditQueryError surfaces a typed 400 message instead of leaking the raw
// time-parse error string into the page.
type auditQueryError struct{ Field, Reason string }

func (e *auditQueryError) Error() string { return e.Field + ": " + e.Reason }

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
