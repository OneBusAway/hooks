package inspector

// Tests for /audit: admin-only HTML view
// of the audit log, with actor email resolution and time-range filtering.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/store"
)

// insertAuditEvent persists one audit_events row owned by actor.
func insertAuditEvent(t *testing.T, f *sessionFixture, actor store.User, action audit.Action, targetType audit.TargetType, targetID string, when time.Time) store.AuditEvent {
	t.Helper()
	uid := actor.ID
	ev := store.AuditEvent{
		ID:          uuid.NewString(),
		At:          when,
		ActorUserID: &uid,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    map[string]any{"k": "v"},
	}
	if err := f.st.Audit().Insert(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestInspectorAudit_AnonymousRedirectsToLogin: GET /audit with no
// session redirects to /login?next=/audit.
func TestInspectorAudit_AnonymousRedirectsToLogin(t *testing.T) {
	f := newSessionFixture(t)
	resp := f.get(t, "/audit")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") || !strings.Contains(loc, "next=") {
		t.Fatalf("Location = %q, want /login?next=...", loc)
	}
}

// TestInspectorAudit_NonAdminRedirectsToMe: a logged-in non-admin getting
// /audit is redirected to /me, mirroring how requireAdmin handles non-admin
// sessions on every other admin route.
func TestInspectorAudit_NonAdminRedirectsToMe(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	resp := f.get(t, "/audit")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/me" {
		t.Fatalf("Location = %q, want /me", loc)
	}
}

// TestInspectorAudit_AdminSeesEvents: admin viewing
// /audit gets the audit log rendered in HTML, with the actor's
// email resolved (not just the bare user_id).
func TestInspectorAudit_AdminSeesEvents(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	other := f.makeUser(t, "other@example.com", store.RoleUser)
	f.loginAs(t, admin)

	insertAuditEvent(t, f, other,
		audit.ActionUserUpdate, audit.TargetTypeUser, other.ID, time.Now().UTC())

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/audit", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}
	bs := string(body)
	if !strings.Contains(bs, "other@example.com") {
		t.Fatalf("expected actor email rendered; body=%s", bs)
	}
	if !strings.Contains(bs, string(audit.ActionUserUpdate)) {
		t.Fatalf("expected action label rendered; body=%s", bs)
	}
	if !strings.Contains(bs, other.ID) {
		t.Fatalf("expected target id rendered; body=%s", bs)
	}
}

// TestInspectorAudit_TimeRangeFilter: the page accepts ?since=
// and ?until= RFC3339 timestamps; rows outside the window are omitted.
func TestInspectorAudit_TimeRangeFilter(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)

	old := insertAuditEvent(t, f, admin,
		audit.ActionUserUpdate, audit.TargetTypeUser, "old-target",
		time.Now().Add(-48*time.Hour).UTC())
	recent := insertAuditEvent(t, f, admin,
		audit.ActionUserUpdate, audit.TargetTypeUser, "recent-target",
		time.Now().Add(-1*time.Hour).UTC())

	since := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	q := url.Values{"since": {since}}
	req, _ := http.NewRequest(http.MethodGet,
		f.srv.URL+"/audit?"+q.Encode(), nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bs := string(body)

	if !strings.Contains(bs, recent.TargetID) {
		t.Errorf("recent event should be rendered; body=%s", bs)
	}
	if strings.Contains(bs, old.TargetID) {
		t.Errorf("old event should be filtered out by since=%s; body=%s", since, bs)
	}
}

// TestInspectorAudit_BadSinceReturns400: a malformed ?since= timestamp is
// rejected with 400 so the operator notices instead of getting an empty
// list.
func TestInspectorAudit_BadSinceReturns400(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)

	req, _ := http.NewRequest(http.MethodGet,
		f.srv.URL+"/audit?since=not-a-timestamp", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
}

// TestInspectorAudit_AnonymousMutationReturns401: not actually applicable —
// /audit is GET-only — but the route mounting itself shouldn't
// expose a POST handler. We exercise this by issuing a POST and asserting
// 405 (method not allowed) is the worst-case outcome (Go's ServeMux returns
// 405 when the path has GET registered but no method match).
func TestInspectorAudit_PostNotAllowed(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)

	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/audit",
		strings.NewReader(""))
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// ServeMux with only GET registered returns 405 for other methods.
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: %d, want 405", resp.StatusCode)
	}
}
