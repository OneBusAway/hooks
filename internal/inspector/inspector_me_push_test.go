package inspector

// Tests for /inspector/me/push (task 11.7): user-owned push-subscription
// view mirroring /inspector/push but without the owner column.
//
// Authentication is session-only (same contract as /inspector/me): the
// legacy hooks_inspector_token raw-bearer cookie carries no current user
// row, so anonymous and bearer-only callers redirect to /login.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// TestInspectorMePush_AnonymousRedirectsToLogin: GET /inspector/me/push
// with no session redirects to /login?next=/inspector/me/push.
func TestInspectorMePush_AnonymousRedirectsToLogin(t *testing.T) {
	f := newSessionFixture(t)
	resp := f.get(t, "/inspector/me/push")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location = %q, want /login?next=...", loc)
	}
	if !strings.Contains(loc, "%2Finspector%2Fme%2Fpush") && !strings.Contains(loc, "/inspector/me/push") {
		t.Fatalf("Location = %q, want next pointing at /inspector/me/push", loc)
	}
}

// TestInspectorMePush_OnlyShowsOwnSubscriptions: subscriptions owned by
// other users do not appear in the page.
func TestInspectorMePush_OnlyShowsOwnSubscriptions(t *testing.T) {
	f := newSessionFixture(t)
	alice := f.makeUser(t, "alice@example.com", store.RoleUser)
	bob := f.makeUser(t, "bob@example.com", store.RoleUser)

	mine := insertOwnedSub(t, f, alice, "render")
	notMine := insertOwnedSub(t, f, bob, "render")

	f.loginAs(t, alice)
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/me/push", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200, body=%s", resp.StatusCode, string(body))
	}

	s := string(body)
	if !strings.Contains(s, mine.ID) {
		t.Errorf("missing own sub id %q in body: %s", mine.ID, s)
	}
	if strings.Contains(s, notMine.ID) {
		t.Errorf("body leaked another user's sub id %q: %s", notMine.ID, s)
	}
}

// TestInspectorMePush_OmitsOwnerColumn: the rendered table does not include
// an "Owner" column (mirrors /inspector/push without it).
func TestInspectorMePush_OmitsOwnerColumn(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	insertOwnedSub(t, f, u, "render")

	f.loginAs(t, u)
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/me/push", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	// The owner column header on /inspector/push is "<th>Owner</th>".
	if strings.Contains(s, "<th>Owner</th>") {
		t.Errorf("/inspector/me/push rendered an Owner column: %s", s)
	}
}

// TestInspectorMePush_AdminSeesFullFleetBanner: an admin viewing
// /inspector/me/push sees a banner linking to /inspector/push for the
// full-fleet view. (The header nav always carries a /inspector/push link
// regardless of role; the banner is distinguished by a "manage every
// owner" phrase.)
func TestInspectorMePush_AdminSeesFullFleetBanner(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/me/push", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	if !strings.Contains(s, "manage every owner") {
		t.Errorf("admin banner missing full-fleet copy: %s", s)
	}
	if !strings.Contains(s, `href="/inspector/push"`) {
		t.Errorf("admin banner missing /inspector/push link: %s", s)
	}
}

// TestInspectorMePush_NonAdminDoesNotSeeFullFleetBanner: a regular user
// does NOT see the admin-only "manage every owner" banner copy. (They do
// still see the global /inspector/push nav link in the page header, which
// is fine; that link 302s them back to /inspector/me.)
func TestInspectorMePush_NonAdminDoesNotSeeFullFleetBanner(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/me/push", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	if strings.Contains(s, "manage every owner") {
		t.Errorf("non-admin saw admin banner copy: %s", s)
	}
}

// TestInspectorMePush_PauseOwnSub: a logged-in user can pause their own
// subscription via the inline action.
func TestInspectorMePush_PauseOwnSub(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	mine := insertOwnedSub(t, f, u, "render")
	f.loginAs(t, u)
	csrf := "csrf-pause"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/me/push/"+mine.ID+"/pause",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.srv.URL)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	got, err := f.st.PushSubscriptions().Get(context.Background(), mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PausedAt == nil {
		t.Errorf("subscription not paused")
	}
}

// TestInspectorMePush_CannotPauseOtherUsersSub: cross-user pause returns
// 404 (probe-resistant) without altering the row.
func TestInspectorMePush_CannotPauseOtherUsersSub(t *testing.T) {
	f := newSessionFixture(t)
	alice := f.makeUser(t, "alice@example.com", store.RoleUser)
	bob := f.makeUser(t, "bob@example.com", store.RoleUser)
	bobs := insertOwnedSub(t, f, bob, "render")

	f.loginAs(t, alice)
	csrf := "csrf-x"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/me/push/"+bobs.ID+"/pause",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.srv.URL)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d, want 404", resp.StatusCode)
	}
	got, err := f.st.PushSubscriptions().Get(context.Background(), bobs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PausedAt != nil {
		t.Errorf("Bob's sub should not have been paused by Alice")
	}
}

// TestInspectorMePush_ResumeOwnSub: a paused subscription can be resumed.
func TestInspectorMePush_ResumeOwnSub(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	mine := insertOwnedSub(t, f, u, "render")
	now := time.Now().UTC()
	if err := f.st.PushSubscriptions().Pause(context.Background(), mine.ID, now); err != nil {
		t.Fatal(err)
	}
	f.loginAs(t, u)
	csrf := "csrf-resume"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/me/push/"+mine.ID+"/resume",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.srv.URL)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	got, err := f.st.PushSubscriptions().Get(context.Background(), mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PausedAt != nil {
		t.Errorf("subscription still paused after resume")
	}
}

// TestInspectorMePush_DeleteOwnSub: a logged-in user can delete their own
// subscription.
func TestInspectorMePush_DeleteOwnSub(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	mine := insertOwnedSub(t, f, u, "render")
	f.loginAs(t, u)
	csrf := "csrf-del"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/me/push/"+mine.ID+"/delete",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.srv.URL)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	if _, err := f.st.PushSubscriptions().Get(context.Background(), mine.ID); err == nil {
		t.Errorf("subscription not deleted")
	}
}

// TestInspectorMePush_PauseRequiresCSRF: a POST without csrf_token is
// rejected with 403 by the CSRF middleware.
func TestInspectorMePush_PauseRequiresCSRF(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	mine := insertOwnedSub(t, f, u, "render")
	f.loginAs(t, u)
	f.primeCSRF(t, "real-csrf")

	// no csrf_token in form
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/me/push/"+mine.ID+"/pause",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

// TestInspectorMePush_RotateOwnSecret: rotating the signing secret returns
// 200 with the new plaintext rendered exactly once on the resulting page.
func TestInspectorMePush_RotateOwnSecret(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	mine := insertOwnedSub(t, f, u, "render")
	f.loginAs(t, u)
	csrf := "csrf-rot"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/me/push/"+mine.ID+"/rotate",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.srv.URL)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200, body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "shown once") && !strings.Contains(string(body), "New signing secret") {
		t.Errorf("rotate response missing one-time plaintext banner: %s", string(body))
	}
}
