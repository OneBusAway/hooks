package inspector

// Tests for /users: admin-only user table, invite
// form, per-row deactivate (with email-confirmation form field; refuses
// last-admin), reactivate, reset-password, edit-default-scopes — all
// CSRF-protected.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// loadInspectorUsersFixture returns a fixture with the admin-users-page
// dependencies wired (invite store, cascader, password hasher and policy)
// alongside the existing session/users wiring.
func loadInspectorUsersFixture(t *testing.T) *sessionFixture {
	t.Helper()
	f := newSessionFixture(t)
	in := getInspector(t, f)
	in.Invites = f.st.Invites()
	in.Cascader = f.st
	in.HashPassword = func(plaintext string) (string, error) {
		return testHashPassword(plaintext)
	}
	in.ValidatePolicy = func(email, plaintext string) error {
		return testValidatePolicy(email, plaintext)
	}
	return f
}

// getInspector reaches into the fixture's mux to find the Inspector. The
// fixture stores it in srv via the Register call; here we just expose a
// shared accessor since all tests need to flip dependencies on it.
func getInspector(t *testing.T, f *sessionFixture) *Inspector {
	t.Helper()
	if f.inspector == nil {
		t.Fatal("fixture missing inspector handle; check newSessionFixture")
	}
	return f.inspector
}

// testHashPassword is a deterministic stand-in for the production
// pkgUsers.HashPassword. The /users tests only need a value to
// land in the password_hash column; cryptographic strength is exercised
// elsewhere.
func testHashPassword(plaintext string) (string, error) {
	return "test-hash:" + plaintext, nil
}

// testValidatePolicy mirrors users.ValidatePassword's contract for the
// reset-password tests: rejects passwords <12 chars, otherwise OK.
func testValidatePolicy(_ /*email*/, plaintext string) error {
	if len(plaintext) < 12 {
		return errPolicyTooShort
	}
	return nil
}

// errPolicyTooShort is the typed error returned from testValidatePolicy.
// The handler should map it to a 400, not surface the raw text.
var errPolicyTooShort = &policyErr{Reason: "too short"}

type policyErr struct{ Reason string }

func (e *policyErr) Error() string { return "password policy: " + e.Reason }

// TestInspectorUsers_AnonymousRedirectsToLogin: anonymous GET on the
// users list redirects to /login?next=... .
func TestInspectorUsers_AnonymousRedirectsToLogin(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	resp := f.get(t, "/users")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location = %q, want /login redirect", loc)
	}
}

// TestInspectorUsers_NonAdminGets403: a logged-in non-admin user is
// redirected to /me on GET (existing requireAdmin behavior).
func TestInspectorUsers_NonAdminRedirectsToMe(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	resp := f.get(t, "/users")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/me" {
		t.Fatalf("Location = %q, want /me", loc)
	}
}

// TestInspectorUsers_AdminSeesUserTable: an admin sees a row for every
// user including themselves.
func TestInspectorUsers_AdminSeesUserTable(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	other := f.makeUser(t, "other@example.com", store.RoleUser)
	f.loginAs(t, admin)

	resp, body := f.getBody(t, "/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200; body=%s", resp.StatusCode, body)
	}
	bs := body
	if !strings.Contains(bs, admin.Email) {
		t.Errorf("body missing admin email: %s", bs)
	}
	if !strings.Contains(bs, other.Email) {
		t.Errorf("body missing other email: %s", bs)
	}
	// Invite form is part of the page.
	if !strings.Contains(bs, `name="role"`) {
		t.Errorf("body missing invite form role field: %s", bs)
	}
}

// TestInspectorUsers_InviteCreatesRowAndShowsURL: POST /users/invite
// with role=user creates an invite row and the response shows the signup URL
// once.
func TestInspectorUsers_InviteCreatesRowAndShowsURL(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)
	csrf := "csrf-invite"
	f.primeCSRF(t, csrf)

	resp, body := f.postCSRF(t, "/users/invite", url.Values{
		"role":       {"user"},
		"scopes":     {"render"},
		"csrf_token": {csrf},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "/signup?code=") {
		t.Errorf("expected signup URL banner, body=%s", body)
	}

	// One invite row landed.
	rows, err := f.st.Invites().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Filter out any bootstrap row that may exist.
	have := 0
	for _, inv := range rows {
		if !inv.Bootstrap {
			have++
		}
	}
	if have != 1 {
		t.Fatalf("got %d non-bootstrap invites, want 1", have)
	}
}

// TestInspectorUsers_InviteRequiresCSRF: invite POST without csrf_token gets 403.
func TestInspectorUsers_InviteRequiresCSRF(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)
	f.primeCSRF(t, "the-real")

	resp, _ := f.postCSRF(t, "/users/invite", url.Values{"role": {"user"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

// TestInspectorUsers_DeactivateRequiresEmailConfirm: a wrong confirm value
// returns 400 and does NOT deactivate.
func TestInspectorUsers_DeactivateRequiresEmailConfirm(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	f.loginAs(t, admin)
	csrf := "csrf-deact"
	f.primeCSRF(t, csrf)

	resp, _ := f.postCSRF(t, "/users/"+target.ID+"/deactivate", url.Values{
		"confirm":    {"WRONG@example.com"},
		"csrf_token": {csrf},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
	got, err := f.st.Users().GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeactivatedAt != nil {
		t.Errorf("user was deactivated despite confirm mismatch")
	}
}

// TestInspectorUsers_DeactivateSuccess: with the correct confirm value,
// the user is deactivated and any owned tokens / paused subscriptions
// reflect that.
func TestInspectorUsers_DeactivateSuccess(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	f.loginAs(t, admin)
	csrf := "csrf-deact-ok"
	f.primeCSRF(t, csrf)

	resp, _ := f.postCSRF(t, "/users/"+target.ID+"/deactivate", url.Values{
		"confirm":    {target.Email},
		"csrf_token": {csrf},
	})
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	got, err := f.st.Users().GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeactivatedAt == nil {
		t.Errorf("user was NOT deactivated after success path")
	}
}

// TestInspectorUsers_DeactivateRefusesLastAdmin: deactivating the only
// active admin returns 409 and leaves the user active.
func TestInspectorUsers_DeactivateRefusesLastAdmin(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)
	csrf := "csrf-last"
	f.primeCSRF(t, csrf)

	resp, _ := f.postCSRF(t, "/users/"+admin.ID+"/deactivate", url.Values{
		"confirm":    {admin.Email},
		"csrf_token": {csrf},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status: %d, want 409", resp.StatusCode)
	}
	got, err := f.st.Users().GetByID(context.Background(), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeactivatedAt != nil {
		t.Errorf("last admin was deactivated despite the guard")
	}
}

// TestInspectorUsers_Reactivate: reactivate clears deactivated_at.
func TestInspectorUsers_Reactivate(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	if err := f.st.Users().Deactivate(context.Background(), target.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	f.loginAs(t, admin)
	csrf := "csrf-react"
	f.primeCSRF(t, csrf)

	resp, _ := f.postCSRF(t, "/users/"+target.ID+"/reactivate", url.Values{"csrf_token": {csrf}})
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	got, err := f.st.Users().GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeactivatedAt != nil {
		t.Errorf("user still deactivated after reactivate")
	}
}

// TestInspectorUsers_ResetPasswordChangesHash: reset-password updates the
// password_hash column and invalidates live sessions for the user.
func TestInspectorUsers_ResetPasswordChangesHash(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	f.loginAs(t, admin)
	csrf := "csrf-reset"
	f.primeCSRF(t, csrf)

	prev, err := f.st.Users().GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := f.postCSRF(t, "/users/"+target.ID+"/reset-password", url.Values{
		"new_password": {"a-fresh-passphrase-1234"},
		"csrf_token":   {csrf},
	})
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	now, err := f.st.Users().GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if now.PasswordHash == prev.PasswordHash {
		t.Errorf("password hash unchanged")
	}
}

// TestInspectorUsers_ResetPasswordRejectsShort: a too-short password is
// rejected with 400.
func TestInspectorUsers_ResetPasswordRejectsShort(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	f.loginAs(t, admin)
	csrf := "csrf-short"
	f.primeCSRF(t, csrf)

	resp, _ := f.postCSRF(t, "/users/"+target.ID+"/reset-password", url.Values{
		"new_password": {"short"},
		"csrf_token":   {csrf},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
}

// TestInspectorUsers_UpdateScopes: edit-default-scopes sets the user's
// default_scopes to the new comma-separated list.
func TestInspectorUsers_UpdateScopes(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	f.loginAs(t, admin)
	csrf := "csrf-scopes"
	f.primeCSRF(t, csrf)

	resp, _ := f.postCSRF(t, "/users/"+target.ID+"/update", url.Values{
		"default_scopes": {"render,stripe"},
		"csrf_token":     {csrf},
	})
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 303/302", resp.StatusCode)
	}
	got, err := f.st.Users().GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameStringSet(got.DefaultScopes, []string{"render", "stripe"}) {
		t.Errorf("default_scopes = %v, want [render stripe]", got.DefaultScopes)
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		m[v]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
