package inspector

// Tests for /me: profile + own tokens (filtered by
// kind) + own subscriptions + ephemeral-PAT mint form.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// insertOwnedToken creates a kind=pat token owned by user u.
func insertOwnedToken(t *testing.T, f *sessionFixture, u store.User, name string, kind store.TokenKind, scopes []string) store.Token {
	t.Helper()
	res, err := tokens.Generate(name, scopes)
	if err != nil {
		t.Fatal(err)
	}
	owner := u.ID
	tok := store.Token{
		ID:          res.ID,
		Name:        name,
		Scopes:      scopes,
		SecretHash:  res.Hash,
		CreatedAt:   time.Now().UTC(),
		OwnerUserID: &owner,
		Kind:        kind,
	}
	if err := f.st.Tokens().Insert(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func insertOwnedSub(t *testing.T, f *sessionFixture, u store.User, source string) store.PushSubscription {
	t.Helper()
	owner := u.ID
	sub := store.PushSubscription{
		ID: uuid.NewString(), Source: source, TargetURL: "https://example.invalid/push",
		Name: "owned", SigningSecretHash: "hash", Cursor: 0,
		CreatedAt:   time.Now().UTC(),
		OwnerUserID: &owner,
	}
	if err := f.st.PushSubscriptions().Insert(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	return sub
}

// sessionCSRF returns the post-session hooks_csrf cookie that auth.Manager.
// SetCookies set when we logged in via the manager. The fixture's loginAs
// helper does NOT set the csrf cookie on its own, so tests that need to
// post a CSRF-protected form prime it here directly.
func (f *sessionFixture) primeCSRF(t *testing.T, value string) {
	t.Helper()
	srvURL, _ := url.Parse(f.srv.URL)
	f.client.Jar.SetCookies(srvURL, []*http.Cookie{{
		Name: auth.CSRFCookie, Value: value, Path: "/",
	}})
}

// TestInspectorMe_AnonymousRedirectsToLogin: /me with no session redirects
// to /login?next=/me.
func TestInspectorMe_AnonymousRedirectsToLogin(t *testing.T) {
	f := newSessionFixture(t)
	resp := f.get(t, "/me")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") || !strings.Contains(loc, "next=") {
		t.Fatalf("Location = %q, want /login?next=...", loc)
	}
	if !strings.Contains(loc, "%2Fme") {
		t.Fatalf("Location = %q, want next pointing at /me", loc)
	}
}

// TestInspectorMe_ShowsProfile: a logged-in user sees their email + role.
func TestInspectorMe_ShowsProfile(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/me", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200, body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "user@example.com") {
		t.Errorf("missing email in body: %s", string(body))
	}
	if !strings.Contains(string(body), "user") { // role
		t.Errorf("missing role in body: %s", string(body))
	}
}

// TestInspectorMe_OnlyShowsOwnTokens: tokens owned by other users do not
// appear in the page.
func TestInspectorMe_OnlyShowsOwnTokens(t *testing.T) {
	f := newSessionFixture(t)
	alice := f.makeUser(t, "alice@example.com", store.RoleUser)
	bob := f.makeUser(t, "bob@example.com", store.RoleUser)

	mine := insertOwnedToken(t, f, alice, "mine-pat", store.TokenKindPAT, []string{"render", "account"})
	notMine := insertOwnedToken(t, f, bob, "bob-pat", store.TokenKindPAT, []string{"render", "account"})

	f.loginAs(t, alice)
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/me", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200, body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), mine.Name) {
		t.Errorf("missing own token name: %s", string(body))
	}
	if strings.Contains(string(body), notMine.Name) {
		t.Errorf("body leaked another user's token: %s", string(body))
	}
}

// TestInspectorMe_KindFilterHidesOtherKinds: ?kind=pat omits listener
// tokens from the rendered table.
func TestInspectorMe_KindFilterHidesOtherKinds(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	pat := insertOwnedToken(t, f, u, "p-mine", store.TokenKindPAT, []string{"render", "account"})
	lst := insertOwnedToken(t, f, u, "l-mine", store.TokenKindListener, []string{"render"})

	f.loginAs(t, u)
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/me?kind=pat", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	if !strings.Contains(s, pat.Name) {
		t.Errorf("kind=pat should still show pat token: %s", s)
	}
	if strings.Contains(s, lst.Name) {
		t.Errorf("kind=pat should NOT show listener token: %s", s)
	}
}

// TestInspectorMe_OnlyShowsOwnSubscriptions: subscriptions owned by other
// users do not appear.
func TestInspectorMe_OnlyShowsOwnSubscriptions(t *testing.T) {
	f := newSessionFixture(t)
	alice := f.makeUser(t, "alice@example.com", store.RoleUser)
	bob := f.makeUser(t, "bob@example.com", store.RoleUser)

	mine := insertOwnedSub(t, f, alice, "render")
	notMine := insertOwnedSub(t, f, bob, "render")

	f.loginAs(t, alice)
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/me", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), mine.ID) {
		t.Errorf("missing own sub id: %s", string(body))
	}
	if strings.Contains(string(body), notMine.ID) {
		t.Errorf("body leaked another user's sub id: %s", string(body))
	}
}

// TestInspectorMe_AdminSeesAdminLinks: an admin viewing /me sees
// links to /users and /audit; a regular user does not.
func TestInspectorMe_AdminSeesAdminLinks(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, admin)

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/me", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	if !strings.Contains(s, "/users") {
		t.Errorf("admin missing /users link: %s", s)
	}
	if !strings.Contains(s, "/audit") {
		t.Errorf("admin missing /audit link: %s", s)
	}
}

func TestInspectorMe_NonAdminDoesNotSeeAdminLinks(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/me", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	if strings.Contains(s, `href="/users"`) {
		t.Errorf("non-admin saw /users link: %s", s)
	}
	if strings.Contains(s, `href="/audit"`) {
		t.Errorf("non-admin saw /audit link: %s", s)
	}
}

// TestInspectorMe_MintEphemeralPATRequiresCSRF: POSTing to mint a token
// without the csrf_token form field fails (403).
func TestInspectorMe_MintEphemeralPATRequiresCSRF(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	u.DefaultScopes = []string{"render"}
	if err := f.st.UpdateUserProfile(context.Background(), u.ID, u.Name, u.DefaultScopes); err != nil {
		t.Fatal(err)
	}
	f.loginAs(t, u)
	f.primeCSRF(t, "the-real-csrf")

	form := url.Values{
		"name":   {"my-pat"},
		"scopes": {"render"},
		// no csrf_token
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/me/tokens",
		strings.NewReader(form.Encode()))
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

// TestInspectorMe_MintEphemeralPATSuccess: with valid CSRF, a logged-in
// user can mint an ephemeral PAT and the plaintext is rendered exactly
// once on the page.
func TestInspectorMe_MintEphemeralPATSuccess(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	u.DefaultScopes = []string{"render"}
	if err := f.st.UpdateUserProfile(context.Background(), u.ID, u.Name, u.DefaultScopes); err != nil {
		t.Fatal(err)
	}
	f.loginAs(t, u)
	csrf := "trusty-csrf-value"
	f.primeCSRF(t, csrf)

	form := url.Values{
		"name":       {"my-pat"},
		"scopes":     {"render"},
		"csrf_token": {csrf},
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/me/tokens",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// CSRF middleware also requires Origin to match.
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

	// Verify exactly one token now belongs to the user, with kind=pat,
	// ephemeral=true, scopes containing render and account.
	rows, err := f.st.Tokens().ListByOwner(context.Background(), u.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d tokens, want 1", len(rows))
	}
	got := rows[0]
	if got.Kind != store.TokenKindPAT {
		t.Errorf("Kind = %q, want pat", got.Kind)
	}
	if !got.Ephemeral {
		t.Errorf("Ephemeral = false, want true")
	}
	if !store.HasScope(got.Scopes, "render") {
		t.Errorf("scopes missing render: %v", got.Scopes)
	}
	if !store.HasScope(got.Scopes, "account") {
		t.Errorf("scopes missing implicit account: %v", got.Scopes)
	}

	// The plaintext should be rendered in the response body. The token
	// plaintext is a base64 string >= 32 chars. We just check that some
	// "shown once" banner appears.
	if !strings.Contains(string(body), "shown once") {
		t.Errorf("body did not show plaintext banner: %s", string(body))
	}
}

// TestInspectorMe_MintRejectsScopesAboveCallerAuthority: a non-admin user
// requesting a scope they do not hold gets 403.
func TestInspectorMe_MintRejectsScopesAboveCallerAuthority(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	// no DefaultScopes -> only the implicit account scope.
	f.loginAs(t, u)
	csrf := "csrf-x"
	f.primeCSRF(t, csrf)

	form := url.Values{
		"name":       {"my-pat"},
		"scopes":     {"render"},
		"csrf_token": {csrf},
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/me/tokens",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.srv.URL)
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

// TestInspectorMe_RevokeOwnToken: a logged-in user can revoke their own
// token through /me/tokens/{id}/revoke.
func TestInspectorMe_RevokeOwnToken(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	mine := insertOwnedToken(t, f, u, "mine-pat", store.TokenKindPAT, []string{"render", "account"})
	f.loginAs(t, u)
	csrf := "csrf-revoke"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/me/tokens/"+mine.ID+"/revoke",
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

	got, err := f.st.Tokens().Get(context.Background(), mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Errorf("token not revoked")
	}
}

// TestInspectorMe_CannotRevokeAnotherUsersToken: a request to revoke
// another user's token id returns 404 (probe-resistant).
func TestInspectorMe_CannotRevokeAnotherUsersToken(t *testing.T) {
	f := newSessionFixture(t)
	alice := f.makeUser(t, "alice@example.com", store.RoleUser)
	bob := f.makeUser(t, "bob@example.com", store.RoleUser)
	bobs := insertOwnedToken(t, f, bob, "bobs-pat", store.TokenKindPAT, []string{"render", "account"})

	f.loginAs(t, alice)
	csrf := "csrf-z"
	f.primeCSRF(t, csrf)

	form := url.Values{"csrf_token": {csrf}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/me/tokens/"+bobs.ID+"/revoke",
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
	got, err := f.st.Tokens().Get(context.Background(), bobs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt != nil {
		t.Errorf("Bob's token should not have been revoked by Alice")
	}
}
