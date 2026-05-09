package inspector

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
	"github.com/onebusaway/hooks/internal/users"
)

// sessionFixture wires the inspector with an auth.Manager so tests can
// drive cookie-session-based authentication paths (tasks 11.10 and 11.12).
type sessionFixture struct {
	srv      *httptest.Server
	st       *store.SQLite
	notifier *pubsub.Notifier
	push     *push.Manager
	auth     *auth.Manager
	client   *http.Client
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tokens.AttachVerifier(st)

	notifier := pubsub.New()
	pmgr := push.New(st.Events(), st.PushSubscriptions(), notifier, slog.New(slog.DiscardHandler))
	t.Cleanup(pmgr.Stop)

	bearer := tokens.New(st.Tokens())
	mgr := auth.NewManager(st.Sessions(), st.Users(), audit.New(st.Audit(), slog.New(slog.DiscardHandler)),
		auth.CookieOptions{TTL: time.Hour})

	in, err := New(st.Events(), st.Tokens(), st.PushSubscriptions(), notifier, pmgr, bearer,
		[]string{"render"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	in.Sessions = mgr
	in.Users = st.Users()
	in.AuditReader = st.Audit()

	mux := http.NewServeMux()
	in.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	return &sessionFixture{srv: srv, st: st, notifier: notifier, push: pmgr, auth: mgr, client: client}
}

// makeUser inserts a user with the given role and returns the created row.
func (f *sessionFixture) makeUser(t *testing.T, email string, role store.Role) store.User {
	t.Helper()
	hash, err := users.HashPassword(secret.String("supercalifragilistic"))
	if err != nil {
		t.Fatal(err)
	}
	u := store.User{
		ID: uuid.NewString(), Email: email, Name: "Tester", Role: role,
		PasswordHash:  hash,
		DefaultScopes: []string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := f.st.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// loginAs creates a session row for u and stores the resulting cookie on
// the fixture's HTTP client jar so subsequent requests are authenticated.
func (f *sessionFixture) loginAs(t *testing.T, u store.User) {
	t.Helper()
	cookie, _, err := f.auth.CreateSession(context.Background(), u.ID, "Test/1.0", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srvURL, _ := url.Parse(f.srv.URL)
	f.client.Jar.SetCookies(srvURL, []*http.Cookie{{Name: auth.SessionCookie, Value: cookie, Path: "/"}})
}

func (f *sessionFixture) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// TestInspector_AnonymousRedirectsToLoginNext (task 11.10): an anonymous
// GET /inspector redirects to /login?next=/inspector, NOT to the legacy
// /inspector/login.
func TestInspector_AnonymousRedirectsToLoginNext(t *testing.T) {
	f := newSessionFixture(t)
	resp := f.get(t, "/inspector")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location = %q, want /login?next=...", loc)
	}
	if !strings.Contains(loc, "next=") {
		t.Fatalf("Location = %q, missing next= parameter", loc)
	}
	// next= must point back at the originally-requested path.
	if !strings.Contains(loc, "next=%2Finspector") && !strings.Contains(loc, "next=/inspector") {
		t.Fatalf("Location = %q, want next pointing at /inspector", loc)
	}
}

// TestInspector_NonAdminSessionRedirectsToMe (task 11.10): a logged-in
// non-admin user GETting /inspector is redirected to /inspector/me.
func TestInspector_NonAdminSessionRedirectsToMe(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	resp := f.get(t, "/inspector")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/inspector/me" {
		t.Fatalf("Location = %q, want /inspector/me", loc)
	}
}

// TestInspector_AdminSessionGrantsAccess (task 11.12): a logged-in admin
// session-cookie user can hit /inspector successfully without any legacy
// bearer token.
func TestInspector_AdminSessionGrantsAccess(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, u)

	resp := f.get(t, "/inspector")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}
}

// TestInspector_NonAdminMutationReturns403 (task 11.10): a logged-in
// non-admin POSTing a mutation gets 403, not a redirect (mutations don't
// redirect; they error).
func TestInspector_NonAdminMutationReturns403(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	form := url.Values{"name": {"foo"}, "scopes": {"render"}}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/tokens/create",
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

// TestInspector_AnonymousMutationReturns401 (task 11.10): an anonymous
// POST returns 401 (no redirect for mutations).
func TestInspector_AnonymousMutationReturns401(t *testing.T) {
	f := newSessionFixture(t)
	form := url.Values{"name": {"foo"}, "scopes": {"render"}}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/tokens/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

// TestInspector_LegacyBearerCookieStillWorks (task 11.11): existing admin
// users with the legacy hooks_inspector_token cookie continue to authenticate
// fully even with the new session middleware in place.
func TestInspector_LegacyBearerCookieStillWorks(t *testing.T) {
	f := newSessionFixture(t)
	admin, _ := tokens.Issue(context.Background(), f.st.Tokens(), "ops", []string{"admin"})

	srvURL, _ := url.Parse(f.srv.URL)
	f.client.Jar.SetCookies(srvURL, []*http.Cookie{{
		Name: "hooks_inspector_token", Value: admin.Plaintext, Path: "/inspector",
	}})

	resp := f.get(t, "/inspector")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}
}

// TestInspector_LegacyBearerCookieAuthorizesMutations (task 11.11): the
// deprecated raw-bearer cookie continues to authenticate state-changing
// requests for v1. /inspector/tokens/create is a representative mutation:
// it bypasses the session-cookie CSRF gate (admin-scoped legacy cookie
// path) and creates a new token row.
func TestInspector_LegacyBearerCookieAuthorizesMutations(t *testing.T) {
	f := newSessionFixture(t)
	admin, _ := tokens.Issue(context.Background(), f.st.Tokens(), "ops", []string{"admin"})

	srvURL, _ := url.Parse(f.srv.URL)
	f.client.Jar.SetCookies(srvURL, []*http.Cookie{{
		Name: "hooks_inspector_token", Value: admin.Plaintext, Path: "/inspector",
	}})

	form := url.Values{"name": {"laptop"}, "scopes": {"render,admin"}}
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/inspector/tokens/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "shown once") {
		t.Fatalf("plaintext banner missing: %s", body)
	}

	// Verify the token actually landed in the store.
	all, err := f.st.Tokens().List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tok := range all {
		if tok.Name == "laptop" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected token 'laptop' in list, got %v", all)
	}
}

// TestInspector_LoginPOSTDeprecationWarning (task 11.11): the v1
// /inspector/login form continues to function in v1 but emits a
// `Deprecation` response header so callers know to migrate to /login.
// (RFC 8594 — the response header form, not the request directive.)
func TestInspector_LoginPOSTDeprecationWarning(t *testing.T) {
	f := newSessionFixture(t)
	admin, _ := tokens.Issue(context.Background(), f.st.Tokens(), "ops", []string{"admin"})

	form := url.Values{"token": {admin.Plaintext}}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	if resp.Header.Get("Deprecation") == "" {
		t.Fatalf("expected Deprecation header on /inspector/login POST")
	}
	// Even though we mark this path deprecated, v1 still issues the
	// legacy cookie so existing operators retain access until v2.
	gotCookie := false
	for _, c := range resp.Cookies() {
		if c.Name == "hooks_inspector_token" && c.Value != "" {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Fatalf("expected legacy hooks_inspector_token cookie still set in v1; got %v",
			resp.Header.Values("Set-Cookie"))
	}
}

// TestInspector_TokensPageShowsOwnerAndKindColumns (task 11.8): admin
// session view of /inspector/tokens renders an owner column ("system"
// for owner-NULL rows, the user's email otherwise) plus a kind column
// distinguishing pat from listener.
func TestInspector_TokensPageShowsOwnerAndKindColumns(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	owner := f.makeUser(t, "owner@example.com", store.RoleUser)
	f.loginAs(t, admin)

	// One system-owned listener token (no owner_user_id).
	if _, err := tokens.Issue(context.Background(), f.st.Tokens(), "system-tok",
		[]string{"render"}); err != nil {
		t.Fatal(err)
	}
	// One user-owned PAT.
	gen, err := tokens.Generate("user-pat", []string{"render"})
	if err != nil {
		t.Fatal(err)
	}
	ownerID := owner.ID
	if err := f.st.Tokens().Insert(context.Background(), store.Token{
		ID: gen.ID, Name: "user-pat", Scopes: []string{"render"},
		SecretHash: gen.Hash, CreatedAt: time.Now().UTC(),
		OwnerUserID: &ownerID, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}

	resp := f.get(t, "/inspector/tokens")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/tokens", nil)
	r2, _ := f.client.Do(req)
	body, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "system") {
		t.Fatalf("expected 'system' owner cell; body=%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "owner@example.com") {
		t.Fatalf("expected owner email; body=%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ">pat<") {
		t.Fatalf("expected kind column with 'pat'; body=%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ">listener<") {
		t.Fatalf("expected kind column with 'listener'; body=%s", bodyStr)
	}
}

// TestInspector_TokensCreateOnBehalfOfUser (task 11.8): the Add Token
// form accepts an optional owner_user_id and mints the token owned by
// that user. The flow validates the user exists; an unknown id returns
// 400 without minting.
func TestInspector_TokensCreateOnBehalfOfUser(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	target := f.makeUser(t, "target@example.com", store.RoleUser)
	f.loginAs(t, admin)

	form := url.Values{
		"name":          {"on-behalf"},
		"scopes":        {"render"},
		"kind":          {"pat"},
		"owner_user_id": {target.ID},
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/tokens/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}

	// Token landed on `target`.
	rows, err := f.st.Tokens().ListByOwner(context.Background(), target.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "on-behalf" || rows[0].Kind != store.TokenKindPAT {
		t.Fatalf("expected one PAT named on-behalf for target; got %+v", rows)
	}

	// Unknown owner → 400, no insert.
	form2 := url.Values{
		"name":          {"orphan"},
		"scopes":        {"render"},
		"owner_user_id": {"not-a-user"},
	}
	req2, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/tokens/create",
		strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := f.client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown owner, got %d", resp2.StatusCode)
	}
}

// TestInspector_PushPageShowsOwnerColumnAndFilter (task 11.9): admin
// view of /inspector/push renders an owner column and supports
// ?owner=<id>|system filtering.
func TestInspector_PushPageShowsOwnerColumnAndFilter(t *testing.T) {
	f := newSessionFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	owner := f.makeUser(t, "owner@example.com", store.RoleUser)
	f.loginAs(t, admin)

	// System-owned subscription.
	sysSub := store.PushSubscription{
		ID:                uuid.NewString(),
		Source:            "render",
		TargetURL:         "https://example.test/sys",
		Name:              "sys-sub",
		SigningSecretHash: "x",
		CreatedAt:         time.Now().UTC(),
	}
	if err := f.st.PushSubscriptions().Insert(context.Background(), sysSub); err != nil {
		t.Fatal(err)
	}
	// User-owned subscription.
	ownerID := owner.ID
	userSub := store.PushSubscription{
		ID:                uuid.NewString(),
		Source:            "render",
		TargetURL:         "https://example.test/user",
		Name:              "user-sub",
		SigningSecretHash: "y",
		CreatedAt:         time.Now().UTC(),
		OwnerUserID:       &ownerID,
	}
	if err := f.st.PushSubscriptions().Insert(context.Background(), userSub); err != nil {
		t.Fatal(err)
	}

	// No filter: both rows + owner column ("system" and email).
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/push", nil)
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
	if !strings.Contains(bs, "/sys") || !strings.Contains(bs, "/user") {
		t.Fatalf("expected both subscription rows; body=%s", bs)
	}
	if !strings.Contains(bs, "owner@example.com") {
		t.Fatalf("expected owner email cell; body=%s", bs)
	}

	// owner=system filter: only the system sub.
	req2, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/inspector/push?owner=system", nil)
	resp2, err := f.client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	bs2 := string(body2)
	if !strings.Contains(bs2, "example.test/sys") {
		t.Fatalf("system filter missing system sub; body=%s", bs2)
	}
	if strings.Contains(bs2, "example.test/user") {
		t.Fatalf("system filter unexpectedly showed user sub; body=%s", bs2)
	}

	// owner=<user_id> filter: only that user's sub.
	req3, _ := http.NewRequest(http.MethodGet,
		f.srv.URL+"/inspector/push?owner="+owner.ID, nil)
	resp3, err := f.client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	bs3 := string(body3)
	if !strings.Contains(bs3, "example.test/user") {
		t.Fatalf("user filter missing user sub; body=%s", bs3)
	}
	if strings.Contains(bs3, "example.test/sys") {
		t.Fatalf("user filter unexpectedly showed system sub; body=%s", bs3)
	}
}
