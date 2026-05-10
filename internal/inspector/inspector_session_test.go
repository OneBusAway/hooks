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
	srv       *httptest.Server
	st        *store.SQLite
	notifier  *pubsub.Notifier
	push      *push.Manager
	auth      *auth.Manager
	client    *http.Client
	inspector *Inspector
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

	mgr := auth.NewManager(st.Sessions(), st.Users(), audit.New(st.Audit(), slog.New(slog.DiscardHandler)),
		auth.CookieOptions{TTL: time.Hour})

	in, err := New(st.Events(), st.Tokens(), st.PushSubscriptions(), notifier, pmgr,
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

	return &sessionFixture{srv: srv, st: st, notifier: notifier, push: pmgr, auth: mgr, client: client, inspector: in}
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

// TestInspector_AnonymousRedirectsToLoginNext: an anonymous GET / redirects
// to /login?next=/.
func TestInspector_AnonymousRedirectsToLoginNext(t *testing.T) {
	f := newSessionFixture(t)
	resp := f.get(t, "/")
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
	if !strings.Contains(loc, "next=%2F") && !strings.Contains(loc, "next=/") {
		t.Fatalf("Location = %q, want next pointing at /", loc)
	}
}

// TestInspector_NonAdminSessionRedirectsToMe: a logged-in non-admin user
// GETting / is redirected to /me.
func TestInspector_NonAdminSessionRedirectsToMe(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	resp := f.get(t, "/")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/me" {
		t.Fatalf("Location = %q, want /me", loc)
	}
}

// TestInspector_AdminSessionGrantsAccess: a logged-in admin can hit /
// successfully.
func TestInspector_AdminSessionGrantsAccess(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	f.loginAs(t, u)

	resp := f.get(t, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}
}

// TestInspector_NonAdminMutationReturns403: a logged-in
// non-admin POSTing a mutation gets 403, not a redirect (mutations don't
// redirect; they error).
func TestInspector_NonAdminMutationReturns403(t *testing.T) {
	f := newSessionFixture(t)
	u := f.makeUser(t, "user@example.com", store.RoleUser)
	f.loginAs(t, u)

	form := url.Values{"name": {"foo"}, "scopes": {"render"}}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/tokens/create",
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

// TestInspector_AnonymousMutationReturns401: an anonymous
// POST returns 401 (no redirect for mutations).
func TestInspector_AnonymousMutationReturns401(t *testing.T) {
	f := newSessionFixture(t)
	form := url.Values{"name": {"foo"}, "scopes": {"render"}}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/tokens/create",
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

// TestInspector_TokensPageShowsOwnerAndKindColumns: admin view of /tokens
// renders an owner column ("system" for owner-NULL rows, the user's email
// otherwise) plus a kind column distinguishing pat from listener.
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

	resp := f.get(t, "/tokens")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d, want 200", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/tokens", nil)
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

// TestInspector_TokensCreateOnBehalfOfUser: the Add Token
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
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/tokens/create",
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
	req2, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/tokens/create",
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

// TestInspector_PushPageShowsOwnerColumnAndFilter: admin
// view of /push renders an owner column and supports
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
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/push", nil)
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
	req2, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/push?owner=system", nil)
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
		f.srv.URL+"/push?owner="+owner.ID, nil)
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

// TestInspector_AllSessionMutationsRequireCSRF: every CSRF-protected
// inspector mutation endpoint returns 403 when posted without a
// `csrf_token` form field, even with a valid session cookie + Origin
// header. Previously each endpoint had its own per-feature `RequiresCSRF`
// test (mint PAT, push pause, users invite); this is the parametric sweep
// that closes the "every form POST without CSRF token returns 403"
// requirement at one stroke and prevents new endpoints from being added
// without the same guard.
func TestInspector_AllSessionMutationsRequireCSRF(t *testing.T) {
	f := loadInspectorUsersFixture(t)
	admin := f.makeUser(t, "admin@example.com", store.RoleAdmin)
	other := f.makeUser(t, "other@example.com", store.RoleUser)
	// Insert a user-owned PAT and push subscription so the
	// /me/{tokens,push}/{id}/* routes resolve a real id rather
	// than 404'ing before they ever reach the CSRF check.
	tok := insertOwnedToken(t, f, admin, "csrf-target", store.TokenKindPAT, []string{"render"})
	sub := insertOwnedSub(t, f, admin, "render")
	f.loginAs(t, admin)
	// Prime the csrf cookie. The endpoints must reject because the form
	// body omits csrf_token, NOT because the cookie is missing.
	f.primeCSRF(t, "real-csrf")

	cases := []struct {
		name string
		path string
	}{
		{"meCreateToken", "/me/tokens"},
		{"meRevokeToken", "/me/tokens/" + tok.ID + "/revoke"},
		{"mePushPause", "/me/push/" + sub.ID + "/pause"},
		{"mePushResume", "/me/push/" + sub.ID + "/resume"},
		{"mePushTest", "/me/push/" + sub.ID + "/test"},
		{"mePushRotate", "/me/push/" + sub.ID + "/rotate"},
		{"mePushDelete", "/me/push/" + sub.ID + "/delete"},
		{"usersInvite", "/users/invite"},
		{"usersDeactivate", "/users/" + other.ID + "/deactivate"},
		{"usersReactivate", "/users/" + other.ID + "/reactivate"},
		{"usersResetPassword", "/users/" + other.ID + "/reset-password"},
		{"usersUpdate", "/users/" + other.ID + "/update"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{} // intentionally no csrf_token
			req, _ := http.NewRequest(http.MethodPost, f.srv.URL+tc.path,
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
				t.Fatalf("%s: status %d, want 403", tc.path, resp.StatusCode)
			}
		})
	}
}
