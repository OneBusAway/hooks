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
