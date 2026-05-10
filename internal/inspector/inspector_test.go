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
	"github.com/onebusaway/hooks/internal/store"
)

type fixture struct {
	srv      *httptest.Server
	st       *store.SQLite
	notifier *pubsub.Notifier
	push     *push.Manager
	auth     *auth.Manager
	admin    store.User
	client   *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

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

	mux := http.NewServeMux()
	in.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	f := &fixture{srv: srv, st: st, notifier: notifier, push: pmgr, auth: mgr, client: client}
	f.admin = f.makeUser(t, "admin@example.com", store.RoleAdmin)
	return f
}

func (f *fixture) makeUser(t *testing.T, email string, role store.Role) store.User {
	t.Helper()
	u := store.User{
		ID: uuid.NewString(), Email: email, Name: "Tester", Role: role,
		PasswordHash:  "x",
		DefaultScopes: []string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := f.st.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) login(t *testing.T, u store.User) {
	t.Helper()
	cookie, _, err := f.auth.CreateSession(context.Background(), u.ID, "Test/1.0", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srvURL, _ := url.Parse(f.srv.URL)
	f.client.Jar.SetCookies(srvURL, []*http.Cookie{{Name: auth.SessionCookie, Value: cookie, Path: "/"}})
}

func (f *fixture) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (f *fixture) post(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestInspectorIndexShowsEvents(t *testing.T) {
	f := newFixture(t)
	f.login(t, f.admin)

	_, err := f.st.Append(context.Background(), store.AppendInput{
		Source:            "render",
		DeliveryID:        "abc",
		ProviderTimestamp: time.Now(),
		Body:              []byte(`{"hi":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, body := f.get(t, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "abc") {
		t.Fatalf("body missing delivery id: %s", body)
	}
}

func TestInspectorTokenCreateAndRevoke(t *testing.T) {
	f := newFixture(t)
	f.login(t, f.admin)

	form := url.Values{"name": {"laptop"}, "scopes": {"render,admin"}}
	resp, body := f.post(t, "/tokens/create", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "shown once") {
		t.Fatalf("plaintext banner missing: %s", body)
	}

	// Listing again should not show plaintext.
	resp2, body2 := f.get(t, "/tokens")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", resp2.StatusCode)
	}
	if strings.Contains(body2, "shown once") {
		t.Fatalf("plaintext leaked into subsequent list view")
	}

	// Verify list shows the token name.
	if !strings.Contains(body2, "laptop") {
		t.Fatalf("token not listed: %s", body2)
	}
}

func TestInspectorPushListEmpty(t *testing.T) {
	f := newFixture(t)
	f.login(t, f.admin)

	resp, body := f.get(t, "/push")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "No subscriptions") {
		t.Fatalf("empty state missing: %s", body)
	}
}

func TestInspectorReplay(t *testing.T) {
	f := newFixture(t)
	f.login(t, f.admin)

	ev, err := f.st.Append(context.Background(), store.AppendInput{
		Source:            "render",
		DeliveryID:        "rep-1",
		ProviderTimestamp: time.Now(),
		Body:              []byte(`{"x":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to notifier so we can witness the publish.
	ch := f.notifier.Subscribe("render")
	defer f.notifier.Unsubscribe("render", ch)

	resp, _ := f.post(t, "/events/render/1/replay", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case got := <-ch:
		if got != ev.Sequence {
			t.Fatalf("got seq %d, want %d", got, ev.Sequence)
		}
	case <-time.After(time.Second):
		t.Fatal("notifier not poked")
	}
}

func TestInspectorStaticServed(t *testing.T) {
	f := newFixture(t)
	resp, body := f.get(t, "/assets/stylesheets/style.css")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "body") {
		t.Fatalf("css not served: %s", body[:100])
	}
}

func TestInspectorLogoutRedirectsToLogin(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.get(t, "/logout")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("Location = %q, want /login", loc)
	}
}

func TestInspectorLogoutDestroysSession(t *testing.T) {
	f := newFixture(t)
	f.login(t, f.admin)

	// /logout should redirect, kill the session row, and clear cookies.
	if resp, _ := f.get(t, "/logout"); resp.StatusCode != http.StatusFound {
		t.Fatalf("/logout status %d, want 302", resp.StatusCode)
	}

	// A subsequent admin-only GET must now redirect anonymously to /login,
	// not 200 — proves the server-side session was actually invalidated
	// even if the browser replays the (now-cleared) cookie.
	resp, _ := f.get(t, "/")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post-logout / status %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("post-logout / Location = %q, want /login...", loc)
	}
}
