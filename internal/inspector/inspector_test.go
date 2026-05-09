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

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/push"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

type fixture struct {
	srv      *httptest.Server
	st       *store.SQLite
	notifier *pubsub.Notifier
	push     *push.Manager
	admin    string
	user     string
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
	tokens.AttachVerifier(st)

	admin, _ := tokens.Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})
	user, _ := tokens.Issue(context.Background(), st.Tokens(), "user", []string{"render"})

	notifier := pubsub.New()
	pmgr := push.New(st.Events(), st.PushSubscriptions(), notifier, slog.New(slog.DiscardHandler))
	t.Cleanup(pmgr.Stop)

	auth := tokens.New(st.Tokens())
	in, err := New(st.Events(), st.Tokens(), st.PushSubscriptions(), notifier, pmgr, auth,
		[]string{"render"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	in.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &fixture{srv: srv, st: st, notifier: notifier, push: pmgr, admin: admin.Plaintext, user: user.Plaintext, client: client}
}

func (f *fixture) login(t *testing.T, plaintext string) {
	t.Helper()
	form := url.Values{}
	form.Set("token", plaintext)
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
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

func TestInspectorLoginRequired(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.get(t, "/inspector")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	// Without a session manager wired, the inspector still redirects
	// anonymous GETs but to the new /login page (task 11.10). The legacy
	// /inspector/login form remains available by direct visit.
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestInspectorRejectsNonAdmin(t *testing.T) {
	f := newFixture(t)
	form := url.Values{}
	form.Set("token", f.user)
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/inspector/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("non-admin login should re-render form, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(b), "invalid or non-admin") {
		t.Fatalf("expected non-admin error, got %s", string(b))
	}

	// And the cookie was never set, so /inspector still redirects to login.
	resp, _ = f.get(t, "/inspector")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestInspectorRevokedCookieRedirectsAndClears(t *testing.T) {
	f := newFixture(t)
	f.login(t, f.admin)

	tok, err := f.st.Tokens().LookupByPlaintext(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Tokens().Revoke(context.Background(), tok.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	resp, _ := f.get(t, "/inspector")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to login, got %q", loc)
	}
	// Cookie should be cleared.
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == "hooks_inspector_token" && (c.MaxAge < 0 || c.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected Set-Cookie to clear hooks_inspector_token, got %v", resp.Header.Values("Set-Cookie"))
	}
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

	resp, body := f.get(t, "/inspector")
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
	resp, body := f.post(t, "/inspector/tokens/create", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "shown once") {
		t.Fatalf("plaintext banner missing: %s", body)
	}

	// Listing again should not show plaintext.
	resp2, body2 := f.get(t, "/inspector/tokens")
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

	resp, body := f.get(t, "/inspector/push")
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

	resp, _ := f.post(t, "/inspector/events/render/1/replay", nil)
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
	resp, body := f.get(t, "/inspector/static/style.css")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "body") {
		t.Fatalf("css not served: %s", body[:100])
	}
}
