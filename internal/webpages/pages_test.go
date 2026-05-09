package webpages

import (
	"context"
	"errors"
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
	"github.com/onebusaway/hooks/internal/invites"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

type fixture struct {
	srv    *httptest.Server
	st     *store.SQLite
	mgr    *auth.Manager
	pages  *Pages
	client *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr := auth.NewManager(st.Sessions(), st.Users(), audit.New(st.Audit(), nil),
		auth.CookieOptions{TTL: time.Hour})
	mgr.SetLogger(slog.New(slog.DiscardHandler))

	signup := DefaultSignupFunc(st.Invites(), st.Users(), audit.New(st.Audit(), nil))
	pages, err := New(mgr, signup, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mux := http.NewServeMux()
	pages.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &fixture{srv: srv, st: st, mgr: mgr, pages: pages, client: client}
}

func (f *fixture) addUser(t *testing.T, email, plaintext string, role store.Role) store.User {
	t.Helper()
	hash, err := users.HashPassword(secret.String(plaintext))
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

func (f *fixture) addInvite(t *testing.T, role store.Role, scopes []string, expiresAt *time.Time) store.Invite {
	t.Helper()
	if scopes == nil {
		scopes = []string{}
	}
	inv := store.Invite{
		Code: strings.ReplaceAll(uuid.NewString(), "-", "")[:16],
		Role: role, DefaultScopes: scopes,
		Bootstrap: false,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}
	if err := f.st.InsertInvite(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestLoginGET_RendersFormAndSetsCSRFCookie(t *testing.T) {
	f := newFixture(t)

	resp, body := f.get(t, "/login")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Errorf("missing csrf_token field in form: %s", body)
	}
	if !strings.Contains(body, `name="email"`) || !strings.Contains(body, `name="password"`) {
		t.Errorf("missing email/password inputs: %s", body)
	}

	var preCSRF *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == PreSessionCSRFCookie {
			preCSRF = c
		}
	}
	if preCSRF == nil || preCSRF.Value == "" {
		t.Fatal("missing hooks_csrf_pre cookie on GET /login")
	}
	// hidden field value must equal the cookie value.
	if !strings.Contains(body, `value="`+preCSRF.Value+`"`) {
		t.Errorf("csrf_token field does not equal cookie value")
	}
}

func TestLoginGET_PreservesCSRFCookieAcrossGETs(t *testing.T) {
	f := newFixture(t)
	resp1, _ := f.get(t, "/login")
	first := cookieValue(resp1, PreSessionCSRFCookie)
	if first == "" {
		t.Fatal("no csrf cookie on first GET")
	}
	// Cookie jar carries it forward; the handler should not re-issue.
	resp2, body2 := f.get(t, "/login")
	for _, c := range resp2.Cookies() {
		if c.Name == PreSessionCSRFCookie && c.Value != first && c.Value != "" {
			t.Errorf("csrf cookie regenerated unnecessarily: %s vs %s", c.Value, first)
		}
	}
	if !strings.Contains(body2, `value="`+first+`"`) {
		t.Errorf("second-GET form did not embed the surviving cookie value")
	}
}

func TestLoginPOST_HappyPath_RedirectsAndSetsSessionCookie(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

	csrf := f.primeCSRF(t, "/login")

	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "supercalifragilistic")
	form.Set("csrf_token", csrf)

	resp, _ := f.postForm(t, "/login", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/inspector" {
		t.Errorf("redirect: %q want /inspector", loc)
	}
	if cookieValue(resp, auth.SessionCookie) == "" {
		t.Error("hooks_session cookie not set after login")
	}
	if cookieValue(resp, auth.CSRFCookie) == "" {
		t.Error("hooks_csrf cookie not set after login")
	}
}

// TestLoginPOST_RotatesPostSessionCSRFCookieAcrossLogins asserts task 4.3:
// the post-session hooks_csrf cookie value is regenerated on every
// successful login. Two logins from the same client (cookie jar carries
// any prior hooks_csrf forward) must produce two distinct cookie values
// so a stale hooks_csrf token cannot be replayed.
func TestLoginPOST_RotatesPostSessionCSRFCookieAcrossLogins(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

	doLogin := func() string {
		csrf := f.primeCSRF(t, "/login")
		form := url.Values{}
		form.Set("email", "alice@example.com")
		form.Set("password", "supercalifragilistic")
		form.Set("csrf_token", csrf)
		resp, _ := f.postForm(t, "/login", form)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status: %d", resp.StatusCode)
		}
		v := cookieValue(resp, auth.CSRFCookie)
		if v == "" {
			t.Fatal("hooks_csrf cookie not set after login")
		}
		return v
	}

	first := doLogin()
	second := doLogin()
	if first == second {
		t.Errorf("hooks_csrf cookie was not rotated across logins: %q == %q", first, second)
	}
}

func TestLoginPOST_BadCredentials_RendersError(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

	csrf := f.primeCSRF(t, "/login")
	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "wrongpasswordverylong")
	form.Set("csrf_token", csrf)

	resp, body := f.postForm(t, "/login", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Invalid email or password") {
		t.Errorf("missing error message in body: %s", body)
	}
	if cookieValue(resp, auth.SessionCookie) != "" {
		t.Error("session cookie should not be set on bad creds")
	}
}

func TestLoginPOST_DeactivatedAccount_RendersError(t *testing.T) {
	f := newFixture(t)
	u := f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)
	now := time.Now().UTC()
	if err := f.st.DeactivateUser(context.Background(), u.ID, now); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	csrf := f.primeCSRF(t, "/login")
	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "supercalifragilistic")
	form.Set("csrf_token", csrf)

	resp, body := f.postForm(t, "/login", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "deactivated") {
		t.Errorf("missing deactivated message: %s", body)
	}
}

func TestLoginPOST_MissingCSRFToken_Rejected(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

	// Prime cookie but submit without the form field.
	_ = f.primeCSRF(t, "/login")
	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "supercalifragilistic")
	resp, _ := f.postForm(t, "/login", form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

func TestLoginPOST_MismatchedCSRFToken_Rejected(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

	_ = f.primeCSRF(t, "/login")
	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "supercalifragilistic")
	form.Set("csrf_token", "definitely-not-the-real-token")
	resp, _ := f.postForm(t, "/login", form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

func TestLoginPOST_RespectsSafeNextRedirect(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

	csrf := f.primeCSRF(t, "/login?next=/device")
	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "supercalifragilistic")
	form.Set("csrf_token", csrf)

	resp, _ := f.postForm(t, "/login?next=/device", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/device" {
		t.Errorf("redirect: %q want /device", loc)
	}
}

func TestLoginPOST_RejectsForeignNextRedirect(t *testing.T) {
	for _, evil := range []string{"//evil.example.com/", "https://evil.example.com/", "evil.example.com"} {
		t.Run(evil, func(t *testing.T) {
			f := newFixture(t)
			f.addUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser)

			csrf := f.primeCSRF(t, "/login?next="+url.QueryEscape(evil))
			form := url.Values{}
			form.Set("email", "alice@example.com")
			form.Set("password", "supercalifragilistic")
			form.Set("csrf_token", csrf)
			resp, _ := f.postForm(t, "/login?next="+url.QueryEscape(evil), form)
			if loc := resp.Header.Get("Location"); loc != "/inspector" {
				t.Errorf("evil next %q produced redirect %q want /inspector", evil, loc)
			}
		})
	}
}

func TestSignupGET_RendersFormWithInviteCode(t *testing.T) {
	f := newFixture(t)
	resp, body := f.get(t, "/signup?code=ABCDEFGHIJKLMNOP")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("missing csrf_token field in body")
	}
	if !strings.Contains(body, `value="ABCDEFGHIJKLMNOP"`) {
		t.Error("missing invite code in body")
	}
}

func TestSignupPOST_HappyPath_RedirectsToLogin(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().UTC().Add(24 * time.Hour)
	inv := f.addInvite(t, store.RoleUser, []string{"render"}, &exp)

	csrf := f.primeCSRF(t, "/signup?code="+inv.Code)
	form := url.Values{}
	form.Set("code", inv.Code)
	form.Set("email", "newbie@example.com")
	form.Set("name", "Newbie")
	form.Set("password", "abracadabra-rocketship")
	form.Set("csrf_token", csrf)

	resp, _ := f.postForm(t, "/signup", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirect: %q want /login", loc)
	}

	// User row must exist.
	if _, err := f.st.GetUserByEmail(context.Background(), "newbie@example.com"); err != nil {
		t.Errorf("user not created: %v", err)
	}
}

func TestSignupPOST_ConsumedInvite_RendersError(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().UTC().Add(24 * time.Hour)
	inv := f.addInvite(t, store.RoleUser, nil, &exp)

	// Mark consumed so the signup flow rejects.
	consumer := f.addUser(t, "first@example.com", "supercalifragilistic", store.RoleUser)
	if err := f.st.MarkInviteConsumed(context.Background(), inv.Code, consumer.ID, time.Now().UTC()); err != nil {
		t.Fatalf("MarkInviteConsumed: %v", err)
	}

	csrf := f.primeCSRF(t, "/signup?code="+inv.Code)
	form := url.Values{}
	form.Set("code", inv.Code)
	form.Set("email", "second@example.com")
	form.Set("name", "Two")
	form.Set("password", "abracadabra-rocketship")
	form.Set("csrf_token", csrf)
	resp, body := f.postForm(t, "/signup", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "already used") {
		t.Errorf("missing 'already used' error: %s", body)
	}
}

func TestSignupPOST_ExpiredInvite_RendersError(t *testing.T) {
	f := newFixture(t)
	past := time.Now().UTC().Add(-time.Hour)
	inv := f.addInvite(t, store.RoleUser, nil, &past)

	csrf := f.primeCSRF(t, "/signup?code="+inv.Code)
	form := url.Values{}
	form.Set("code", inv.Code)
	form.Set("email", "expired@example.com")
	form.Set("name", "Late")
	form.Set("password", "abracadabra-rocketship")
	form.Set("csrf_token", csrf)
	resp, body := f.postForm(t, "/signup", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "expired") {
		t.Errorf("missing expired-invite error: %s", body)
	}
}

func TestSignupPOST_PasswordPolicyViolation_RendersError(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().UTC().Add(24 * time.Hour)
	inv := f.addInvite(t, store.RoleUser, nil, &exp)

	csrf := f.primeCSRF(t, "/signup?code="+inv.Code)
	form := url.Values{}
	form.Set("code", inv.Code)
	form.Set("email", "newbie@example.com")
	form.Set("name", "Newbie")
	form.Set("password", "short") // < 12 chars
	form.Set("csrf_token", csrf)
	resp, body := f.postForm(t, "/signup", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "12 characters") {
		t.Errorf("missing password-policy error: %s", body)
	}
}

func TestSignupPOST_MissingCSRFToken_Rejected(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().UTC().Add(24 * time.Hour)
	inv := f.addInvite(t, store.RoleUser, nil, &exp)

	_ = f.primeCSRF(t, "/signup?code="+inv.Code)
	form := url.Values{}
	form.Set("code", inv.Code)
	form.Set("email", "newbie@example.com")
	form.Set("name", "Newbie")
	form.Set("password", "abracadabra-rocketship")
	resp, _ := f.postForm(t, "/signup", form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"/inspector":                      "/inspector",
		"/inspector/me":                   "/inspector/me",
		"//evil.example.com":              "",
		"https://evil.example.com/foo":    "",
		"http://evil.example.com/foo":     "",
		"javascript:alert(1)":             "",
		"evil.example.com":                "",
		`/path?weird=true&also=fine#hash`: "/path?weird=true&also=fine#hash",
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignupErrorMessage(t *testing.T) {
	cases := []struct {
		err     error
		wantSub string
	}{
		{invites.ErrSignupInviteNotFound, "not found"},
		{invites.ErrSignupInviteConsumed, "already used"},
		{invites.ErrSignupInviteExpired, "expired"},
		{invites.ErrSignupBadPassword, "12 characters"},
		{invites.ErrSignupEmailInUse, "already exists"},
		{errors.New("random other error"), "Could not create"},
	}
	for _, c := range cases {
		got := signupErrorMessage(c.err)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("signupErrorMessage(%v) = %q want substring %q", c.err, got, c.wantSub)
		}
	}
}

// --- helpers --------------------------------------------------------------

func (f *fixture) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := f.client.Get(f.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (f *fixture) postForm(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// primeCSRF GETs the page once so the cookie jar receives the
// hooks_csrf_pre cookie, then returns its value for inclusion in a
// subsequent form submission.
func (f *fixture) primeCSRF(t *testing.T, path string) string {
	t.Helper()
	f.get(t, path)
	srvURL, _ := url.Parse(f.srv.URL)
	for _, c := range f.client.Jar.Cookies(srvURL) {
		if c.Name == PreSessionCSRFCookie {
			return c.Value
		}
	}
	t.Fatal("primeCSRF: no cookie set")
	return ""
}

func cookieValue(resp *http.Response, name string) string {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
