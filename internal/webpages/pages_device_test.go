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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/devicepair"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

// fakeApprover stubs DeviceApprover so the tests don't need a real
// devicepair.API. Each method records its argument(s) and returns a
// caller-controlled error so the rendering branches are exercised.
type fakeApprover struct {
	mu sync.Mutex

	lookupResult store.DevicePairing
	lookupErr    error
	lookupCalls  []string

	approveErr   error
	approveCalls []approveCall

	denyErr   error
	denyCalls []string
}

type approveCall struct {
	UserCode string
	Password string
	Scopes   []string
	Caller   string
}

func (f *fakeApprover) LookupPairing(_ context.Context, userCode string) (store.DevicePairing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookupCalls = append(f.lookupCalls, userCode)
	if f.lookupErr != nil {
		return store.DevicePairing{}, f.lookupErr
	}
	return f.lookupResult, nil
}

func (f *fakeApprover) ApproveCore(_ context.Context, caller store.User, userCode string, password secret.String, grantedScopes []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approveCalls = append(f.approveCalls, approveCall{
		UserCode: userCode, Password: password.Reveal(),
		Scopes: append([]string{}, grantedScopes...),
		Caller: caller.ID,
	})
	return f.approveErr
}

func (f *fakeApprover) DenyCore(_ context.Context, caller store.User, userCode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denyCalls = append(f.denyCalls, userCode+":"+caller.ID)
	return f.denyErr
}

type deviceFixture struct {
	srv      *httptest.Server
	st       *store.SQLite
	mgr      *auth.Manager
	approver *fakeApprover
	client   *http.Client
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "d.db"), store.SQLiteOptions{})
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
	approver := &fakeApprover{}
	pages.MountDevice(approver)

	mux := http.NewServeMux()
	pages.RegisterWithMiddleware(mux, mgr.Middleware)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &deviceFixture{srv: srv, st: st, mgr: mgr, approver: approver, client: client}
}

func (f *deviceFixture) loginUser(t *testing.T, email, plaintext string, role store.Role, scopes []string) store.User {
	t.Helper()
	hash, err := users.HashPassword(secret.String(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	u := store.User{
		ID: uuid.NewString(), Email: email, Name: "Tester", Role: role,
		PasswordHash: hash, DefaultScopes: append([]string{}, scopes...),
		CreatedAt: time.Now().UTC(),
	}
	if err := f.st.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	cookieValue, _, err := f.mgr.CreateSession(context.Background(), u.ID, "test-ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Use a real http response writer to drive SetCookies; the test
	// needs the produced cookies and CSRF token to flow into the
	// client's cookie jar.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, f.srv.URL+"/", nil)
	if _, err := f.mgr.SetCookies(rec, req, cookieValue); err != nil {
		t.Fatal(err)
	}
	srvURL, _ := url.Parse(f.srv.URL)
	f.client.Jar.SetCookies(srvURL, rec.Result().Cookies())
	return u
}

func (f *deviceFixture) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := f.client.Get(f.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (f *deviceFixture) postForm(t *testing.T, path string, form url.Values) (*http.Response, string) {
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

func (f *deviceFixture) sessionCSRFToken() string {
	srvURL, _ := url.Parse(f.srv.URL)
	for _, c := range f.client.Jar.Cookies(srvURL) {
		if c.Name == auth.CSRFCookie {
			return c.Value
		}
	}
	return ""
}

// --- /device GET ---------------------------------------------------------

func TestDeviceGET_AnonymousRedirectsToLogin(t *testing.T) {
	f := newDeviceFixture(t)

	resp, _ := f.get(t, "/device")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Errorf("Location = %q, want /login?next=...", loc)
	}
	if !strings.Contains(loc, "%2Fdevice") {
		t.Errorf("Location = %q does not preserve /device as next", loc)
	}
}

func TestDeviceGET_AnonymousPreservesUserCodeQuery(t *testing.T) {
	f := newDeviceFixture(t)
	resp, _ := f.get(t, "/device?user_code=ABCD-EFGH")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "user_code") {
		t.Errorf("Location = %q does not preserve user_code", loc)
	}
}

func TestDeviceGET_LoggedInWithoutCode_RendersLookupForm(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, []string{"render"})

	resp, body := f.get(t, "/device")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `name="user_code"`) {
		t.Errorf("missing user_code field in body: %s", body)
	}
	if !strings.Contains(body, "Approve a device") {
		t.Errorf("missing page heading: %s", body)
	}
}

func TestDeviceGET_LoggedInWithCode_RendersApprovalForm(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, []string{"render"})

	f.approver.lookupResult = store.DevicePairing{
		DeviceCode:          "deadbeef",
		UserCode:            "ABCD-EFGH",
		Status:              store.DevicePairingStatusPending,
		ExpiresAt:           time.Now().Add(15 * time.Minute),
		RequestingIP:        "192.0.2.10",
		RequestingUserAgent: "hooksctl/dev",
		RequestedScopes:     []string{"render", "stripe"},
	}

	resp, body := f.get(t, "/device?user_code=ABCD-EFGH")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `192.0.2.10`) {
		t.Errorf("missing requesting IP: %s", body)
	}
	if !strings.Contains(body, `hooksctl/dev`) {
		t.Errorf("missing requesting user-agent: %s", body)
	}
	if !strings.Contains(body, `name="granted_scopes" value="render"`) {
		t.Errorf("missing render scope checkbox: %s", body)
	}
	if !strings.Contains(body, `name="granted_scopes" value="stripe"`) {
		t.Errorf("missing stripe scope checkbox: %s", body)
	}
	if !strings.Contains(body, `Approve only if you started this on this machine`) {
		t.Errorf("missing safety warning: %s", body)
	}
	if !strings.Contains(body, `name="password"`) {
		t.Errorf("missing password input: %s", body)
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Errorf("missing csrf field: %s", body)
	}
	csrf := f.sessionCSRFToken()
	if csrf == "" || !strings.Contains(body, `value="`+csrf+`"`) {
		t.Errorf("CSRF field does not match cookie")
	}
}

func TestDeviceGET_UnknownUserCode_ShowsLookupErr(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)
	f.approver.lookupErr = store.ErrNotFound

	resp, body := f.get(t, "/device?user_code=ZZZZ-ZZZZ")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Code not found") {
		t.Errorf("missing not-found error: %s", body)
	}
}

func TestDeviceGET_NonPendingStatus_ShowsLookupErr(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)
	f.approver.lookupResult = store.DevicePairing{
		UserCode: "ABCD-EFGH",
		Status:   store.DevicePairingStatusDone,
	}

	resp, body := f.get(t, "/device?user_code=ABCD-EFGH")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "no longer pending") {
		t.Errorf("missing not-pending error: %s", body)
	}
}

// --- /device POST: approve ----------------------------------------------

func TestDevicePOST_Approve_HappyPath(t *testing.T) {
	f := newDeviceFixture(t)
	caller := f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, []string{"render"})

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("password", "supercalifragilistic")
	form["granted_scopes"] = []string{"render"}
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, body := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Device approved") {
		t.Errorf("missing approved confirmation: %s", body)
	}
	if len(f.approver.approveCalls) != 1 {
		t.Fatalf("approve called %d times, want 1", len(f.approver.approveCalls))
	}
	got := f.approver.approveCalls[0]
	if got.UserCode != "ABCD-EFGH" {
		t.Errorf("user_code = %q", got.UserCode)
	}
	if got.Password != "supercalifragilistic" {
		t.Errorf("password not forwarded")
	}
	if got.Caller != caller.ID {
		t.Errorf("caller mismatch: got %q want %q", got.Caller, caller.ID)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "render" {
		t.Errorf("scopes = %v want [render]", got.Scopes)
	}
}

func TestDevicePOST_Approve_NormalizesUserCode(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, []string{"render"})

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "  abcd-efgh  ") // lowercase + whitespace
	form.Set("password", "supercalifragilistic")
	form["granted_scopes"] = []string{"render"}
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, _ := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if len(f.approver.approveCalls) != 1 {
		t.Fatalf("approve calls: %d", len(f.approver.approveCalls))
	}
	if f.approver.approveCalls[0].UserCode != "ABCD-EFGH" {
		t.Errorf("user_code = %q, want normalized", f.approver.approveCalls[0].UserCode)
	}
}

func TestDevicePOST_Approve_PasswordVerifyFailure_RendersError(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, []string{"render"})

	f.approver.approveErr = devicepair.ErrApprovePasswordVerify
	f.approver.lookupResult = store.DevicePairing{
		UserCode: "ABCD-EFGH", Status: store.DevicePairingStatusPending,
		ExpiresAt:       time.Now().Add(time.Minute),
		RequestedScopes: []string{"render"},
	}

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("password", "wrong")
	form["granted_scopes"] = []string{"render"}
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, body := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Password verification failed") {
		t.Errorf("missing password error: %s", body)
	}
	// Form is re-rendered with full approval shape.
	if !strings.Contains(body, `name="password"`) {
		t.Errorf("re-rendered form missing password input")
	}
}

func TestDevicePOST_Approve_ScopesExceedAuthority_RendersError(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)

	f.approver.approveErr = devicepair.ErrApproveScopesExceedAuthority
	f.approver.lookupResult = store.DevicePairing{
		UserCode: "ABCD-EFGH", Status: store.DevicePairingStatusPending,
		ExpiresAt:       time.Now().Add(time.Minute),
		RequestedScopes: []string{"stripe"},
	}

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("password", "supercalifragilistic")
	form["granted_scopes"] = []string{"stripe"}
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, body := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "do not hold") {
		t.Errorf("missing scope-authority error: %s", body)
	}
}

func TestDevicePOST_Approve_PairingExpired_ShowsLookup(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, []string{"render"})

	f.approver.approveErr = devicepair.ErrApprovePairingExpired

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("password", "supercalifragilistic")
	form["granted_scopes"] = []string{"render"}
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, body := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "expired") {
		t.Errorf("missing expired message: %s", body)
	}
}

// --- /device POST: deny --------------------------------------------------

func TestDevicePOST_Deny_HappyPath(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)

	form := url.Values{}
	form.Set("action", "deny")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, body := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Device denied") {
		t.Errorf("missing denied confirmation: %s", body)
	}
	if len(f.approver.denyCalls) != 1 {
		t.Fatalf("deny calls: %d", len(f.approver.denyCalls))
	}
}

func TestDevicePOST_Deny_NotFound_RendersLookupErr(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)
	f.approver.denyErr = devicepair.ErrDenyUserCodeNotFound

	form := url.Values{}
	form.Set("action", "deny")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, body := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Code not found") {
		t.Errorf("missing not-found error: %s", body)
	}
}

// --- CSRF rejection ------------------------------------------------------

func TestDevicePOST_MissingCSRF_Rejected(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("password", "supercalifragilistic")

	resp, _ := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
	if len(f.approver.approveCalls) != 0 {
		t.Errorf("approve was called despite missing CSRF: %v", f.approver.approveCalls)
	}
}

func TestDevicePOST_MismatchedCSRF_Rejected(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("password", "supercalifragilistic")
	form.Set("csrf_token", "definitely-not-the-real-token")

	resp, _ := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

func TestDevicePOST_Anonymous_RedirectsToLogin(t *testing.T) {
	f := newDeviceFixture(t)
	form := url.Values{}
	form.Set("action", "approve")
	form.Set("user_code", "ABCD-EFGH")

	resp, _ := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q want /login...", loc)
	}
}

func TestDevicePOST_UnknownAction_400(t *testing.T) {
	f := newDeviceFixture(t)
	f.loginUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, nil)

	form := url.Values{}
	form.Set("action", "explode")
	form.Set("user_code", "ABCD-EFGH")
	form.Set("csrf_token", f.sessionCSRFToken())

	resp, _ := f.postForm(t, "/device", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
}

// --- type-assertion sanity check ----------------------------------------

func TestDeviceApproverInterfaceImplementedByAPI(t *testing.T) {
	// Compile-time check: *devicepair.API must satisfy DeviceApprover.
	var _ DeviceApprover = (*devicepair.API)(nil)

	// And errors.Is on a nil approve error must yield nil.
	if errors.Is(nil, devicepair.ErrApproveBadInput) {
		t.Fatal("nil should not match a typed sentinel")
	}
}
