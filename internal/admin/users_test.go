package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
	pkgUsers "github.com/onebusaway/hooks/internal/users"
)

type fixture struct {
	st    *store.SQLite
	mgr   *auth.Manager
	api   *API
	srv   *httptest.Server
	admin store.User
	user  store.User
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "admin.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	tokens.AttachVerifier(s)

	pwHash, err := pkgUsers.HashPassword(secret.String("supercalifragilistic"))
	if err != nil {
		t.Fatal(err)
	}
	admin := store.User{
		ID: uuid.NewString(), Email: "admin@example.com", Name: "Admin",
		Role: store.RoleAdmin, PasswordHash: pwHash, CreatedAt: time.Now().UTC(),
	}
	user := store.User{
		ID: uuid.NewString(), Email: "user@example.com", Name: "User",
		Role: store.RoleUser, PasswordHash: pwHash, DefaultScopes: []string{"render"},
		CreatedAt: time.Now().UTC(),
	}
	if err := s.InsertUser(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	rec := audit.New(s.Audit(), nil)
	mgr := auth.NewManager(s.Sessions(), s.Users(), rec, auth.CookieOptions{TTL: time.Hour})

	api := &API{
		Users:       s.Users(),
		Sessions:    s.Sessions(),
		Tokens:      s.Tokens(),
		Subs:        s.PushSubscriptions(),
		Audit:       rec,
		AuditReader: s.Audit(),
		Cascader:    s,
		HashPassword: func(p string) (string, error) {
			return pkgUsers.HashPassword(secret.String(p))
		},
		ValidatePolicy: func(email, plain string) error {
			return pkgUsers.ValidatePassword(email, secret.String(plain))
		},
		Auth:   mgr,
		Bearer: tokens.New(s.Tokens()),
	}

	mux := http.NewServeMux()
	wrapped := http.NewServeMux()
	api.Register(wrapped)
	mux.Handle("/", mgr.Middleware(wrapped))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &fixture{st: s, mgr: mgr, api: api, srv: srv, admin: admin, user: user}
}

func (f *fixture) cookies(t *testing.T, u store.User) []*http.Cookie {
	t.Helper()
	val, _, err := f.mgr.CreateSession(context.Background(), u.ID, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return []*http.Cookie{{Name: auth.SessionCookie, Value: val}}
}

func (f *fixture) do(t *testing.T, method, path string, cookies []*http.Cookie, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, f.srv.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestListUsers_AdminOK_NonAdmin403(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodGet, "/api/users", f.cookies(t, f.admin), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list: %d", resp.StatusCode)
	}
	resp = f.do(t, http.MethodGet, "/api/users", f.cookies(t, f.user), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("user list: want 403 got %d", resp.StatusCode)
	}
}

func TestPatchUser_UpdatesDefaultScopes(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPatch, "/api/users/"+f.user.ID, f.cookies(t, f.admin), map[string]any{
		"default_scopes": []string{"render", "stripe"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("patch: %d body=%s", resp.StatusCode, body)
	}
	u, err := f.st.GetUserByID(context.Background(), f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.DefaultScopes) != 2 || u.DefaultScopes[0] != "render" || u.DefaultScopes[1] != "stripe" {
		t.Errorf("default_scopes=%v", u.DefaultScopes)
	}
}

func TestDeactivate_LastAdminBlocked(t *testing.T) {
	f := newFixture(t)
	// Trying to deactivate the only admin should return 409.
	resp := f.do(t, http.MethodPost, "/api/users/"+f.admin.ID+"/deactivate", f.cookies(t, f.admin), map[string]any{
		"confirm": f.admin.Email,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func TestDeactivate_ConfirmMismatch400(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPost, "/api/users/"+f.user.ID+"/deactivate", f.cookies(t, f.admin), map[string]any{
		"confirm": "nope",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeactivate_CascadesTokensAndSubs(t *testing.T) {
	f := newFixture(t)
	// Mint a token and a subscription owned by the user.
	owner := f.user.ID
	if err := f.st.Insert(context.Background(), store.Token{
		ID: uuid.NewString(), Name: "u-pat", Scopes: []string{"account"},
		SecretHash: "$argon2id$v=19$m=65536,t=1,p=4$aaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt:  time.Now().UTC(), OwnerUserID: &owner, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}
	subID := uuid.NewString()
	if err := f.st.InsertPush(context.Background(), store.PushSubscription{
		ID: subID, Source: "render", TargetURL: "https://example.com/hook",
		SigningSecretHash: "x", CreatedAt: time.Now().UTC(), OwnerUserID: &owner,
	}); err != nil {
		t.Fatal(err)
	}
	resp := f.do(t, http.MethodPost, "/api/users/"+f.user.ID+"/deactivate", f.cookies(t, f.admin), map[string]any{
		"confirm": f.user.Email,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	// Decode the populated-path response to verify the API contract: a
	// regression returning {0,0} despite the cascade succeeding would not
	// have failed the `0/0` assertion further down (which only covers the
	// no-tokens user added in a follow-up test).
	var firstBody struct {
		TokensRevoked       int64 `json:"tokens_revoked"`
		SubscriptionsPaused int64 `json:"subscriptions_paused"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&firstBody); err != nil {
		t.Fatal(err)
	}
	if firstBody.TokensRevoked != 1 {
		t.Errorf("tokens_revoked: %d (want 1)", firstBody.TokensRevoked)
	}
	if firstBody.SubscriptionsPaused != 1 {
		t.Errorf("subscriptions_paused: %d (want 1)", firstBody.SubscriptionsPaused)
	}
	u, err := f.st.GetUserByID(context.Background(), f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.DeactivatedAt == nil {
		t.Error("deactivated_at not set")
	}
	owned, err := f.st.ListTokensByOwner(context.Background(), f.user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 {
		t.Fatalf("expected 1 owned token, got %d", len(owned))
	}
	for _, tok := range owned {
		if tok.RevokedAt == nil {
			t.Errorf("token %s not revoked", tok.ID)
		}
	}
	subs, err := f.st.ListPushByOwner(context.Background(), f.user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 owned sub, got %d", len(subs))
	}
	for _, sub := range subs {
		if sub.PausedAt == nil {
			t.Errorf("sub %s not paused", sub.ID)
		}
	}

	// Response body should also report the cascade counts.
	var body struct {
		TokensRevoked       int64 `json:"tokens_revoked"`
		SubscriptionsPaused int64 `json:"subscriptions_paused"`
	}
	// resp body was already consumed for status check; re-issue the
	// deactivate to a fresh user to verify counts.
	other := uuid.NewString()
	if err := f.st.InsertUser(context.Background(), store.User{
		ID: other, Email: "z@example.com", Name: "Z", Role: store.RoleUser,
		PasswordHash: "x", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	resp2 := f.do(t, http.MethodPost, "/api/users/"+other+"/deactivate", f.cookies(t, f.admin), map[string]any{
		"confirm": "z@example.com",
	})
	defer resp2.Body.Close()
	if err := json.NewDecoder(resp2.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.TokensRevoked != 0 || body.SubscriptionsPaused != 0 {
		t.Errorf("counts: tokens=%d subs=%d (want 0/0 for user with no tokens)", body.TokensRevoked, body.SubscriptionsPaused)
	}
}

func TestResetPassword_InvalidatesSessions(t *testing.T) {
	f := newFixture(t)
	// Establish a session for the user.
	cookieVal, _, err := f.mgr.CreateSession(context.Background(), f.user.ID, "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	resp := f.do(t, http.MethodPost, "/api/users/"+f.user.ID+"/reset-password", f.cookies(t, f.admin), map[string]any{
		"new_password": "alongerpassphrase",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if _, _, err := f.mgr.Lookup(context.Background(), cookieVal); err == nil {
		t.Error("session should be invalid after reset")
	}
}

// A request that carries BOTH a non-admin session cookie AND a valid
// admin bearer token must succeed. Round 1 of the review caught that the
// old requireAdmin short-circuited 403 on the cookie path before
// consulting the bearer; this test pins the precedence change.
func TestRequireAdmin_NonAdminCookie_AdminBearer_Allowed(t *testing.T) {
	f := newFixture(t)
	// Mint an admin bearer token.
	res, err := tokens.Issue(context.Background(), f.st.Tokens(), "ops", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	// Build a request carrying both credentials.
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/api/users", nil)
	for _, c := range f.cookies(t, f.user) {
		req.AddCookie(c)
	}
	req.Header.Set("Authorization", "Bearer "+res.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
}

func TestListAudit_AdminOK_NonAdmin403(t *testing.T) {
	f := newFixture(t)
	// Generate at least one audit event by calling reactivate (no-op success).
	resp := f.do(t, http.MethodPost, "/api/users/"+f.user.ID+"/reactivate", f.cookies(t, f.admin), nil)
	resp.Body.Close()

	resp = f.do(t, http.MethodGet, "/api/audit", f.cookies(t, f.admin), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin: %d body=%s", resp.StatusCode, body)
	}
	// Decode and verify at least one event came back; if the SQL filter
	// regresses to "always empty" the bare status check above would
	// happily pass while the audit trail returned nothing.
	var auditBody struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&auditBody); err != nil {
		t.Fatal(err)
	}
	if len(auditBody.Events) == 0 {
		t.Error("audit list returned no events; the reactivate above should have generated one")
	}
	resp = f.do(t, http.MethodGet, "/api/audit", f.cookies(t, f.user), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("user: want 403 got %d", resp.StatusCode)
	}
}

// TestAuditCoverage_AdminActions (task 10.6): each representative admin
// action produces exactly one audit_events row with the expected action,
// target_type, and target_id. The breadth here is intentional but bounded:
// we exercise three distinct actions per audit constant family
// (`user.update`, `user.reactivate`, `user.password_reset`) so a regression
// that drops the recordAudit call for any one of them surfaces here.
func TestAuditCoverage_AdminActions(t *testing.T) {
	f := newFixture(t)
	adminCookies := f.cookies(t, f.admin)
	ctx := context.Background()

	// 1. user.update via PATCH /api/users/{id}.
	resp := f.do(t, http.MethodPatch, "/api/users/"+f.user.ID, adminCookies, map[string]any{
		"name": "Renamed",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d", resp.StatusCode)
	}

	// 2. user.reactivate via POST /api/users/{id}/reactivate (no-op on an
	//    already-active user is still a successful 204 + audit row).
	resp = f.do(t, http.MethodPost, "/api/users/"+f.user.ID+"/reactivate", adminCookies, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reactivate: %d", resp.StatusCode)
	}

	// 3. user.password_reset via POST /api/users/{id}/reset-password.
	resp = f.do(t, http.MethodPost, "/api/users/"+f.user.ID+"/reset-password", adminCookies, map[string]any{
		"new_password": "freshpassword-1234",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reset-password: %d", resp.StatusCode)
	}

	rows, err := f.st.Audit().List(ctx, store.AuditQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	want := map[audit.Action]bool{
		audit.ActionUserUpdate:        false,
		audit.ActionUserReactivate:    false,
		audit.ActionUserPasswordReset: false,
	}
	for _, ev := range rows {
		if _, expected := want[ev.Action]; !expected {
			continue
		}
		if want[ev.Action] {
			t.Errorf("duplicate audit row for action %s", ev.Action)
		}
		want[ev.Action] = true
		if ev.TargetType != audit.TargetTypeUser {
			t.Errorf("action=%s: TargetType=%q want %q", ev.Action, ev.TargetType, audit.TargetTypeUser)
		}
		if ev.TargetID != f.user.ID {
			t.Errorf("action=%s: TargetID=%q want %q", ev.Action, ev.TargetID, f.user.ID)
		}
		if ev.ActorUserID == nil || *ev.ActorUserID != f.admin.ID {
			t.Errorf("action=%s: ActorUserID=%v want %q", ev.Action, ev.ActorUserID, f.admin.ID)
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("expected audit row for action %s; got none", action)
		}
	}
}
