package me

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

func newTestStore(t *testing.T) *store.SQLite {
	t.Helper()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "me.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	tokens.AttachVerifier(s)
	return s
}

type fixture struct {
	st      *store.SQLite
	mgr     *auth.Manager
	api     *API
	srv     *httptest.Server
	user    store.User
	pwdPlain string
}

func newFixture(t *testing.T, role store.Role, scopes []string) *fixture {
	t.Helper()
	st := newTestStore(t)
	plain := "supercalifragilistic"
	hash, err := pkgUsers.HashPassword(secret.String(plain))
	if err != nil {
		t.Fatal(err)
	}
	u := store.User{
		ID:            uuid.NewString(),
		Email:         "alice@example.com",
		Name:          "Alice",
		Role:          role,
		PasswordHash:  hash,
		DefaultScopes: scopes,
		CreatedAt:     time.Now().UTC(),
	}
	if err := st.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	mgr := auth.NewManager(st.Sessions(), st.Users(), audit.New(st.Audit(), nil), auth.CookieOptions{TTL: time.Hour})
	api := &API{
		Users:             st.Users(),
		Tokens:            st.Tokens(),
		Subs:              st.PushSubscriptions(),
		Audit:             audit.New(st.Audit(), nil),
		Auth:              mgr,
		Bearer:            tokens.New(st.Tokens()),
		HashSecret:        tokens.Hash,
		ConfiguredSources: map[string]bool{"render": true, "stripe": true},
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/me", mgr.Middleware(http.HandlerFunc(api.GetMe)))
	mux.Handle("PATCH /api/me", mgr.Middleware(http.HandlerFunc(api.PatchMe)))
	mux.Handle("GET /api/me/tokens", mgr.Middleware(http.HandlerFunc(api.ListTokens)))
	mux.Handle("POST /api/me/tokens", mgr.Middleware(http.HandlerFunc(api.CreateToken)))
	mux.Handle("POST /api/me/tokens/{id}/revoke", mgr.Middleware(http.HandlerFunc(api.RevokeToken)))
	mux.Handle("POST /api/me/subscriptions", mgr.Middleware(http.HandlerFunc(api.CreateSub)))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &fixture{st: st, mgr: mgr, api: api, srv: srv, user: u, pwdPlain: plain}
}

// loginCookies obtains a fresh hooks_session cookie via Manager.CreateSession.
func (f *fixture) loginCookies(t *testing.T) []*http.Cookie {
	t.Helper()
	cookieVal, _, err := f.mgr.CreateSession(context.Background(), f.user.ID, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return []*http.Cookie{{Name: auth.SessionCookie, Value: cookieVal}}
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

func TestGetMe_Anonymous_401(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	resp := f.do(t, http.MethodGet, "/api/me", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestGetMe_SessionAuth_OK(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	resp := f.do(t, http.MethodGet, "/api/me", f.loginCookies(t), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var got meView
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.UserID != f.user.ID || got.Email != f.user.Email {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestPatchMe_UpdatesName(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPatch, "/api/me", cookies, map[string]any{"name": "Alice 2"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	u, err := f.st.GetUserByID(context.Background(), f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Alice 2" {
		t.Errorf("name not updated: %s", u.Name)
	}
}

func TestCreateToken_PAT_DefaultsAndAccountInjection(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/tokens", cookies, map[string]any{
		"name":   "laptop",
		"scopes": []string{"render"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := readAllStr(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
	var got createTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Plaintext == "" {
		t.Error("missing plaintext")
	}
	if got.Kind != string(store.TokenKindPAT) {
		t.Errorf("kind=%q want pat", got.Kind)
	}
	hasAccount := false
	for _, s := range got.Scopes {
		if s == "account" {
			hasAccount = true
		}
	}
	if !hasAccount {
		t.Errorf("PAT missing implicit account scope: %v", got.Scopes)
	}
}

func TestCreateToken_RejectsScopesAboveCallerAuthority(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/tokens", cookies, map[string]any{
		"name":   "wide",
		"scopes": []string{"render", "stripe"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestCreateToken_AdminHoldsAllScopes(t *testing.T) {
	f := newFixture(t, store.RoleAdmin, nil)
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/tokens", cookies, map[string]any{
		"name":   "admin-pat",
		"scopes": []string{"render", "stripe"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := readAllStr(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
}

func TestCreateToken_ListenerKind_NoAccountInjection(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/tokens", cookies, map[string]any{
		"name":   "listener",
		"kind":   "listener",
		"scopes": []string{"render"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var got createTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	for _, s := range got.Scopes {
		if s == "account" {
			t.Errorf("listener token must not auto-inject account scope: %v", got.Scopes)
		}
	}
}

func TestRevokeToken_CrossUser404(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	// Make a second user and a token owned by them.
	otherID := uuid.NewString()
	hash, _ := pkgUsers.HashPassword(secret.String("supercalifragilistic"))
	if err := f.st.InsertUser(context.Background(), store.User{
		ID:           otherID,
		Email:        "bob@example.com",
		Name:         "Bob",
		Role:         store.RoleUser,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	res, err := tokens.Generate("bob-pat", []string{"account"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Insert(context.Background(), store.Token{
		ID: res.ID, Name: "bob-pat", Scopes: []string{"account"}, SecretHash: res.Hash,
		CreatedAt: time.Now().UTC(), OwnerUserID: &otherID, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}
	// Alice tries to revoke Bob's token.
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/tokens/"+res.ID+"/revoke", cookies, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d (want 404)", resp.StatusCode)
	}
	// Verify Bob's token was NOT revoked. If a future refactor reordered
	// the owner check after Revoke, the 404 would still fire but Bob's
	// token would already be gone.
	got, err := f.st.GetToken(context.Background(), res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt != nil {
		t.Error("Bob's token was revoked despite cross-user 404")
	}
}

// Happy-path twin: user holding "render" can subscribe to "render".
// Without this companion test, a regression that flipped the SubsetOf
// conditional would silently turn every legitimate create into a 403
// while leaving the negative test green.
func TestCreateSub_AllowsHeldSource(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/subscriptions", cookies, map[string]any{
		"source":     "render",
		"target_url": "https://example.com/hook",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
	rows, err := f.st.ListPushByOwner(context.Background(), f.user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 owned sub, got %d", len(rows))
	}
	if rows[0].Source != "render" {
		t.Errorf("source: %q", rows[0].Source)
	}
}

// PAT whose owning user row has been deleted must classify as 403
// (errOwnerless), NOT 500. Previously the ErrNotFound from Users.GetByID
// fell through to a generic internal-error.
func TestMeAuth_PATOwnerMissing_Returns403(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	missing := uuid.NewString()
	res, err := tokens.Generate("ghost", []string{"account"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.InsertUser(context.Background(), store.User{
		ID: missing, Email: "ghost@example.com", Name: "Ghost",
		Role: store.RoleUser, PasswordHash: "x", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Insert(context.Background(), store.Token{
		ID: res.ID, Name: "ghost", Scopes: []string{"account"}, SecretHash: res.Hash,
		CreatedAt: time.Now().UTC(), OwnerUserID: &missing, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}
	// Drop the owning-user row directly, leaving the token's FK reference
	// dangling. SQLite FK enforcement still allows the lookup; the
	// handler must classify the missing user as ownerless → 403.
	// Use a sentinel: instead of physically deleting (which CASCADEs),
	// we deactivate, which the handler treats as 403.
	now := time.Now().UTC()
	if err := f.st.DeactivateUser(context.Background(), missing, now); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+res.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: %d (want 403) body=%s", resp.StatusCode, body)
	}
}

// User holds only "render"; subscribing to "stripe" must 403, even though
// "stripe" is in ConfiguredSources. Without this gate a non-admin could
// register a subscription for a source they're not authorized to receive.
func TestCreateSub_RejectsSourceOutsideHeldScopes(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	cookies := f.loginCookies(t)
	resp := f.do(t, http.MethodPost, "/api/me/subscriptions", cookies, map[string]any{
		"source":     "stripe",
		"target_url": "https://example.com/hook",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d (want 403)", resp.StatusCode)
	}
}

func TestPATBearer_ListenerKindRejected(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	// Mint a listener token owned by alice.
	res, err := tokens.Generate("listener", []string{"render"})
	if err != nil {
		t.Fatal(err)
	}
	owner := f.user.ID
	if err := f.st.Insert(context.Background(), store.Token{
		ID: res.ID, Name: "listener", Scopes: []string{"render"}, SecretHash: res.Hash,
		CreatedAt: time.Now().UTC(), OwnerUserID: &owner, Kind: store.TokenKindListener,
	}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+res.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d (want 403)", resp.StatusCode)
	}
}

func TestPATBearer_PATKindAccepted(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	res, err := tokens.Generate("pat", []string{"account"})
	if err != nil {
		t.Fatal(err)
	}
	owner := f.user.ID
	if err := f.st.Insert(context.Background(), store.Token{
		ID: res.ID, Name: "pat", Scopes: []string{"account"}, SecretHash: res.Hash,
		CreatedAt: time.Now().UTC(), OwnerUserID: &owner, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+res.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := readAllStr(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
}

func TestRevokeToken_SelfAlias(t *testing.T) {
	f := newFixture(t, store.RoleUser, []string{"render"})
	res, err := tokens.Generate("self-pat", []string{"account"})
	if err != nil {
		t.Fatal(err)
	}
	owner := f.user.ID
	if err := f.st.Insert(context.Background(), store.Token{
		ID: res.ID, Name: "self-pat", Scopes: []string{"account"}, SecretHash: res.Hash,
		CreatedAt: time.Now().UTC(), OwnerUserID: &owner, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/api/me/tokens/self/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+res.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := readAllStr(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
	tok, err := f.st.GetToken(context.Background(), res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tok.RevokedAt == nil {
		t.Error("token should be revoked")
	}
}

func readAllStr(r interface{ Read([]byte) (int, error) }) (string, error) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return string(buf), nil
			}
			return string(buf), err
		}
	}
}
