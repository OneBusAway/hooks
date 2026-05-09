package invites

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

type fakeAdmin struct {
	user store.User
	ok   bool
}

func (f fakeAdmin) FromContext(ctx context.Context) (store.User, store.Session, bool) {
	return f.user, store.Session{}, f.ok
}

func newTest(t *testing.T) (*store.SQLite, *API) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "i.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	api := NewAPI(s.Invites(), s.Users(), audit.New(s.Audit(), nil), nil)
	return s, api
}

func mustAdmin(t *testing.T, s *store.SQLite) store.User {
	t.Helper()
	hash, _ := users.HashPassword(secret.String("supercalifragilistic"))
	u := store.User{
		ID: uuid.NewString(), Email: "admin@example.com", Name: "Admin",
		Role: store.RoleAdmin, PasswordHash: hash, DefaultScopes: []string{},
		CreatedAt: time.Now().UTC(),
	}
	if err := s.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCreateAndList(t *testing.T) {
	s, api := newTest(t)
	admin := mustAdmin(t, s)
	api.Auth = fakeAdmin{user: admin, ok: true}

	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(createRequest{Role: "user", DefaultScopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/invites", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	var created inviteResponse
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.Code == "" {
		t.Fatal("missing code")
	}

	// List shows it.
	resp, err = http.Get(srv.URL + "/api/invites")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", resp.StatusCode)
	}
}

func TestSignup_HappyPath(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Insert an invite directly.
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "INVITE12345ABCDE", Role: store.RoleUser, DefaultScopes: []string{"render"},
		CreatedAt: now, ExpiresAt: &exp,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "invite12345abcde", Email: "alice@example.com",
		Name: "Alice", Password: "supercalifragilistic",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Invite is now consumed.
	inv, _ := s.GetInviteByCode(context.Background(), "INVITE12345ABCDE")
	if inv.ConsumedAt == nil {
		t.Error("invite not consumed")
	}

	// User exists with role + default_scopes.
	u, err := s.GetUserByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != store.RoleUser {
		t.Errorf("role: %s", u.Role)
	}
	if len(u.DefaultScopes) != 1 || u.DefaultScopes[0] != "render" {
		t.Errorf("default_scopes: %v", u.DefaultScopes)
	}

	// Replay returns 409 (already consumed).
	body, _ = json.Marshal(signupRequest{
		Code: "INVITE12345ABCDE", Email: "bob@example.com",
		Name: "Bob", Password: "supercalifragilistic2",
	})
	resp, err = http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("replay: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSignup_ExpiredInvite_410(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "EXPIREDABCDEFGHI", Role: store.RoleUser, DefaultScopes: []string{},
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "EXPIREDABCDEFGHI", Email: "alice@example.com",
		Name: "A", Password: "supercalifragilistic",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("expired: %d", resp.StatusCode)
	}
}

func TestSignup_BadPassword_400(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "GOODCODE12345678", Role: store.RoleUser, DefaultScopes: []string{},
		CreatedAt: now, ExpiresAt: &exp,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "GOODCODE12345678", Email: "alice@example.com",
		Name: "A", Password: "short",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

// TestSignup_RetiresBootstrapInvite covers §16.6(a): a successful signup
// using a NON-bootstrap invite still sweeps any bootstrap=true invite
// in the same tx (MarkBootstrapInvitesConsumed).
func TestSignup_RetiresBootstrapInvite(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	bootstrapExp := now.Add(24 * time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "BOOTSTRAPCODE000A", Role: store.RoleAdmin,
		Bootstrap: true, CreatedAt: now, ExpiresAt: &bootstrapExp,
	}); err != nil {
		t.Fatal(err)
	}

	regExp := now.Add(time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "REGULARINV000001A", Role: store.RoleUser,
		DefaultScopes: []string{"render"},
		CreatedAt:     now, ExpiresAt: &regExp,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "REGULARINV000001A", Email: "alice@example.com",
		Name: "Alice", Password: "supercalifragilistic",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: %d", resp.StatusCode)
	}

	bs, err := s.GetInviteByCode(context.Background(), "BOOTSTRAPCODE000A")
	if err != nil {
		t.Fatal(err)
	}
	if bs.ConsumedAt == nil {
		t.Error("bootstrap invite was not retired by an unrelated signup")
	}
}

// TestSignup_ConsumedBootstrap_409 covers §16.6(b): once the bootstrap
// invite is consumed, a signup attempt using that code returns 409.
func TestSignup_ConsumedBootstrap_409(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	consumed := now.Add(-time.Minute)
	bootstrapExp := now.Add(24 * time.Hour)
	priorUserID := uuid.NewString()
	hash, _ := users.HashPassword(secret.String("supercalifragilistic"))
	if err := s.InsertUser(context.Background(), store.User{
		ID: priorUserID, Email: "first@example.com", Name: "First",
		Role: store.RoleAdmin, PasswordHash: hash, DefaultScopes: []string{},
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "BOOTSTRAPCODE0009", Role: store.RoleAdmin,
		Bootstrap: true, CreatedAt: now, ExpiresAt: &bootstrapExp,
		ConsumedAt: &consumed, ConsumedByUserID: &priorUserID,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "BOOTSTRAPCODE0009", Email: "second@example.com",
		Name: "Second", Password: "supercalifragilistic",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status: %d (want 409)", resp.StatusCode)
	}
}

// TestSignup_ExpiredBootstrap_410 covers §16.6(c): an expired bootstrap
// invite returns 410.
func TestSignup_ExpiredBootstrap_410(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "BOOTSTRAPEXPIRED1", Role: store.RoleAdmin,
		Bootstrap: true, CreatedAt: now.Add(-25 * time.Hour), ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "BOOTSTRAPEXPIRED1", Email: "alice@example.com",
		Name: "Alice", Password: "supercalifragilistic",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status: %d (want 410)", resp.StatusCode)
	}
}

// TestSignup_AdminInviteStoresDefaultScopes covers §16.6(d): an
// admin-role invite stores default_scopes (forwarded as a future-
// reserved field) but the auth path does not gate on them — admins
// implicitly hold all scopes.
func TestSignup_AdminInviteStoresDefaultScopes(t *testing.T) {
	s, api := newTest(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	if err := s.InsertInvite(context.Background(), store.Invite{
		Code: "ADMININVITE00001A", Role: store.RoleAdmin,
		DefaultScopes: []string{"render", "stripe"},
		CreatedAt:     now, ExpiresAt: &exp,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(signupRequest{
		Code: "ADMININVITE00001A", Email: "admin2@example.com",
		Name: "Admin Two", Password: "supercalifragilistic",
	})
	resp, err := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	u, err := s.GetUserByEmail(context.Background(), "admin2@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != store.RoleAdmin {
		t.Errorf("role: %s (want admin)", u.Role)
	}
	if len(u.DefaultScopes) != 2 {
		t.Errorf("default_scopes copied from invite: %v", u.DefaultScopes)
	}
}

func TestNewCode_FormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		c, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != CodeLength {
			t.Errorf("code length %d", len(c))
		}
		if seen[c] {
			t.Errorf("duplicate code: %s", c)
		}
		seen[c] = true
	}
}
