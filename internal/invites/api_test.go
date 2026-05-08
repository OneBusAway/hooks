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
	api := NewAPI(s.Invites(), s.Users(), s.Audit(), nil)
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
	resp, _ := http.Post(srv.URL+"/api/invites", "application/json", bytes.NewReader(body))
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
	resp, _ = http.Get(srv.URL + "/api/invites")
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
	resp, _ := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
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
	resp, _ = http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
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
	resp, _ := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
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
	resp, _ := http.Post(srv.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", resp.StatusCode)
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
