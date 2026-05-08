package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

func newTestStore(t *testing.T) *store.SQLite {
	t.Helper()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "auth.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newManagerWithUser(t *testing.T, email, plaintext string, role store.Role, deactivated bool) (*Manager, *store.SQLite, store.User) {
	t.Helper()
	s := newTestStore(t)
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
	if deactivated {
		t := time.Now().UTC()
		u.DeactivatedAt = &t
	}
	if err := s.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s.Sessions(), s.Users(), s.Audit(), CookieOptions{TTL: time.Hour})
	return m, s, u
}

func TestLogin_HappyPath_SetsCookieAndRow(t *testing.T) {
	m, s, u := newManagerWithUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, false)
	api := NewAPI(m)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(loginRequest{Email: "alice@example.com", Password: "supercalifragilistic"})
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case SessionCookie:
			sessionCookie = c
		case CSRFCookie:
			csrfCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("missing hooks_session cookie")
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("missing hooks_csrf cookie")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie not HttpOnly")
	}
	if csrfCookie.HttpOnly {
		t.Error("csrf cookie should NOT be HttpOnly")
	}

	// Row exists.
	id, _, _ := strings.Cut(sessionCookie.Value, ".")
	got, err := s.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != u.ID {
		t.Errorf("session.UserID=%s, want %s", got.UserID, u.ID)
	}
}

func TestLogin_BadPassword_GenericError(t *testing.T) {
	m, _, _ := newManagerWithUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, false)
	api := NewAPI(m)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(loginRequest{Email: "alice@example.com", Password: "wrong-password-12345"})
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestLogin_DeactivatedUser_403(t *testing.T) {
	m, _, _ := newManagerWithUser(t, "bob@example.com", "supercalifragilistic", store.RoleUser, true)
	api := NewAPI(m)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(loginRequest{Email: "bob@example.com", Password: "supercalifragilistic"})
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestLookup_ExpiredCookie_RejectedAndDeleted(t *testing.T) {
	m, s, u := newManagerWithUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, false)
	// Manually insert a session that's already expired.
	plaintext, _ := secret.NewRandom()
	id := uuid.NewString()
	expired := store.Session{
		ID: id, UserID: u.ID, SecretHash: hashSessionSecret(plaintext),
		CreatedAt: time.Now().Add(-2 * time.Hour),
		LastUsedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-time.Minute),
	}
	if err := s.InsertSession(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	_, _, err := m.Lookup(context.Background(), id+"."+plaintext)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Lookup: want ErrExpired, got %v", err)
	}
	if _, err := s.GetSession(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired session should be deleted on lookup, got %v", err)
	}
}

func TestLookup_VerifiesViaSHA256_NotArgon(t *testing.T) {
	m, s, u := newManagerWithUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, false)
	plaintext, _ := secret.NewRandom()
	id := uuid.NewString()

	// Manually build a session row with SHA-256 of plaintext as expected.
	sess := store.Session{
		ID: id, UserID: u.ID, SecretHash: hashSessionSecret(plaintext),
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	}
	if err := s.InsertSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	// Right plaintext succeeds.
	gotUser, _, err := m.Lookup(context.Background(), id+"."+plaintext)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if gotUser.ID != u.ID {
		t.Errorf("user.ID=%s, want %s", gotUser.ID, u.ID)
	}

	// Wrong plaintext fails (and the row is NOT deleted since it's not expired).
	_, _, err = m.Lookup(context.Background(), id+"."+"wrong")
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong plaintext: want ErrInvalid, got %v", err)
	}
	if _, err := s.GetSession(context.Background(), id); err != nil {
		t.Errorf("session row was wrongly deleted: %v", err)
	}
}

func TestLogout_DeletesRow_ExpiresCookie(t *testing.T) {
	m, s, u := newManagerWithUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, false)
	api := NewAPI(m)
	mux := http.NewServeMux()
	api.Register(mux)
	mux.Handle("GET /probe", m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := m.FromContext(r.Context()); ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cookieValue, _, err := m.CreateSession(context.Background(), u.ID, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	jar, _ := http.DefaultClient, ""
	_ = jar
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookieValue})
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", resp.StatusCode)
	}

	id, _, _ := strings.Cut(cookieValue, ".")
	if _, err := s.GetSession(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session not deleted: %v", err)
	}

	// Reusing the cookie now hits middleware ClearCookies path; /probe is anon.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/probe", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookieValue})
	resp, err = http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("reused cookie should not authenticate: %d", resp.StatusCode)
	}
}
