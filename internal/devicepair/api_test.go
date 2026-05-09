package devicepair

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

type fakeAuth struct {
	user store.User
	ok   bool
}

func (f fakeAuth) FromContext(ctx context.Context) (store.User, store.Session, bool) {
	return f.user, store.Session{}, f.ok
}

func newTest(t *testing.T) *store.SQLite {
	t.Helper()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "dp.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustUser(t *testing.T, s *store.SQLite, role store.Role, scopes []string) (store.User, string) {
	t.Helper()
	plaintext := "supercalifragilistic"
	hash, _ := users.HashPassword(secret.String(plaintext))
	u := store.User{
		ID: uuid.NewString(), Email: uuid.NewString() + "@example.com",
		Name: "T", Role: role, PasswordHash: hash,
		DefaultScopes: append([]string{}, scopes...),
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u, plaintext
}

func TestStart_Pending(t *testing.T) {
	s := newTest(t)
	api := NewAPI(s, fakeAuth{}, nil, "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	if sr.DeviceCode == "" || sr.UserCode == "" {
		t.Fatalf("missing codes: %+v", sr)
	}
}

func TestApprove_RequiresPasswordReentry(t *testing.T) {
	s := newTest(t)
	user, plaintext := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, nil, "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Start a pairing.
	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	// Approve with wrong password -> 401.
	body, _ = json.Marshal(approveRequest{UserCode: sr.UserCode, Password: "wrong-password-1234", GrantedScopes: []string{"render"}})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}

	// Approve with right password -> ok.
	body, _ = json.Marshal(approveRequest{UserCode: sr.UserCode, Password: plaintext, GrantedScopes: []string{"render"}})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("right password: %d", resp.StatusCode)
	}
}

func TestApprove_WideningScopesRejected(t *testing.T) {
	s := newTest(t)
	user, plaintext := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, nil, "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	// Granted scopes include something not in requested.
	body, _ = json.Marshal(approveRequest{
		UserCode:      sr.UserCode,
		Password:      plaintext,
		GrantedScopes: []string{"render", "stripe"},
	})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("widening: %d", resp.StatusCode)
	}
}

func TestApprove_ScopesUserDoesNotHold(t *testing.T) {
	s := newTest(t)
	user, plaintext := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, nil, "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// CLI requests a scope user doesn't hold.
	body, _ := json.Marshal(startRequest{Scopes: []string{"stripe"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	body, _ = json.Marshal(approveRequest{UserCode: sr.UserCode, Password: plaintext, GrantedScopes: []string{"stripe"}})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

func TestPoll_StateTransitions(t *testing.T) {
	s := newTest(t)
	user, plaintext := mustUser(t, s, store.RoleUser, []string{"render"})
	api := NewAPI(s, fakeAuth{user: user, ok: true}, audit.New(s.Audit(), nil), "https://h.example/device")
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Start.
	body, _ := json.Marshal(startRequest{Scopes: []string{"render"}})
	resp, err := http.Post(srv.URL+"/api/auth/device/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var sr startResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	// Poll while pending -> 202.
	body, _ = json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("pending poll: %d", resp.StatusCode)
	}

	// Approve.
	body, _ = json.Marshal(approveRequest{UserCode: sr.UserCode, Password: plaintext, GrantedScopes: []string{"render"}})
	resp, err = http.Post(srv.URL+"/api/auth/device/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Poll while approved_unfetched -> 200 with token.
	body, _ = json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approved poll: %d", resp.StatusCode)
	}
	var pr pollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()
	if pr.Token == "" {
		t.Fatal("missing plaintext token")
	}

	// Allow the deferred mark-fetched goroutine to run.
	time.Sleep(50 * time.Millisecond)

	// Poll again -> 410 (done, plaintext purged).
	body, _ = json.Marshal(pollRequest{DeviceCode: sr.DeviceCode})
	resp, err = http.Post(srv.URL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Errorf("post-fetch poll: %d", resp.StatusCode)
	}
}

func TestUserCodeFormat(t *testing.T) {
	for i := 0; i < 16; i++ {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Errorf("user_code shape: %q", c)
		}
	}
}
