package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onebusaway/hooks/internal/store"
)

func TestTokenAPIRequiresAdmin(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	AttachVerifier(st)

	nonAdmin, _ := Issue(context.Background(), st.Tokens(), "user", []string{"render"})
	admin, _ := Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})

	api := NewAPI(st.Tokens(), New(st.Tokens()))
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// No token → 401.
	resp, _ := http.Get(srv.URL + "/api/tokens")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Non-admin → 403.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+nonAdmin.Plaintext)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Admin lists fine.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+admin.Plaintext)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestTokenAPICreateAndRevoke(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	AttachVerifier(st)

	admin, _ := Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})
	api := NewAPI(st.Tokens(), New(st.Tokens()))
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"name": "ci", "scopes": []string{"render"}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+admin.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	var created struct {
		ID        string `json:"id"`
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if created.Plaintext == "" || created.ID == "" {
		t.Fatalf("missing fields: %+v", created)
	}

	// Revoke.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/tokens/"+created.ID+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+admin.Plaintext)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Confirm revoked token can't auth.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+created.Plaintext)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked still works: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestTokenAPIListNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	AttachVerifier(st)

	admin, _ := Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})

	api := NewAPI(st.Tokens(), New(st.Tokens()))
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+admin.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if strings.Contains(buf.String(), admin.Plaintext) {
		t.Fatalf("listing leaked plaintext: %s", buf.String())
	}
}
