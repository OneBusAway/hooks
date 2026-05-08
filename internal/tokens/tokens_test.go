package tokens

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/onebusaway/hooks/internal/store"
)

func newSQLite(t *testing.T) *store.SQLite {
	t.Helper()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	AttachVerifier(s)
	return s
}

func TestIssueAndLookup(t *testing.T) {
	s := newSQLite(t)
	res, err := Issue(context.Background(), s.Tokens(), "laptop", []string{"render"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Tokens().LookupByPlaintext(context.Background(), res.Plaintext)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if tok.Name != "laptop" {
		t.Fatalf("name = %q", tok.Name)
	}
	// Hash in DB must NOT equal plaintext.
	tokens, _ := s.Tokens().List(context.Background(), false)
	if tokens[0].SecretHash == res.Plaintext {
		t.Fatalf("plaintext leaked into hash column")
	}
}

func TestParseScopes(t *testing.T) {
	got := ParseScopes("render, admin , render,")
	want := []string{"render", "admin"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestRevokedTokenIsRejected(t *testing.T) {
	s := newSQLite(t)
	res, err := Issue(context.Background(), s.Tokens(), "laptop", []string{"render"})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.Tokens().LookupByPlaintext(context.Background(), res.Plaintext)
	if err := s.Tokens().Revoke(context.Background(), tok.ID, tok.CreatedAt.Add(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tokens().LookupByPlaintext(context.Background(), res.Plaintext); err == nil {
		t.Fatalf("revoked token still resolves")
	}
}

func TestAdminAloneCannotSubscribe(t *testing.T) {
	s := newSQLite(t)
	res, _ := Issue(context.Background(), s.Tokens(), "ops", []string{"admin"})
	auth := New(s.Tokens())
	r := httptest.NewRequest(http.MethodGet, "/subscribe/render", nil)
	r.Header.Set("Authorization", "Bearer "+res.Plaintext)

	if _, err := auth.AuthorizeSource(r, "render"); err == nil {
		t.Fatalf("admin-only token should NOT pass AuthorizeSource(render)")
	}
	if _, err := auth.AuthorizeAdmin(r); err != nil {
		t.Fatalf("admin-only token failed admin check: %v", err)
	}
}

func TestCombinedScopeWorksForBoth(t *testing.T) {
	s := newSQLite(t)
	res, _ := Issue(context.Background(), s.Tokens(), "ops", []string{"admin", "render"})
	auth := New(s.Tokens())
	r := httptest.NewRequest(http.MethodGet, "/subscribe/render", nil)
	r.Header.Set("Authorization", "Bearer "+res.Plaintext)

	if _, err := auth.AuthorizeSource(r, "render"); err != nil {
		t.Fatalf("AuthorizeSource: %v", err)
	}
	if _, err := auth.AuthorizeAdmin(r); err != nil {
		t.Fatalf("AuthorizeAdmin: %v", err)
	}
}

func TestMissingHeaderIs401(t *testing.T) {
	s := newSQLite(t)
	auth := New(s.Tokens())
	r := httptest.NewRequest(http.MethodGet, "/subscribe/render", nil)
	if _, err := auth.AuthorizeSource(r, "render"); !IsAuthError(err) {
		t.Fatalf("missing header gave %v", err)
	}
}

func TestUnknownTokenIs401(t *testing.T) {
	s := newSQLite(t)
	auth := New(s.Tokens())
	r := httptest.NewRequest(http.MethodGet, "/subscribe/render", nil)
	r.Header.Set("Authorization", "Bearer not-a-real-token")
	if _, err := auth.AuthorizeSource(r, "render"); !IsAuthError(err) {
		t.Fatalf("unknown token gave %v", err)
	}
}
