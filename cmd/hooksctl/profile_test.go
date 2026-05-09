package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProfilePath_XDGConfigHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", filepath.Join(dir, "home")) // ensure HOME isn't picked up
	got, err := profilePath("default")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "hooks", "credentials.default")
	if got != want {
		t.Errorf("profilePath = %q, want %q", got, want)
	}
}

func TestProfilePath_FallsBackToHomeDotConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", dir)
	got, err := profilePath("staging")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, ".config", "hooks", "credentials.staging")
	if got != want {
		t.Errorf("profilePath = %q, want %q", got, want)
	}
}

func TestProfilePath_DefaultsProfileToDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got, err := profilePath("")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "credentials.default" {
		t.Errorf("got %q, want trailing credentials.default", got)
	}
}

func TestSaveAndLoadProfile_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	exp := time.Date(2027, 5, 8, 12, 0, 0, 0, time.UTC)
	p := profile{
		ServerURL: "https://hooks.example.com",
		Token:     "tok-abcdef0123456789",
		CreatedAt: now,
		ExpiresAt: &exp,
	}
	if err := saveProfile("alpha", p); err != nil {
		t.Fatal(err)
	}
	got, err := loadProfile("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != p.ServerURL {
		t.Errorf("ServerURL = %q, want %q", got.ServerURL, p.ServerURL)
	}
	if got.Token != p.Token {
		t.Errorf("Token mismatch")
	}
	if !got.CreatedAt.Equal(p.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, p.CreatedAt)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, exp)
	}
}

func TestSaveProfile_NoExpiresAt_OmitsLine(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p := profile{
		ServerURL: "https://hooks.example.com",
		Token:     "tok",
		CreatedAt: time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC),
	}
	if err := saveProfile("default", p); err != nil {
		t.Fatal(err)
	}
	path, _ := profilePath("default")
	raw, _ := os.ReadFile(path) //nolint:gosec
	if strings.Contains(string(raw), "expires_at") {
		t.Errorf("expected no expires_at in %q", raw)
	}
}

func TestSaveProfile_FileMode0600(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p := profile{ServerURL: "x", Token: "y", CreatedAt: time.Now().UTC()}
	if err := saveProfile("default", p); err != nil {
		t.Fatal(err)
	}
	path, _ := profilePath("default")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
}

func TestLoadProfile_Missing_ReturnsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if _, err := loadProfile("nope"); !os.IsNotExist(err) {
		t.Errorf("err = %v, want IsNotExist", err)
	}
}

func TestDeleteProfile_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p := profile{ServerURL: "x", Token: "y", CreatedAt: time.Now().UTC()}
	if err := saveProfile("default", p); err != nil {
		t.Fatal(err)
	}
	if err := deleteProfile("default"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile("default"); !os.IsNotExist(err) {
		t.Errorf("expected NotExist after delete, got %v", err)
	}
}

func TestDeleteProfile_AlreadyMissing_NoError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := deleteProfile("default"); err != nil {
		t.Errorf("expected nil err for missing profile delete, got %v", err)
	}
}

func TestParseProfileTOML_TolerantOfWhitespace(t *testing.T) {
	raw := `
# comment
server_url = "https://example.com"
  token   =   "abc"
created_at = "2026-05-08T12:00:00Z"
`
	p, err := parseProfileTOML([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.ServerURL != "https://example.com" || p.Token != "abc" {
		t.Errorf("parsed = %+v", p)
	}
	if !p.CreatedAt.Equal(time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("CreatedAt = %v", p.CreatedAt)
	}
}

func TestResolveToken_Precedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// profile only
	if err := saveProfile("default", profile{ServerURL: "https://srv", Token: "from-profile", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	g := globals{}
	resolveProfile(&g, "")
	if g.Token != "from-profile" || g.Server != "https://srv" {
		t.Errorf("expected profile fallback, got token=%q server=%q", g.Token, g.Server)
	}

	// HOOKS_TOKEN beats profile (set on globals before resolve)
	g2 := globals{Token: "from-env"}
	resolveProfile(&g2, "")
	if g2.Token != "from-env" {
		t.Errorf("expected HOOKS_TOKEN to win, got %q", g2.Token)
	}

	// --token (already set) beats everything
	g3 := globals{Token: "from-flag"}
	resolveProfile(&g3, "")
	if g3.Token != "from-flag" {
		t.Errorf("expected --token to win, got %q", g3.Token)
	}
}
