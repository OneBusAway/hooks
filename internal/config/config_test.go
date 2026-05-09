package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

type fakeRegistry struct {
	known map[string]bool
}

func (f fakeRegistry) Has(name string) bool { return f.known[name] }

func newRegistry(names ...string) fakeRegistry {
	r := fakeRegistry{known: map[string]bool{}}
	for _, n := range names {
		r.known[n] = true
	}
	return r
}

func TestParseValid(t *testing.T) {
	t.Setenv("RENDER_SECRET", "shhh")
	yaml := `
sources:
  render:
    verifier: render
    secret: ${RENDER_SECRET}
    retention: 24h
`
	cfg, err := Parse([]byte(yaml), newRegistry("render"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	src, ok := cfg.Sources["render"]
	if !ok {
		t.Fatalf("render source missing")
	}
	if src.Secret.Reveal() != "shhh" {
		t.Fatalf("secret not interpolated: %q", src.Secret.Reveal())
	}
	if src.Retention != 24*time.Hour {
		t.Fatalf("retention = %v, want 24h", src.Retention)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Fatalf("default listen addr lost")
	}
}

func TestParseRejectsTokensField(t *testing.T) {
	yaml := `
tokens:
  - id: foo
sources:
  render:
    verifier: render
    secret: x
`
	_, err := Parse([]byte(yaml), newRegistry("render"))
	if err == nil {
		t.Fatalf("expected error for tokens: field")
	}
	if !strings.Contains(err.Error(), "tokens") {
		t.Fatalf("error doesn't mention tokens: %v", err)
	}
}

func TestParseRejectsUnknownVerifier(t *testing.T) {
	yaml := `
sources:
  render:
    verifier: nope
    secret: x
`
	_, err := Parse([]byte(yaml), newRegistry("render"))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected unknown-verifier error, got %v", err)
	}
}

func TestParseRejectsMissingVerifier(t *testing.T) {
	yaml := `
sources:
  render:
    secret: x
`
	_, err := Parse([]byte(yaml), newRegistry("render"))
	if err == nil || !strings.Contains(err.Error(), "no verifier") {
		t.Fatalf("expected missing-verifier error, got %v", err)
	}
}

func TestParseRejectsEmptySecret(t *testing.T) {
	t.Setenv("MISSING_SECRET", "")
	yaml := `
sources:
  render:
    verifier: render
    secret: ${MISSING_SECRET}
`
	_, err := Parse([]byte(yaml), newRegistry("render"))
	if err == nil || !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("expected empty-secret error, got %v", err)
	}
}

func TestRetentionForever(t *testing.T) {
	yaml := `
sources:
  render:
    verifier: render
    secret: x
    retention: forever
`
	cfg, err := Parse([]byte(yaml), newRegistry("render"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Sources["render"].Retention != 0 {
		t.Fatalf("forever should map to 0, got %v", cfg.Sources["render"].Retention)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("HOOKS_LISTEN_ADDR", ":9090")
	t.Setenv("HOOKS_DATABASE_URL", "/tmp/x.db")
	t.Setenv("HOOKS_LOG_LEVEL", "debug")
	yaml := `
sources:
  render:
    verifier: render
    secret: x
`
	cfg, err := Parse([]byte(yaml), newRegistry("render"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ListenAddr != ":9090" || cfg.DatabaseURL != "/tmp/x.db" || cfg.LogLevel != "debug" {
		t.Fatalf("env override not applied: %+v", cfg)
	}
}

func TestListenAddrPrecedence(t *testing.T) {
	cases := []struct {
		name        string
		hooksListen string // HOOKS_LISTEN_ADDR; "" treated as unset
		port        string // PORT; "" treated as unset
		yamlListen  string // listen_addr in yaml; "" means omit
		want        string // expected ListenAddr; ignored when wantErr is set
		wantErr     string // substring expected in Parse error; "" means no error
	}{
		{name: "port honored when nothing else set", port: "10000", want: ":10000"},
		{name: "yaml beats port", port: "10000", yamlListen: ":7777", want: ":7777"},
		{name: "HOOKS_LISTEN_ADDR beats port", hooksListen: ":9090", port: "10000", want: ":9090"},
		{name: "HOOKS_LISTEN_ADDR beats yaml", hooksListen: ":9090", yamlListen: ":7777", want: ":9090"},
		{name: "unset everywhere falls back to default", want: DefaultListenAddr},
		{name: "non-numeric port errors", port: "not-a-number", wantErr: "PORT="},
		{name: "out-of-range port errors", port: "70000", wantErr: "PORT="},
		{name: "port 0 errors", port: "0", wantErr: "PORT="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOOKS_LISTEN_ADDR", tc.hooksListen)
			t.Setenv("PORT", tc.port)
			yaml := "sources:\n  render:\n    verifier: render\n    secret: x\n"
			if tc.yamlListen != "" {
				yaml = "listen_addr: \"" + tc.yamlListen + "\"\n" + yaml
			}
			cfg, err := Parse([]byte(yaml), newRegistry("render"))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if cfg.ListenAddr != tc.want {
				t.Fatalf("ListenAddr = %q, want %q", cfg.ListenAddr, tc.want)
			}
		})
	}
}

func TestPerSourceOverrides(t *testing.T) {
	yaml := `
body_size_limit: 1MiB
sources:
  render:
    verifier: render
    secret: x
    skew_window: 10m
    body_size_limit: 5MiB
`
	cfg, err := Parse([]byte(yaml), newRegistry("render"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	src := cfg.Sources["render"]
	if src.SkewWindow != 10*time.Minute {
		t.Fatalf("skew_window override = %v", src.SkewWindow)
	}
	if src.BodySizeLimit != 5<<20 {
		t.Fatalf("body_size_limit override = %d", src.BodySizeLimit)
	}
}

func TestRoundTripWithInterpolation(t *testing.T) {
	t.Setenv("RENDER_SECRET", "abc123")
	yaml := `
sources:
  render:
    verifier: render
    secret: "${RENDER_SECRET}"
`
	cfg, err := Parse([]byte(yaml), newRegistry("render"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Sources["render"].Secret.Reveal() != "abc123" {
		t.Fatalf("interpolation lost")
	}
}

func TestNoSourcesIsError(t *testing.T) {
	_, err := Parse([]byte(""), newRegistry())
	if err == nil {
		t.Fatalf("expected error for empty config")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/h.yaml"
	if err := os.WriteFile(path, []byte("sources:\n  render:\n    verifier: render\n    secret: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, newRegistry("render"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := cfg.Sources["render"]; !ok {
		t.Fatalf("render source missing")
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"1024": 1024,
		"1KiB": 1024,
		"1MiB": 1 << 20,
		"5MiB": 5 << 20,
		"1MB":  1_000_000,
	}
	for in, want := range cases {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}

func TestEnvInterpolationWithDefault(t *testing.T) {
	os.Unsetenv("UNSET_VAR")
	out, err := interpolateEnv("a=${UNSET_VAR:-fallback}")
	if err != nil || out != "a=fallback" {
		t.Fatalf("got %q, %v", out, err)
	}
}
