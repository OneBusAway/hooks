// Package config loads and validates the hooks server's YAML configuration.
//
// Listener tokens and push subscriptions live in the database, never in the
// YAML file. The loader will refuse to start if it sees a `tokens:` field.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/secret"
	"gopkg.in/yaml.v3"
)

// Defaults applied when omitted from YAML or env.
const (
	DefaultListenAddr      = ":8080"
	DefaultDatabaseURL     = "./hooks.db"
	DefaultLogLevel        = "info"
	DefaultBodySizeLimit   = 1 << 20 // 1 MiB
	DefaultDedupeWindow    = 24 * time.Hour
	DefaultSkewWindow      = 5 * time.Minute
	DefaultSourceRetention = 30 * 24 * time.Hour
)

// Source describes one inbound webhook provider.
type Source struct {
	// Name is the URL path segment under /ingest/. Set from the YAML map key.
	Name string `yaml:"-"`

	// Verifier names a registered verifier (e.g. "render"). Required.
	Verifier string `yaml:"verifier"`

	// Secret is the per-source signing secret used by the verifier.
	Secret secret.String `yaml:"secret"`

	// Retention controls auto-prune. Zero means "no auto-prune"
	// (the literal `forever` in YAML maps to zero).
	Retention time.Duration `yaml:"retention"`

	// SkewWindow optionally overrides the global replay-attack skew.
	SkewWindow time.Duration `yaml:"skew_window"`

	// BodySizeLimit optionally overrides the global per-request body cap.
	BodySizeLimit int64 `yaml:"body_size_limit"`
}

// Web carries the optional web/auth knobs introduced by the developer-
// accounts work. All fields default to safe values when omitted.
type Web struct {
	// SessionTTL is the sliding-expiry window for hooks_session cookies.
	// Defaults to 30 days when zero.
	SessionTTL time.Duration
	// TrustProxyHeaders, when true, lets the cookie's Secure flag honor
	// X-Forwarded-Proto from a trusted reverse proxy.
	TrustProxyHeaders bool
	// PublicURL is the externally reachable base URL (used for the
	// device-pairing verification page and cmd/hooks signup output).
	PublicURL string
}

// Config is the parsed, validated runtime configuration.
type Config struct {
	ListenAddr    string
	DatabaseURL   string
	LogLevel      string
	BodySizeLimit int64
	DedupeWindow  time.Duration
	SkewWindow    time.Duration

	// Web carries optional knobs for the cookie-session and device-pairing
	// flows. Zero values map to safe defaults.
	Web Web

	// Sources is keyed by source name (the URL path segment).
	Sources map[string]Source
}

// rawConfig mirrors the on-disk YAML schema.
type rawConfig struct {
	ListenAddr    string               `yaml:"listen_addr"`
	DatabaseURL   string               `yaml:"database_url"`
	LogLevel      string               `yaml:"log_level"`
	BodySizeLimit string               `yaml:"body_size_limit"`
	DedupeWindow  string               `yaml:"dedupe_window"`
	SkewWindow    string               `yaml:"skew_window"`
	Web           rawWeb               `yaml:"web"`
	Sources       map[string]rawSource `yaml:"sources"`
	Tokens        any                  `yaml:"tokens"` // forbidden; presence => error
}

type rawWeb struct {
	SessionTTL        string `yaml:"session_ttl"`
	TrustProxyHeaders bool   `yaml:"trust_proxy_headers"`
	PublicURL         string `yaml:"public_url"`
}

type rawSource struct {
	Verifier      string `yaml:"verifier"`
	Secret        string `yaml:"secret"`
	Retention     string `yaml:"retention"`
	SkewWindow    string `yaml:"skew_window"`
	BodySizeLimit string `yaml:"body_size_limit"`
}

// VerifierRegistry is the minimal interface used to validate that every
// configured source names a registered provider plugin.
type VerifierRegistry interface {
	Has(name string) bool
}

// Load reads and validates a hooks.yaml file from path. The provided
// registry must contain every verifier the config refers to; an unknown
// verifier is a startup-fatal error.
func Load(path string, registry VerifierRegistry) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data, registry)
}

// Parse parses raw YAML bytes after env interpolation and applies the same
// validation as Load.
func Parse(data []byte, registry VerifierRegistry) (*Config, error) {
	interpolated, err := interpolateEnv(string(data))
	if err != nil {
		return nil, err
	}

	var raw rawConfig
	dec := yaml.NewDecoder(strings.NewReader(interpolated))
	dec.KnownFields(false)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if raw.Tokens != nil {
		return nil, errors.New("config: `tokens:` is not allowed in hooks.yaml — listener tokens live in the database (manage them with `hooksctl token`)")
	}

	cfg := &Config{
		ListenAddr:    firstNonEmpty(raw.ListenAddr, DefaultListenAddr),
		DatabaseURL:   firstNonEmpty(raw.DatabaseURL, DefaultDatabaseURL),
		LogLevel:      firstNonEmpty(raw.LogLevel, DefaultLogLevel),
		BodySizeLimit: DefaultBodySizeLimit,
		DedupeWindow:  DefaultDedupeWindow,
		SkewWindow:    DefaultSkewWindow,
		Sources:       map[string]Source{},
	}

	if raw.BodySizeLimit != "" {
		n, err := parseSize(raw.BodySizeLimit)
		if err != nil {
			return nil, fmt.Errorf("body_size_limit: %w", err)
		}
		cfg.BodySizeLimit = n
	}
	if raw.DedupeWindow != "" {
		d, err := time.ParseDuration(raw.DedupeWindow)
		if err != nil {
			return nil, fmt.Errorf("dedupe_window: %w", err)
		}
		cfg.DedupeWindow = d
	}
	if raw.SkewWindow != "" {
		d, err := time.ParseDuration(raw.SkewWindow)
		if err != nil {
			return nil, fmt.Errorf("skew_window: %w", err)
		}
		cfg.SkewWindow = d
	}

	if raw.Web.SessionTTL != "" {
		d, err := time.ParseDuration(raw.Web.SessionTTL)
		if err != nil {
			return nil, fmt.Errorf("web.session_ttl: %w", err)
		}
		cfg.Web.SessionTTL = d
	}
	cfg.Web.TrustProxyHeaders = raw.Web.TrustProxyHeaders
	cfg.Web.PublicURL = raw.Web.PublicURL

	for name, rs := range raw.Sources {
		s, err := buildSource(name, rs, cfg)
		if err != nil {
			return nil, err
		}
		cfg.Sources[name] = s
	}

	if err := cfg.validate(registry); err != nil {
		return nil, err
	}

	cfg.applyEnvOverrides()
	return cfg, nil
}

func buildSource(name string, rs rawSource, cfg *Config) (Source, error) {
	s := Source{
		Name:          name,
		Verifier:      rs.Verifier,
		Secret:        secret.String(rs.Secret),
		Retention:     DefaultSourceRetention,
		SkewWindow:    cfg.SkewWindow,
		BodySizeLimit: cfg.BodySizeLimit,
	}
	if rs.Retention != "" {
		ret, err := parseRetention(rs.Retention)
		if err != nil {
			return Source{}, fmt.Errorf("source %q retention: %w", name, err)
		}
		s.Retention = ret
	}
	if rs.SkewWindow != "" {
		d, err := time.ParseDuration(rs.SkewWindow)
		if err != nil {
			return Source{}, fmt.Errorf("source %q skew_window: %w", name, err)
		}
		s.SkewWindow = d
	}
	if rs.BodySizeLimit != "" {
		n, err := parseSize(rs.BodySizeLimit)
		if err != nil {
			return Source{}, fmt.Errorf("source %q body_size_limit: %w", name, err)
		}
		s.BodySizeLimit = n
	}
	return s, nil
}

func (c *Config) validate(registry VerifierRegistry) error {
	if len(c.Sources) == 0 {
		return errors.New("config: no sources defined; at least one source is required")
	}
	for name, s := range c.Sources {
		if s.Verifier == "" {
			return fmt.Errorf("config: source %q has no verifier; v1 does not support unsigned sources", name)
		}
		if registry != nil && !registry.Has(s.Verifier) {
			return fmt.Errorf("config: source %q names verifier %q which is not registered", name, s.Verifier)
		}
		if s.Secret.Empty() {
			return fmt.Errorf("config: source %q has an empty secret (did the ${ENV} placeholder fail to resolve?)", name)
		}
	}
	return nil
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("HOOKS_LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("HOOKS_DATABASE_URL"); v != "" {
		c.DatabaseURL = v
	}
	if v := os.Getenv("HOOKS_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("HOOKS_PUBLIC_URL"); v != "" {
		c.Web.PublicURL = v
	}
}

// interpolateEnv expands `${VAR}` (and `${VAR:-default}`) references against
// os.Getenv. An undefined variable expands to the empty string; validation
// downstream catches resulting empty secrets with a clearer message.
var envRefRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

func interpolateEnv(in string) (string, error) {
	return envRefRE.ReplaceAllStringFunc(in, func(match string) string {
		m := envRefRE.FindStringSubmatch(match)
		name := m[1]
		def := m[3]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return def
	}), nil
}

func parseRetention(in string) (time.Duration, error) {
	in = strings.TrimSpace(in)
	switch strings.ToLower(in) {
	case "0", "forever", "never":
		return 0, nil
	}
	// Support "<n>d" because time.ParseDuration tops out at hours.
	if strings.HasSuffix(in, "d") {
		var days int64
		if _, err := fmt.Sscanf(strings.TrimSuffix(in, "d"), "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid retention %q: %w", in, err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(in)
}

// parseSize accepts "1024", "1KiB", "1MiB", "10MB", etc. Binary (KiB/MiB/GiB)
// and decimal (KB/MB/GB) suffixes are both supported.
func parseSize(in string) (int64, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return 0, errors.New("empty size")
	}
	multipliers := []struct {
		suffix string
		mult   int64
	}{
		{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"GB", 1_000_000_000}, {"MB", 1_000_000}, {"KB", 1_000},
		{"B", 1},
	}
	for _, m := range multipliers {
		if strings.HasSuffix(in, m.suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(in, m.suffix))
			var n int64
			if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil {
				return 0, fmt.Errorf("invalid size %q: %w", in, err)
			}
			return n * m.mult, nil
		}
	}
	var n int64
	if _, err := fmt.Sscanf(in, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", in, err)
	}
	return n, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
