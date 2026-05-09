package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// profile is the on-disk credentials record written by `hooksctl login`
// and read by every command that needs an authenticated request.
//
// File format is a tiny TOML subset (key = value with optional quotes);
// only four keys are recognised. Unknown keys are tolerated so future
// additions are backward-compatible.
type profile struct {
	ServerURL string
	Token     string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// profilePath resolves the credentials filepath for the given profile
// name (defaulting to "default" when empty). It honours XDG_CONFIG_HOME
// per design.md and creates the parent directory mode 0700.
func profilePath(name string) (string, error) {
	if name == "" {
		name = "default"
	}
	dir, err := profileDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials."+name), nil
}

func profileDir() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "hooks"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "hooks"), nil
}

// saveProfile writes the credentials file with mode 0600. It overwrites
// any existing file atomically (write-then-rename) so a crashed write
// does not leave a half-empty credentials file behind.
func saveProfile(name string, p profile) error {
	path, err := profilePath(name)
	if err != nil {
		return err
	}
	data := encodeProfileTOML(p)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// loadProfile reads the credentials file. If the file does not exist
// the returned error wraps os.ErrNotExist so callers can use os.IsNotExist
// to distinguish missing-credentials from other I/O errors.
func loadProfile(name string) (profile, error) {
	path, err := profilePath(name)
	if err != nil {
		return profile{}, err
	}
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return profile{}, err
	}
	return parseProfileTOML(raw)
}

// deleteProfile removes the credentials file for the given profile.
// A missing file is not an error (idempotent — `hooksctl logout` may
// race with manual cleanup).
func deleteProfile(name string) error {
	path, err := profilePath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func encodeProfileTOML(p profile) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "server_url = %q\n", p.ServerURL)
	fmt.Fprintf(&b, "token = %q\n", p.Token)
	fmt.Fprintf(&b, "created_at = %q\n", p.CreatedAt.UTC().Format(time.RFC3339))
	if p.ExpiresAt != nil {
		fmt.Fprintf(&b, "expires_at = %q\n", p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return []byte(b.String())
}

// parseProfileTOML accepts the narrow `key = "value"` subset we write.
// Comments (#) and blank lines are skipped; unknown keys are tolerated.
func parseProfileTOML(raw []byte) (profile, error) {
	var p profile
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return profile{}, fmt.Errorf("profile: line %d: missing '='", n+1)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = strings.TrimPrefix(val, `"`)
		val = strings.TrimSuffix(val, `"`)
		switch key {
		case "server_url":
			p.ServerURL = val
		case "token":
			p.Token = val
		case "created_at":
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return profile{}, fmt.Errorf("profile: created_at: %w", err)
			}
			p.CreatedAt = t
		case "expires_at":
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return profile{}, fmt.Errorf("profile: expires_at: %w", err)
			}
			p.ExpiresAt = &t
		}
	}
	return p, nil
}

// resolveProfile fills g.Token / g.Server from the named profile when
// no explicit --token / HOOKS_TOKEN is already in play. Precedence is:
//
//	g.Token already set (from --token or HOOKS_TOKEN) > profile file > unset.
//
// Server URL only inherits from the profile when g.Server is the
// hard-coded default (i.e. the user didn't pass --server or HOOKS_SERVER).
func resolveProfile(g *globals, name string) {
	if g.Token != "" {
		// --token or HOOKS_TOKEN already won; only fill server from profile
		// if it's still the default (this lets users mix --token with a
		// profile-stored server URL).
		if g.Server == defaultServerURL || g.Server == "" {
			if p, err := loadProfile(name); err == nil && p.ServerURL != "" {
				g.Server = p.ServerURL
			}
		}
		return
	}
	p, err := loadProfile(name)
	if err != nil {
		return
	}
	g.Token = p.Token
	if p.ServerURL != "" && (g.Server == defaultServerURL || g.Server == "") {
		g.Server = p.ServerURL
	}
}

const defaultServerURL = "http://localhost:8080"
