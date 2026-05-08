// Package tokens issues, hashes, and verifies listener bearer tokens.
//
// Plaintext tokens are 32 random bytes encoded as URL-safe base64. They are
// shown to the operator exactly once at issuance and stored at rest as
// Argon2id hashes. Lookup uses constant-time comparison; comparing every row
// is O(N) but fine for the operator-token volume we expect (dozens, not
// thousands).
package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/store"
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow OWASP-recommended defaults; tweak only
// after benchmarking on the smallest target deployment.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

// IssueResult is what `token add` returns. The plaintext is shown to the
// operator exactly once and never persisted.
type IssueResult struct {
	ID        string
	Plaintext string
	Hash      string
}

// Generate creates a new token plaintext (URL-safe base64 of 32 random bytes)
// and its Argon2id hash, returning a fresh ID.
func Generate(name string, scopes []string) (IssueResult, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return IssueResult{}, fmt.Errorf("rand: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw[:])
	hash, err := Hash(plaintext)
	if err != nil {
		return IssueResult{}, err
	}
	return IssueResult{
		ID:        uuid.NewString(),
		Plaintext: plaintext,
		Hash:      hash,
	}, nil
}

// Hash returns an Argon2id-encoded representation of plaintext suitable for
// storing in the listener_tokens table.
func Hash(plaintext string) (string, error) {
	var salt [saltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	digest := argon2.IDKey([]byte(plaintext), salt[:], argonTime, argonMemory, argonThreads, argonKeyLen)
	return encode(salt[:], digest), nil
}

// Verify reports whether plaintext matches the encoded Argon2id hash.
func Verify(plaintext, encoded string) (bool, error) {
	salt, digest, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(plaintext), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return constantTimeEqual(got, digest), nil
}

func encode(salt, digest []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
}

func decode(s string) (salt, digest []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("invalid argon2 hash")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("salt: %w", err)
	}
	digest, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("digest: %w", err)
	}
	return salt, digest, nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

// ParseScopes accepts a comma-separated string and returns trimmed,
// duplicate-free scope names.
func ParseScopes(in string) []string {
	if in == "" {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range strings.Split(in, ",") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Issue creates a new token, persists its hash via tokens, and returns the
// plaintext exactly once.
func Issue(ctx context.Context, ts store.TokenStore, name string, scopes []string) (IssueResult, error) {
	if name == "" {
		return IssueResult{}, errors.New("token name is required")
	}
	if len(scopes) == 0 {
		return IssueResult{}, errors.New("at least one scope is required")
	}
	res, err := Generate(name, scopes)
	if err != nil {
		return IssueResult{}, err
	}
	tok := store.Token{
		ID:         res.ID,
		Name:       name,
		Scopes:     scopes,
		SecretHash: res.Hash,
		CreatedAt:  time.Now().UTC(),
	}
	if err := ts.Insert(ctx, tok); err != nil {
		return IssueResult{}, fmt.Errorf("persist token: %w", err)
	}
	return res, nil
}
