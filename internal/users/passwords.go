// Package users provides identity-domain helpers (password hashing,
// password policy, scope evaluation) layered on top of internal/store's
// User/Session/Invite/DevicePairing types. Public types live in store;
// this package owns the auth-domain logic that depends on argon2 and
// crypto/rand.
package users

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/onebusaway/hooks/internal/secret"
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Match the existing token hasher in internal/tokens
// so callers don't have to remember which is which. Tweak only after
// benchmarking on the smallest target deployment.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

// HashPassword returns an Argon2id-encoded representation of plaintext
// suitable for storing in users.password_hash.
func HashPassword(plaintext secret.String) (string, error) {
	var salt [saltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	digest := argon2.IDKey([]byte(plaintext.Reveal()), salt[:], argonTime, argonMemory, argonThreads, argonKeyLen)
	return encode(salt[:], digest), nil
}

// VerifyPassword reports whether plaintext matches the encoded Argon2id
// hash. Always runs the full Argon2 derivation even on malformed encoded
// input (returning (false, nil)) so the timing of a verify call does not
// leak whether a row was present.
func VerifyPassword(plaintext secret.String, encoded string) (bool, error) {
	salt, digest, err := decode(encoded)
	if err != nil {
		// Run a dummy Argon2 derivation to keep timing uniform on a
		// malformed-hash row, then return false without leaking the err.
		var dummySalt [saltLen]byte
		_ = argon2.IDKey([]byte(plaintext.Reveal()), dummySalt[:], argonTime, argonMemory, argonThreads, argonKeyLen)
		return false, nil
	}
	got := argon2.IDKey([]byte(plaintext.Reveal()), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return secret.Equal(got, digest), nil
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
