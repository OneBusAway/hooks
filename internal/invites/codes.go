// Package invites implements the invite-code lifecycle (admin issues,
// signup consumes) plus the bootstrap-on-init invariant. The HTTP surface
// at /api/invites is admin-only; /api/auth/signup is unauthenticated and
// gated by an invite code.
package invites

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// CodeLength is the rune count of a generated invite code (16 base32 chars).
const CodeLength = 16

// RFC 4648 base32 alphabet (A-Z2-7); 32 characters, no padding when used
// for fixed-length codes. We accept any case at consume time.
var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewCode returns a fresh 16-char base32 invite code.
func NewCode() (string, error) {
	// 10 random bytes -> 16 base32 chars.
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return codeEncoding.EncodeToString(raw[:]), nil
}

// NormalizeCode upper-cases and trims whitespace from a user-supplied
// code. Used at consume time so a paste-in works regardless of case.
func NormalizeCode(in string) string {
	return strings.ToUpper(strings.TrimSpace(in))
}
