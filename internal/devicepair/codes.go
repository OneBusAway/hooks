// Package devicepair implements the CLI device-pairing flow described in
// design.md: the CLI POSTs to /api/auth/device/start, prints a short
// user_code, and polls /api/auth/device/poll while the user logs in to
// /device on the web and approves. Approval mints a PAT (kind='pat')
// owned by the approving user, narrowed to the requested scopes.
package devicepair

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Alphabet for user_code: 8 chars from base32 minus 0, 1, I, L, O, U
// (high transcription-resistance). 30 characters; the user-code shape is
// XXXX-XXXX (8 alphabet chars + a literal hyphen).
const userCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewDeviceCode returns a fresh 32-char hex device_code (16 random bytes).
// The device_code is what the CLI keeps; it never hits a human's eyes.
func NewDeviceCode() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// NewUserCode returns a fresh XXXX-XXXX user_code drawn uniformly from
// the 30-character alphabet. The user reads this off the CLI's stdout
// and types it into the /device approval page.
func NewUserCode() (string, error) {
	var raw [8]byte
	out := make([]byte, 0, 9)
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	for i, b := range raw {
		out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
		if i == 3 {
			out = append(out, '-')
		}
	}
	return string(out), nil
}

// NormalizeUserCode upper-cases, trims, and strips internal whitespace
// from a user-supplied user_code so paste-in works regardless of case
// or accidental spaces.
func NormalizeUserCode(in string) string {
	in = strings.ToUpper(strings.TrimSpace(in))
	return strings.ReplaceAll(in, " ", "")
}
