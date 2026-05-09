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

// userCodeAlphabet is the 31-char alphabet specified in design.md and
// tasks.md §7.1: the RFC 4648 base32 alphabet (A–Z, 2–7) minus the
// visually-confusable letters I, L, and O — extended to 2–9 (8 and 9
// added because they have no letter look-alikes in the remaining set
// and broaden the codespace from the bare 31-letter form). The user-
// code shape is XXXX-XXXX (8 alphabet chars plus a literal hyphen).
const userCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

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
// the 31-character alphabet. Uses rejection sampling against the largest
// multiple of len(alphabet) that fits in a byte (31*8 = 248), so each
// alphabet position has exactly 1/31 probability — the naive `b % 31`
// over [0,256) introduces a ~13% bias on the first 8 codepoints.
//
// The user reads this off the CLI's stdout and types it into the
// /device approval page; an unbiased distribution preserves the
// 31^8 = ~8.5e11 search space against guessing during the 15-minute
// approval window.
func NewUserCode() (string, error) {
	const codeLen = 8
	const alpha = len(userCodeAlphabet)
	// Largest byte value such that [0, limit) is an exact multiple of
	// alpha. 256 / 31 = 8, so limit = 248. Every byte we DON'T reject
	// maps to exactly one alphabet position via modulo, eliminating
	// modulo bias entirely.
	const limit = (256 / alpha) * alpha
	out := make([]byte, 0, codeLen+1)
	var buf [16]byte
	bufPos := len(buf) // forces initial fill on first iteration
	produced := 0
	for produced < codeLen {
		if bufPos >= len(buf) {
			if _, err := rand.Read(buf[:]); err != nil {
				return "", err
			}
			bufPos = 0
		}
		b := buf[bufPos]
		bufPos++
		if int(b) >= limit {
			continue // bias-rejection
		}
		out = append(out, userCodeAlphabet[int(b)%alpha])
		produced++
		if produced == 4 {
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
