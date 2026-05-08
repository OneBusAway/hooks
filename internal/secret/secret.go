// Package secret provides a typed string that redacts itself when logged or
// JSON-encoded, plus helpers for constant-time comparison.
package secret

import (
	"crypto/subtle"
	"encoding/json"
)

// String is a credential that must never appear in logs, structured-log
// fields, or JSON output. Convert to plaintext explicitly via Reveal.
type String string

const redacted = "[REDACTED]"

func (s String) String() string { return redacted }

func (s String) GoString() string { return redacted }

func (s String) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// Reveal returns the underlying plaintext. Callers should use this only at
// the boundary where the secret is actually consumed (HMAC computation,
// outbound bearer header, etc.) and not retain the plaintext in logs.
func (s String) Reveal() string { return string(s) }

// Empty reports whether the underlying secret has zero length.
func (s String) Empty() bool { return len(s) == 0 }

// Equal compares two byte slices in constant time.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// EqualString is the string-input convenience form of Equal.
func EqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
