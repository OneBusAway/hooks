package users

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/onebusaway/hooks/internal/secret"
)

// MinPasswordLength is the minimum codepoint count for a new password.
const MinPasswordLength = 12

// PolicyError is the typed error returned by ValidatePassword. The Reason
// field is safe to log; the Plaintext is never carried.
type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string { return "password policy: " + e.Reason }

// Reasons surfaced to logs (never to API responses, which return a generic
// "password does not meet policy" message).
const (
	ReasonTooShort       = "too short"
	ReasonContainsEmail  = "contains email"
)

// ValidatePassword enforces the v1 password policy: length ≥ 12 codepoints
// and case-insensitive non-containment of the user's email or its
// local-part. Failed validation returns a *PolicyError so callers may match
// for logging; the plaintext is never logged.
func ValidatePassword(email string, plaintext secret.String) error {
	pw := plaintext.Reveal()
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return &PolicyError{Reason: ReasonTooShort}
	}
	lower := strings.ToLower(pw)
	emailLower := strings.ToLower(strings.TrimSpace(email))
	if emailLower != "" {
		if strings.Contains(lower, emailLower) {
			return &PolicyError{Reason: ReasonContainsEmail}
		}
		// Local-part substring check, but only for local-parts of 3+ chars
		// — checking single- or double-character local-parts is too noisy
		// (almost every password contains "a" or "ab").
		if at := strings.Index(emailLower, "@"); at >= 3 {
			local := emailLower[:at]
			if strings.Contains(lower, local) {
				return &PolicyError{Reason: ReasonContainsEmail}
			}
		}
	}
	return nil
}

// IsPolicyError reports whether err is a *PolicyError. Useful for handler
// code that wants to convert policy violations to HTTP 400 while letting
// other errors bubble.
func IsPolicyError(err error) bool {
	var pe *PolicyError
	return errors.As(err, &pe)
}
