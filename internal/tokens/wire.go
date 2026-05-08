package tokens

import "github.com/onebusaway/hooks/internal/store"

// AttachVerifier wires this package's argon2 Verify into the SQLite store so
// LookupByPlaintext can perform constant-time hash comparison without the
// store package importing argon2.
func AttachVerifier(s *store.SQLite) {
	s.SetTokenHashCompare(func(plaintext, encoded string) (bool, error) {
		return Verify(plaintext, encoded)
	})
}
