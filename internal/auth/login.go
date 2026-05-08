package auth

import (
	"context"
	"errors"

	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

// dummyHash is run when the lookup-by-email returns ErrNotFound, so the
// per-request Argon2 cost is paid regardless of whether a row exists. This
// neutralizes the obvious timing oracle for email enumeration.
const dummyHash = "$argon2id$v=19$m=65536,t=1,p=4$aaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// Authenticate looks up the user by email and constant-time verifies the
// supplied password. ErrBadCredentials is returned for both unknown-email
// and wrong-password to defeat email enumeration via response timing or
// status. ErrDeactivated is returned when the credentials are correct but
// the account is deactivated.
func (m *Manager) Authenticate(ctx context.Context, email string, password secret.String) (store.User, error) {
	u, err := m.Users.GetByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		// Run a dummy verify so timing doesn't leak email existence.
		_, _ = users.VerifyPassword(password, dummyHash)
		return store.User{}, ErrBadCredentials
	}
	if err != nil {
		return store.User{}, err
	}
	ok, err := users.VerifyPassword(password, u.PasswordHash)
	if err != nil {
		return store.User{}, err
	}
	if !ok {
		return store.User{}, ErrBadCredentials
	}
	if u.DeactivatedAt != nil {
		return store.User{}, ErrDeactivated
	}
	return u, nil
}
