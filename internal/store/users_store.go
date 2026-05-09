package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
)

func userFromGen(r sqlcgen.User) (User, error) {
	u := User{
		ID:            r.ID,
		Email:         r.Email,
		Name:          r.Name,
		Role:          Role(r.Role),
		PasswordHash:  r.PasswordHash,
		CreatedAt:     time.Unix(0, r.CreatedAt).UTC(),
		DeactivatedAt: timePtrFromNullInt64(r.DeactivatedAt),
		ExternalID:    ptrFromNullString(r.ExternalID),
	}
	if err := json.Unmarshal([]byte(r.DefaultScopes), &u.DefaultScopes); err != nil {
		return User{}, err
	}
	if u.DefaultScopes == nil {
		u.DefaultScopes = []string{}
	}
	return u, nil
}

// InsertUser persists a new user. The caller is responsible for setting
// CreatedAt; if zero, the wrapper stamps it to now().
func (s *SQLite) InsertUser(ctx context.Context, u User) error {
	if u.ID == "" {
		return errors.New("InsertUser: empty id")
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	scopes, err := json.Marshal(scopesOrEmpty(u.DefaultScopes))
	if err != nil {
		return err
	}
	role := string(u.Role)
	if role == "" {
		role = string(RoleUser)
	}
	return s.q.InsertUser(ctx, sqlcgen.InsertUserParams{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Role:          role,
		PasswordHash:  u.PasswordHash,
		DefaultScopes: string(scopes),
		CreatedAt:     u.CreatedAt.UTC().UnixNano(),
		DeactivatedAt: nullInt64FromTime(u.DeactivatedAt),
		ExternalID:    nullStringPtr(u.ExternalID),
	})
}

func (s *SQLite) GetUserByID(ctx context.Context, id string) (User, error) {
	row, err := s.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFromGen(row)
}

func (s *SQLite) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row, err := s.q.GetUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFromGen(row)
}

func (s *SQLite) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		u, err := userFromGen(r)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func (s *SQLite) ListUsersByRole(ctx context.Context, role Role) ([]User, error) {
	rows, err := s.q.ListUsersByRole(ctx, string(role))
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		u, err := userFromGen(r)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func (s *SQLite) UpdateUserProfile(ctx context.Context, id, name string, defaultScopes []string) error {
	scopes, err := json.Marshal(scopesOrEmpty(defaultScopes))
	if err != nil {
		return err
	}
	n, err := s.q.UpdateUserProfile(ctx, sqlcgen.UpdateUserProfileParams{
		Name:          name,
		DefaultScopes: string(scopes),
		ID:            id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeactivateUser(ctx context.Context, id string, when time.Time) error {
	n, err := s.q.DeactivateUser(ctx, sqlcgen.DeactivateUserParams{
		DeactivatedAt: nullInt64FromUnix(when),
		ID:            id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) ReactivateUser(ctx context.Context, id string) error {
	n, err := s.q.ReactivateUser(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) SetUserPasswordHash(ctx context.Context, id, hash string) error {
	n, err := s.q.SetUserPasswordHash(ctx, sqlcgen.SetUserPasswordHashParams{
		PasswordHash: hash,
		ID:           id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUsers returns the number of rows in the users table. Used by
// `hooks init` to gate the bootstrap-invite emission without materializing
// the full ListUsers result.
func (s *SQLite) CountUsers(ctx context.Context) (int64, error) {
	return s.q.CountUsers(ctx)
}

func (s *SQLite) CountActiveAdmins(ctx context.Context) (int64, error) {
	return s.q.CountActiveAdmins(ctx)
}

func (s *SQLite) CountActiveAdminsExcluding(ctx context.Context, id string) (int64, error) {
	return s.q.CountActiveAdminsExcluding(ctx, id)
}

// DeactivateUserCascade runs the cascading-revoke transaction described in
// design.md: set deactivated_at on the user, revoke every owned token (any
// kind, including ephemeral), and pause every owned subscription. The
// last-admin guard is enforced inside the tx by a re-check after the
// caller-supplied pre-check, protecting against races where two admins
// deactivate each other concurrently.
//
// Returns ErrLastAdmin if the operation would leave zero active admins.
func (s *SQLite) DeactivateUserCascade(ctx context.Context, id string, when time.Time) (CascadeRevokeResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CascadeRevokeResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	// Look up the user inside the tx so we know their role.
	u, err := q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return CascadeRevokeResult{}, ErrNotFound
	}
	if err != nil {
		return CascadeRevokeResult{}, err
	}
	if u.DeactivatedAt.Valid {
		return CascadeRevokeResult{}, ErrAlreadyDeactivated
	}
	if u.Role == string(RoleAdmin) {
		n, err := q.CountActiveAdminsExcluding(ctx, id)
		if err != nil {
			return CascadeRevokeResult{}, err
		}
		if n == 0 {
			return CascadeRevokeResult{}, ErrLastAdmin
		}
	}

	if _, err := q.DeactivateUser(ctx, sqlcgen.DeactivateUserParams{
		DeactivatedAt: nullInt64FromUnix(when),
		ID:            id,
	}); err != nil {
		return CascadeRevokeResult{}, err
	}
	tokRevoked, err := q.RevokeTokensByOwner(ctx, sqlcgen.RevokeTokensByOwnerParams{
		RevokedAt:   nullInt64FromUnix(when),
		OwnerUserID: sql.NullString{String: id, Valid: true},
	})
	if err != nil {
		return CascadeRevokeResult{}, err
	}
	subPaused, err := q.PausePushSubscriptionsByOwner(ctx, sqlcgen.PausePushSubscriptionsByOwnerParams{
		PausedAt:    nullInt64FromUnix(when),
		OwnerUserID: sql.NullString{String: id, Valid: true},
	})
	if err != nil {
		return CascadeRevokeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CascadeRevokeResult{}, err
	}
	return CascadeRevokeResult{
		TokensRevoked:       tokRevoked,
		SubscriptionsPaused: subPaused,
	}, nil
}

// CascadeRevokeResult reports the impact of DeactivateUserCascade.
type CascadeRevokeResult struct {
	TokensRevoked       int64
	SubscriptionsPaused int64
}

// ErrLastAdmin is returned when an operation would leave zero active admins.
var ErrLastAdmin = errors.New("store: would leave zero active admins")

// ErrAlreadyDeactivated is returned when a user is already deactivated.
var ErrAlreadyDeactivated = errors.New("store: user already deactivated")

func scopesOrEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
