package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
)

// isUniqueEmailViolation reports whether err is the modernc.org/sqlite
// constraint-violation that fires when an INSERT into users races the
// idx_users_email_nocase unique index. The typed-error path matches
// SQLITE_CONSTRAINT_UNIQUE specifically — a primary-key collision on
// users.id surfaces as SQLITE_CONSTRAINT_PRIMARYKEY and is intentionally
// NOT classified as "email in use" (a UUID collision is an internal-
// state surprise, not a user-facing 409). The message-substring fallback
// at the bottom protects against driver upgrades that wrap the typed
// error or change its code; it still gates on "users.email" /
// idx_users_email_nocase so unrelated UNIQUE failures (e.g. a future
// constraint on another table) are not misclassified.
func isUniqueEmailViolation(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
		msg := strings.ToLower(se.Error())
		if strings.Contains(msg, "users.email") || strings.Contains(msg, "idx_users_email_nocase") {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "users.email") || strings.Contains(msg, "idx_users_email_nocase")
}

func inviteFromGen(r sqlcgen.Invite) (Invite, error) {
	inv := Invite{
		Code:             r.Code,
		Role:             Role(r.Role),
		CreatedByUserID:  ptrFromNullString(r.CreatedByUserID),
		Bootstrap:        r.Bootstrap != 0,
		CreatedAt:        time.Unix(0, r.CreatedAt).UTC(),
		ExpiresAt:        timePtrFromNullInt64(r.ExpiresAt),
		ConsumedAt:       timePtrFromNullInt64(r.ConsumedAt),
		ConsumedByUserID: ptrFromNullString(r.ConsumedByUserID),
	}
	if err := json.Unmarshal([]byte(r.DefaultScopes), &inv.DefaultScopes); err != nil {
		return Invite{}, err
	}
	if inv.DefaultScopes == nil {
		inv.DefaultScopes = []string{}
	}
	return inv, nil
}

func inviteToInsertParams(inv Invite) (sqlcgen.InsertInviteParams, error) {
	scopes, err := json.Marshal(scopesOrEmpty(inv.DefaultScopes))
	if err != nil {
		return sqlcgen.InsertInviteParams{}, err
	}
	bootstrap := int64(0)
	if inv.Bootstrap {
		bootstrap = 1
	}
	return sqlcgen.InsertInviteParams{
		Code:             inv.Code,
		Role:             string(inv.Role),
		DefaultScopes:    string(scopes),
		CreatedByUserID:  nullStringPtr(inv.CreatedByUserID),
		Bootstrap:        bootstrap,
		CreatedAt:        inv.CreatedAt.UTC().UnixNano(),
		ExpiresAt:        nullInt64FromTime(inv.ExpiresAt),
		ConsumedAt:       nullInt64FromTime(inv.ConsumedAt),
		ConsumedByUserID: nullStringPtr(inv.ConsumedByUserID),
	}, nil
}

func (s *SQLite) InsertInvite(ctx context.Context, inv Invite) error {
	if inv.Code == "" {
		return errors.New("InsertInvite: empty code")
	}
	if inv.CreatedAt.IsZero() {
		inv.CreatedAt = time.Now().UTC()
	}
	params, err := inviteToInsertParams(inv)
	if err != nil {
		return err
	}
	return s.q.InsertInvite(ctx, params)
}

func (s *SQLite) GetInviteByCode(ctx context.Context, code string) (Invite, error) {
	row, err := s.q.GetInviteByCode(ctx, code)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	if err != nil {
		return Invite{}, err
	}
	return inviteFromGen(row)
}

func (s *SQLite) MarkInviteConsumed(ctx context.Context, code, byUser string, at time.Time) error {
	n, err := s.q.MarkInviteConsumed(ctx, sqlcgen.MarkInviteConsumedParams{
		ConsumedAt:       nullInt64FromUnix(at),
		ConsumedByUserID: sql.NullString{String: byUser, Valid: true},
		Code:             code,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) MarkBootstrapInvitesConsumed(ctx context.Context, byUser string, at time.Time) (int64, error) {
	return s.q.MarkBootstrapInvitesConsumed(ctx, sqlcgen.MarkBootstrapInvitesConsumedParams{
		ConsumedAt:       nullInt64FromUnix(at),
		ConsumedByUserID: sql.NullString{String: byUser, Valid: true},
	})
}

func (s *SQLite) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := s.q.ListInvites(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rows))
	for _, r := range rows {
		inv, err := inviteFromGen(r)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, nil
}

func (s *SQLite) ListInvitesByConsumed(ctx context.Context, consumed bool) ([]Invite, error) {
	flag := int64(0)
	if consumed {
		flag = 1
	}
	rows, err := s.q.ListInvitesByConsumed(ctx, flag)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rows))
	for _, r := range rows {
		inv, err := inviteFromGen(r)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, nil
}

func (s *SQLite) DeleteInvite(ctx context.Context, code string) error {
	n, err := s.q.DeleteInvite(ctx, code)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnsureBootstrapInvite is the idempotent insert described in design.md:
// inside a tx, look up the existing bootstrap invite. If none exists OR the
// existing one has expired, replace it with a fresh code generated by
// codeFn() and a fresh now+ttl expiry. If a fresh, unconsumed bootstrap
// invite already exists, return it unchanged.
func (s *SQLite) EnsureBootstrapInvite(ctx context.Context, codeFn func() string, ttl time.Duration, now time.Time) (Invite, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	row, err := q.GetBootstrapInvite(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// fall through — no bootstrap row, create one.
	case err != nil:
		return Invite{}, err
	default:
		inv, err := inviteFromGen(row)
		if err != nil {
			return Invite{}, err
		}
		// Active bootstrap row that hasn't expired and isn't consumed?
		if inv.ConsumedAt == nil && (inv.ExpiresAt == nil || inv.ExpiresAt.After(now)) {
			if err := tx.Commit(); err != nil {
				return Invite{}, err
			}
			return inv, nil
		}
		// Expired or consumed bootstrap row — replace it.
		if err := q.DeleteBootstrapInvite(ctx); err != nil {
			return Invite{}, err
		}
	}

	exp := now.Add(ttl)
	fresh := Invite{
		Code:          codeFn(),
		Role:          RoleAdmin,
		DefaultScopes: []string{},
		Bootstrap:     true,
		CreatedAt:     now,
		ExpiresAt:     &exp,
	}
	params, err := inviteToInsertParams(fresh)
	if err != nil {
		return Invite{}, err
	}
	if err := q.InsertInvite(ctx, params); err != nil {
		return Invite{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invite{}, err
	}
	return fresh, nil
}

// SignupTx is the atomic invite-consume + user-insert flow described in
// design.md. In a single transaction it: inserts the user (returning
// ErrEmailInUse on a unique-email collision), marks the invite consumed
// (returning ErrInviteConsumed if already consumed), and sweeps any
// bootstrap invite the same user retires implicitly. Any failure rolls
// the entire tx back, so a duplicate email or stale invite leaves no
// half-applied state.
func (s *SQLite) SignupTx(ctx context.Context, code string, u User, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	// Insert the user first so the FK references from invites.consumed_by_user_id
	// resolve at statement time. Concurrent signups against the same code race
	// on email-uniqueness AND consumed_at-IS-NULL; whichever tx commits first
	// wins, the rest see ErrInviteConsumed (or a unique-violation on email).
	scopes, err := json.Marshal(scopesOrEmpty(u.DefaultScopes))
	if err != nil {
		return err
	}
	role := string(u.Role)
	if role == "" {
		role = string(RoleUser)
	}
	if err := q.InsertUser(ctx, sqlcgen.InsertUserParams{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Role:          role,
		PasswordHash:  u.PasswordHash,
		DefaultScopes: string(scopes),
		CreatedAt:     u.CreatedAt.UTC().UnixNano(),
		DeactivatedAt: nullInt64FromTime(u.DeactivatedAt),
		ExternalID:    nullStringPtr(u.ExternalID),
	}); err != nil {
		if isUniqueEmailViolation(err) {
			return ErrEmailInUse
		}
		return err
	}

	n, err := q.MarkInviteConsumed(ctx, sqlcgen.MarkInviteConsumedParams{
		ConsumedAt:       nullInt64FromUnix(now),
		ConsumedByUserID: sql.NullString{String: u.ID, Valid: true},
		Code:             code,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteConsumed
	}

	// Always sweep bootstrap invites: a fresh signup retires the bootstrap
	// row (if any) regardless of which invite was used.
	if _, err := q.MarkBootstrapInvitesConsumed(ctx, sqlcgen.MarkBootstrapInvitesConsumedParams{
		ConsumedAt:       nullInt64FromUnix(now),
		ConsumedByUserID: sql.NullString{String: u.ID, Valid: true},
	}); err != nil {
		return err
	}

	return tx.Commit()
}

// ErrInviteConsumed is returned when MarkInviteConsumed (or SignupTx) finds
// the invite already consumed.
var ErrInviteConsumed = errors.New("store: invite already consumed")
