package invites

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

// Provision is the transport-agnostic invite-consume + user-insert flow.
// Both the JSON /api/auth/signup handler and the server-rendered /signup
// page call into this so the policy (password validation, atomic
// SignupTx, audit recording) lives in one place.
//
// All inputs are assumed to be already trimmed/normalized by the caller
// (NormalizeCode for code; strings.TrimSpace for email/name); empty-input
// rejection is the caller's job. Returns one of:
//
//   - ErrSignupInviteNotFound, ErrSignupInviteConsumed, ErrSignupInviteExpired
//   - ErrSignupBadPassword, ErrSignupEmailInUse
//   - any other error from the store (caller should treat as 500)
func Provision(
	ctx context.Context,
	invStore store.InviteStore,
	uStore store.UserStore,
	rec audit.Recorder,
	code, email, name string,
	password secret.String,
	now time.Time,
) (store.User, error) {
	inv, err := invStore.GetByCode(ctx, code)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, ErrSignupInviteNotFound
	}
	if err != nil {
		return store.User{}, err
	}
	if inv.ConsumedAt != nil {
		return store.User{}, ErrSignupInviteConsumed
	}
	if inv.ExpiresAt != nil && inv.ExpiresAt.Before(now) {
		return store.User{}, ErrSignupInviteExpired
	}
	if err := users.ValidatePassword(email, password); err != nil {
		return store.User{}, ErrSignupBadPassword
	}
	hash, err := users.HashPassword(password)
	if err != nil {
		return store.User{}, err
	}
	u := store.User{
		ID:            uuid.NewString(),
		Email:         email,
		Name:          name,
		Role:          inv.Role,
		PasswordHash:  hash,
		DefaultScopes: append([]string{}, inv.DefaultScopes...),
		CreatedAt:     now,
	}
	type signupTxer interface {
		SignupTx(ctx context.Context, code string, u store.User, now time.Time) error
	}
	if tx, ok := invStore.(signupTxer); ok {
		if err := tx.SignupTx(ctx, code, u, now); err != nil {
			if errors.Is(err, store.ErrInviteConsumed) {
				return store.User{}, ErrSignupInviteConsumed
			}
			if errors.Is(err, store.ErrEmailInUse) {
				return store.User{}, ErrSignupEmailInUse
			}
			return store.User{}, err
		}
	} else {
		// Fallback: best-effort sequence. Not safe under concurrent signup
		// races, but used only by tests with a mock store that doesn't
		// implement SignupTx.
		if err := uStore.Insert(ctx, u); err != nil {
			return store.User{}, err
		}
		if err := invStore.MarkConsumed(ctx, code, u.ID, now); err != nil {
			return store.User{}, err
		}
		_, _ = invStore.MarkBootstrapsConsumed(ctx, u.ID, now)
	}
	if rec != nil {
		id := u.ID
		rec.Record(ctx, store.AuditEvent{
			ActorUserID: &id,
			Action:      audit.ActionUserCreate,
			TargetType:  audit.TargetTypeUser,
			TargetID:    u.ID,
			Metadata:    map[string]any{"email": u.Email, "role": string(u.Role)},
		})
		rec.Record(ctx, store.AuditEvent{
			ActorUserID: &id,
			Action:      audit.ActionInviteConsume,
			TargetType:  audit.TargetTypeInvite,
			TargetID:    code,
		})
	}
	return u, nil
}

// Provision error vocabulary. Callers compare with errors.Is to map onto
// transport-specific responses (JSON status codes vs HTML error strings).
var (
	ErrSignupInviteNotFound = errors.New("invites: invite not found")
	ErrSignupInviteConsumed = errors.New("invites: invite already consumed")
	ErrSignupInviteExpired  = errors.New("invites: invite expired")
	ErrSignupBadPassword    = errors.New("invites: password does not meet policy")
	ErrSignupEmailInUse     = errors.New("invites: email already in use")
)
