package store

import (
	"context"
	"errors"
	"time"
)

// Tokens returns a TokenStore view of s.
func (s *SQLite) Tokens() TokenStore { return tokenStoreAdapter{s} }

// PushSubscriptions returns a PushSubscriptionStore view of s.
func (s *SQLite) PushSubscriptions() PushSubscriptionStore { return pushStoreAdapter{s} }

// Events returns an EventStore view of s. (s already implements EventStore;
// this exists for symmetry.)
func (s *SQLite) Events() EventStore { return s }

type tokenStoreAdapter struct{ s *SQLite }

func (a tokenStoreAdapter) Insert(ctx context.Context, t Token) error {
	return a.s.Insert(ctx, t)
}
func (a tokenStoreAdapter) LookupByPlaintext(ctx context.Context, plaintext string) (Token, error) {
	return a.s.LookupByPlaintext(ctx, plaintext)
}
func (a tokenStoreAdapter) TouchLastUsed(ctx context.Context, id string, when time.Time) error {
	return a.s.TouchLastUsed(ctx, id, when)
}
func (a tokenStoreAdapter) List(ctx context.Context, includeRevoked bool) ([]Token, error) {
	return a.s.List(ctx, includeRevoked)
}
func (a tokenStoreAdapter) Revoke(ctx context.Context, id string, when time.Time) error {
	return a.s.Revoke(ctx, id, when)
}
func (a tokenStoreAdapter) ListByOwner(ctx context.Context, ownerUserID string, includeRevoked bool) ([]Token, error) {
	return a.s.ListTokensByOwner(ctx, ownerUserID, includeRevoked)
}
func (a tokenStoreAdapter) ListSystem(ctx context.Context, includeRevoked bool) ([]Token, error) {
	return a.s.ListSystemTokens(ctx, includeRevoked)
}
func (a tokenStoreAdapter) Get(ctx context.Context, id string) (Token, error) {
	return a.s.GetToken(ctx, id)
}
func (a tokenStoreAdapter) UpdateOwner(ctx context.Context, id string, ownerUserID *string) error {
	return a.s.UpdateTokenOwner(ctx, id, ownerUserID)
}

type pushStoreAdapter struct{ s *SQLite }

func (a pushStoreAdapter) Insert(ctx context.Context, sub PushSubscription) error {
	return a.s.InsertPush(ctx, sub)
}
func (a pushStoreAdapter) List(ctx context.Context, includePaused bool) ([]PushSubscription, error) {
	return a.s.ListPush(ctx, includePaused)
}
func (a pushStoreAdapter) ListBySource(ctx context.Context, source string, includePaused bool) ([]PushSubscription, error) {
	return a.s.ListPushBySource(ctx, source, includePaused)
}
func (a pushStoreAdapter) Get(ctx context.Context, id string) (PushSubscription, error) {
	return a.s.GetPush(ctx, id)
}
func (a pushStoreAdapter) UpdateCursorAndSuccess(ctx context.Context, id string, cursor int64, when time.Time) error {
	return a.s.UpdateCursorAndSuccess(ctx, id, cursor, when)
}
func (a pushStoreAdapter) RecordFailure(ctx context.Context, id string, when time.Time, errMsg string) error {
	return a.s.RecordFailure(ctx, id, when, errMsg)
}
func (a pushStoreAdapter) Pause(ctx context.Context, id string, when time.Time) error {
	return a.s.PausePush(ctx, id, when)
}
func (a pushStoreAdapter) Resume(ctx context.Context, id string) error {
	return a.s.ResumePush(ctx, id)
}
func (a pushStoreAdapter) RotateSecret(ctx context.Context, id, newHash string) error {
	return a.s.RotatePushSecret(ctx, id, newHash)
}
func (a pushStoreAdapter) Delete(ctx context.Context, id string) error {
	return a.s.DeletePush(ctx, id)
}
func (a pushStoreAdapter) ListByOwner(ctx context.Context, ownerUserID string, includePaused bool) ([]PushSubscription, error) {
	return a.s.ListPushByOwner(ctx, ownerUserID, includePaused)
}
func (a pushStoreAdapter) ListSystem(ctx context.Context, includePaused bool) ([]PushSubscription, error) {
	return a.s.ListSystemPush(ctx, includePaused)
}
func (a pushStoreAdapter) UpdateOwner(ctx context.Context, id string, ownerUserID *string) error {
	return a.s.UpdatePushOwner(ctx, id, ownerUserID)
}

// Users returns a UserStore view of s.
func (s *SQLite) Users() UserStore { return userStoreAdapter{s} }

// Sessions returns a SessionStore view of s.
func (s *SQLite) Sessions() SessionStore { return sessionStoreAdapter{s} }

// Invites returns an InviteStore view of s.
func (s *SQLite) Invites() InviteStore { return inviteStoreAdapter{s} }

// DevicePairings returns a DevicePairingStore view of s.
func (s *SQLite) DevicePairings() DevicePairingStore { return devicePairingStoreAdapter{s} }

// Audit returns an AuditStore view of s.
func (s *SQLite) Audit() AuditStore { return auditStoreAdapter{s} }

type userStoreAdapter struct{ s *SQLite }

func (a userStoreAdapter) Insert(ctx context.Context, u User) error { return a.s.InsertUser(ctx, u) }
func (a userStoreAdapter) GetByID(ctx context.Context, id string) (User, error) {
	return a.s.GetUserByID(ctx, id)
}
func (a userStoreAdapter) GetByEmail(ctx context.Context, email string) (User, error) {
	return a.s.GetUserByEmail(ctx, email)
}
func (a userStoreAdapter) List(ctx context.Context) ([]User, error) { return a.s.ListUsers(ctx) }
func (a userStoreAdapter) ListByRole(ctx context.Context, role Role) ([]User, error) {
	return a.s.ListUsersByRole(ctx, role)
}
func (a userStoreAdapter) UpdateProfile(ctx context.Context, id, name string, defaultScopes []string) error {
	return a.s.UpdateUserProfile(ctx, id, name, defaultScopes)
}
func (a userStoreAdapter) Deactivate(ctx context.Context, id string, when time.Time) error {
	return a.s.DeactivateUser(ctx, id, when)
}
func (a userStoreAdapter) Reactivate(ctx context.Context, id string) error {
	return a.s.ReactivateUser(ctx, id)
}
func (a userStoreAdapter) SetPasswordHash(ctx context.Context, id, hash string) error {
	return a.s.SetUserPasswordHash(ctx, id, hash)
}
func (a userStoreAdapter) CountActiveAdmins(ctx context.Context) (int64, error) {
	return a.s.CountActiveAdmins(ctx)
}
func (a userStoreAdapter) CountActiveAdminsExcluding(ctx context.Context, id string) (int64, error) {
	return a.s.CountActiveAdminsExcluding(ctx, id)
}

type sessionStoreAdapter struct{ s *SQLite }

func (a sessionStoreAdapter) Insert(ctx context.Context, sess Session) error {
	return a.s.InsertSession(ctx, sess)
}
func (a sessionStoreAdapter) LookupByID(ctx context.Context, id string) (Session, error) {
	return a.s.GetSession(ctx, id)
}
func (a sessionStoreAdapter) Touch(ctx context.Context, id string, lastUsedAt, expiresAt time.Time) error {
	return a.s.TouchSession(ctx, id, lastUsedAt, expiresAt)
}
func (a sessionStoreAdapter) Delete(ctx context.Context, id string) error {
	return a.s.DeleteSession(ctx, id)
}
func (a sessionStoreAdapter) DeleteByUser(ctx context.Context, userID string) error {
	return a.s.DeleteSessionsByUser(ctx, userID)
}
func (a sessionStoreAdapter) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	return a.s.DeleteExpiredSessions(ctx, before)
}

type inviteStoreAdapter struct{ s *SQLite }

func (a inviteStoreAdapter) Insert(ctx context.Context, inv Invite) error {
	return a.s.InsertInvite(ctx, inv)
}
func (a inviteStoreAdapter) GetByCode(ctx context.Context, code string) (Invite, error) {
	return a.s.GetInviteByCode(ctx, code)
}
func (a inviteStoreAdapter) MarkConsumed(ctx context.Context, code, byUser string, at time.Time) error {
	return a.s.MarkInviteConsumed(ctx, code, byUser, at)
}
func (a inviteStoreAdapter) MarkBootstrapsConsumed(ctx context.Context, byUser string, at time.Time) (int64, error) {
	return a.s.MarkBootstrapInvitesConsumed(ctx, byUser, at)
}
func (a inviteStoreAdapter) List(ctx context.Context) ([]Invite, error) {
	return a.s.ListInvites(ctx)
}
func (a inviteStoreAdapter) ListByConsumed(ctx context.Context, consumed bool) ([]Invite, error) {
	return a.s.ListInvitesByConsumed(ctx, consumed)
}
func (a inviteStoreAdapter) Delete(ctx context.Context, code string) error {
	return a.s.DeleteInvite(ctx, code)
}
func (a inviteStoreAdapter) EnsureBootstrap(ctx context.Context, codeFn func() string, ttl time.Duration, now time.Time) (Invite, error) {
	return a.s.EnsureBootstrapInvite(ctx, codeFn, ttl, now)
}

type devicePairingStoreAdapter struct{ s *SQLite }

func (a devicePairingStoreAdapter) Insert(ctx context.Context, dp DevicePairing) error {
	return a.s.InsertDevicePairing(ctx, dp)
}
func (a devicePairingStoreAdapter) GetByDeviceCode(ctx context.Context, deviceCode string) (DevicePairing, error) {
	return a.s.GetDevicePairingByDeviceCode(ctx, deviceCode)
}
func (a devicePairingStoreAdapter) GetByUserCode(ctx context.Context, userCode string) (DevicePairing, error) {
	return a.s.GetDevicePairingByUserCode(ctx, userCode)
}
func (a devicePairingStoreAdapter) Approve(ctx context.Context, userCode, userID, plaintextToken, tokenID string) error {
	// This stub adapter cannot mint a Token row from arbitrary token id only —
	// callers needing the full transactional approve path should use
	// SQLite.ApproveDevicePairing directly. Kept here so the interface is
	// satisfied; it is a no-op pre-condition error.
	return errors.New("DevicePairingStore.Approve: use SQLite.ApproveDevicePairing for transactional approval")
}
func (a devicePairingStoreAdapter) Deny(ctx context.Context, userCode, userID string) error {
	return a.s.DenyDevicePairing(ctx, userCode, userID)
}
func (a devicePairingStoreAdapter) MarkFetched(ctx context.Context, deviceCode string) error {
	return a.s.MarkDevicePairingFetched(ctx, deviceCode)
}
func (a devicePairingStoreAdapter) ExpirePending(ctx context.Context, before time.Time) (int64, error) {
	return a.s.ExpirePendingDevicePairings(ctx, before)
}
func (a devicePairingStoreAdapter) DeleteOld(ctx context.Context, before time.Time) (int64, error) {
	return a.s.DeleteOldDevicePairings(ctx, before)
}

type auditStoreAdapter struct{ s *SQLite }

func (a auditStoreAdapter) Insert(ctx context.Context, e AuditEvent) error {
	return a.s.InsertAuditEvent(ctx, e)
}
func (a auditStoreAdapter) List(ctx context.Context, q AuditQuery) ([]AuditEvent, error) {
	return a.s.ListAuditEvents(ctx, q)
}

// Compile-time assertions.
var (
	_ EventStore            = (*SQLite)(nil)
	_ TokenStore            = tokenStoreAdapter{}
	_ PushSubscriptionStore = pushStoreAdapter{}
	_ UserStore             = userStoreAdapter{}
	_ SessionStore          = sessionStoreAdapter{}
	_ InviteStore           = inviteStoreAdapter{}
	_ DevicePairingStore    = devicePairingStoreAdapter{}
	_ AuditStore            = auditStoreAdapter{}
)
