package store

import (
	"context"
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

// Compile-time assertions.
var (
	_ EventStore             = (*SQLite)(nil)
	_ TokenStore             = tokenStoreAdapter{}
	_ PushSubscriptionStore  = pushStoreAdapter{}
)
