// Package store defines the storage interfaces (events, listener tokens, push
// subscriptions) and provides the default SQLite implementation.
//
// The interfaces are deliberately minimal so a Postgres-backed implementation
// can land later without rippling through the rest of the codebase.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrDuplicate is returned by EventStore.Append when an event with the same
// (source, delivery_id) already exists within the configured dedupe window.
// Callers MUST distinguish this from generic errors so the ingest handler can
// return HTTP 200 instead of 5xx.
var ErrDuplicate = errors.New("store: duplicate (source, delivery_id) within dedupe window")

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: not found")

// Event is one captured webhook delivery.
type Event struct {
	Source            string
	Sequence          int64
	DeliveryID        string
	ProviderTimestamp time.Time
	ReceivedAt        time.Time
	Headers           map[string]string
	Body              []byte
	BodySHA256        string
}

// AppendInput is the data the ingest handler hands to the store.
type AppendInput struct {
	Source            string
	DeliveryID        string
	ProviderTimestamp time.Time
	Headers           map[string]string
	Body              []byte
}

// EventStore is the per-source append-only event log.
type EventStore interface {
	// Append persists a verified event. The store assigns the next per-source
	// sequence number and returns the resulting Event with Sequence,
	// ReceivedAt, and BodySHA256 populated. ErrDuplicate is returned when
	// (source, delivery_id) already exists within the dedupe window.
	Append(ctx context.Context, in AppendInput) (Event, error)

	// ReadSince returns events for source where Sequence > cursor, in ascending
	// order, up to limit rows.
	ReadSince(ctx context.Context, source string, cursor int64, limit int) ([]Event, error)

	// Get returns the event identified by (source, sequence) or ErrNotFound.
	Get(ctx context.Context, source string, sequence int64) (Event, error)

	// LatestSequence returns the highest sequence written for source, or 0 if
	// no events exist.
	LatestSequence(ctx context.Context, source string) (int64, error)

	// Prune deletes events for source whose ReceivedAt is older than cutoff.
	// Returns the number of rows deleted.
	Prune(ctx context.Context, source string, cutoff time.Time) (int64, error)

	// PruneAll deletes events across every source whose ReceivedAt is older
	// than cutoff. Used by the manual `hooks prune` CLI subcommand.
	PruneAll(ctx context.Context, cutoff time.Time) (int64, error)

	// Sources returns the set of source identifiers known to the store
	// (i.e., that have at least one event).
	Sources(ctx context.Context) ([]string, error)

	// Ping confirms the store is reachable; used by /readyz.
	Ping(ctx context.Context) error

	// Close releases backing resources.
	Close() error
}

// ScopeAdmin is the special scope granting access to the inspector and
// management APIs.
const ScopeAdmin = "admin"

// Token is a listener bearer token's metadata (never the plaintext).
type Token struct {
	ID         string
	Name       string
	Scopes     []string
	SecretHash string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// HasScope reports whether scopes include name.
func HasScope(scopes []string, name string) bool {
	for _, s := range scopes {
		if s == name {
			return true
		}
	}
	return false
}

// TokenStore manages listener tokens.
type TokenStore interface {
	Insert(ctx context.Context, t Token) error
	LookupByPlaintext(ctx context.Context, plaintext string) (Token, error)
	TouchLastUsed(ctx context.Context, id string, when time.Time) error
	List(ctx context.Context, includeRevoked bool) ([]Token, error)
	Revoke(ctx context.Context, id string, when time.Time) error
}

// PushSubscription is the durable record of a push subscription.
// SigningSecretHash is what's stored at rest; the dispatcher holds the
// plaintext secret in memory after registration (and re-receives it on
// rotate-secret) for HMAC computation.
type PushSubscription struct {
	ID                  string
	Source              string
	TargetURL           string
	SigningSecretHash   string
	Name                string
	Cursor              int64
	PausedAt            *time.Time
	CreatedAt           time.Time
	LastAttemptAt       *time.Time
	LastSuccessAt       *time.Time
	LastError           string
	ConsecutiveFailures int
}

// PushSubscriptionStore manages push subscriptions and their cursors.
type PushSubscriptionStore interface {
	Insert(ctx context.Context, s PushSubscription) error
	List(ctx context.Context, includePaused bool) ([]PushSubscription, error)
	ListBySource(ctx context.Context, source string, includePaused bool) ([]PushSubscription, error)
	Get(ctx context.Context, id string) (PushSubscription, error)

	// UpdateCursorAndSuccess advances cursor, sets last_success_at to when,
	// resets consecutive_failures to 0, and clears last_error in one transaction.
	UpdateCursorAndSuccess(ctx context.Context, id string, cursor int64, when time.Time) error

	// RecordFailure increments consecutive_failures and records last_attempt_at +
	// last_error in one transaction. Cursor is unchanged.
	RecordFailure(ctx context.Context, id string, when time.Time, errMsg string) error

	Pause(ctx context.Context, id string, when time.Time) error
	Resume(ctx context.Context, id string) error
	RotateSecret(ctx context.Context, id, newHash string) error
	Delete(ctx context.Context, id string) error
}
