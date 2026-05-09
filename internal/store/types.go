// Package store defines the storage interfaces (events, listener tokens,
// push subscriptions, users, sessions, invites, device pairings, audit
// events) and provides the default SQLite implementation.
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

// ErrTokenKindRequired is returned by SQLite.Insert when a Token literal
// omits Kind. Empty Kind used to silently coerce to listener, which
// authorizes /subscribe/<source>; making the empty case loud forces
// callers to make the privilege choice explicit.
var ErrTokenKindRequired = errors.New("store: token kind required (use TokenKindPAT or TokenKindListener)")

// ErrEmailInUse is returned by SignupTx when the user-insert collides
// with the case-insensitive unique index on users.email. Callers
// translate this to HTTP 409.
var ErrEmailInUse = errors.New("store: email already in use")

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

// ScopeAccount is the implicit scope every active user holds; required for
// PATs to authorize /api/me/* endpoints.
const ScopeAccount = "account"

// TokenKind distinguishes a personal access token (PAT) from a listener
// token. PATs authorize /api/me/* and the inspector; listener tokens
// authorize /subscribe/<source>. Stored in the listener_tokens.kind column.
type TokenKind string

const (
	// TokenKindPAT is a personal access token.
	TokenKindPAT TokenKind = "pat"
	// TokenKindListener is a long-lived listener (subscribe) token.
	TokenKindListener TokenKind = "listener"
)

// Token is a listener bearer token's metadata (never the plaintext).
type Token struct {
	ID         string
	Name       string
	Scopes     []string
	SecretHash string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time

	// OwnerUserID is the owning user's id, or nil for a system-owned token
	// (typically those minted by `hooks init` before the first user account).
	OwnerUserID *string

	// Kind is "pat" or "listener". Empty string is treated as "listener" by
	// the wrapper layer so existing rows behave as before.
	Kind TokenKind

	// Ephemeral marks tokens auto-issued by `hooksctl forward` (etc.) that
	// the prune loop revokes after 24h of inactivity.
	Ephemeral bool

	// ExpiresAt is the absolute expiry of the token (nullable, max 1 year).
	ExpiresAt *time.Time
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
	ListByOwner(ctx context.Context, ownerUserID string, includeRevoked bool) ([]Token, error)
	ListSystem(ctx context.Context, includeRevoked bool) ([]Token, error)
	Get(ctx context.Context, id string) (Token, error)
	Revoke(ctx context.Context, id string, when time.Time) error
	UpdateOwner(ctx context.Context, id string, ownerUserID *string) error
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

	// OwnerUserID is the owning user's id, or nil for a system-owned
	// subscription.
	OwnerUserID *string
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

	// ListByOwner returns subscriptions owned by ownerUserID. Use ListSystem
	// for owner-NULL rows.
	ListByOwner(ctx context.Context, ownerUserID string, includePaused bool) ([]PushSubscription, error)
	// ListSystem returns subscriptions with owner_user_id IS NULL.
	ListSystem(ctx context.Context, includePaused bool) ([]PushSubscription, error)
	// UpdateOwner reassigns the owner; nil sets owner_user_id to NULL.
	UpdateOwner(ctx context.Context, id string, ownerUserID *string) error
}

// Role is a user's role in the system.
type Role string

const (
	// RoleAdmin grants implicit access to every source scope plus admin.
	RoleAdmin Role = "admin"
	// RoleUser grants only the user's default_scopes (plus implicit account).
	RoleUser Role = "user"
)

// User is an account holder.
type User struct {
	ID            string
	Email         string
	Name          string
	Role          Role
	PasswordHash  string
	DefaultScopes []string
	CreatedAt     time.Time
	DeactivatedAt *time.Time
	ExternalID    *string
}

// Session is a server-stored web session backing the hooks_session cookie.
// SecretHash is sha256(plaintext); the cookie carries id.plaintext.
type Session struct {
	ID         string
	UserID     string
	SecretHash string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	UserAgent  string
	IP         string
}

// Invite is a single-use signup gate.
type Invite struct {
	Code              string
	Role              Role
	DefaultScopes     []string
	CreatedByUserID   *string
	Bootstrap         bool
	CreatedAt         time.Time
	ExpiresAt         *time.Time
	ConsumedAt        *time.Time
	ConsumedByUserID  *string
}

// DevicePairingStatus is the lifecycle state of a device-pairing row.
type DevicePairingStatus string

const (
	DevicePairingStatusPending           DevicePairingStatus = "pending"
	DevicePairingStatusApprovedUnfetched DevicePairingStatus = "approved_unfetched"
	DevicePairingStatusDone              DevicePairingStatus = "done"
	DevicePairingStatusDenied            DevicePairingStatus = "denied"
	DevicePairingStatusExpired           DevicePairingStatus = "expired"
)

// DevicePairing is the row backing the CLI device-pairing flow.
type DevicePairing struct {
	DeviceCode          string
	UserCode            string
	Status              DevicePairingStatus
	CreatedAt           time.Time
	ExpiresAt           time.Time
	UserID              *string
	RequestingIP        string
	RequestingUserAgent string
	RequestedScopes     []string
	PlaintextToken      *string
	TokenID             *string
}

// AuditEvent is one row in the audit log.
type AuditEvent struct {
	ID           string
	At           time.Time
	ActorUserID  *string
	ActorTokenID *string
	Action       string
	TargetType   string
	TargetID     string
	Metadata     map[string]any
}

// UserStore manages user accounts.
type UserStore interface {
	Insert(ctx context.Context, u User) error
	GetByID(ctx context.Context, id string) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	List(ctx context.Context) ([]User, error)
	ListByRole(ctx context.Context, role Role) ([]User, error)
	UpdateProfile(ctx context.Context, id, name string, defaultScopes []string) error
	Deactivate(ctx context.Context, id string, when time.Time) error
	Reactivate(ctx context.Context, id string) error
	SetPasswordHash(ctx context.Context, id, hash string) error
	CountActiveAdmins(ctx context.Context) (int64, error)
	CountActiveAdminsExcluding(ctx context.Context, id string) (int64, error)
}

// SessionStore manages user_sessions rows.
type SessionStore interface {
	Insert(ctx context.Context, s Session) error
	LookupByID(ctx context.Context, id string) (Session, error)
	Touch(ctx context.Context, id string, lastUsedAt, expiresAt time.Time) error
	Delete(ctx context.Context, id string) error
	DeleteByUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// InviteStore manages invites.
type InviteStore interface {
	Insert(ctx context.Context, inv Invite) error
	GetByCode(ctx context.Context, code string) (Invite, error)
	MarkConsumed(ctx context.Context, code, byUser string, at time.Time) error
	MarkBootstrapsConsumed(ctx context.Context, byUser string, at time.Time) (int64, error)
	List(ctx context.Context) ([]Invite, error)
	ListByConsumed(ctx context.Context, consumed bool) ([]Invite, error)
	Delete(ctx context.Context, code string) error
	EnsureBootstrap(ctx context.Context, codeFn func() string, ttl time.Duration, now time.Time) (Invite, error)
}

// DevicePairingStore manages CLI device-pairing rows.
type DevicePairingStore interface {
	Insert(ctx context.Context, p DevicePairing) error
	GetByDeviceCode(ctx context.Context, deviceCode string) (DevicePairing, error)
	GetByUserCode(ctx context.Context, userCode string) (DevicePairing, error)
	Approve(ctx context.Context, userCode, userID, plaintextToken, tokenID string) error
	Deny(ctx context.Context, userCode, userID string) error
	MarkFetched(ctx context.Context, deviceCode string) error
	ExpirePending(ctx context.Context, before time.Time) (int64, error)
	DeleteOld(ctx context.Context, before time.Time) (int64, error)
}

// AuditStore writes to and reads from the immutable audit_events table.
type AuditStore interface {
	Insert(ctx context.Context, e AuditEvent) error
	List(ctx context.Context, q AuditQuery) ([]AuditEvent, error)
}

// AuditQuery filters a List call.
type AuditQuery struct {
	ActorUserID *string
	Since       *time.Time
	Until       *time.Time
	Limit       int
}
