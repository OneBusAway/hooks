## ADDED Requirements

### Requirement: Append-only event log

The event store SHALL be append-only for events. Once an event is persisted, its body, headers, and event metadata SHALL NOT be mutable through any public API. The event store SHALL expose only append, read-by-cursor, read-by-id, and prune operations on events.

#### Scenario: Stored events cannot be modified
- **WHEN** an event has been written
- **THEN** no public method exists to alter its body, headers, or `delivery_id`

### Requirement: Per-source monotonic sequence

Every event SHALL be assigned a strictly monotonic, gapless 64-bit sequence number scoped to its source. Sequence numbers SHALL begin at 1 for each source's first event and increment by exactly 1.

#### Scenario: Sequences are gapless within a source
- **WHEN** three events are persisted to source `render`
- **THEN** their sequence numbers are 1, 2, 3 in the order they were accepted

#### Scenario: Sequences are independent across sources
- **WHEN** the first event for source `render` and the first event for source `stripe` are persisted
- **THEN** both have sequence number 1

### Requirement: Durability before acknowledgement

The store's append operation SHALL not return success until the underlying storage has confirmed the write is durable through the operating system's `fsync` (or equivalent). Configuration knobs that weaken this guarantee SHALL be documented as unsafe.

#### Scenario: Power loss after a 200 response loses no events
- **WHEN** the process is killed by SIGKILL immediately after the store's append returns success
- **THEN** the event is present after restart

### Requirement: Cursor-based reads

The store SHALL support reading events for a given source where `sequence > cursor`, returning them in ascending sequence order. Reads SHALL accept a maximum batch size and return at most that many events.

#### Scenario: Reading from a cursor yields only newer events
- **WHEN** a caller requests events for source `render` with `since=5` and `limit=100`
- **THEN** the store returns events with sequence 6 through min(N, 105) in order

#### Scenario: Reading from `latest` yields nothing
- **WHEN** a caller requests events with `since` equal to the current highest sequence
- **THEN** the store returns an empty result without error

### Requirement: Deduplication index

The store SHALL maintain an index over `(source, delivery_id)` and SHALL refuse to insert a row whose `(source, delivery_id)` already exists within the configured dedupe window (default 24 hours). The refusal SHALL be distinguishable from other errors so the ingestion layer can return HTTP 200 instead of 5xx.

#### Scenario: Duplicate insert is reported as duplicate
- **WHEN** a second insert is attempted for an existing `(source, delivery_id)` within the window
- **THEN** the store returns a sentinel `ErrDuplicate` and the row count for that source is unchanged

### Requirement: Event metadata fields

Each stored event SHALL carry: `source` (string), `sequence` (int64), `delivery_id` (string), `provider_timestamp` (RFC3339), `received_at` (RFC3339), `headers` (string→string map), `body` (bytes), and `body_sha256` (hex string).

#### Scenario: Reading a stored event returns the full record
- **WHEN** a caller looks up an event by `(source, sequence)`
- **THEN** every metadata field above is present and populated

### Requirement: Storage backend interfaces

The store layer SHALL expose three Go interfaces — `EventStore`, `TokenStore`, and `PushSubscriptionStore` — so the SQLite implementation can be replaced (e.g. with Postgres) without changes to ingestion, subscription, push, or inspector code. Each interface SHALL be small enough to fit on one screen.

#### Scenario: Alternate backend implements the same interfaces
- **WHEN** an alternate backend implements all three interfaces
- **THEN** the ingestion, subscription, push, and inspector packages compile against it without modification

### Requirement: Default SQLite implementation

The default implementation SHALL use SQLite via `modernc.org/sqlite` (pure Go, no CGO) with WAL mode enabled and `synchronous=NORMAL`. The schema migration SHALL run automatically on startup and SHALL be idempotent.

#### Scenario: Fresh database is initialized on first run
- **WHEN** the binary starts against a non-existent database file
- **THEN** the file is created, the schema is applied, and the service is ready to accept writes

#### Scenario: Existing database survives restart
- **WHEN** the binary is restarted against an existing database file
- **THEN** previously stored events remain readable and sequence numbers continue from where they left off

### Requirement: Listener-token persistence

The store SHALL provide a `listener_tokens` table with columns `id` (text), `name` (text), `scopes` (json or comma-separated string of source identifiers and/or `admin`), `secret_hash` (Argon2id), `created_at`, `last_used_at` (nullable), `revoked_at` (nullable). The `TokenStore` SHALL support `Insert`, `LookupByPlaintext` (verifying against `secret_hash` with constant-time compare), `TouchLastUsed`, `List`, and `Revoke`. Plaintext token values SHALL never be stored.

#### Scenario: Hashed token survives restart
- **WHEN** a token is issued and the process is restarted
- **THEN** the token continues to authenticate correctly via the persisted hash

#### Scenario: Plaintext is never recoverable
- **WHEN** an attacker has read access to the database file
- **THEN** no SELECT can recover a plaintext token (only the Argon2id hash is present)

### Requirement: Push-subscription persistence

The store SHALL provide a `push_subscriptions` table with columns: `id` (text), `source` (text, NOT NULL), `target_url` (text), `signing_secret_hash` (Argon2id, used to verify CLI ops; the dispatcher holds the plaintext in-memory for HMAC signing only), `name` (nullable), `cursor` (int64), `paused_at` (nullable), `created_at`, `last_attempt_at` (nullable), `last_success_at` (nullable), `last_error` (text, truncated to 1 KB, nullable), `consecutive_failures` (int). The `PushSubscriptionStore` SHALL support `Insert` (returning plaintext secret), `List` (active by default; `IncludePaused` option), `Get`, `UpdateCursorAndSuccess` (atomic with attempt-result write), `RecordFailure`, `Pause`, `Resume`, `RotateSecret`, and `Delete`.

Note on signing-secret storage: storing the secret as Argon2id-hashed at rest means the dispatcher must hold the plaintext in memory after registration. We accept this trade-off: the plaintext is generated at registration, retained in-process for as long as the dispatcher runs, and only re-supplied via `hooksctl push rotate-secret` thereafter. The on-disk hash exists so that operator-side verification (e.g. consumer reports a signature mismatch) can confirm a particular secret matches a particular subscription without exposing other plaintexts.

#### Scenario: Cursor and attempt-result update together
- **WHEN** a delivery returns 2xx
- **THEN** in a single transaction the cursor advances, `last_success_at` is set to now, and `consecutive_failures` is reset to 0

#### Scenario: Failure record does not advance cursor
- **WHEN** `RecordFailure` is called
- **THEN** the cursor is unchanged and `consecutive_failures` is incremented atomically with `last_attempt_at` and `last_error`

### Requirement: Auto-prune with 30-day default

The service SHALL run a pruner goroutine that wakes every hour and deletes events whose `received_at` is older than the source's configured retention duration. The default retention SHALL be 30 days. A retention of `0` (or the literal string `forever` in YAML) SHALL disable auto-prune for that source. Per-source retention SHALL be configurable in `hooks.yaml`. The pruner SHALL use a single transaction per source per pass and log how many rows were deleted.

#### Scenario: Default retention prunes 31-day-old events
- **WHEN** an event with `received_at` 31 days ago exists and the source's retention is the default 30 days
- **THEN** the next pruner pass removes that event and the deletion is logged

#### Scenario: `retention: forever` keeps everything
- **WHEN** a source's retention is configured as `0` or `forever`
- **THEN** the pruner pass leaves all of that source's events untouched

#### Scenario: Per-source retention is independent
- **WHEN** source `render` has retention `30d` and source `stripe` has retention `7d`
- **THEN** stripe events older than 7 days are pruned while render events 8–30 days old remain

### Requirement: Manual prune command

The store SHALL support an additional manual prune operation that deletes events older than a caller-supplied duration regardless of the configured per-source retention, exposed via a `hooks prune --older-than=<duration>` CLI subcommand. This SHALL be additive to (not a replacement for) auto-prune.

#### Scenario: Manual prune is more aggressive than auto-prune
- **WHEN** `hooks prune --older-than=7d` runs and the configured retention is 30 days
- **THEN** events older than 7 days are deleted from every source

### Requirement: Body integrity check

The store SHALL store `body_sha256` alongside the body, and a `hooks verify` CLI command SHALL recompute hashes for every stored event and report any mismatch.

#### Scenario: Verify reports a tampered row
- **WHEN** the body bytes for a row are altered out-of-band and `hooks verify` runs
- **THEN** the command exits non-zero and prints the affected `(source, sequence)`
