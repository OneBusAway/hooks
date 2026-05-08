## ADDED Requirements

### Requirement: Authenticated SSE subscription endpoint

The service SHALL expose `GET /subscribe/<source>` which streams events for the named source as Server-Sent Events. The endpoint SHALL require a bearer token via the `Authorization: Bearer <token>` header. Requests with a missing, malformed, or unrecognized token SHALL be rejected with HTTP 401. Requests with a valid token whose scopes do not include the requested source SHALL be rejected with HTTP 403.

#### Scenario: Valid token streams events for a scoped source
- **WHEN** a client opens `GET /subscribe/render` with a bearer token whose scopes include `render`
- **THEN** the response is HTTP 200 with `Content-Type: text/event-stream` and events begin streaming

#### Scenario: Token without source scope is rejected
- **WHEN** a client opens `GET /subscribe/render` with a token scoped only to `stripe`
- **THEN** the service responds with HTTP 403

#### Scenario: Missing token is rejected
- **WHEN** a client opens `GET /subscribe/render` without an `Authorization` header
- **THEN** the service responds with HTTP 401

### Requirement: Cursor-based replay-then-live delivery

The endpoint SHALL accept a `since` query parameter that controls where the stream begins:
- An integer N SHALL replay all stored events with `sequence > N`, then transition to live tailing.
- The literal string `latest` SHALL skip the backlog and start at live tailing only.
- The default (no parameter) SHALL behave as `since=0` (full replay from the beginning).

The endpoint SHALL also honor the standard SSE `Last-Event-ID` request header as equivalent to `since=<that value>`. When both `since` and `Last-Event-ID` are present, the larger of the two SHALL be used so that browser auto-reconnect cannot regress the cursor.

#### Scenario: Replay and live tail are continuous in one stream
- **WHEN** a client subscribes with `since=5` while the highest stored sequence is 8, and a new event arrives during the connection
- **THEN** the client receives sequences 6, 7, 8 in order, then sequence 9 when it lands, all on the same connection without re-handshake

#### Scenario: `latest` skips the backlog
- **WHEN** a client subscribes with `since=latest` and the highest stored sequence is 100
- **THEN** the client receives no historical events, only sequences ≥ 101 as they arrive

#### Scenario: Browser reconnect uses Last-Event-ID
- **WHEN** an EventSource connection drops at sequence 42 and the browser auto-reconnects with `Last-Event-ID: 42`
- **THEN** the server resumes streaming from sequence 43

### Requirement: SSE message format

Each event SHALL be sent as one SSE message with:
- `id:` set to the event's sequence number,
- `event:` set to the source identifier,
- `data:` set to a single line of JSON containing `delivery_id`, `provider_timestamp`, `received_at`, `headers`, and a base64-encoded `body`.

#### Scenario: Event payload round-trips
- **WHEN** a client receives an SSE message and base64-decodes the `body` field
- **THEN** the resulting bytes are byte-identical to the body originally received from the provider

### Requirement: At-least-once delivery semantics

The server SHALL guarantee that every stored event is sent to a connected, scoped subscriber at least once before the connection closes normally, even if the live notification fan-out drops a signal due to backpressure. Listeners SHALL be expected to deduplicate by `delivery_id`, and this expectation SHALL be documented at the endpoint.

#### Scenario: Slow listener does not lose events
- **WHEN** a subscriber is slow enough that the in-process notification channel drops a signal
- **THEN** the subscriber still receives the affected event(s) on its next read because the server backfills from the store

### Requirement: Keepalives and idle handling

The server SHALL emit an SSE comment line (`: keepalive\n\n`) at least every 30 seconds on otherwise idle connections so intermediaries do not close them. The server SHALL detect a closed client connection via context cancellation and SHALL release subscription resources promptly.

#### Scenario: Idle stream stays open
- **WHEN** no events arrive for 5 minutes on an open subscription
- **THEN** the connection remains open and at least 9 keepalive comments have been written

#### Scenario: Disconnected client frees resources
- **WHEN** a subscriber closes its TCP connection mid-stream
- **THEN** the server-side goroutine and channel registration for that subscriber are released within 1 second

### Requirement: Replay batch caps

A single replay response SHALL flush at most 1000 events between flushes, to bound peak memory and latency. Beyond 1000 events the server SHALL flush, yield to other subscribers, and continue.

#### Scenario: Large backlog does not OOM the server
- **WHEN** a subscriber requests `since=0` against a store with 50,000 events
- **THEN** the server delivers all events in order without buffering more than 1000 at a time

### Requirement: Concurrent subscribers per source

The server SHALL support at least 100 concurrent subscribers per source without losing or reordering events for any of them.

#### Scenario: Two subscribers see the same events in the same order
- **WHEN** two clients subscribe to the same source with `since=0` while events are being ingested
- **THEN** both clients see the same sequence numbers in the same ascending order

### Requirement: Database-backed listener tokens

Listener tokens (bearer tokens used for SSE subscription, the inspector, and the token/push management APIs) SHALL be stored in SQLite in a `listener_tokens` table. Each row SHALL contain at minimum: `id`, `name`, `scopes` (a list including any combination of source identifiers and the special scope `admin`), `secret_hash` (Argon2id), `created_at`, `last_used_at`, `revoked_at`. Plaintext tokens SHALL never be persisted; configuration files (e.g. `hooks.yaml`) SHALL NOT contain listener tokens.

#### Scenario: Plaintext token is never persisted
- **WHEN** a listener token is issued
- **THEN** the database row contains only the Argon2id hash; no SELECT against the database can recover the plaintext

#### Scenario: hooks.yaml never contains tokens
- **WHEN** the configuration loader is asked to parse a `hooks.yaml` containing a `tokens:` field
- **THEN** the loader fails with an explicit error explaining that tokens live in the database

### Requirement: Listener-token CLI

The `hooksctl` binary SHALL provide:
- `hooksctl token add --name <label> --scopes <list>` to issue a new token, printing the plaintext to stdout exactly once.
- `hooksctl token list` to show `id`, `name`, `scopes`, `created_at`, `last_used_at` for every active token; revoked tokens are excluded by default and shown with `--include-revoked`.
- `hooksctl token revoke <id>` to invalidate a token immediately.

The same operations SHALL also be available as authenticated HTTP endpoints under `/api/tokens` for use by the inspector UI; only `admin`-scoped tokens SHALL be authorized to call those endpoints.

#### Scenario: Issued token authenticates a subscription
- **WHEN** an admin runs `hooksctl token add --name laptop --scopes render` and supplies the printed token to a subscribe call
- **THEN** the subscribe call is authenticated successfully

#### Scenario: Revoked token is rejected within 1 second
- **WHEN** a token is revoked and a subscriber attempts to use it
- **THEN** the next request fails with HTTP 401 within one second of the revocation

#### Scenario: Listing does not reveal plaintext
- **WHEN** an admin runs `hooksctl token list`
- **THEN** no row contains the plaintext token; only id, name, scopes, and timestamps are shown

#### Scenario: Non-admin token cannot list tokens via API
- **WHEN** a client calls `GET /api/tokens` with a token whose scopes do not include `admin`
- **THEN** the service responds with HTTP 403

### Requirement: `admin` scope semantics

The special scope `admin` SHALL grant access to the inspector UI, the token-management API, and the push-subscription-management API. The `admin` scope SHALL NOT implicitly grant subscribe access for any source; an admin token MUST explicitly include source scopes (e.g. `["admin", "render"]`) to also subscribe.

#### Scenario: Admin scope alone cannot subscribe to a source
- **WHEN** a client opens `GET /subscribe/render` with a token whose scopes are `["admin"]` only
- **THEN** the service responds with HTTP 403

#### Scenario: Combined-scope token can both manage and subscribe
- **WHEN** a client uses a token scoped `["admin", "render"]`
- **THEN** the same token authenticates both `/inspector` and `/subscribe/render`
