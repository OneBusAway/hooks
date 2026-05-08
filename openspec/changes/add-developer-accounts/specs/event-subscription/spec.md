## ADDED Requirements

### Requirement: `account` scope semantics

The special scope `account` SHALL grant access to a user's own self-service endpoints under `/api/me/*` (tokens and push subscriptions belonging to that user). The `account` scope SHALL NOT implicitly grant any source subscription, the `admin` scope, or visibility into another user's resources. Every active user SHALL implicitly hold `account` regardless of whether the scope appears in their `default_scopes` list, so that `/api/me` is always reachable by an authenticated user. When a user mints a `kind='pat'` token via `POST /api/me/tokens`, the server SHALL force-include `account` in the persisted scope set if absent; an empty `scopes` array on a `kind='pat'` request SHALL be rejected with HTTP 400 as misconfiguration.

#### Scenario: Account scope alone reaches /api/me
- **WHEN** a user with `default_scopes = []` calls `GET /api/me/tokens` using a session cookie or PAT
- **THEN** the response is HTTP 200, returning that user's own tokens (possibly empty)

#### Scenario: Account scope cannot subscribe
- **WHEN** a client calls `GET /subscribe/render` with a token whose only explicit scope is `account`
- **THEN** the response is HTTP 403

#### Scenario: Account scope cannot manage other users
- **WHEN** a non-admin user calls `GET /api/users` or `POST /api/invites`
- **THEN** the response is HTTP 403

#### Scenario: PAT minted with empty scopes is rejected
- **WHEN** a user POSTs `/api/me/tokens` with `{kind: "pat", scopes: []}`
- **THEN** the response is HTTP 400 and no token is minted

### Requirement: Scope evaluation is token-level

All scope checks performed by the authentication and authorization layer SHALL be evaluated against the **bearer's** scopes — i.e. the scopes recorded on the `listener_tokens` row whose hash matched the supplied bearer. For requests that present a `hooks_session` cookie instead of a bearer, the policy boundary SHALL treat the request as if the session's user had a synthetic bearer with scopes equal to `default_scopes ∪ {account}`, plus the full source-scope set and `admin` if the user has the admin role. This unifies cookie and bearer authentication into a single policy predicate; "user-level" and "token-level" scope concepts are not distinct.

#### Scenario: PAT scopes determine /subscribe access, not user defaults
- **GIVEN** a user with `default_scopes = ["render", "stripe"]`
- **WHEN** they present a PAT scoped to `["account", "render"]` at `/subscribe/stripe`
- **THEN** the response is HTTP 403, even though the user holds `stripe` at the user level

#### Scenario: Cookie session evaluates against user's full effective scopes
- **GIVEN** an admin user with no `default_scopes`
- **WHEN** they load `/inspector/tokens` using only a `hooks_session` cookie
- **THEN** the request is admitted, since the synthetic bearer derived from the session includes `admin`

## MODIFIED Requirements

### Requirement: Database-backed listener tokens

Listener tokens (bearer credentials used for SSE subscription, the inspector, and the token/push management APIs) SHALL be stored in SQLite in a `listener_tokens` table. Each row SHALL contain at minimum: `id`, `name`, `scopes` (a list including any combination of source identifiers, the special scope `admin`, and the special scope `account`), `secret_hash` (Argon2id), `created_at`, `last_used_at`, `revoked_at`, `owner_user_id` (nullable foreign key into `users`), `kind` (TEXT, `'pat'` or `'listener'`, default `'listener'`), `ephemeral` (BOOL, default false), and `expires_at` (TIMESTAMP, nullable; capped at 1 year on creation). Plaintext tokens SHALL never be persisted (except in the narrow `device_pairings.plaintext_token` window) and SHALL never appear in any log line; configuration files (e.g. `hooks.yaml`) SHALL NOT contain listener tokens. A row whose `owner_user_id` is NULL is a system-owned token (e.g. minted by `hooks init`) and SHALL continue to authenticate exactly as before users existed; setting `owner_user_id=NULL` SHALL NOT mutate scope assignment.

The `kind` column distinguishes credential intent:

- `kind='pat'` rows are personal access tokens minted by device pairing or by `hooksctl me token add --kind pat`. They authorize `/api/me/*` and (if admin-scoped) the inspector. They SHALL NOT authorize `/subscribe/<source>`.
- `kind='listener'` rows are subscription credentials minted by `hooksctl token add`, `hooksctl me token add --kind listener`, or `hooksctl forward`'s ephemeral path. They authorize `/subscribe/<source>` and (if admin-scoped) the inspector. They SHALL NOT authorize `/api/me/*`.

A request presenting a token whose `kind` does not match the endpoint's expectation SHALL receive HTTP 403. The migration that adds the `kind` column SHALL backfill all existing rows with `kind='listener'`, preserving today's behavior (existing tokens authenticate `/subscribe/*` and the inspector).

#### Scenario: Plaintext token is never persisted
- **WHEN** a listener token is issued via `/api/tokens`, `/api/me/tokens`, or `hooksctl token add`
- **THEN** the database row contains only the Argon2id hash; no SELECT against `listener_tokens` can recover the plaintext

#### Scenario: hooks.yaml never contains tokens
- **WHEN** the configuration loader is asked to parse a `hooks.yaml` containing a `tokens:` field
- **THEN** the loader fails with an explicit error explaining that tokens live in the database

#### Scenario: User-owned token references its owner
- **WHEN** an authenticated user mints a token via `POST /api/me/tokens`
- **THEN** the resulting `listener_tokens` row has `owner_user_id` equal to the calling user

#### Scenario: PAT cannot subscribe
- **WHEN** a client opens `GET /subscribe/render` with a token whose `kind='pat'` (regardless of its scope set)
- **THEN** the response is HTTP 403

#### Scenario: Listener token cannot reach /api/me
- **WHEN** a client calls `GET /api/me/tokens` with a token whose `kind='listener'`
- **THEN** the response is HTTP 403

#### Scenario: Pre-existing system token continues to authenticate
- **GIVEN** a `listener_tokens` row backfilled to `owner_user_id=NULL`, `kind='listener'`, with scopes including `render`
- **WHEN** a client opens `GET /subscribe/render` with that bearer
- **THEN** the response is HTTP 200 and streaming proceeds

#### Scenario: Plaintext token never appears in logs
- **WHEN** a token is issued, used, or revoked
- **THEN** no log line emitted by the relay contains the plaintext bearer; `internal/secret.String` is used at every log boundary

#### Scenario: Expired PAT returns 401
- **GIVEN** a `kind='pat'` token whose `expires_at` is in the past
- **WHEN** a client calls any authenticated endpoint with that token
- **THEN** the response is HTTP 401

### Requirement: Listener-token CLI

The `hooksctl` binary SHALL provide:

- `hooksctl token add --name <label> --scopes <list>` (admin only) to issue a system-owned `kind='listener'` token, printing the plaintext to stdout exactly once.
- `hooksctl token list [--owner <user_id>] [--include-revoked] [--kind pat|listener]` (admin) to show id, name, scopes, owner, kind, created_at, last_used_at, expires_at, and revoked_at.
- `hooksctl token revoke <id>` (admin) to invalidate any token immediately.
- `hooksctl me token add --name <label> --scopes <list> [--kind pat|listener] [--ephemeral] [--expires-in <duration>]` to mint a user-owned token (default `kind='pat'`) under the currently logged-in account, printing the plaintext exactly once.
- `hooksctl me token list [--include-revoked]` and `hooksctl me token revoke <id>` to manage the calling user's own tokens.
- `hooksctl me sub {add,list,pause,resume,rotate-secret,rm,test}` for parity with admin push subcommands, scoped to the caller's subscriptions.

The same operations SHALL be available as authenticated HTTP endpoints. `/api/tokens` SHALL require `admin` scope; `/api/me/tokens` SHALL require `account` scope (held implicitly by every active user). Non-admin callers of `/api/tokens` SHALL receive HTTP 403; callers of `/api/me/tokens` who are not authenticated as a user (e.g. anonymous, or a system-owned token with no `owner_user_id`) SHALL receive HTTP 401.

#### Scenario: Issued admin token authenticates a subscription
- **WHEN** an admin runs `hooksctl token add --name laptop --scopes render` and supplies the printed token to a subscribe call
- **THEN** the subscribe call is authenticated successfully

#### Scenario: User-issued listener token authenticates a subscription
- **WHEN** a logged-in user runs `hooksctl me token add --name ci --scopes render --kind listener` and supplies the printed token to a subscribe call
- **THEN** the subscribe call is authenticated successfully

#### Scenario: User-issued PAT does not authenticate a subscription
- **WHEN** a logged-in user runs `hooksctl me token add --name ci --scopes render` (default kind `pat`) and presents the resulting token at `/subscribe/render`
- **THEN** the response is HTTP 403

#### Scenario: Revoked token is rejected within 1 second
- **WHEN** a token is revoked (by its owner or by an admin) and a subscriber attempts to use it
- **THEN** the next request fails with HTTP 401 within one second of the revocation

#### Scenario: Listing does not reveal plaintext
- **WHEN** an admin runs `hooksctl token list` or a user runs `hooksctl me token list`
- **THEN** no row contains the plaintext token; only id, name, scopes, owner, kind, and timestamps are shown

#### Scenario: Non-admin token cannot list all tokens via API
- **WHEN** a client calls `GET /api/tokens` with a token whose scopes do not include `admin`
- **THEN** the service responds with HTTP 403

#### Scenario: Anonymous client cannot list /api/me/tokens
- **WHEN** a client calls `GET /api/me/tokens` with no `Authorization` header and no session cookie
- **THEN** the service responds with HTTP 401

#### Scenario: Non-admin cannot revoke another user's token
- **WHEN** a non-admin user calls `POST /api/tokens/{id}/revoke` (admin endpoint) for a token they do not own
- **THEN** the service responds with HTTP 403

### Requirement: `admin` scope semantics

The special scope `admin` SHALL grant access to admin areas of the inspector, the token-management API at `/api/tokens`, the push-subscription-management API at `/api/push-subscriptions`, the user-management APIs at `/api/users` and `/api/invites`, and the audit-log surface at `/api/audit` and `/inspector/audit`. The `admin` scope SHALL NOT implicitly grant subscribe access for any source; an admin token MUST explicitly include source scopes (e.g. `["admin", "render"]`) to also subscribe. An `admin`-scoped token SHALL implicitly authorize `/api/me/*` against its owning user (or, if `owner_user_id` is NULL, SHALL be treated as a system identity that is allowed only to manage system-owned resources via `/api/tokens` and `/api/push-subscriptions`).

#### Scenario: Admin scope alone cannot subscribe to a source
- **WHEN** a client opens `GET /subscribe/render` with a token whose scopes are `["admin"]` only
- **THEN** the service responds with HTTP 403

#### Scenario: Combined-scope token can both manage and subscribe
- **WHEN** a client uses a token scoped `["admin", "render"]` and `kind='listener'`
- **THEN** the same token authenticates both `/inspector` and `/subscribe/render`

#### Scenario: System admin token cannot reach /api/me
- **WHEN** a request is made to `/api/me/tokens` with a system-owned admin token (no `owner_user_id`)
- **THEN** the service responds with HTTP 401, since `/api/me` requires a user identity
