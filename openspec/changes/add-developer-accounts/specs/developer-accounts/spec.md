## ADDED Requirements

### Requirement: User identity model

The service SHALL persist user identities with stable `id`, unique (case-insensitive) `email`, display `name`, role (`admin` or `user`), Argon2id-hashed password, optional `default_scopes`, `created_at`, optional `deactivated_at`, and optional `external_id`. The service SHALL never log a plaintext password and SHALL never return a password hash from any HTTP endpoint. All plaintext password material SHALL flow through `internal/secret.String` at config and log boundaries; comparisons SHALL use `secret.Equal*` or constant-time primitives.

#### Scenario: Email is unique
- **WHEN** an attempt is made to create two users with the same email (case-insensitive)
- **THEN** the second creation fails with HTTP 409

#### Scenario: Password hash never leaves the database
- **WHEN** a client fetches a user record via `GET /api/users/{id}` or `GET /api/me`
- **THEN** the response body does not contain `password_hash` or any plaintext password material

#### Scenario: Deactivated users cannot authenticate
- **WHEN** a user's `deactivated_at` is non-null and they attempt to log in via the web form
- **THEN** the response is HTTP 403 with no session cookie set, and no row is created in `user_sessions`

### Requirement: Password policy

Signup and admin password reset SHALL reject any password shorter than 12 Unicode codepoints OR any password whose case-folded form contains the user's email local-part or full email. Rejected requests SHALL return HTTP 400 with a generic "password does not meet policy" message; the failed-policy reason MAY be logged but the attempted plaintext SHALL NOT.

#### Scenario: Short password rejected
- **WHEN** a signup is submitted with `password = "short1!"` (7 characters)
- **THEN** the response is HTTP 400 and no user row is created

#### Scenario: Email-containing password rejected
- **WHEN** a signup is submitted with `email = "alice@example.com"` and `password = "Alice@example.com12345"`
- **THEN** the response is HTTP 400 and no user row is created

#### Scenario: Plaintext password is not logged on policy failure
- **WHEN** a signup is rejected by password policy
- **THEN** any log line written by the handler contains the policy reason (e.g. `length < 12`) but does not contain the attempted plaintext

### Requirement: Invite-gated signup

The service SHALL require an unconsumed, unexpired invite code for every account creation. Signup SHALL fail with HTTP 410 if the invite is expired, HTTP 409 if already consumed, and HTTP 404 if no such invite exists. On successful signup the invite SHALL be marked consumed atomically with user creation; if user creation fails for any reason the invite SHALL remain unconsumed.

#### Scenario: Valid invite produces a user
- **WHEN** a signup is submitted with a valid invite code, an unused email, and a policy-compliant password
- **THEN** a user is created with the role and default_scopes from the invite, the invite is marked consumed, an `audit_events` row is recorded with action `user.create`, and the request returns HTTP 201

#### Scenario: Reused invite is rejected
- **WHEN** a signup is submitted with an invite code whose `consumed_at` is non-null
- **THEN** the response is HTTP 409 and no user is created

#### Scenario: Bootstrap invite auto-disables after first account
- **GIVEN** a fresh deployment where `hooks init` created a single `bootstrap=true` invite
- **WHEN** any user is created (whether via the bootstrap invite or any other invite)
- **THEN** the bootstrap invite is marked consumed and any subsequent signup attempt using its code returns HTTP 409

#### Scenario: Expired bootstrap invite returns 410
- **GIVEN** a `bootstrap=true` invite whose `expires_at` is in the past
- **WHEN** a signup is submitted using its code
- **THEN** the response is HTTP 410 and no user is created

### Requirement: Password-based web login with sessions

The service SHALL expose `POST /api/auth/login` accepting `{email, password}` and, on a successful match against an active user's password hash, issue a session by inserting a row into `user_sessions` and setting a `Cookie: hooks_session=<id>.<plaintext>` with `HttpOnly`, `SameSite=Lax`, and `Secure` set when `r.TLS != nil` OR (when `web.trust_proxy_headers=true` in `hooks.yaml`) `r.Header.Get("X-Forwarded-Proto") == "https"`. The session row SHALL store `secret_hash = SHA-256(plaintext)` (NOT Argon2id) — session secrets are 256-bit random and do not require a slow hash. Sessions SHALL have a default TTL of 30 days, sliding on each authenticated request that uses them. The login response SHALL also set a `hooks_csrf` cookie carrying a per-session random token used for the CSRF double-submit pattern.

#### Scenario: Successful login sets a session cookie and a CSRF cookie
- **WHEN** a client POSTs valid credentials to `/api/auth/login`
- **THEN** the response sets a `hooks_session` cookie (HttpOnly, SameSite=Lax) whose value matches a row in `user_sessions`, and a `hooks_csrf` cookie carrying a fresh random token

#### Scenario: Session secret stored as SHA-256
- **WHEN** a session is created
- **THEN** the `user_sessions.secret_hash` column contains the SHA-256 digest of the cookie plaintext, not an Argon2id-encoded value

#### Scenario: Password verification is constant-time
- **WHEN** an attacker probes login with timing measurements against valid and invalid emails
- **THEN** server-side password verification runs Argon2id regardless of whether the email exists, so per-request latency does not reveal account existence

#### Scenario: Logout invalidates the session
- **WHEN** a logged-in client POSTs to `/api/auth/logout` with a valid CSRF token
- **THEN** the corresponding `user_sessions` row is deleted, the cookie is cleared via `Set-Cookie: hooks_session=; Max-Age=0`, the `hooks_csrf` cookie is cleared, and an `audit_events` row with action `session.delete` is recorded

### Requirement: CSRF and request-origin enforcement on cookie-authenticated mutations

Every state-changing endpoint that accepts a session cookie SHALL enforce both an `Origin`/`Referer` check (matching the request host) and a CSRF double-submit token check (the `hooks_csrf` cookie value SHALL constant-time match the form's `csrf_token` field or the JSON body's `csrf_token` field). `Origin: null` SHALL be treated as cross-origin and rejected. Endpoints invoked only with `Authorization: Bearer` (no session cookie) SHALL be exempt from CSRF checks; the legacy raw-bearer-in-cookie path SHALL also be exempt because the cookie is itself the bearer in that path.

Endpoints covered: `/api/auth/login`, `/api/auth/logout`, `/api/auth/signup`, `/api/auth/device/approve`, `/api/auth/device/deny`, every `/api/me/*` mutation, every `/api/users/*` mutation, every `/api/invites/*` mutation, every admin `/api/tokens` mutation, every admin `/api/push-subscriptions` mutation.

#### Scenario: Missing Origin is rejected
- **WHEN** a cookie-authenticated POST arrives with no `Origin` and no `Referer`
- **THEN** the response is HTTP 403 and no state changes

#### Scenario: Cross-origin POST is rejected
- **WHEN** a cookie-authenticated POST arrives with `Origin: https://attacker.example`
- **THEN** the response is HTTP 403 and no state changes

#### Scenario: Origin null is rejected
- **WHEN** a cookie-authenticated POST arrives with `Origin: null`
- **THEN** the response is HTTP 403 and no state changes

#### Scenario: Mismatched CSRF token is rejected
- **WHEN** a cookie-authenticated POST arrives with a valid Origin but a `csrf_token` field that does not match the `hooks_csrf` cookie value
- **THEN** the response is HTTP 403 and no state changes

#### Scenario: Bearer-only mutation bypasses CSRF
- **WHEN** a `hooksctl` request hits `/api/me/tokens` with `Authorization: Bearer <PAT>` and no cookie
- **THEN** the request is admitted (subject to bearer auth and scope checks) without an Origin or CSRF check

### Requirement: Rate limiting on authentication endpoints

The service SHALL apply a token-bucket-per-IP (or per-user where applicable) rate limit to authentication-related endpoints. Limit-exceeded requests SHALL receive HTTP 429 with a `Retry-After: <seconds>` header. The implementation MAY keep buckets in process memory; bucket state MAY reset on process restart. The defaults SHALL be at least:
- `POST /api/auth/login` — 5/min/IP, 30/hour/IP
- `POST /api/auth/signup` — 3/min/IP, 10/hour/IP
- `POST /api/auth/device/start` — 10/min/IP
- `POST /api/auth/device/poll` — 60/min/IP
- `POST /api/auth/device/approve` — 10/min/user

#### Scenario: Burst on /api/auth/login is throttled
- **WHEN** a single IP POSTs to `/api/auth/login` six times within one minute
- **THEN** the sixth request returns HTTP 429 with a `Retry-After` header

#### Scenario: Distinct IPs are not coupled
- **WHEN** two different source IPs each POST to `/api/auth/login` five times within one minute
- **THEN** none of the ten requests is rate-limited

### Requirement: CLI device-pairing flow

The service SHALL expose `POST /api/auth/device/start` (unauthenticated, rate-limited) accepting an optional `{scopes: [...], admin: bool}` body and returning `{device_code, user_code, verification_uri, interval, expires_in}`. The `user_code` SHALL be 8 base32 characters (excluding `0`, `1`, `I`, `O`, `L`) formatted `XXXX-XXXX`. Device-start SHALL record `requesting_ip`, `requesting_user_agent`, and `requested_scopes` (defaulting to `["account"]`) on the `device_pairings` row.

The service SHALL expose `POST /api/auth/device/poll {device_code}` (unauthenticated, rate-limited) returning HTTP 202 while pending, HTTP 200 with `{token, user_id, name, scopes}` exactly once after approval, HTTP 410 after the plaintext has been fetched or after expiry, and HTTP 403 if the user denied.

The service SHALL expose `GET /device` (web) for an authenticated user to enter a `user_code`, see the requesting IP, user-agent, and requested scopes, narrow scopes via checkboxes, and approve. The page SHALL display the explicit warning "Approve only if you started this on this machine."

The service SHALL expose `POST /api/auth/device/approve {user_code, password, granted_scopes}` (authenticated, CSRF-checked, rate-limited) which:
- SHALL re-verify the user's password against the stored hash (running Argon2id even on miss to avoid timing oracles); session alone SHALL NOT be sufficient.
- SHALL reject with HTTP 403 if `granted_scopes` is not a subset of both `requested_scopes` and the calling user's held scopes (admin-implicit-all-scopes applies).
- SHALL mint a `kind='pat'` listener-token row scoped to `granted_scopes` (with `account` always implicitly included) owned by the calling user.
- SHALL transition the device row's `status` to `approved_unfetched` and record `audit_events` action `device_pairing.approve`.

Pairings SHALL expire 15 minutes after creation. The transition from `approved_unfetched` to `done` and the NULL-out of `plaintext_token` SHALL be performed as a deferred update on response-handler return; it SHALL NOT be tied to TCP-write success. If the response write fails, the row SHALL remain `approved_unfetched` so a CLI retry succeeds.

#### Scenario: Successful pairing returns a token exactly once
- **GIVEN** a CLI has called `/api/auth/device/start` with default scopes and a logged-in user has approved the user_code via `/device` (re-entering their password)
- **WHEN** the CLI polls `/api/auth/device/poll` with the matching device_code
- **THEN** the first such poll after approval returns HTTP 200 with a personal access token whose scopes equal the granted scopes, and any subsequent poll returns HTTP 410

#### Scenario: Approval defaults to account-only scope
- **GIVEN** `hooksctl login` was invoked with no `--scopes` flag
- **WHEN** the user approves the pairing
- **THEN** the resulting PAT's scopes are exactly `["account"]`

#### Scenario: Approver may narrow but not widen scopes
- **GIVEN** `requested_scopes = ["account", "render", "stripe"]` and the calling user holds `["render", "stripe"]`
- **WHEN** the user approves with `granted_scopes = ["account", "render"]`
- **THEN** the resulting PAT's scopes are exactly `["account", "render"]`

#### Scenario: Approver cannot widen beyond user's held scopes
- **GIVEN** the calling user holds `["render"]` only
- **WHEN** an approval is submitted with `granted_scopes = ["account", "render", "stripe"]`
- **THEN** the response is HTTP 403 and no token is minted

#### Scenario: Admin scope rejected for non-admin
- **GIVEN** `hooksctl login --admin` was invoked and the user is non-admin
- **WHEN** the user attempts approval
- **THEN** the response is HTTP 403 and no token is minted

#### Scenario: Approval requires re-entered password
- **GIVEN** a logged-in user with a valid session
- **WHEN** the user POSTs to `/api/auth/device/approve` with a missing or wrong `password`
- **THEN** the response is HTTP 401 and no token is minted

#### Scenario: Approver page surfaces requesting context
- **WHEN** a user loads `/device` for a pending pairing
- **THEN** the page renders the requesting IP, the requesting user-agent, the requested scopes, and a visible warning text containing "Approve only if you started this on this machine"

#### Scenario: Plaintext token is purged after fetch
- **WHEN** a CLI fetches the token via the first successful poll
- **THEN** the `plaintext_token` column on the corresponding `device_pairings` row is overwritten with NULL by a deferred update that runs after the response handler returns

#### Scenario: Expired pairing rejects polls
- **WHEN** a CLI polls a device_code more than `expires_in` seconds after creation without an approval
- **THEN** the response is HTTP 410 and the pairing is marked expired

#### Scenario: Denied pairing rejects polls
- **WHEN** a logged-in user denies a pairing via `/device`
- **THEN** subsequent polls of that device_code return HTTP 403

### Requirement: Personal access tokens for users

The service SHALL allow a user to mint a personal access token (PAT) via `POST /api/me/tokens` with `{name, scopes, kind?, ephemeral?, expires_at_seconds?}`. The PAT SHALL be a `listener_tokens` row whose `owner_user_id` references the calling user and whose `kind` defaults to `'pat'` (selectable to `'listener'` for SSE-only credentials). The service SHALL reject any request whose `scopes` are not a subset of the user's held scopes (their `default_scopes` plus the implicit `account` scope; admins implicitly hold all source scopes plus `admin`). For `kind='pat'` the server SHALL force-include `account` in the persisted scope set if absent. For `kind='pat'` an empty `scopes` array SHALL be rejected with HTTP 400. The `expires_at_seconds` field SHALL be capped at 31536000 seconds (1 year); existing rows with NULL `expires_at` SHALL never expire on a clock basis. Authentication of an expired PAT SHALL return HTTP 401. The plaintext SHALL be returned in the create response and never readable thereafter, and SHALL never appear in any log line; `internal/secret.String` SHALL be used at log boundaries.

#### Scenario: User mints a PAT within their scopes
- **GIVEN** a non-admin user with `default_scopes = ["render"]`
- **WHEN** they POST `/api/me/tokens` with `{name: "ci", scopes: ["render"]}`
- **THEN** the response is HTTP 201 with `plaintext` set, the token row's `owner_user_id` matches the user, `kind='pat'`, and the persisted scopes include both `render` and `account`

#### Scenario: User cannot exceed their granted scopes
- **GIVEN** a non-admin user with `default_scopes = ["render"]`
- **WHEN** they POST `/api/me/tokens` with `{name: "everything", scopes: ["render", "stripe", "admin"]}`
- **THEN** the response is HTTP 403 and no token row is created

#### Scenario: Admin holds all scopes implicitly
- **GIVEN** an admin user
- **WHEN** they POST `/api/me/tokens` with `{name: "anything", scopes: ["render", "admin"]}`
- **THEN** the response is HTTP 201 even if no `default_scopes` are set on the user row

#### Scenario: User can list and revoke only their own tokens
- **WHEN** a user calls `GET /api/me/tokens` or `POST /api/me/tokens/{id}/revoke`
- **THEN** the listing contains only tokens with `owner_user_id` equal to that user, and revoke returns HTTP 404 for any token id not owned by them

#### Scenario: PAT cannot subscribe
- **WHEN** a client opens `GET /subscribe/render` with a token whose `kind='pat'`
- **THEN** the response is HTTP 403, even if the PAT's scopes include `render`

#### Scenario: Listener token cannot reach /api/me
- **WHEN** a client calls `GET /api/me/tokens` with a token whose `kind='listener'`
- **THEN** the response is HTTP 403

#### Scenario: PAT past expires_at returns 401
- **GIVEN** a PAT with `expires_at` set to one second ago
- **WHEN** a client calls any authenticated endpoint with that PAT
- **THEN** the response is HTTP 401 and no row state changes

#### Scenario: hooksctl logout revokes the PAT
- **GIVEN** a logged-in CLI with a credentials file containing a PAT
- **WHEN** the user runs `hooksctl logout`
- **THEN** the CLI POSTs `/api/me/tokens/self/revoke` (where `self` resolves server-side to the bearer's own token id), then deletes the credentials file; if the revoke fails the file is still deleted but the CLI exits non-zero with a stderr warning

### Requirement: Self-service push subscriptions

The service SHALL expose `/api/me/subscriptions` for a user to register, list, pause, resume, rotate-secret, and delete push subscriptions whose `owner_user_id` references that user. The semantics, signing, retry, and cursor behavior of these subscriptions SHALL match the existing push-delivery capability — only ownership and the URL surface change.

#### Scenario: User registers a push subscription
- **WHEN** an authenticated user POSTs `/api/me/subscriptions` with `{source: "render", target_url: "...", secret: "..."}`
- **THEN** a `push_subscriptions` row is created with `owner_user_id` equal to that user, and the response includes the subscription id

#### Scenario: User cannot manage another user's subscription
- **WHEN** a user attempts `GET /api/me/subscriptions/{id}` or any management mutation on a subscription owned by another user
- **THEN** the response is HTTP 404

#### Scenario: Admin still sees all subscriptions
- **WHEN** an admin calls `GET /api/push?owner=<user_id>` (or unfiltered)
- **THEN** the response includes the user's subscriptions and may target them with admin-scope mutations

### Requirement: Cascading revocation on deactivation

The service SHALL, on `POST /api/users/{id}/deactivate` (admin only, CSRF-checked), atomically set `users.deactivated_at`, set `revoked_at` on every `listener_tokens` row owned by the user (regardless of `kind` or `ephemeral`), and set `paused_at` on every `push_subscriptions` row owned by the user. The deactivation request SHALL require a `{confirm: "<email>"}` body field whose value matches the target user's email, returning HTTP 400 otherwise. The service SHALL refuse with HTTP 409 if the deactivation would leave zero active admins (last-admin guard). Reactivation via `POST /api/users/{id}/reactivate` SHALL clear `deactivated_at` only — tokens and subscriptions SHALL remain revoked or paused respectively. This intentional friction matches GitHub's account-disable UX and is documented in `docs/accounts.md`.

#### Scenario: Deactivation revokes tokens and pauses subscriptions
- **GIVEN** a user with two active tokens (one PAT, one listener) and one running push subscription
- **WHEN** an admin POSTs `/api/users/{id}/deactivate` with the matching `confirm` email and a valid CSRF token
- **THEN** all three of the user's resources are revoked or paused in the same transaction as the user update, and an `audit_events` row with action `user.deactivate` is recorded

#### Scenario: Deactivation requires email confirmation
- **WHEN** an admin POSTs `/api/users/{id}/deactivate` with a missing or mismatched `confirm` field
- **THEN** the response is HTTP 400 and the user remains active

#### Scenario: Last-admin deactivation refused
- **GIVEN** a deployment with exactly one active admin
- **WHEN** an admin POSTs `/api/users/{id}/deactivate` against that admin (themselves)
- **THEN** the response is HTTP 409 and no state changes

#### Scenario: Reactivation does not restore tokens
- **GIVEN** a user previously deactivated whose tokens were revoked
- **WHEN** an admin POSTs `/api/users/{id}/reactivate`
- **THEN** `deactivated_at` is cleared but every previously-revoked token remains revoked and every paused subscription remains paused; the user must reissue tokens and unpause subscriptions themselves

### Requirement: Bootstrap invite for fresh deployments

When `hooks init` runs against a database that has no users, it SHALL ensure exactly one invite row exists with `bootstrap=true`, `role=admin`, `expires_at = now + 24h`, and a randomly generated 16-character base32 code. If a `bootstrap=true` row already exists but its `expires_at` is in the past, `hooks init` SHALL replace it atomically with a fresh code and a fresh 24-hour expiry. `hooks init` SHALL print this invite's signup URL once, prefixed with `signup:`, alongside a note describing the 24h TTL and single-use semantics. Re-running `hooks init` against a database that has users SHALL NOT print or create a bootstrap invite.

#### Scenario: First init prints a signup URL with 24h TTL
- **GIVEN** a freshly initialised database
- **WHEN** `hooks init` runs
- **THEN** stdout contains a single line beginning with `signup: ` followed by a URL of the form `<server>/signup?code=<16-char-base32>`, and the corresponding invite row has `expires_at` approximately 24 hours in the future

#### Scenario: Subsequent init does not re-prompt bootstrap
- **GIVEN** a database with at least one user record
- **WHEN** `hooks init` runs again
- **THEN** stdout contains no `signup:` line and no new invite row is inserted

#### Scenario: Expired bootstrap invite is replaced on next init
- **GIVEN** a userless database whose existing bootstrap invite has `expires_at` in the past
- **WHEN** `hooks init` runs again
- **THEN** the expired bootstrap row is replaced atomically with a new code and a fresh 24-hour expiry, and stdout contains the new `signup:` line

#### Scenario: Expired bootstrap invite rejects signup
- **GIVEN** a `bootstrap=true` invite whose `expires_at` is in the past
- **WHEN** a signup is submitted with that code
- **THEN** the response is HTTP 410

### Requirement: Admin-issued invites

The service SHALL expose `POST /api/invites` (admin, CSRF-checked) accepting `{role, default_scopes?, ttl?}` and returning `{code, role, default_scopes, expires_at}`. Invites without a TTL SHALL default to expiring 7 days from creation. For `role='admin'` invites the body MAY include `default_scopes`; the field SHALL be stored on the invite row but SHALL NOT affect authentication (admin role implicitly holds every source scope plus `admin`). The service SHALL expose `GET /api/invites` (admin) and `DELETE /api/invites/{code}` (admin, CSRF-checked). The CLI command `hooks invite` (server-side, admin scope) and the CLI subcommands `hooksctl invite create | list | revoke` (remote, hits `/api/invites` using the admin's PAT) SHALL be both available; both surfaces SHALL print or display the resulting signup URL on creation. Invite lifecycle events SHALL be recorded in `audit_events`.

#### Scenario: Admin issues a default 7-day invite
- **WHEN** an admin POSTs `/api/invites` with no `ttl`
- **THEN** the response invite has `expires_at` approximately 7 days in the future, and an `audit_events` row with action `invite.create` is recorded

#### Scenario: Non-admin cannot issue invites
- **WHEN** a non-admin user calls `POST /api/invites`
- **THEN** the response is HTTP 403

#### Scenario: hooksctl invite create produces a signup URL
- **GIVEN** a logged-in admin CLI
- **WHEN** the operator runs `hooksctl invite create --role user --scopes render --ttl 7d`
- **THEN** the CLI prints the signup URL (containing the new invite code) exactly once

#### Scenario: Admin-role invite stores default_scopes but ignores them
- **WHEN** an admin POSTs `/api/invites` with `{role: "admin", default_scopes: ["render"]}` and a user signs up with that code
- **THEN** the resulting user has `role='admin'` and authentication treats them as holding all source scopes regardless of the persisted `default_scopes` value

### Requirement: Editing user defaults

The service SHALL expose `PATCH /api/users/{id}` (admin only, CSRF-checked) accepting `{name?, default_scopes?}`. The endpoint SHALL NOT allow editing of `email`, `role`, or password (separate endpoints handle reset). On success an `audit_events` row with action `user.update` SHALL be recorded.

#### Scenario: Admin updates a user's default scopes
- **WHEN** an admin PATCHes `/api/users/{id}` with `{default_scopes: ["render", "stripe"]}`
- **THEN** the user row's `default_scopes` is updated and subsequent `POST /api/me/tokens` requests by that user with `scopes` ⊆ `["account", "render", "stripe"]` succeed

#### Scenario: PATCH cannot escalate role
- **WHEN** an admin PATCHes `/api/users/{id}` with `{role: "admin"}`
- **THEN** the response is HTTP 400 and the user's role is unchanged

### Requirement: System-owned tokens remain valid

A listener-token row whose `owner_user_id` is NULL SHALL continue to authenticate exactly as before this change, with its existing scopes unchanged. The migration SHALL backfill existing rows with `owner_user_id=NULL`, `kind='listener'`, `ephemeral=0`, and `expires_at=NULL` without altering any other column. Such tokens SHALL be visible to admins via `GET /api/tokens` and identified by a NULL or `system` owner field in the response.

#### Scenario: Pre-existing system token authenticates against /subscribe
- **GIVEN** a token row with `owner_user_id` NULL, `kind='listener'` (after backfill), and scopes including `render`
- **WHEN** a client opens `GET /subscribe/render` with that bearer
- **THEN** the response is HTTP 200 and streaming proceeds

#### Scenario: Migration leaves existing tokens intact
- **WHEN** the schema migration that adds `owner_user_id`, `kind`, `ephemeral`, and `expires_at` runs
- **THEN** no existing `listener_tokens` row's `name`, `scopes`, `secret_hash`, `created_at`, `last_used_at`, or `revoked_at` value is altered, and no existing token's authentication behavior changes
