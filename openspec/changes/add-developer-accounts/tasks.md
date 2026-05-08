## 1. Schema migrations and storage primitives

- [ ] 1.1 Create migration adding `users` table (id PK, email UNIQUE NOCASE, name, role TEXT CHECK IN ('admin','user'), password_hash, default_scopes JSON, created_at, deactivated_at NULLABLE, external_id NULLABLE)
- [ ] 1.2 Create migration adding `user_sessions` table (id PK UUID, user_id FK, secret_hash, created_at, last_used_at, expires_at, user_agent, ip)
- [ ] 1.3 Create migration adding `invites` table (code PK, role, default_scopes JSON, created_by_user_id FK NULLABLE, bootstrap BOOL DEFAULT 0, created_at, expires_at NULLABLE, consumed_at NULLABLE, consumed_by_user_id FK NULLABLE)
- [ ] 1.4 Create migration adding `device_pairings` table (device_code PK, user_code UNIQUE, status TEXT CHECK IN ('pending','approved_unfetched','done','denied','expired'), created_at, expires_at, user_id FK NULLABLE, requesting_ip TEXT, requesting_user_agent TEXT, requested_scopes JSON, plaintext_token NULLABLE, token_id FK NULLABLE)
- [ ] 1.5 Add `owner_user_id` (nullable FK to `users.id`), `kind` (TEXT CHECK IN ('pat','listener') DEFAULT 'listener'), `ephemeral` (BOOL DEFAULT 0), and `expires_at` (TIMESTAMP NULLABLE) columns to `listener_tokens`. Backfill existing rows with `owner_user_id=NULL`, `kind='listener'`, `ephemeral=0`, `expires_at=NULL`. Verify the backfill leaves every existing row's existing scopes untouched.
- [ ] 1.6 Add `owner_user_id` (nullable FK to `users.id`) column to `push_subscriptions`; backfill with NULL
- [ ] 1.7 Create migration adding `audit_events` table (id PK, at TIMESTAMP, actor_user_id FK NULLABLE, actor_token_id FK NULLABLE, action TEXT, target_type TEXT, target_id TEXT, metadata JSON)
- [ ] 1.8 Add indexes: `users.email` (UNIQUE NOCASE already), `user_sessions.user_id`, `invites.consumed_at`, `device_pairings.user_code`, `device_pairings.expires_at`, `listener_tokens.owner_user_id`, `listener_tokens.kind`, `listener_tokens.expires_at`, `push_subscriptions.owner_user_id`, `audit_events.at`, `audit_events.actor_user_id`
- [ ] 1.9 Verify all migrations are idempotent (`IF NOT EXISTS` / `ALTER TABLE` guarded by a probe SELECT) and that running them twice on a fresh DB or against an existing v1 DB succeeds

## 2. Users package — domain types and store

- [ ] 2.1 Create `internal/users` package with types `User`, `Role` (const `RoleAdmin`, `RoleUser`), `Session`, `Invite`, `DevicePairing`
- [ ] 2.2 Define `UserStore` interface (`Insert`, `GetByID`, `GetByEmail`, `List`, `UpdateProfile` (covering name and `default_scopes`), `Deactivate`, `Reactivate`, `SetPasswordHash`, `CountActiveAdmins`)
- [ ] 2.3 Define `SessionStore` interface (`Insert`, `LookupByID`, `Touch`, `Delete`, `DeleteExpired`)
- [ ] 2.4 Define `InviteStore` interface (`Insert`, `GetByCode`, `MarkConsumed`, `List`, `Delete`, `EnsureBootstrap` (idempotent insert with 24h TTL; replaces an expired bootstrap row atomically))
- [ ] 2.5 Define `DevicePairingStore` interface (`Insert` (records requesting IP, user-agent, requested_scopes), `GetByDeviceCode`, `GetByUserCode`, `Approve` (sets approver, granted scopes, plaintext_token, token_id), `Deny`, `MarkFetched` (deferred from handler return), `DeleteExpired`)
- [ ] 2.6 Implement all four stores in `internal/store/sqlite.go` next to the existing event/token/push stores; `MaxOpenConns=1`, WAL discipline preserved
- [ ] 2.7 Implement adapters in `internal/store/adapters.go` to expose the new stores via the same interface-resolution pattern as `TokenStore`/`PushSubscriptionStore`
- [ ] 2.8 Add Argon2id password-hashing helpers in `internal/users/passwords.go` (Hash, Verify, both constant-time-correct, parameters identical to the existing token hasher). All plaintext password material flows through `internal/secret.String` at boundaries.
- [ ] 2.9 Wire a verifier injection point analogous to `tokens.AttachVerifier` so the store package never imports argon2 directly
- [ ] 2.10 Add `internal/users/policy.go` with `ValidatePassword(email, plaintext) error` enforcing length ≥ 12 and email-substring rejection (case-folded). Failed validation returns a typed error; the policy reason is logged but the plaintext is not.
- [ ] 2.11 Contract tests covering: email uniqueness (case-insensitive), password roundtrip, deactivation timestamp, invite single-use atomicity (concurrent goroutines, only one wins), bootstrap-invite idempotent insert + expired-bootstrap replacement, last-admin guard prevents demoting/deactivating the final admin, password policy rejects short and email-containing passwords
- [ ] 2.12 Crash-safety subprocess test: insert user mid-tx, kill, restart, verify state

## 3. Authentication endpoints — sessions and login

- [ ] 3.1 `POST /api/auth/login` handler: parse `{email, password}`, lookup by email (always run Argon2id even on miss to defeat timing oracles), constant-time verify, reject if `deactivated_at` non-null
- [ ] 3.2 On success, insert a `user_sessions` row with random `(id, secret)`. Hash the secret with **SHA-256** (not Argon2), store the digest as `secret_hash`. Set `Cookie: hooks_session=<id>.<plaintext>` with `HttpOnly`; `Secure` is set if `r.TLS != nil` OR (when `web.trust_proxy_headers=true`) `X-Forwarded-Proto: https`; `SameSite=Lax`, `Path=/`, `Max-Age=2592000`. Also set `Cookie: hooks_csrf=<random>` (HttpOnly false, SameSite=Lax) for the CSRF double-submit pattern.
- [ ] 3.3 `POST /api/auth/logout` handler: parse cookie, delete session row, expire cookie (and the CSRF cookie), record an `audit_events` row with action `session.delete`
- [ ] 3.4 Session middleware: parse `hooks_session` cookie, split on `.`, lookup by id, compute SHA-256 of the supplied plaintext, constant-time compare against `secret_hash`, touch `last_used_at`, attach `(*User, *Session)` to request context
- [ ] 3.5 Sliding expiry: on each authenticated session use, if `last_used_at` is more than 1h newer than persisted, update `expires_at = now + ttl`
- [ ] 3.6 Background sweeper goroutine that calls `SessionStore.DeleteExpired` every 15 minutes
- [ ] 3.7 Tests: successful login sets cookie + row; bad password returns generic error; deactivated user gets 403; expired cookie is rejected and deleted; logout invalidates cookie even if reused; session secret is verified with SHA-256, not Argon2

## 4. CSRF and request-origin defenses

- [ ] 4.1 Implement `internal/web/csrf.go` middleware that, for any cookie-authenticated mutation: (a) requires `Origin` (or `Referer` fallback) to match the request host; (b) rejects `Origin: null`; (c) reads `hooks_csrf` cookie and the form/JSON `csrf_token` field and constant-time compares them. Bearer-only requests (no `hooks_session` cookie) are exempt.
- [ ] 4.2 Apply CSRF middleware to: `/api/auth/login`, `/api/auth/logout`, `/api/auth/signup`, `/api/auth/device/approve`, `/api/auth/device/deny`, all `/api/me/*` mutations, all `/api/users/*` mutations, all `/api/invites/*` mutations, all admin `/api/tokens` mutations, all admin `/api/push-subscriptions` mutations
- [ ] 4.3 Server-rendered inspector forms: include a hidden `csrf_token` field whose value matches the `hooks_csrf` cookie; rotate the CSRF cookie value on session creation/login
- [ ] 4.4 Tests: missing `Origin` returns 403; mismatched `Origin` returns 403; `Origin: null` returns 403; missing CSRF cookie returns 403; mismatched CSRF token returns 403; valid Origin + matching CSRF token + cookie session passes; bearer-only PAT calls bypass CSRF entirely; legacy bearer-in-cookie path bypasses CSRF (since the cookie *is* the bearer in that path)

## 5. Rate limiting

- [ ] 5.1 Implement `internal/ratelimit` package with a token-bucket-per-key middleware (`KeyByIP`, `KeyByUser`); buckets live in process memory and are GC'd on idle
- [ ] 5.2 Apply rate limits: `POST /api/auth/login` (5/min/IP, 30/hour/IP), `POST /api/auth/signup` (3/min/IP, 10/hour/IP), `POST /api/auth/device/start` (10/min/IP), `POST /api/auth/device/poll` (60/min/IP), `POST /api/auth/device/approve` (10/min/user)
- [ ] 5.3 On limit-exceeded responses: HTTP 429 with `Retry-After: <seconds>` header; record the rejection at debug log level (no plaintext in logs)
- [ ] 5.4 Tests: bucket refills, separate IPs do not collide, 429 includes `Retry-After`, per-user buckets correctly key on the authenticated user

## 6. Invites — admin endpoints + bootstrap

- [ ] 6.1 `POST /api/invites` (admin): create invite with random 16-char base32 code, body `{role, default_scopes?, ttl?}`, default ttl 7d. For `role='admin'` the body MAY include `default_scopes` (stored, but unused at auth time; reserved for future role expansion). Record an `audit_events` row.
- [ ] 6.2 `GET /api/invites` (admin): list pending and consumed; filter by `consumed=true|false`
- [ ] 6.3 `DELETE /api/invites/{code}` (admin): hard-delete unconsumed invite; return 409 if consumed; record `audit_events`
- [ ] 6.4 `POST /api/auth/signup` (unauthenticated) accepting `{code, email, name, password}`: validate invite freshness (404/410/409 for missing/expired/consumed), enforce password policy (`internal/users.ValidatePassword`), create user with role + default_scopes from the invite, mark invite consumed atomically (single transaction; rollback on user-insert failure). Record `audit_events` for `user.create` and `invite.consume`.
- [ ] 6.5 Bootstrap-invite ensure-on-init: in `cmd/hooks` init path (and on server boot), if `users` is empty, call `InviteStore.EnsureBootstrap()` which inserts a `bootstrap=true, role=admin, expires_at=now+24h` row with a fresh code if no bootstrap row already exists; if a bootstrap row exists but is expired, replace it atomically.
- [ ] 6.6 Bootstrap-invite consumption: on every successful signup, also mark any `bootstrap=true` invite as consumed; signup attempts using a consumed bootstrap code return 409; signup attempts using an expired bootstrap code return 410
- [ ] 6.7 `cmd/hooks invite` subcommand (server-side): prints a signup URL for a freshly created (admin-scoped) invite by hitting the API with the local admin token loaded from disk
- [ ] 6.8 `hooksctl invite create [--role user|admin] [--scopes render,...] [--ttl 7d]`, `hooksctl invite list [--include-consumed]`, `hooksctl invite revoke <code>` — CLI subcommands that hit `/api/invites` using the admin's PAT
- [ ] 6.9 Tests: invite creation idempotency, bootstrap auto-insert idempotent, bootstrap consumed exactly once, expired bootstrap replaced on next init, expired invite rejected with 410, race test (two concurrent signups with same invite — exactly one succeeds), admin-role invite stores `default_scopes` but auth path ignores them, password policy rejection paths

## 7. CLI device pairing

- [ ] 7.1 `POST /api/auth/device/start` (unauthenticated): accept optional `{scopes: [...], admin: bool}` body; default `scopes=["account"]`. Generate `device_code` (random 32 hex), `user_code` (8 base32 alphabet `23456789ABCDEFGHJKMNPQRSTUVWXYZ`, `XXXX-XXXX` format), record `requesting_ip` (from `RemoteAddr` or trusted proxy header) and `requesting_user_agent`, store `requested_scopes`. `expires_in=900s`. Return `{device_code, user_code, verification_uri, interval, expires_in}`. The endpoint is rate-limited per task 5.2.
- [ ] 7.2 Validate at start time: if `admin: true` is requested by an unknown caller, the request still succeeds (the server doesn't know the user yet). The actual scope-vs-user check happens at approval. The handler MAY reject patently invalid requested scopes (unknown source names) with 400.
- [ ] 7.3 `POST /api/auth/device/poll {device_code}` (unauthenticated): lookup, return 404 if missing, 410 if `expired` or `done`, 403 if `denied`, 202 if `pending`. On `approved_unfetched`, return 200 with `{token, user_id, name, scopes}`. **Do not bind the `done` transition to TCP-write success**: schedule the transition (`status='done'`, `plaintext_token=NULL`, `last_used_at=now`) as a deferred update that runs after the response handler returns. If the response write fails, the row stays `approved_unfetched` and the next poll succeeds.
- [ ] 7.4 `GET /device` (web): if not logged in, redirect to `/login?next=/device`; otherwise render a form prompting for the user_code, the requesting IP, the requesting user-agent, the requested scopes (with checkboxes for narrowing), the explicit "Approve only if you started this on this machine" warning, a CSRF token, and a password re-entry field
- [ ] 7.5 `POST /api/auth/device/approve {user_code, password, granted_scopes}` (authenticated, CSRF-checked, rate-limited per 5.2): re-verify the password against the user's hash (constant-time, runs Argon2 even on miss); look up the device pairing by `user_code`; verify `granted_scopes` is a subset of `requested_scopes` AND a subset of the calling user's held scopes (admin-implicit if applicable); reject with 403 if either constraint is violated; mint a `kind='pat'` PAT with `owner_user_id=caller`, `scopes=granted_scopes`, store plaintext into `device_pairings.plaintext_token`, store `token_id`, set `status=approved_unfetched`, set `user_id=caller`. Record `audit_events` with action `device_pairing.approve` and metadata containing the granted scopes.
- [ ] 7.6 `POST /api/auth/device/deny {user_code}` (authenticated, CSRF-checked): set `status=denied`; record `audit_events` action `device_pairing.deny`
- [ ] 7.7 Background sweeper: every 60s, transition all `pending` rows past `expires_at` to `expired`, and hard-delete rows in any terminal state older than 24h
- [ ] 7.8 `hooksctl login [--server <url>] [--profile <name>] [--scopes render,stripe] [--admin]`: implement the start-print-poll loop with the documented interval and a 15-minute hard cap. Pass `--scopes` and `--admin` to `/api/auth/device/start`. Write `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>` with mode `0600`, TOML format with keys `server_url`, `token`, `created_at`, optional `expires_at`. Profile defaults to `default`.
- [ ] 7.9 `hooksctl logout [--profile <name>]`: read profile, POST `/api/me/tokens/{self}/revoke` for the locally-stored PAT (the server resolves `self` to the bearer's own token id), then POST `/api/auth/logout` if a session cookie is also present, then delete the credentials file. If the revoke POST fails (network error), still delete the local file but exit non-zero with a warning to stderr; do not leak the plaintext token in any log line.
- [ ] 7.10 `hooksctl whoami`: GET `/api/me`, print email + role + server URL
- [ ] 7.11 Update `cmd/hooksctl/main.go` to load the profile credentials file before falling back to `HOOKS_TOKEN`; precedence is `--token` > `HOOKS_TOKEN` > profile file > unauthenticated
- [ ] 7.12 Tests: pairing race (two polls within microseconds of approval — exactly one returns 200, the other 410); approval requires re-entered password (session alone returns 401); approval narrowing scopes succeeds; approval widening scopes returns 403; approval requesting scopes the user does not hold returns 403; denied flow returns 403; expiry sweeper transitions stale pendings; CLI integration test against an in-process server using the existing `httptest` harness; logout revokes PAT then deletes file; logout exits non-zero when revoke fails but still deletes file

## 8. Self-service /api/me endpoints

- [ ] 8.1 `GET /api/me`: returns calling user's id, email, name, role, default_scopes, created_at; 401 if anonymous
- [ ] 8.2 `PATCH /api/me {name?}`: updates own name (only field editable in v1); 400 on empty
- [ ] 8.3 `GET /api/me/tokens [?include_revoked=1] [?kind=pat|listener]`: list own active and (when `include_revoked=1`) revoked tokens; 401 if anonymous
- [ ] 8.4 `POST /api/me/tokens {name, scopes, kind?, ephemeral?, expires_at_seconds?}` (CSRF-checked when cookie-authenticated): validate scopes are a subset of caller's held scopes (admin holds all source scopes; user holds `default_scopes` plus implicit `account`). Reject empty `scopes` for `kind='pat'` with 400. For `kind='pat'` (default), force-include `account` in the stored scope set if absent; for `kind='listener'`, do NOT auto-inject `account`. Cap `expires_at_seconds` at 1 year (31536000); for `ephemeral=true` the cap is 24h-since-last-use enforced by the prune loop, not the column. Insert with `owner_user_id=caller`. Return plaintext exactly once.
- [ ] 8.5 `POST /api/me/tokens/{id}/revoke` (CSRF-checked when cookie-authenticated): 404 if id not owned by caller; otherwise set `revoked_at`. The literal id `self` resolves to the bearer's own token id (used by `hooksctl logout`).
- [ ] 8.6 `GET/POST/PATCH/DELETE /api/me/subscriptions[/{id}[/{action}]]` (mutations CSRF-checked): full parity with `/api/push-subscriptions` operationally, scoped to caller-owned rows; ignore any `owner_user_id` field in the request body
- [ ] 8.7 Authentication enforcement: PATs (`kind='pat'`) authorize `/api/me/*` and the inspector but NOT `/subscribe/<source>`. Listener tokens (`kind='listener'`) authorize `/subscribe/<source>` and (when admin-scoped) the inspector but NOT `/api/me/*`. Mismatched-kind requests return 403.
- [ ] 8.8 `hooksctl me token add --name <label> --scopes <list> [--kind pat|listener] [--ephemeral] [--expires-in 30d]`, `hooksctl me token list [--include-revoked]`, `hooksctl me token revoke <id>` — CLI subcommands hitting `/api/me/tokens`
- [ ] 8.9 `hooksctl me sub {add,list,pause,resume,rotate-secret,rm,test}` — CLI parity with admin `hooksctl push` subcommands but scoped to the caller's subscriptions via `/api/me/subscriptions`
- [ ] 8.10 Tests: scope-subset enforcement (request `["render","stripe"]` when user holds only `["render"]` → 403); admin-implicit-scopes test; cross-user 404 (user A cannot revoke user B's token); body-`owner_user_id`-ignored test; PAT cannot subscribe → 403; listener token cannot reach `/api/me` → 403; ephemeral expiry-by-inactivity covered by prune-loop tests; expired non-ephemeral PAT (past `expires_at`) returns 401

## 9. Admin /api/users and /api/invites surface

- [ ] 9.1 `GET /api/users` (admin): list all users with id/email/name/role/default_scopes/created_at/deactivated_at; support `?role=user|admin` filter
- [ ] 9.2 `GET /api/users/{id}` (admin): full record; 404 if not found
- [ ] 9.3 `PATCH /api/users/{id} {name?, default_scopes?}` (admin, CSRF-checked): admin-only profile edit. Cannot edit `email`, `role`, or password via this endpoint. Record `audit_events` action `user.update`.
- [ ] 9.4 `POST /api/users/{id}/deactivate {confirm: <email>}` (admin, CSRF-checked): atomic transaction — set `deactivated_at`, set `revoked_at` on every owned token (regardless of `kind` or `ephemeral`), set `paused_at` on every owned subscription. Reject with HTTP 409 if the target is the only active admin (last-admin guard). Reject with HTTP 400 on `confirm` mismatch. Record `audit_events`.
- [ ] 9.5 `POST /api/users/{id}/reactivate` (admin, CSRF-checked): clear `deactivated_at` only; tokens and subscriptions remain revoked/paused. Record `audit_events`.
- [ ] 9.6 `POST /api/users/{id}/reset-password {new_password}` (admin, CSRF-checked): enforce password policy, set new password hash, invalidate all sessions for that user; respond with HTTP 204. Record `audit_events`.
- [ ] 9.7 `GET /api/tokens?owner=<user_id|system>` (admin) extended to support owner filter; `system` matches `owner_user_id IS NULL`. Add `kind` filter.
- [ ] 9.8 `PATCH /api/tokens/{id} {owner_user_id?}` (admin, CSRF-checked): transfer ownership (or set NULL for system); record `audit_events` action `token.transfer_owner`
- [ ] 9.9 Same `?owner=` filter and `PATCH` ownership transfer for `/api/push-subscriptions` (CSRF-checked); record `audit_events` action `subscription.transfer_owner`
- [ ] 9.10 Tests: cascading revoke is atomic (failure mid-tx leaves nothing partially deactivated); confirm-email mismatch returns 400; last-admin deactivation returns 409; reactivation does not auto-restore tokens; ownership transfer is reflected in `/api/me` calls by the new owner; `PATCH /api/users/{id}` updates default_scopes; password reset rejects short passwords

## 10. Audit log

- [ ] 10.1 Create `internal/audit` package with `Recorder` interface (`Record(ctx, Event)`) and a SQLite-backed implementation that inserts into `audit_events`
- [ ] 10.2 Wire the recorder through `server.Build` and call it from every endpoint listed in design.md's "Audit log" section
- [ ] 10.3 `GET /api/audit?actor=<id>&since=<rfc3339>&until=<rfc3339>&limit=<n>` (admin only): paginated read of `audit_events` ordered by `at DESC`
- [ ] 10.4 `/inspector/audit` (admin only): HTML view rendering the event stream with actor email resolution and a simple time-range filter
- [ ] 10.5 Append-only invariant: no DELETE or UPDATE statement against `audit_events` in production code paths; the prune loop does not touch this table
- [ ] 10.6 Tests: every audited action produces exactly one event row with the expected `action`, `target_type`, `target_id`, and metadata; non-admin callers of `/api/audit` and `/inspector/audit` get 403

## 11. Inspector UI changes

- [ ] 11.1 `/login` page: serve embedded HTML form, POST to `/api/auth/login`, redirect on success; include hidden CSRF token; render error message slot for invalid credentials
- [ ] 11.2 `/signup` page: serve form expecting `?code=` param; POST to `/api/auth/signup`; include hidden CSRF token; on success redirect to `/login`
- [ ] 11.3 `/device` page: prompt for user_code, display requesting IP / user-agent / requested scopes (with narrowing checkboxes), the "Approve only if you started this on this machine" warning, the password re-entry field, and a CSRF token. POST to `/api/auth/device/approve`; "Deny" button POSTs to `/api/auth/device/deny`.
- [ ] 11.4 `/inspector/me`: profile + own tokens (filtered by `kind`) + own subscriptions + "mint ephemeral PAT" form (CSRF-protected); admin sees a link to `/inspector/users` and `/inspector/audit`
- [ ] 11.5 `/inspector/users` (admin): user table, "Issue invite" form (signup URL shown once), per-row deactivate (with email-confirmation modal; refuses last-admin), reactivate, reset-password, edit-default-scopes — all CSRF-protected
- [ ] 11.6 `/inspector/audit` (admin): audit-event log with actor and time-range filtering
- [ ] 11.7 `/inspector/me/push`: user-owned push-subscription view mirroring `/inspector/push` but without the owner column
- [ ] 11.8 Update `/inspector/tokens` (admin): add owner column (`system` vs user email) and `kind` column; add optional `owner_user_id` field on Add Token form for minting on behalf of users
- [ ] 11.9 Update `/inspector/push` (admin): add owner column; add `?owner=` filter dropdown
- [ ] 11.10 Update `/inspector` redirect logic: anonymous → `/login?next=/inspector`; non-admin user → `/inspector/me`
- [ ] 11.11 Preserve legacy raw-bearer cookie path for `/inspector` with **full mutation access** for v1 (deprecation in v2); never set this cookie format on new logins
- [ ] 11.12 Add session-cookie middleware that complements the existing token-bearer middleware on the inspector router
- [ ] 11.13 Tests: anonymous redirect, non-admin redirect, admin session grants access, legacy cookie path still authorizes mutations, deactivate confirmation modal blocks bad input, last-admin deactivation refused, all `/inspector/me/*` views are scoped to caller, every form POST without CSRF token returns 403

## 12. `hooksctl forward` ephemeral-token integration

- [ ] 12.1 Detect login state at startup: if a profile credentials file exists and `HOOKS_TOKEN` is unset, use the profile token
- [ ] 12.2 If running with a user PAT (i.e. `/api/me` returns 200 with a user) and no `--token` flag is set, POST `/api/me/tokens` with `kind='listener'`, `scopes=[<source>]`, `ephemeral=true` to mint an ephemeral listener token before opening SSE; store the returned `id` and `plaintext`
- [ ] 12.3 Use the ephemeral token for the SSE handshake; record token id in memory
- [ ] 12.4 Trap SIGINT / SIGTERM and on broken-pipe exit: POST `/api/me/tokens/{id}/revoke` with a 5s timeout; ignore errors but log on stderr
- [ ] 12.5 Skip ephemeral minting when `HOOKS_TOKEN` is explicitly set in the env OR when `--token <id>` is passed (preserve current behavior for CI, system tokens, and power-user long-lived listener tokens)
- [ ] 12.6 Update existing `cmd/hooksctl/forward_e2e_test.go` to cover three branches: explicit `HOOKS_TOKEN` (no `/api/me/tokens` call), `--token <id>` (no mint, no revoke), and login-aware mode (token created and revoked)
- [ ] 12.7 Server-side: extend the prune loop to revoke `ephemeral=true` tokens whose `last_used_at` is more than 24h in the past (or whose `created_at` is more than 24h in the past if never used), regardless of owner. Document the "unused for 24h" semantics in `docs/security.md`.

## 13. `hooks init` bootstrap-URL output

- [ ] 13.1 In the init flow, after schema migrations, count rows in `users`. If zero, call `InviteStore.EnsureBootstrap()` and capture the code (the call inserts a fresh 24h-TTL row, or replaces an existing expired bootstrap row atomically)
- [ ] 13.2 If a bootstrap code exists, print one line `signup: <server-url>/signup?code=<code>` after the existing token/curl output, with a note about the 24h TTL and single-use semantics
- [ ] 13.3 If `users` is non-empty (e.g. re-running `hooks init --force` against a populated DB), do not call `EnsureBootstrap` and do not print the signup line
- [ ] 13.4 Add a `--server-url` flag (or read `HOOKS_PUBLIC_URL` env var) so the printed signup URL points at the public hostname rather than `localhost`; fall back to a placeholder with a note if neither is set
- [ ] 13.5 Test: fresh DB → init prints signup line with valid code → second init (no users yet) within 24h prints the same code (idempotent) → second init after expiry prints a *new* code; existing DB with users → init does not insert another bootstrap row

## 14. Documentation

- [ ] 14.1 `docs/accounts.md`: walk through the cloud onboarding flow — deploy, hit signup URL, log in, run `hooksctl login` (covering `--scopes`/`--admin`), run `hooksctl forward` (default ephemeral path AND `--token` long-lived path)
- [ ] 14.2 Update `docs/security.md` with: the device-pairing plaintext window; the cookie session model and SHA-256-vs-Argon2 rationale; the cascading-revoke + reactivation-friction semantics; the CSRF strategy; the rate-limiting defaults; the audit-log surface; the password policy
- [ ] 14.3 Update `README.md` with a short "for developers joining a deployed relay" section pointing at `docs/accounts.md`
- [ ] 14.4 Update `CLAUDE.md` to mention the new `internal/users`, `internal/audit`, `internal/ratelimit` packages, the `/api/me/*` and `/api/auth/*` surfaces, the cookie session model (SHA-256 hashed, distinct from token Argon2id), the CSRF posture, the kind-split tokens (`pat` vs `listener`), and the system-vs-user-owned distinction on tokens and subscriptions

## 15. Verification and release

- [ ] 15.1 `make lint` clean (no new staticcheck/gosec warnings; new password, session, and audit paths inspected for plaintext-leak risk; verify all new persisted secrets flow through `internal/secret.String`)
- [ ] 15.2 `make test` clean across all packages
- [ ] 15.3 Manual smoke test against a freshly initialized DB: bootstrap signup → login → mint PAT via device pairing (verify password re-entry, scope-narrowing UI) → `hooksctl me token list` → `hooksctl forward` against a local target → see ephemeral token appear and disappear → check `/inspector/audit` for the resulting events
- [ ] 15.4 Manual smoke test of the cascading-revoke path: create user, mint two tokens (one PAT, one listener) and a push sub under them, deactivate, verify all three are immediately rejected/halted, verify last-admin guard prevents deactivating the only admin
- [ ] 15.5 Manual smoke test of the CSRF defenses: POST to `/api/me/tokens` from a tool that omits the CSRF cookie/token → 403; same with mismatched `Origin` → 403; legitimate inspector form succeeds
- [ ] 15.6 Manual smoke test of rate limiting: hammer `/api/auth/login` from one IP and confirm 429 with `Retry-After`
- [ ] 15.7 Release notes section enumerating the new endpoints, the cookie format change, the kind-split on `listener_tokens`, and the no-op migration story for existing v1 deployments
