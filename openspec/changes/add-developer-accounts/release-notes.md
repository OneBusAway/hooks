# Release notes — `add-developer-accounts`

This change introduces remote-first developer onboarding for the relay.
A deployed instance can now hand out developer accounts over the network
via invite codes, password login, and a CLI device-pairing flow — no
shell access to the host required. Cookie-authenticated surfaces are
CSRF-protected and rate-limited; an audit log records admin-meaningful
actions.

## Highlights for operators

- **No-op migration for existing v1 deployments.** `migrate()` adds the
  new columns (`owner_user_id`, `kind`, `ephemeral`, `expires_at` on
  `listener_tokens`; `owner_user_id` on `push_subscriptions`) via probe-
  and-`ALTER` deltas. Pre-existing tokens authenticate `/subscribe/<source>`
  unchanged; pre-existing push subscriptions resume dispatch with their
  cursors intact. There is no schema-version pin; running the new binary
  against a v1 database is the supported upgrade path.
- **Storage moves to sqlc-generated queries.** Hand-rolled SQL in
  `internal/store/sqlite.go` is replaced by a thin wrapper over the
  generated `*sqlcgen.Queries` type. This is a code-only change with
  zero on-disk impact — the existing contract tests (`contract_test.go`,
  `latest_test.go`) are the regression baseline and pass unchanged.
  Contributors must run `make sqlc` after editing `*.sql` queries or
  `internal/store/schema.sql`; CI's `make sqlc-diff` (wired into
  `make lint`) fails when the committed `internal/store/sqlcgen/`
  diverges from the schema/queries.
- **`hooks init` prints a signup URL.** On a fresh database `init` now
  emits one bootstrap invite (24-hour TTL, single-use, auto-disables
  once any account exists) alongside the existing token output. Run
  with `--server-url` (or set `HOOKS_PUBLIC_URL`) so the printed URL
  points at the public hostname.

## New endpoints

### Authentication & sessions

- `POST /api/auth/login` — email + password, sets `hooks_session` and
  `hooks_csrf` cookies.
- `POST /api/auth/logout` — deletes the session row and expires both
  cookies.
- `POST /api/auth/signup` — invite-gated user creation.
- `POST /api/auth/device/start` — CLI requests a device + user code.
- `POST /api/auth/device/poll` — CLI polls until approved.
- `POST /api/auth/device/approve` — authenticated approver mints a PAT.
- `POST /api/auth/device/deny` — authenticated approver denies a pairing.

### Self-service `/api/me/*`

- `GET /api/me`, `PATCH /api/me`
- `GET|POST /api/me/tokens`, `POST /api/me/tokens/{id}/revoke`
- `GET|POST /api/me/subscriptions`, `GET|DELETE /api/me/subscriptions/{id}`
- `POST /api/me/subscriptions/{id}/{pause,resume,rotate-secret,test}`

### Admin `/api/users` and `/api/audit`

- `GET /api/users`, `GET /api/users/{id}`, `PATCH /api/users/{id}`
- `POST /api/users/{id}/{deactivate,reactivate,reset-password}`
- `PATCH /api/tokens/{id}` and `PATCH /api/push-subscriptions/{id}` for
  ownership transfer; `?owner=` filter on `GET` versions.
- `GET /api/audit` — paginated read of `audit_events`.

### Invites

- `POST /api/invites`, `GET /api/invites`, `DELETE /api/invites/{code}`.

## Cookie format change

- `hooks_session` carries `<id>.<plaintext>`; the server stores the
  SHA-256 of the plaintext as `secret_hash`. (Argon2id remains for
  password and token hashes; sessions use SHA-256 because the
  randomness is already 256 bits — Argon2's slowness adds nothing.)
- `hooks_csrf` is a non-HttpOnly companion cookie used by the
  double-submit CSRF check. It rotates on every login.
- Both cookies are `SameSite=Lax`, `Path=/`. `Secure` is set when
  `r.TLS != nil` or (when `web.trust_proxy_headers=true`)
  `X-Forwarded-Proto: https`.

## `listener_tokens.kind` split

- `kind='pat'` — authorizes `/api/me/*` and the inspector. Cannot
  subscribe.
- `kind='listener'` — authorizes `/subscribe/<source>` (and, when
  admin-scoped, the inspector). Cannot manage `/api/me/*`.
- A mismatched-kind request returns 403, not 401 — a real token, but
  not the right kind.
- `hooksctl forward`, when running with a profile-loaded user PAT,
  auto-mints an `ephemeral=true, kind='listener'` token before opening
  the SSE stream and revokes it on exit. Set `HOOKS_TOKEN` or pass
  `--token <id>` to keep the existing long-lived-token behavior.

## CLI

- `hooksctl login [--scopes …] [--admin]` — runs the device-pairing
  loop and writes `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>`.
- `hooksctl logout` — revokes the saved PAT and deletes the credentials
  file.
- `hooksctl whoami` — reports email + role + server.
- `hooksctl me token {add,list,revoke}` and
  `hooksctl me sub {add,list,pause,resume,rotate-secret,rm,test}` —
  caller-scoped equivalents of the admin `token` and `push` subcommands.
- `hooksctl invite {create,list,revoke}` — admin-scoped invite
  management without shelling into the host.

## Defenses

- **CSRF.** Every cookie-authenticated mutation requires a same-host
  `Origin` (or `Referer` fallback) and a constant-time match between
  the `hooks_csrf` cookie and the form/header `csrf_token` value.
  Bearer-only requests bypass entirely.
- **Rate limiting.** Token-bucket-per-key middleware, with `KeyByIP`
  and `KeyByUser`. Defaults: login 5/min/IP + 30/hour/IP; signup 3/min
  + 10/hour; device start 10/min/IP; device poll 60/min/IP; device
  approve 10/min/user. 429 responses include `Retry-After`.
- **Password policy.** Length ≥ 12; rejects passwords containing the
  user's email substring (case-folded). Failure reason is logged; the
  plaintext is never persisted to logs.

## Audit log

A new `audit_events` table records invite lifecycle, user lifecycle,
session create/delete, ownership transfer, password reset, and device-
pairing approve/deny/start. Visible at `GET /api/audit` and
`/inspector/audit` (admin-only). The table is append-only — no DELETE
or UPDATE in production code paths, and the prune loop does not touch
it.

## Breaking changes

None for v1. The legacy raw-bearer-in-cookie inspector path retains
**full mutation access** to keep operator bootstrap working; deprecation
is scheduled for v2.

## Contributor notes

- `make sqlc` regenerates `internal/store/sqlcgen/`; `sqlc.yaml` at the
  repo root is the configuration of record. The schema lives at
  `internal/store/schema.sql` (canonical, fully-migrated); upgrade-only
  deltas live in `internal/store/migrations.go`.
- New packages: `internal/users`, `internal/audit`, `internal/ratelimit`,
  `internal/auth`, `internal/devicepair`, `internal/invites`,
  `internal/me`, `internal/admin`, `internal/web`, `internal/webpages`.
- See `docs/accounts.md` for the full onboarding walkthrough and
  `docs/security.md` for the security posture (cookie model, CSRF,
  cascading revoke, rate-limit defaults, password policy, audit log).
