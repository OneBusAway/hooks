## Context

The relay's first cut shipped with a single-operator mental model: the person who runs `hooks init` is the same person who runs `hooksctl token add`, and credentials are passed to teammates by some out-of-band mechanism (Slack DM, a 1Password share, shell access to the server). That model collapses the moment we deploy the relay to Render or any other PaaS:

- Operators do not have shell access on a managed PaaS (or they have it via a deploy SSH that is awkward to script).
- A new teammate needs a way to *get* a token without an admin running CLI commands per-onboarding.
- Push-subscription registration today requires either an admin token in the dev's hands or out-of-band coordination with whoever has one.
- Cookie sessions for the inspector are currently the raw plaintext bearer token; usable, but ill-suited to multi-user contexts.

The data model already separates tokens, push subscriptions, and the event store cleanly. Token lookup is Argon2id-hashed and constant-time. The HTTP surface has a small admin scope. We add a user identity layer that *owns* tokens and subscriptions, plus a remote-friendly authentication flow, without disturbing those cores.

We deliberately stop short of a multi-tenant SaaS posture. There is one relay deployment per team. Users within that deployment trust each other broadly; the security boundary is "people in our org" vs "the public internet". This is the same posture as a self-hosted Plausible or Forgejo instance.

The guiding tension throughout is **best-in-class webhook DX vs. a highly secure environment**. Where the two collide, defaults are secure and the DX path is an explicit, documented opt-in.

## Goals / Non-Goals

**Goals:**
- A developer with no shell access to the relay host can, in one browser session, create an account on a deployed relay and get a CLI ready to consume webhooks.
- `hooksctl login` over the network — no shared filesystem, no password ever entered into the CLI.
- After login, `hooksctl forward` and `hooksctl push add` work with no further token plumbing.
- Listener tokens and push subscriptions are owned by users; revoking a user revokes their resources.
- Admin retains full visibility and management over every user's resources.
- Bootstrap a brand-new cloud deployment from a browser — `hooks init` prints a one-time admin-bootstrap signup URL that auto-disables once the first account exists or after 24 hours.
- Existing token + subscription state continues to work without migration.
- Every cookie-authenticated mutation is CSRF-protected; every authentication endpoint is rate-limited; every admin-meaningful action is recorded in an audit log.

**Non-Goals:**
- Open public signup (any URL anyone hits creates an account). Signup is always gated on an invite code.
- Email verification, forgot-password recovery flows. Admin resets passwords directly via the inspector or `hooksctl user reset-password`.
- OAuth / SSO. The interface is shaped to allow an external IdP later (the User has a stable `external_id` field reserved), but v1 is local password only.
- Per-user *quotas* on tokens or subscriptions. We log how many of each a user has, but enforce no caps in v1.
- Multi-tenant org separation, billing, role hierarchies beyond `admin` / `user`.
- A web flow for password change in v1 — admin reset is sufficient. (We will add user self-service password change as a follow-up but intentionally exclude it here to keep the surface small.)
- Replacing the existing system-owned-token bootstrap path. `hooks init` still mints a system admin token; user accounts are layered on top.
- HIBP-style breach-corpus checks on signup passwords. Length and email-substring rejection are sufficient for v1.

## Decisions

### Identity model: two roles, single concept

A `users` table with a `role` column (`admin` | `user`) and a stable `id`, `email` (unique, NOCASE), `name`, `password_hash` (Argon2id), `created_at`, `deactivated_at`. Listener tokens and push subscriptions get a nullable `owner_user_id`. NULL means "system-owned" — the existing bootstrap admin token from `hooks init` remains valid and continues to authorize as admin without belonging to a user. **Setting `owner_user_id=NULL` does not mutate scope assignment**; system tokens retain whatever scopes they were minted with, which today are the admin scope plus any explicitly-listed source scopes.

We considered `roles` as a many-to-many relation. Rejected: the v1 RBAC surface is two values, and a column-per-row is direct and reversible.

We considered making the first user always implicit (e.g. derived from `hooks init`). Rejected: the existing init token is a *system* credential, not a person; conflating the two would force admins to log in as the system token, which is not how we want service credentials handled.

### Authentication: web sessions + personal access tokens + listener tokens

Two credential **shapes**, three credential **kinds**, one user record:

- **Web session**: the inspector's `Cookie: hooks_session=<id>.<plaintext>` carries a server-side session row. The session secret plaintext is 32 random bytes; we store its **SHA-256 digest** on the row (not Argon2id) and constant-time compare. Argon2's slowness exists to defend against offline attacks on low-entropy passwords; session secrets are 256-bit random and have no offline-attack surface. Skipping Argon2 here removes a per-request CPU tax without weakening the threat model. 30-day TTL, sliding on activity.
- **Personal access token (PAT)** — `kind='pat'` listener-token row, owned by a user. Sent as `Authorization: Bearer <token>`. The CLI device-pairing flow returns one of these. PATs authorize `/api/me/*` and the inspector but **NOT** `/subscribe/<source>`. Plaintext is hashed with Argon2id (low-entropy attacker-knowable derivation paths via the device-pairing window justify the heavier hash; consistent with our existing token primitive).
- **Listener token** — `kind='listener'` listener-token row. Authorizes `/subscribe/<source>` and (when admin-scoped) the inspector. Cannot reach `/api/me/*`. Argon2id-hashed.

The two kinds share a row schema and a hashing primitive but are routed by `kind` at lookup time, so a stolen `pat` cannot be used to silently subscribe to events and a stolen `listener` cannot mint new tokens. PATs and listener tokens both support `expires_at` (nullable; max 1 year on creation).

Why three: the inspector needs a cookie (browsers can't be told to send `Authorization` for arbitrary navigation), the CLI needs a long-lived bearer for management calls, and SSE consumers need a long-lived bearer for the data plane — and the data-plane bearer must not also grant write access to `/api/me`.

We considered putting the PAT directly in the cookie (today's behavior, just with a user attached). Rejected: cookies carrying long-lived high-privilege bearers are awkward to revoke (you'd have to revoke the underlying PAT, which then breaks the CLI), and conflate the lifetime of a "browser visit" with "machine credential".

We considered using Argon2id for session-cookie verification too. Rejected: per-request Argon2 over a 32-byte-random secret is pure cost. SHA-256 is sufficient given the input distribution; we keep Argon2 for passwords and bearer-token plaintexts where the attacker controls the input space.

### CLI device pairing

The flow:

1. `hooksctl login --server https://hooks.example.com [--scopes render,stripe] [--admin]` posts to `/api/auth/device/start` with the requested scopes (default `["account"]`). Server returns `{device_code, user_code, verification_uri, interval, expires_in}`. The `user_code` is short and human-readable (`ABCD-EFGH`, base32, 8 chars without `0/1/I/O/L`). The server records `requesting_ip`, `requesting_user_agent`, and `requested_scopes` on the device row.
2. CLI prints: "Visit https://hooks.example.com/device and enter ABCD-EFGH" and (on TTY) tries to open the browser. CLI then polls `POST /api/auth/device/poll {device_code}` every `interval` seconds.
3. The `/device` page asks the user to log in (or signup with an invite) if not already, then shows the pending pairing prominently displaying the requesting client's user-agent, IP, and the requested scopes, with the explicit warning **"Approve only if you started this on this machine."**. The page contains a CSRF-protected form requiring the user to **re-enter their password** (session alone is not sufficient). The approver may narrow the requested scopes via checkboxes but cannot widen them. Approval mints a **PAT** (`kind='pat'`) scoped to the (possibly narrowed) requested set; the request is rejected with HTTP 403 if the requested scopes exceed what the user holds. A user requesting `--admin` who is not an admin is rejected at `/api/auth/device/start` time.
4. Approval inserts a `listener_tokens` row with `kind='pat'`, `owner_user_id=user`, and the agreed scopes; stores `(plaintext, secret_hash)` on the device row temporarily; sets `status=approved_unfetched`. Subsequent CLI poll returns `200` with `{token, user_id, name, scopes}`. **The transition to `done` and the NULL-out of `plaintext_token` happen as a deferred update on handler return** — we explicitly do not tie the commit to TCP-write success. If the response write fails partway, the row stays `approved_unfetched` and the next poll (CLI's retry) succeeds. The user can re-run `hooksctl login` if they get nothing.
5. CLI writes the token to `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>` (file mode `0600`, format TOML, see "Credentials file format" below). `--profile <name>` lets users keep multiple servers configured; default profile name is `default`.

States: `pending` (initial), `approved_unfetched` (user clicked approve, CLI hasn't polled yet), `done` (CLI fetched, plaintext purged), `denied`, `expired`. `expires_in` defaults to 15 minutes. The device row is purged 24h after terminal state.

We considered a simpler "paste a PAT into the CLI" flow. Rejected: it requires copy/paste of a long secret across the user's screen and is hostile to terminal multiplexing / screen sharing.

### Device-pairing default scope and phishing defenses

A logged-in user can be socially engineered into approving an attacker-started pairing (the attacker hits `/api/auth/device/start` from their machine and tricks the victim into typing the user code). Three layered defenses:

1. **Narrow-by-default scope**. Approval defaults to `account` only. Even a successful phish yields a PAT that cannot subscribe to events or mint further tokens beyond what the calling user has. The CLI explicitly opts in to broader scope via `--scopes` and `--admin`; the `/device` page surfaces the requested scopes prominently and lets the approver narrow them.
2. **Approver context display**. The `/device` page shows the requesting client's user-agent, IP, and human-readable scope list, with a "Approve only if you started this on this machine" warning.
3. **Password re-entry**. Approval requires the user to type their password into a CSRF-protected form alongside the user code. A live session alone is insufficient. This raises the bar for an attacker to "phish the password and the user code in the same session", which is materially harder than "trick a logged-in user into clicking Approve".

Each mitigation is cheap individually; together they are layered. Documented in `docs/security.md`.

### CSRF and request-origin defenses

Every state-changing endpoint that accepts a cookie session checks **both**:

- **Origin/Referer**: the `Origin` header (or `Referer` if `Origin` is absent) must match the request host. `Origin: null` is treated as cross-origin and rejected. Browsers without an `Origin` header on POST (rare in current versions) fall back to `Referer`; absent both, the request is rejected.
- **CSRF token (server-rendered double submit)**: every inspector mutation form embeds a per-session random CSRF token in a hidden field. The server reads the matching token from a `hooks_csrf` cookie set alongside the session and constant-time compares the form value to the cookie. API endpoints that are *only* called by `hooksctl` over `Authorization: Bearer` (no cookie) are exempt — bearer-only requests can't be CSRF'd.

Endpoints covered: `/api/auth/login`, `/api/auth/logout`, `/api/auth/signup`, `/api/auth/device/approve`, `/api/auth/device/deny`, `/api/me/*` mutations, `/api/users/*` mutations, `/api/invites/*` mutations, admin `/api/tokens` mutations, admin `/api/push-subscriptions` mutations.

We considered SameSite=Lax cookies as a sole CSRF defense. Rejected: Lax permits top-level cross-site GETs (fine — they're idempotent) but POSTs from a malicious origin still need defense in depth, and the `Origin`+token combination is well-understood and cheap to implement.

### Session-cookie verification

Session row stores `secret_hash = sha256(plaintext)` where `plaintext` is 32 random bytes (`crypto/rand` → URL-safe base64). On request: split cookie on `.`, look up by `id` (UUIDv4 → O(1)), compute SHA-256 of the supplied plaintext, constant-time compare against `secret_hash`. Argon2id is reserved for passwords (low-entropy attacker input space) and listener-token plaintexts (interim window where plaintext is captured during device pairing). Per-request CPU cost goes from "Argon2 over one row" to "one SHA-256 + a constant-time compare", which matters under any sustained inspector load.

### Invite codes and bootstrap

Signup is always invite-gated. The invite is a row `(code, role, default_scopes JSON, created_by_user_id, bootstrap, created_at, expires_at, consumed_at, consumed_by_user_id)`. `code` is base32, 16 chars, uniformly random. `consumed_at IS NOT NULL` makes it single-use. Admin generates invites via `hooks invite` (server-side CLI, no network), via `hooksctl invite create` (remote, hits `/api/invites` with the admin's PAT), or via `/api/invites` directly. Invites can carry the `admin` role — that's how a second admin is added.

For `admin`-role invites, `default_scopes` are accepted on the wire and **stored**, but **unused** at auth time: admin role implicitly holds all source scopes plus `admin`. Persisting the field keeps the invite payload uniform with non-admin invites and reserves room for richer roles later without a migration.

The bootstrap problem: a freshly deployed cloud relay has nobody who can run CLI commands. Solution: `hooks init` (or its first run on an empty DB) inserts a single special invite row tagged `bootstrap=true`, role `admin`, **`expires_at = now + 24h`**. `hooks init` prints the signup URL containing this code. The bootstrap invite is consumed automatically the first time *any* user record is created, regardless of which invite was used to create it. After that, the bootstrap invite is dead — even if someone copied the URL, signing up via it returns 409. If the bootstrap invite expires before being used, the operator can re-run `hooks init` against the still-userless DB to regenerate it (the existing expired bootstrap row is replaced atomically); a fresh expiration window starts.

We considered allowing open signup until the first account is created. Rejected: races between bootstrap and someone else hitting the URL widen the window unnecessarily; a single-use code is just as easy. We considered an unbounded TTL on the bootstrap invite. Rejected: a never-expiring admin-role invite sitting in the database after the operator forgets about it is a liability proportional to deployment lifetime; 24 hours is enough for any real onboarding cadence.

### Self-service vs admin endpoints

- `/api/me/tokens` — list/create/revoke listener tokens or PATs owned by the calling user; `kind` is selectable on create (`pat` default).
- `/api/me/subscriptions` — list/create/pause/resume/rotate-secret/delete push subscriptions owned by the calling user.
- `/api/me` — get/patch own profile (name only in v1).
- `/api/users` (admin) — list, create-by-invite, deactivate, reactivate, edit `default_scopes` and `name`.
- `/api/invites` (admin) — issue, list, revoke.
- `/api/tokens`, `/api/push` (admin) — preserved; gain `?owner=<user_id>` filter; can target any user's resources.

Scope rules for token issuance under `/api/me/tokens`:

- A user can only request scopes they *hold*. The `account` scope is always implicitly held by every active user, and the server forces `account` into every minted PAT's scope set unless the caller is explicitly minting a `kind='listener'` token (in which case `account` is not auto-injected — listener tokens have no business reaching `/api/me/*`).
- Admins implicitly hold every source scope and `admin`.
- Non-admin users hold the source scopes their admin granted at user-create time (stored on the user row as `default_scopes`), editable via `PATCH /api/users/{id}`.
- Empty scope arrays on `kind='pat'` are rejected as misconfiguration; the server normalizes to `["account"]` rather than minting an unprivileged ghost token.

We considered letting users request arbitrary scopes and gating creation on admin approval. Rejected: that's an inferior version of "admin grants me a token directly" and adds latency to dev onboarding.

### Scope evaluation: token-level

All scope checks are evaluated against the **bearer's scopes**. For cookie-session requests, the auth layer treats the request as if the session's user had a synthetic bearer with scopes equal to `default_scopes ∪ {account}` (and additionally the full source-scope set + `admin` if the user has the admin role). This unifies the two authentication shapes into a single "what scopes does this caller have" predicate at the policy boundary.

Documented once in `specs/event-subscription/spec.md` to remove ambiguity around "user-level vs token-level" phrasing.

### Token and subscription ownership semantics

- Setting `owner_user_id = NULL` is reserved for system tokens minted by `hooks init` or `hooksctl token add` against an empty DB. The migration leaves all existing rows at NULL; they continue to work with their original scopes. NULLing ownership does **not** mutate the row's scopes — system identity is orthogonal to scope assignment.
- Deactivating a user (via `/api/users/{id}/deactivate`) sets `deactivated_at` and *atomically* revokes their tokens (sets `revoked_at` on every PAT and listener token, including ephemeral ones — there's no special case) and pauses their push subscriptions (sets `paused_at`). Reactivation does not auto-resume — the user must reissue tokens and unpause subscriptions themselves. **This matches GitHub's account-disable UX.** The friction is intentional: reactivation should be a deliberate, observable action, not a silent restoration of prior privilege.
- Last-admin guard: `POST /api/users/{id}/deactivate` refuses with HTTP 409 if it would leave zero active admins. Same guard applies to any future role-demotion endpoint.
- Admin can transfer ownership via `PATCH /api/tokens/{id} {"owner_user_id": "..."}` or `PATCH /api/push-subscriptions/{id}` for cleanup / migration scenarios.

### `hooksctl forward` modes

After `hooksctl login`, `hooksctl forward --source render --to http://localhost:3000` defaults to:

1. POST `/api/me/tokens` with `kind='listener'`, `name='forward-<hostname>-<random-suffix>'`, `scopes=[<source>]`, `ephemeral=true`.
2. Open SSE on `/subscribe/<source>` with that token.
3. On disconnect (Ctrl-C, broken pipe, exit), POST to `/api/me/tokens/{id}/revoke`.
4. Crash recovery: `ephemeral=true` tokens are auto-revoked when **unused for 24h** (`now - last_used_at > 24h`) by the existing prune loop. A live `forward` keeps `last_used_at` fresh; a stopped `forward` whose revoke POST failed leaves the token to expire on inactivity.

A `--token <id>` flag short-circuits the mint/revoke dance and reuses a long-lived `kind='listener'` token the user minted via `hooksctl me token add --kind listener --scopes render`. This is the "I run forward all day every day" power-user path — documented in `docs/accounts.md`. Ephemeral remains the friendly default.

This means a dev's laptop can come and go without leaving credential debris.

### Credentials file format

The credentials file lives at `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>`, default profile `default`. Format is TOML:

```
server_url  = "https://hooks.example.com"
token       = "<plaintext PAT>"
created_at  = "2026-05-08T12:00:00Z"
expires_at  = "2027-05-08T12:00:00Z"   # optional; omitted when no expiry
```

File mode is `0600`. The `<host>`-suffixed naming used in earlier drafts is **abandoned** in favor of `<profile>`, eliminating ambiguity around "which file does the CLI read by default" in single-server installs.

### Cookie session storage

Sessions live in `user_sessions(id, user_id, secret_hash, created_at, last_used_at, expires_at, user_agent, ip)`. The cookie value is `<session_id>.<plaintext>`. Server splits on the dot, looks up by id, hashes plaintext via SHA-256, constant-time compares. Session id is a UUIDv4 to make lookup O(1); the secret hash protects against id-only theft. The session cookie is marked `Secure` if `r.TLS != nil` OR (when `web.trust_proxy_headers=true` in `hooks.yaml`) `r.Header.Get("X-Forwarded-Proto") == "https"`. Default config does not trust proxy headers.

We considered JWTs / signed cookies. Rejected: opaque server-stored sessions are revocable instantly (a JWT is valid until expiry no matter what), and we already have the storage primitive.

### Audit log

`audit_events(id PK, at TIMESTAMP, actor_user_id FK NULLABLE, actor_token_id FK NULLABLE, action TEXT, target_type TEXT, target_id TEXT, metadata JSON)`. Recorded actions:

- `invite.create`, `invite.revoke`, `invite.consume`
- `user.create`, `user.deactivate`, `user.reactivate`, `user.role_change`, `user.update`
- `user.password_reset`
- `token.transfer_owner`, `subscription.transfer_owner`
- `session.create`, `session.delete`
- `device_pairing.start`, `device_pairing.approve`, `device_pairing.deny`

Surfaced at `/inspector/audit` (admin only). The page supports filtering by actor and time range. The audit log is **append-only**: there is no UI or API surface to delete entries; the prune loop does not touch this table. A future admin may run SQL by hand to expire old entries; v1 declines to define a retention policy because the data is small (a few hundred bytes per event in a table that grows on operator actions, not webhook traffic).

We considered embedding audit metadata into the row touched by each action (e.g. `created_by_user_id` on `users`). Rejected: that captures *creation* but not deletion or revocation, and it can't model multi-actor histories. A dedicated table costs little and gives admins one place to look. Promoted from "Open Question" to "Decision" because the `audit-log` capability is now declared in `proposal.md`.

### Rate limiting

Token-bucket-per-IP middleware in `internal/ratelimit`, applied to the auth surfaces:

- `POST /api/auth/login` — 5/min/IP, 30/hour/IP.
- `POST /api/auth/signup` — 3/min/IP, 10/hour/IP.
- `POST /api/auth/device/start` — 10/min/IP.
- `POST /api/auth/device/poll` — 60/min/IP (the per-`device_code` `interval` is server-controlled by the response payload already).
- `POST /api/auth/device/approve` — 10/min/user.

Excess requests return HTTP 429 with `Retry-After: <seconds>`. Buckets live in process memory; on restart they reset to full (acceptable in a single-process deployment). Future Postgres/Redis backend can swap the implementation without changing the middleware contract.

### Password policy

`internal/users` enforces on signup and password reset:

- Length ≥ 12 characters (Unicode codepoints).
- The password (case-folded) does not contain the user's email local-part or full email.

Rejected requests return HTTP 400 with a generic "password does not meet policy" message; the server logs the *failed-policy reason* (length / contains-email) but never the attempted plaintext. We deliberately do not integrate HIBP-style breach corpora in v1; the goal is "block the obvious mistakes", not "block all known-breached passwords".

### Storage layer: sqlc-generated queries

We adopt [sqlc](https://sqlc.dev) (engine `sqlite`) as the source of truth for every SQL query in `internal/store`. This change is the moment to do it: we are adding five new tables (`users`, `user_sessions`, `invites`, `device_pairings`, `audit_events`), altering two existing tables (`listener_tokens`, `push_subscriptions`), and introducing roughly two dozen new queries (owner-filtered token and subscription lookups, cascading deactivation, audit insert/read, invite lifecycle, device-pairing state transitions). Hand-rolling that volume of SQL alongside the existing hand-rolled paths gives us two storage idioms in the same package and twice the surface for typos and stale-after-refactor bugs. sqlc gives us compile-time-checked types end-to-end with effectively no runtime cost (the generated code is a thin wrapper over `database/sql`).

**Scope note.** This change moves *all* storage to sqlc, not only the newly added tables. The existing `events`, `listener_tokens`, and `push_subscriptions` queries are also rewritten as `.sql` files and regenerated. Mixing two query patterns in `internal/store` is worse than uniformly using sqlc; doing the migration in this change keeps `internal/store/sqlite.go` from having to grow to encompass both styles. The existing `internal/store/contract_test.go` and `internal/store/latest_test.go` are interface-level tests and continue to pass against the rewrite without modification — that is the regression baseline for "no behavior change to existing storage callers."

#### Layout

```
sqlc.yaml                                    # repo root, version: "2"
internal/store/
  ├─ types.go                                # public types (Event, Token, …) + new types (User, Session, Invite, DevicePairing, AuditEvent). Unchanged in shape; the existing public surface is preserved.
  ├─ adapters.go                             # public-interface adapters; gains new ones for the new stores.
  ├─ sqlite.go                               # boot, *sql.DB pool, pragmas, migrate(), interface impls — much shorter; delegates queries to sqlc.
  ├─ migrations.go                           # idempotent ALTER TABLE deltas for upgrading existing v1 deployments (see "Schema vs migrations" below).
  ├─ schema.sql                              # canonical fully-migrated schema; sqlc reads this for type inference; embedded into binary for fresh-DB CREATE TABLE. Lives OUTSIDE queries/ so sqlc does not parse it twice.
  ├─ queries/
  │   ├─ events.sql                          # rewritten queries for the events table.
  │   ├─ tokens.sql                          # listener_tokens queries (with the new owner/kind/ephemeral/expires_at columns).
  │   ├─ push.sql                            # push_subscriptions queries (with owner column).
  │   ├─ users.sql                           # NEW.
  │   ├─ sessions.sql                        # NEW.
  │   ├─ invites.sql                         # NEW.
  │   ├─ device_pairings.sql                 # NEW.
  │   └─ audit.sql                           # NEW.
  └─ sqlcgen/                                # checked in; regenerated via `go generate ./...`.
      ├─ db.go                               # DBTX, *Queries, WithTx.
      ├─ models.go                           # one struct per table.
      └─ <name>.sql.go                       # one file per query .sql input.
```

`schema.sql` lives one level above the `queries/` directory on purpose. sqlc's `queries:` setting walks every `.sql` file in the directory it points at, so a `schema.sql` co-located with the query files would be read twice — once as schema and again (without `-- name:` annotations) as a query file — and sqlc would either error on the unrecognized DDL or, worse, silently re-parse the CREATEs. Keeping the two paths disjoint side-steps that.

`sqlc.yaml`:

```yaml
version: "2"
sql:
  - engine: sqlite
    schema: internal/store/schema.sql
    queries: internal/store/queries
    gen:
      go:
        package: sqlcgen
        out: internal/store/sqlcgen
        emit_interface: true        # so wrapper code can mock *Queries in tests if needed
        emit_json_tags: false       # we do not serialize generated structs over the wire
        emit_prepared_queries: false
        # We deliberately do NOT enable emit_pointers_for_null_types: it is a
        # global toggle (per-column control would require an `overrides:` block
        # per nullable column, which we don't want either). We keep sqlc's
        # defaults (sql.NullInt64 / sql.NullString) so the wrapper layer is the
        # single place that converts to the public types' *time.Time / *string
        # shapes. See "Type mapping" below.
```

A `//go:generate go tool sqlc generate` directive in `internal/store/sqlc_gen.go` keeps regeneration discoverable. CI runs `sqlc diff` (added to `make lint`) so a query-without-regenerated-code change fails the build.

#### Schema vs migrations

`internal/store/schema.sql` is the **canonical fully-migrated schema** — what a brand-new database looks like after every migration has been applied. sqlc reads this file at codegen time for type inference; the runtime also applies it verbatim on every boot via `db.ExecContext(schemaSQL)` (the file is `//go:embed`-ed into `sqlite.go`). Every `CREATE TABLE` and `CREATE INDEX` in the file uses `IF NOT EXISTS` so re-applying is idempotent.

`internal/store/migrations.go` carries the "delta" steps that bring an existing v1 deployment forward — specifically, the `ALTER TABLE listener_tokens ADD COLUMN owner_user_id …` and the four sibling additions, plus `ALTER TABLE push_subscriptions ADD COLUMN owner_user_id …`. SQLite has no `ADD COLUMN IF NOT EXISTS`; each delta probes `PRAGMA table_info(<table>)` and only issues the ALTER when the column is absent. Deltas run *after* the canonical schema apply, so a fresh DB sees them as no-ops (the columns already exist from the canonical CREATE TABLE) and an existing DB sees them add the missing columns. CHECK constraints on existing rows: SQLite enforces CHECK constraints at write time, not at ALTER time; the backfill writes valid values (`kind='listener'`) so the CHECK never fires on existing rows.

We considered switching to a versioned migration runner (`golang-migrate`, `goose`). Rejected for v1: the codebase has exactly one tool-applied migration today (the implicit "create-if-missing" inline schema), the additive delta is small, and a third-party migration runner would be more new infrastructure than the change warrants. The probe-and-ALTER pattern remains correct as long as we never need to drop or rename a column; if we hit that, we revisit.

#### Type mapping conventions

sqlc's SQLite engine maps types straightforwardly:

| SQL column                         | sqlc-generated Go type | Wrapper-layer public type      |
|------------------------------------|------------------------|--------------------------------|
| `INTEGER NOT NULL` (UNIX nanos)    | `int64`                | `time.Time` (UTC)              |
| `INTEGER` (nullable, UNIX nanos)   | `sql.NullInt64`        | `*time.Time` (UTC, nil if invalid) |
| `INTEGER NOT NULL` (numeric)       | `int64`                | `int64`                        |
| `TEXT NOT NULL`                    | `string`               | `string`                       |
| `TEXT` (nullable)                  | `sql.NullString`       | `*string` or `""` (per field)  |
| `TEXT` containing JSON             | `string`               | `[]string` / `map[string]any` (wrapper marshals/unmarshals) |
| `TEXT` comma-separated scopes      | `string`               | `[]string` (existing splitScopes/joinScopes helpers) |
| `BOOL NOT NULL` (`INTEGER 0/1`)    | `int64`                | `bool` (wrapper converts)      |
| `BLOB NOT NULL`                    | `[]byte`               | `[]byte`                       |

We deliberately keep sqlc's defaults (no `emit_pointers_for_null_types`) so the conversion happens in exactly one place — the wrapper layer in `sqlite.go` and friends. Public callers continue to see `time.Time`, `*time.Time`, `[]string`, `bool`. Generated code stays close to the SQL.

The existing custom encoding for the `scopes` column (comma-separated TEXT) is preserved unchanged; the wrapper helpers `splitScopes` and `joinScopes` already exist (`sqlite.go:642`). New JSON-shaped TEXT columns (`invites.default_scopes`, `device_pairings.requested_scopes`, `audit_events.metadata`) are marshaled/unmarshaled in the wrapper using `encoding/json`. Empty arrays marshal to `[]`, never `null`, so `IS NULL` does not have to be a meaningful state for those columns at the SQL layer; they are `TEXT NOT NULL DEFAULT '[]'` (or `'{}'` for object-shaped metadata).

#### Transactions

Every multi-statement invariant in the change runs through `*sql.DB.BeginTx` → `q.WithTx(tx)` → multiple sqlc-generated calls → `tx.Commit()`. Specifically:

- `EventStore.Append` — dedupe SELECT, `MAX(sequence)+1`, INSERT (existing invariant, preserved verbatim).
- `Signup` — `MarkInviteConsumed` + `InsertUser` + audit `InsertEvent` for `user.create` and `invite.consume`. Roll back if user-insert fails; the invite stays unconsumed.
- `DeactivateUser` — `SetUserDeactivatedAt` + `RevokeTokensByOwner` + `PauseSubscriptionsByOwner` + audit `InsertEvent` for `user.deactivate`. Last-admin guard runs as `CountActiveAdminsExcluding($id) :one` before opening the tx and as a re-check inside it (the second check protects against a race where two admins deactivate each other concurrently; the second tx sees zero admins and 409s).
- `BootstrapInviteEnsure` — within a tx: `SELECT bootstrap row` → if missing or expired, `DELETE` + `INSERT` with fresh code and `now+24h`.
- `DevicePairingApprove` — within a tx: `GetDevicePairingByUserCode FOR UPDATE`-equivalent (see below) + `InsertToken` + `UpdateDevicePairingApproved` (sets `status='approved_unfetched'`, `plaintext_token=?`, `token_id=?`) + audit `InsertEvent`.

SQLite under `MaxOpenConns=1` serializes writers; we do not need explicit row-level locking. The single-writer invariant is documented in CLAUDE.md and unchanged by this work.

#### What stays hand-written (and why)

A few paths remain in Go even with sqlc-generated SQL underneath:

- **`TokenStore.LookupByPlaintext`** — sqlc generates `ListActiveTokens :many`; the wrapper iterates the rows and calls the injected `s.tokenHash(plaintext, encoded)` per row to do the Argon2id constant-time compare. This loop cannot be expressed as a SQL query (the hash function lives in `internal/tokens` to keep `internal/store` argon2-free; CLAUDE.md captures the rationale). Same pattern applies to `SessionStore.LookupByID` (SHA-256 compare) and `UserStore.AuthenticatePassword` (Argon2id over `password_hash`).
- **`Append`'s headers and body sha256 computation** — staged in Go (`json.Marshal(headers)`, `sha256.Sum256(body)`) before the sqlc-generated insert is called. Putting that in SQL would mean letting SQLite hash the body, which sqlc's SQLite engine does not have a clean way to bind anyway.
- **Time conversion** — `time.Time` ↔ UNIX nanoseconds happens at the wrapper boundary, not inside sqlc-generated code.
- **Cascading-revoke metadata** — the audit row's `metadata` JSON (counts of revoked tokens, paused subscriptions) is composed in Go from the `RowsAffected()` returns of the prior statements in the tx.

These are the only SQL-adjacent code paths in Go. Everything else — every parameterized SELECT, INSERT, UPDATE, DELETE — is generated.

#### Migration of existing tests

`internal/store/contract_test.go` and `internal/store/latest_test.go` continue to drive the public interface; they pass against the sqlc-backed implementation unchanged, which serves as the safety net that the rewrite preserves observable behavior. We add `internal/store/sqlcgen_test.go` exercising the new sqlc-generated methods directly (one happy-path call per generated method, against an in-memory SQLite database initialized from `schema.sql`) — small but it catches regression in the canonical schema and codegen output.

### Data model summary

```
users              (id, email [+ UNIQUE INDEX on email COLLATE NOCASE], name, role,
                    password_hash, default_scopes JSON, created_at, deactivated_at, external_id NULLABLE)
user_sessions      (id, user_id FK, secret_hash, created_at, last_used_at,
                    expires_at, user_agent, ip)
invites            (code UNIQUE, role, default_scopes JSON, created_by_user_id FK NULLABLE,
                    bootstrap BOOL, created_at, expires_at, consumed_at, consumed_by_user_id FK)
device_pairings    (device_code, user_code, status, created_at, expires_at,
                    user_id FK NULLABLE, requesting_ip, requesting_user_agent,
                    requested_scopes JSON, plaintext_token NULLABLE, token_id FK NULLABLE)
listener_tokens    (... existing columns ..., owner_user_id FK NULLABLE,
                    kind TEXT CHECK IN ('pat','listener') DEFAULT 'listener',
                    ephemeral BOOL DEFAULT 0,
                    expires_at TIMESTAMP NULLABLE)
push_subscriptions (... existing columns ..., owner_user_id FK NULLABLE)
audit_events       (id PK, at, actor_user_id FK NULLABLE, actor_token_id FK NULLABLE,
                    action, target_type, target_id, metadata JSON)
```

`device_pairings.plaintext_token` is the only place plaintext token material is persisted, and it is purged the instant the CLI fetches it (or 24h after a terminal state). That's an acceptable narrow window — equivalent to the existing reveal-once UX of token creation.

All persisted secret material (passwords, token hashes, session secret hashes, plaintext device-pairing tokens during their narrow window) flows through `internal/secret.String` at config and log boundaries; comparisons use `secret.Equal*` or `hmac.Equal`. No plaintext secret SHALL appear in logs.

## Risks / Trade-offs

- **Bootstrap invite leak**: if `hooks init` output is logged to a system log capture, the bootstrap signup URL is in there. → Mitigation: 24-hour TTL, single-use, "expires once any account is created" notice in the printed line; admins can manually delete the bootstrap invite via SQL or `hooks invite revoke <code>` if concerned.
- **Plaintext token at rest in `device_pairings`**: a small window (between approval and first poll) where a user-issued PAT is stored plaintext in SQLite. → Mitigation: 15-minute hard cap on pairings; plaintext column zeroed in a deferred update on response-handler return; we already accept the same model for `hooksctl token add`'s reveal-once. Documented in `docs/security.md`.
- **Race in device-pair fetch**: CLI polls and sees `approved`, but a network timeout makes it miss the response. → Mitigation: server transitions `approved_unfetched → done` and NULLs `plaintext_token` as a deferred write *after* the response handler returns. If the response write fails partway, the row remains `approved_unfetched` and the next poll succeeds. There is a narrow window where the plaintext could be fetched twice if a misbehaving client somehow obtained two simultaneous polls of the same `device_code` *and* the first response failed mid-write — both sides compute the same plaintext, which is the same secret, so this is observation-equivalent to a single fetch. Acceptable v1.
- **Revocation semantics of "deactivate user"**: cascading revoke is a hard-delete-ish action. If misclicked it's painful. → Mitigation: API requires `confirm=<email>` body field for deactivate; inspector UI requires typing the email in to confirm; last-admin guard refuses with 409 if no admins would remain. Reactivation flips `deactivated_at` to NULL but does not restore tokens (user must reissue) — matches GitHub's UX. Documented explicitly in `docs/accounts.md` so operators are not surprised.
- **Legacy raw-bearer cookie**: existing inspector users have a cookie carrying their admin token plaintext. → Decision: the legacy cookie continues to authenticate **fully** (mutations included) for v1, with deprecation in v2. A "read-only legacy cookie" would silently break existing inspector mutation flows on day 1, which is exactly the kind of breakage the additive-migration story tries to avoid. New logins always create `user_sessions`; the legacy path is accept-on-read only, never set on a new login.
- **Phishing the device-pairing approval**: an attacker starts a pairing and tricks the victim into typing the user code. → Mitigation: narrow-by-default scope (`account` only), approver-context display (UA, IP, requested scopes), explicit warning, and password re-entry requirement in the approval form. Each cheap individually; layered they raise the bar materially.
- **Per-process rate-limit state**: in-process token buckets reset on restart. → Trade-off: acceptable for a single-process SQLite deployment; fits the existing operational posture. A future Redis-backed bucket can replace the implementation behind the same middleware contract without changing semantics.
- **sqlc adoption scope**: the change replaces all hand-rolled SQL in `internal/store` (events, tokens, push) on top of adding the new tables, not just the new tables. → Trade-off: a one-time mechanical rewrite of ~10 existing query call-sites is the price; the win is one query pattern in the package, compile-time-checked end-to-end. The existing `contract_test.go` is the safety net that no observable behavior changes — if a contract test regresses, the sqlc rewrite is wrong, not the test. CI gains a `sqlc diff` step (in `make lint`) so a `.sql` change without regenerated code fails the build instead of producing a runtime mismatch.
- **Schema-vs-migrations split**: `internal/store/schema.sql` describes the post-migration shape (canonical, used by sqlc); `migrations.go` carries idempotent ALTER deltas for existing v1 deployments. → Risk: someone edits the canonical file without adding the corresponding delta and breaks upgrades from existing deployments. → Mitigation: a unit test (`internal/store/migrations_test.go`) opens a SQLite DB, applies the *previous* (v1) schema, then runs `migrate()`, then asserts every column declared in `internal/store/schema.sql` is present. This catches the omission deterministically and is fast (in-memory DB).

## Migration Plan

1. Land the canonical schema in `internal/store/schema.sql` — the new tables (`users`, `user_sessions`, `invites`, `device_pairings`, `audit_events`) and the column additions on `listener_tokens` and `push_subscriptions` are written into the canonical file. Run `go tool sqlc generate` and commit `internal/store/sqlcgen/`. `internal/store/migrations.go` ships the probe-and-ALTER deltas that bring an existing v1 database forward; a fresh DB sees them as no-ops because the canonical CREATE TABLE statements already include the new columns. `IF NOT EXISTS` discipline on every CREATE so re-running is safe. Existing `listener_tokens` rows are backfilled with `kind='listener'` (preserving today's behavior — they all authenticate `/subscribe/*` and the inspector but not `/api/me/*`, which is correct because `/api/me/*` is a new surface).
2. On boot, if `users` is empty, ensure exactly one bootstrap invite exists (idempotent insert); if the existing bootstrap row is expired, replace it with a fresh code and a fresh 24h TTL. `hooks init` prints the signup URL; subsequent boots do nothing if an account exists.
3. Existing system-owned admin tokens continue to work with their existing scopes. The release notes recommend admins:
   - Sign up via the bootstrap URL.
   - Mint themselves a PAT with `hooksctl login`.
   - Optionally `hooksctl token revoke <system-token>` once their PAT works.
4. Rollback: drop the new tables and the new columns. The columns are nullable / defaulted and unused by old code, so a partial-rollback (only drop new tables, leave columns) is also safe. Rolling back the sqlc move specifically (the rewritten queries on existing tables) does not require a database action — it is a code-only revert. The on-disk rows are identical before and after the rewrite.
5. No data backfill required for existing tokens or subscriptions — they remain `owner_user_id = NULL` with their existing scopes and authorize as today.

## Open Questions

- Do we want SSO/OIDC? The schema reserves `users.external_id` so adding a provider later is additive. No work for it now.
- Should the audit log have an explicit retention policy in v1? Current decision: no — the table grows on operator actions, not webhook traffic, so size is bounded in practice. If an operator needs cleanup they can SQL-delete; we will revisit if anyone reports growth surprises.
