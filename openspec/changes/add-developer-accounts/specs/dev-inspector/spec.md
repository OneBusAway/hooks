## ADDED Requirements

### Requirement: Login form and session cookies

The inspector SHALL serve a login form at `/login` accepting `email` and `password` and POSTing to `/api/auth/login`. On successful login the response SHALL set `Cookie: hooks_session=<id>.<plaintext>` (HttpOnly, SameSite=Lax, Secure when TLS is detected per the developer-accounts requirement) and `Cookie: hooks_csrf=<token>` (SameSite=Lax) and redirect to the post-login destination (the `next` query parameter if present and same-origin, otherwise `/inspector/me`). The login form SHALL include an Origin-header check on submission to prevent cross-origin POSTs and SHALL display a generic "invalid credentials" message regardless of whether the email exists. The form SHALL embed the per-session CSRF token in a hidden field.

#### Scenario: Successful login redirects to /inspector/me
- **WHEN** a user POSTs valid credentials to `/api/auth/login` from the form at `/login` with no `next` parameter
- **THEN** the response is HTTP 303 redirecting to `/inspector/me`, with both `hooks_session` and `hooks_csrf` cookies set

#### Scenario: Invalid credentials show generic error
- **WHEN** a login is submitted with an unknown email or wrong password
- **THEN** the form re-renders with the message "invalid credentials" and no cookie is set, regardless of which field was wrong

#### Scenario: Cross-origin login POST is rejected
- **WHEN** a POST to `/api/auth/login` arrives with an `Origin` header that does not match the request host
- **THEN** the service responds with HTTP 403 and no session is created

#### Scenario: Origin null is rejected
- **WHEN** a POST to `/api/auth/login` arrives with `Origin: null`
- **THEN** the service responds with HTTP 403 and no session is created

### Requirement: CSRF token on every cookie-authenticated form

Every server-rendered inspector form whose submission mutates state SHALL include a hidden `csrf_token` field whose value matches the `hooks_csrf` cookie. The handler SHALL constant-time compare the form value to the cookie before processing. Forms include but are not limited to: login, signup, device approve/deny, "mint ephemeral PAT" on `/inspector/me`, every action on `/inspector/users` (issue invite, deactivate, reactivate, reset password, edit defaults), every action on `/inspector/tokens` (add, revoke, transfer ownership), every action on `/inspector/push` and `/inspector/me/push` (pause, resume, rotate-secret, delete, test, transfer ownership).

#### Scenario: Form POST without csrf_token is rejected
- **WHEN** an inspector form is submitted with a valid `hooks_session` cookie but no `csrf_token` field
- **THEN** the response is HTTP 403 and no state changes

#### Scenario: Mismatched csrf_token is rejected
- **WHEN** an inspector form is submitted with a `csrf_token` value that does not match the `hooks_csrf` cookie
- **THEN** the response is HTTP 403 and no state changes

### Requirement: Per-user inspector landing page

The inspector SHALL serve `/inspector/me` to any authenticated user. The page SHALL show: the calling user's name, email, role, default scopes, a list of their active listener tokens (with `kind` column and revoke action), a list of their push subscriptions (linked to `/inspector/me/push`), and a button to mint a new ephemeral PAT via the existing `POST /api/me/tokens` endpoint (CSRF-protected). Admins SHALL also see links to `/inspector/users` and `/inspector/audit` from this page.

#### Scenario: Authenticated non-admin user reaches /inspector/me
- **WHEN** a non-admin user with a valid session visits `/inspector/me`
- **THEN** the response is HTTP 200 rendering only their own profile, tokens, and subscriptions

#### Scenario: Anonymous user redirected to login
- **WHEN** a request to `/inspector/me` arrives without a valid session cookie or PAT
- **THEN** the response is HTTP 303 redirecting to `/login?next=/inspector/me`

### Requirement: Admin user-management view at `/inspector/users`

The inspector SHALL serve `/inspector/users` to admin-scoped clients only. The page SHALL list every user with id, email, name, role, default scopes, created_at, and deactivated_at; provide an "Issue invite" form (CSRF-protected) that calls `POST /api/invites` and displays the resulting signup URL once; provide per-row actions to deactivate (with email-confirmation dialog; refused with a clear message if the deactivation would leave zero active admins), reactivate, reset password, and edit `default_scopes`/`name` via `PATCH /api/users/{id}`. Non-admin requests SHALL receive HTTP 403.

#### Scenario: Admin lists users
- **WHEN** an admin loads `/inspector/users`
- **THEN** the page shows a table of all users including their roles, default scopes, and deactivation state

#### Scenario: Issue invite shows signup URL once
- **WHEN** an admin submits the "Issue invite" form
- **THEN** the resulting page shows a signup URL with the invite code embedded; refreshing the page does not show the URL again

#### Scenario: Deactivate confirmation requires typing the email
- **WHEN** an admin clicks "Deactivate" without supplying the matching email in the confirmation dialog
- **THEN** the request is rejected with HTTP 400 and the user remains active

#### Scenario: Last-admin deactivation refused
- **GIVEN** the deployment has exactly one active admin
- **WHEN** that admin attempts to deactivate themselves via the UI
- **THEN** the response is HTTP 409 with a clear "cannot deactivate the only active admin" message

#### Scenario: Edit default scopes
- **WHEN** an admin submits the "Edit defaults" form for a user with `{default_scopes: ["render", "stripe"]}`
- **THEN** the user's row updates and the next time that user logs in they can mint PATs scoped to `render` or `stripe`

### Requirement: Admin audit-log view at `/inspector/audit`

The inspector SHALL serve `/inspector/audit` to admin-scoped clients only, rendering rows from `audit_events` with actor email resolution, the recorded action, target type and id, metadata summary, and timestamp. The page SHALL support filtering by actor and time range. Non-admin requests SHALL receive HTTP 403.

#### Scenario: Admin reviews recent events
- **WHEN** an admin loads `/inspector/audit`
- **THEN** the page renders the most recent 50 audit events with timestamps, ordered by `at DESC`

### Requirement: Per-user push-subscription view at `/inspector/me/push`

The inspector SHALL serve `/inspector/me/push` to any authenticated user, listing only push subscriptions whose `owner_user_id` matches the calling user. The view SHALL match the columns and inline actions of `/inspector/push` (omitting the owner column) and SHALL never display plaintext signing secrets on the list view. Admins SHALL be able to load the view and see only their own subscriptions, with a banner linking to `/inspector/push` for the full-fleet view.

#### Scenario: User sees only their subscriptions
- **WHEN** a user with one push subscription loads `/inspector/me/push`
- **THEN** the page shows exactly that subscription and no others

### Requirement: `hooksctl login` command

The `hooksctl` binary SHALL provide `hooksctl login [--server <url>] [--profile <name>] [--scopes <list>] [--admin]`. The command SHALL POST `/api/auth/device/start` (passing requested `scopes` and `admin`), print the verification URI and user code, attempt to open the URL in the user's default browser, then poll `/api/auth/device/poll` at the server-supplied interval until approval or expiry. On approval the command SHALL write the returned token to `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>` with file mode `0600` in TOML format containing keys `server_url`, `token`, `created_at`, and (optionally) `expires_at`. The default profile name SHALL be `default`. On expiry or denial the command SHALL exit non-zero with a message naming the cause. The plaintext token SHALL NOT appear in any log line or stdout (other than the credentials-file write).

#### Scenario: Successful login persists credentials
- **GIVEN** a server URL and an unauthenticated CLI
- **WHEN** the user runs `hooksctl login --server https://hooks.example.com` and approves the pairing in their browser (re-entering their password)
- **THEN** `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.default` is created with mode 0600, contains a TOML document with `server_url` and `token` keys, and the next `hooksctl me token list` invocation succeeds

#### Scenario: Login with narrow scopes
- **WHEN** a user runs `hooksctl login --server https://hooks.example.com --scopes render`
- **THEN** the resulting PAT in the credentials file has scopes `["account", "render"]`

#### Scenario: Logout revokes PAT and clears credentials
- **WHEN** a logged-in user runs `hooksctl logout [--profile <name>]`
- **THEN** the CLI POSTs `/api/me/tokens/self/revoke` against the locally-stored PAT, then deletes the credentials file; if the revoke fails the file is still deleted but the CLI exits non-zero with a stderr warning

#### Scenario: Whoami reports identity
- **WHEN** a logged-in user runs `hooksctl whoami`
- **THEN** stdout shows the user's email, role, and the server URL

## MODIFIED Requirements

### Requirement: Web inspector at `/inspector`

The service SHALL serve an HTML inspector at `/inspector` that lists recent events across all sources, with pagination and per-source filtering. Access SHALL require either (a) a valid session cookie whose user has `admin` role, or (b) a bearer token whose scopes include `admin`. Unauthenticated requests SHALL be redirected to `/login?next=/inspector`. For backwards compatibility, a cookie carrying a raw admin-scoped bearer token (the legacy v1 inspector cookie) SHALL continue to authenticate **including for state-changing actions** in v1; this legacy path is deprecated and slated for removal in v2. The inspector SHALL NOT issue new cookies in the legacy raw-bearer format on any login.

#### Scenario: Admin session grants access
- **WHEN** an admin loads `/inspector` with a session cookie whose user has `admin` role
- **THEN** the page renders a list of the most recent 50 events with source, sequence, received-at, and a body preview

#### Scenario: Non-admin user is redirected to /inspector/me
- **WHEN** an authenticated non-admin user loads `/inspector`
- **THEN** the response is HTTP 303 redirecting to `/inspector/me`

#### Scenario: Unauthenticated user redirected to login
- **WHEN** a user without a session or token loads `/inspector`
- **THEN** the response is HTTP 303 redirecting to `/login?next=/inspector`

#### Scenario: Legacy raw-bearer cookie still authenticates mutations
- **WHEN** a request to `/inspector` arrives with the legacy cookie format set by the v1 inspector (a raw admin token) and the request is a state-changing action
- **THEN** the request authenticates and succeeds; the legacy path remains functional in v1 and is deprecated for v2

### Requirement: Token-management view at `/inspector/tokens`

The inspector SHALL render a `/inspector/tokens` page (admin only) listing every active listener token with: id, name, scopes, owner (user email or `system`), `kind` (`pat`/`listener`), `created_at`, `last_used_at`, `expires_at`. The page SHALL provide an "Add token" form (CSRF-protected; name + scopes + kind, plus optional `owner_user_id` to mint on behalf of a user) and an inline "Revoke" action for any row regardless of owner. New token plaintext SHALL be displayed exactly once on the resulting confirmation page; subsequent navigation SHALL not show it again. Non-admin requests SHALL receive HTTP 303 to `/inspector/me`.

#### Scenario: Admin sees all tokens with owner and kind columns
- **WHEN** an admin loads `/inspector/tokens` in a deployment with both system and user-owned tokens
- **THEN** the table shows the owner column with `system` for `owner_user_id IS NULL` rows and the owning user's email otherwise, and a `kind` column distinguishing `pat` from `listener`

#### Scenario: Add token shows plaintext exactly once
- **WHEN** an admin submits the Add token form with name "Aaron's laptop", kind "listener", and scopes "render,admin"
- **THEN** the resulting page shows the plaintext token once with a copy button; a refresh shows only the metadata, not the token

#### Scenario: Revoked token disappears from default list
- **WHEN** an admin revokes a token
- **THEN** the next list page does not show that token unless `?include-revoked=1` is set

#### Scenario: Non-admin redirected to self-service
- **WHEN** a non-admin user attempts to load `/inspector/tokens`
- **THEN** the response is HTTP 303 to `/inspector/me`

### Requirement: `hooksctl forward` command

`hooksctl forward <source> --to <url>` SHALL subscribe to the server, replay any missed events since the cursor stored at `${XDG_STATE_HOME:-$HOME/.local/state}/hooks/cursor-<server-host>-<source>`, then continue live, POSTing each event body to `<url>` with the original headers preserved (excluding hop-by-hop headers). The command SHALL update the cursor file only after the local target returns a 2xx response.

When invoked while logged in (i.e. a valid PAT is loaded from the credentials file or `HOOKS_TOKEN` is unset) and no `--token` flag is set, `hooksctl forward` SHALL automatically mint an ephemeral `kind='listener'` token via `POST /api/me/tokens` (with `name=forward-<host>-<rand>`, `scopes=[<source>]`, `ephemeral=true`) and use it for the SSE connection. On clean exit (Ctrl-C, `--once` completion, broken target signaling termination) the command SHALL revoke that token via `POST /api/me/tokens/{id}/revoke`. If `HOOKS_TOKEN` is set explicitly OR `--token <id>` is passed, that token SHALL be used as-is and no ephemeral token SHALL be created. The `--token` flag enables a power-user workflow where a developer mints a long-lived `kind='listener'` token via `hooksctl me token add --kind listener --scopes render` and reuses it across many `forward` invocations.

Ephemeral tokens are auto-revoked by the server-side prune loop when their `last_used_at` is more than 24h in the past (or `created_at` if never used), regardless of owner. A live `forward` keeps the token alive indefinitely; a stopped `forward` whose revoke POST failed leaves the token to expire on inactivity.

#### Scenario: Local target receives identical bytes
- **WHEN** `hooksctl forward render --to http://localhost:3000/webhooks/render` runs and an event with body `B` arrives
- **THEN** `localhost:3000/webhooks/render` receives a POST whose body is byte-identical to `B`

#### Scenario: Cursor advances only on 2xx
- **WHEN** the local target returns 500 for a forwarded event
- **THEN** the on-disk cursor is not advanced past that event's sequence

#### Scenario: Resuming after a crash starts at the right place
- **WHEN** `hooksctl forward` is killed and restarted with the same `--source` and server
- **THEN** the next forwarded event is the one immediately after the last successfully-2xx-acknowledged sequence

#### Scenario: Logged-in invocation mints and revokes an ephemeral listener token
- **GIVEN** a logged-in CLI with no `HOOKS_TOKEN` set in the environment and no `--token` flag
- **WHEN** the user runs `hooksctl forward render --to http://localhost:3000/x`
- **THEN** an ephemeral `kind='listener'` token is created against `/api/me/tokens` before the SSE connection opens, and on Ctrl-C the same token id is revoked via `/api/me/tokens/{id}/revoke`

#### Scenario: `--token` flag uses long-lived listener token
- **GIVEN** a logged-in CLI and a previously-minted long-lived listener token id
- **WHEN** the user runs `hooksctl forward render --to http://localhost:3000/x --token <id>`
- **THEN** no `/api/me/tokens` POST is made on startup, no revoke POST is made on exit, and the supplied long-lived token is used directly for the SSE handshake

#### Scenario: Explicit HOOKS_TOKEN bypasses ephemeral minting
- **GIVEN** `HOOKS_TOKEN` is set in the environment
- **WHEN** the user runs `hooksctl forward render --to http://localhost:3000/x`
- **THEN** the supplied token is used directly and no `/api/me/tokens` call is made

#### Scenario: Ephemeral token expires on inactivity
- **GIVEN** an `ephemeral=true` listener token whose `last_used_at` is 25 hours ago
- **WHEN** the prune loop runs
- **THEN** the token's `revoked_at` is set; subsequent attempts to use it return HTTP 401

### Requirement: `hooks init` first-run experience

`hooks init` SHALL create `hooks.yaml` and a SQLite database in the current directory, generate a system admin-scoped listener token, and print to stdout: (a) the path to the config file, (b) the admin token (printed exactly once), (c) the URL to register with Render, (d) example `hooksctl forward` and `hooksctl push add` invocations, and (e) if and only if the database has zero `users` rows, a single line beginning with `signup: ` containing the bootstrap signup URL whose code maps to a `bootstrap=true, role=admin, expires_at=now+24h` invite. If a `bootstrap=true` row already exists but is expired, `hooks init` SHALL replace it atomically with a fresh code and a fresh 24h TTL. Re-running `hooks init` against a database with at least one user SHALL NOT print or create a bootstrap invite. Re-running `hooks init` against an existing config file SHALL refuse to overwrite without a `--force` flag.

#### Scenario: First run prints both admin token and bootstrap signup URL
- **WHEN** a developer runs `hooks init` in an empty directory
- **THEN** stdout contains the admin token printed once, and a single `signup:` line whose URL contains a 16-char base32 code that resolves to a `bootstrap=true` invite with `expires_at` approximately 24 hours in the future

#### Scenario: Subsequent run with users present omits signup URL
- **GIVEN** a database that already has at least one user
- **WHEN** `hooks init --force` is run
- **THEN** stdout does not contain a `signup:` line and no new bootstrap invite is inserted

#### Scenario: Expired bootstrap invite replaced on rerun
- **GIVEN** a userless database whose existing bootstrap invite is past `expires_at`
- **WHEN** `hooks init` runs again
- **THEN** the bootstrap row is replaced with a fresh code and 24h TTL, and a fresh `signup:` line is printed

#### Scenario: Second run does not clobber config
- **WHEN** `hooks init` is run in a directory that already contains `hooks.yaml`
- **THEN** the command exits non-zero with a message instructing the user to pass `--force`
