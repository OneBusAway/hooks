## ADDED Requirements

### Requirement: Web inspector at `/inspector`

The service SHALL serve an HTML inspector at `/inspector` that lists recent events across all sources, with pagination and per-source filtering. Access SHALL require a bearer token whose scopes include `admin`. Unauthenticated requests SHALL be redirected to a token-entry form that stores the token in a cookie scoped to `/inspector` and the management API paths.

#### Scenario: Admin-scoped token grants access
- **WHEN** a user loads `/inspector` with a cookie-stored token whose scopes include `admin`
- **THEN** the page renders a list of the most recent 50 events with source, sequence, received-at, and a body preview

#### Scenario: Non-admin token is rejected
- **WHEN** a user loads `/inspector` with a token scoped only to `render`
- **THEN** the response is HTTP 403, not the event list

#### Scenario: Unauthenticated user sees token entry
- **WHEN** a user without a cookie token loads `/inspector`
- **THEN** the response is the token-entry form

### Requirement: Event detail view

The inspector SHALL provide a detail view at `/inspector/events/<source>/<sequence>` showing the full headers, the body (pretty-printed if JSON), the `delivery_id`, both timestamps, and the `body_sha256`. The page SHALL include a "Copy as curl" affordance that produces a request that would re-trigger ingestion (with the original signature header preserved) for use against a local instance.

#### Scenario: Detail view renders JSON body pretty
- **WHEN** an event has a `Content-Type: application/json` header and a valid JSON body
- **THEN** the body is rendered with two-space indentation and syntax highlighting

#### Scenario: Copy-as-curl reproduces the request
- **WHEN** an admin clicks "Copy as curl" on an event
- **THEN** the clipboard contains a `curl` command that, when executed against a local instance with the same source secret, results in the same `delivery_id` being ingested

### Requirement: Replay-to-listeners action

The inspector SHALL provide a "Replay to listeners" action on each event that re-publishes the event to all currently connected SSE subscribers and dispatches it to all eligible non-paused push subscriptions, without inserting a new row in the event store. The action SHALL be confirmable. Replay-to-push deliveries SHALL set `X-Hooks-Replay: 1` and SHALL NOT advance any subscription's cursor.

#### Scenario: Replay reaches connected SSE subscribers
- **WHEN** an admin clicks "Replay to listeners" on event `(render, 17)` and a subscriber is connected to `/subscribe/render`
- **THEN** the subscriber receives sequence 17 again on its stream

#### Scenario: Replay dispatches to push subscriptions without advancing cursor
- **WHEN** an admin replays event `(render, 17)` and an active push subscription on `render` has cursor=20
- **THEN** the subscription's target receives a POST for sequence 17 with `X-Hooks-Replay: 1`, and the cursor remains 20

#### Scenario: Replay does not duplicate the event in storage
- **WHEN** an admin replays event `(render, 17)`
- **THEN** the event store still contains exactly one row with `(source=render, sequence=17)`

### Requirement: Token-management view at `/inspector/tokens`

The inspector SHALL render a `/inspector/tokens` page listing every active listener token with: id, name, scopes, `created_at`, `last_used_at`. The page SHALL provide an "Add token" form (name + scopes) and an inline "Revoke" action. New token plaintext SHALL be displayed exactly once on the resulting confirmation page; subsequent navigation SHALL not show it again.

#### Scenario: Add token shows plaintext exactly once
- **WHEN** an admin submits the Add token form with name "Aaron's laptop" and scopes "render,admin"
- **THEN** the resulting page shows the plaintext token once with a copy button; a refresh shows only the metadata, not the token

#### Scenario: Revoked token disappears from default list
- **WHEN** an admin revokes a token
- **THEN** the next list page does not show that token unless `?include-revoked=1` is set

#### Scenario: Non-admin token cannot reach token management
- **WHEN** a user with a `render`-only token attempts to load `/inspector/tokens`
- **THEN** the response is HTTP 403

### Requirement: Push-subscription management view at `/inspector/push`

The inspector SHALL render a `/inspector/push` page listing every push subscription with: id (linked to detail), source, `target_url`, cursor, queue depth (highest source sequence − cursor), `consecutive_failures`, `last_error` (truncated to 200 chars on the list), `last_attempt_at`, `last_success_at`, and `paused_at`. Inline actions SHALL include `pause`, `resume`, `rotate-secret`, `delete`, and `test`. The signing secret SHALL never be displayed on the list view; `rotate-secret` SHALL show the new plaintext exactly once on the resulting confirmation page.

#### Scenario: Queue depth increases visibly during outage
- **WHEN** a subscription's target is down and 5 new events arrive for its source
- **THEN** the inspector shows queue depth 5, last_error populated, and a stale `last_attempt_at`

#### Scenario: Rotate-secret displays new plaintext exactly once
- **WHEN** an admin clicks "Rotate secret" on a subscription
- **THEN** the resulting page shows the new plaintext secret with a copy button and a banner stating it will not be shown again; subsequent loads of the page do not display the secret

### Requirement: `hooksctl` CLI binary

The project SHALL ship a separate `hooksctl` binary providing developer-side commands. The binary SHALL be invokable without the server running for offline help. Commands SHALL accept a `--server <url>` flag (default `http://localhost:8080`) and a `--token <token>` flag (default from `HOOKS_TOKEN` env var).

#### Scenario: Help text lists every subcommand
- **WHEN** a developer runs `hooksctl --help`
- **THEN** the output lists at least `tail`, `forward`, `replay`, `token`, and `push`

### Requirement: `hooksctl tail` command

`hooksctl tail <source> [--since <seq|latest>]` SHALL connect to the server's subscribe endpoint and print events to stdout in a human-readable form, one event per line by default, with `--json` for machine-readable output.

#### Scenario: Tail prints live events
- **WHEN** a developer runs `hooksctl tail render --since latest` and a webhook arrives
- **THEN** a line describing the event is printed to stdout within 2 seconds

#### Scenario: Tail exits cleanly on Ctrl-C and reports last-acked sequence
- **WHEN** the user sends SIGINT to a running `hooksctl tail`
- **THEN** the command exits 0 and the final stderr line reads `last-acked: <sequence>`

### Requirement: `hooksctl forward` command

`hooksctl forward <source> --to <url>` SHALL subscribe to the server, replay any missed events since the cursor stored at `${XDG_STATE_HOME:-$HOME/.local/state}/hooks/cursor-<server-host>-<source>`, then continue live, POSTing each event body to `<url>` with the original headers preserved (excluding hop-by-hop headers). The command SHALL update the cursor file only after the local target returns a 2xx response.

#### Scenario: Local target receives identical bytes
- **WHEN** `hooksctl forward render --to http://localhost:3000/webhooks/render` runs and an event with body `B` arrives
- **THEN** `localhost:3000/webhooks/render` receives a POST whose body is byte-identical to `B`

#### Scenario: Cursor advances only on 2xx
- **WHEN** the local target returns 500 for a forwarded event
- **THEN** the on-disk cursor is not advanced past that event's sequence

#### Scenario: Resuming after a crash starts at the right place
- **WHEN** `hooksctl forward` is killed and restarted with the same `--source` and server
- **THEN** the next forwarded event is the one immediately after the last successfully-2xx-acknowledged sequence

### Requirement: `hooksctl forward` retry behavior

`hooksctl forward` SHALL retry on 5xx and connection errors with exponential backoff capped at 60 seconds, indefinitely by default (mirroring the server-side push policy). A `--exit-on-error` flag SHALL change this to exit non-zero on the first failure for use in CI.

#### Scenario: Default mode survives a flapping target
- **WHEN** the local target is unreachable for 30 seconds and then returns
- **THEN** the forwarder reconnects and delivers the queued events without losing any

### Requirement: `hooksctl push` command

`hooksctl push` SHALL provide subcommands `add`, `list`, `get`, `pause`, `resume`, `rotate-secret`, `rm`, and `test`, each operating against the server's `/api/push-subscriptions` endpoints with an `admin`-scoped token.

#### Scenario: hooksctl push add registers and prints secret once
- **WHEN** a developer runs `hooksctl push add --source render --to https://example.com/hook --name staging`
- **THEN** the command prints the new subscription's id and signing secret exactly once and exits 0

#### Scenario: hooksctl push list reflects server state
- **WHEN** a developer runs `hooksctl push list`
- **THEN** the output shows the same id, source, target_url, cursor, queue depth, consecutive failures, and last error visible in `/inspector/push`

#### Scenario: hooksctl push test exercises the path
- **WHEN** a developer runs `hooksctl push test <id>` against a reachable target
- **THEN** the target receives a POST with `X-Hooks-Test: 1` and a non-real delivery_id, and the test does not advance the subscription's cursor

#### Scenario: hooksctl push rotate-secret prints new plaintext once
- **WHEN** a developer runs `hooksctl push rotate-secret <id>`
- **THEN** the command prints the new plaintext signing secret exactly once and exits 0; the old secret no longer verifies any subsequent push

### Requirement: `hooks init` first-run experience

`hooks init` SHALL create `hooks.yaml` and a SQLite database in the current directory, generate an `admin`-scoped listener token, and print to stdout: (a) the path to the config file, (b) the admin token (printed exactly once), (c) the URL to register with Render, and (d) example `hooksctl forward` and `hooksctl push add` invocations. Re-running `hooks init` against an existing config SHALL refuse to overwrite without a `--force` flag.

#### Scenario: First run produces a working config
- **WHEN** a developer runs `hooks init` in an empty directory
- **THEN** `hooks.yaml` and `hooks.db` are created, an admin-scoped token is printed exactly once, and the printed example commands work without further edits

#### Scenario: Second run does not clobber
- **WHEN** `hooks init` is run in a directory that already contains `hooks.yaml`
- **THEN** the command exits non-zero with a message instructing the user to pass `--force`

### Requirement: `--dev` mode

The server SHALL accept a `--dev` flag that: enables verbose request logging, opens the inspector in the default browser on startup, and prints copy-paste-ready Render registration and `hooksctl forward` / `hooksctl push add` commands.

#### Scenario: Dev mode prints quickstart
- **WHEN** the server is started with `--dev`
- **THEN** the first stderr lines include the inspector URL, an admin token, a curl command to register a Render webhook, a `hooksctl forward` command, and a `hooksctl push add` command

### Requirement: Health and readiness endpoints

The service SHALL expose `GET /healthz` returning HTTP 200 once the HTTP listener is open and the event store schema is applied, and `GET /readyz` returning HTTP 200 only when the store can complete a round-trip ping. Neither endpoint SHALL require authentication.

#### Scenario: Healthz responds during startup before storage is ready
- **WHEN** the HTTP listener is open but the database is mid-migration
- **THEN** `/healthz` returns 200 and `/readyz` returns 503

#### Scenario: Readyz reflects database loss
- **WHEN** the database file becomes unreadable mid-run
- **THEN** `/readyz` returns 503 within 5 seconds and `/healthz` continues to return 200
