## Context

The repository is empty apart from the OpenSpec scaffold. We are building a Go service from scratch that captures inbound webhooks, persists them durably, and delivers them to authenticated subscribers via two modes — pull (SSE) and push (outbound HTTP) — with a strong bias toward developer-environment use cases where consumers are frequently offline. The first concrete provider is [Render](https://render.com/docs/webhooks.md), which signs each delivery with HMAC-SHA256 over `timestamp.body` and includes a `Render-Webhook-Id` for deduplication.

The single hardest design constraint is **never lose an authentic webhook, ever**. A 200 to the provider is a promise of durability. Everything else — replay UX, multi-listener fan-out, push retries, the inspector — is layered on top of that promise.

## Goals / Non-Goals

**Goals:**
- Single binary, single config file, zero required external services for the default deployment.
- Cryptographic verification (HMAC) on every inbound delivery and every outbound push, both with constant-time comparison and replay-window enforcement.
- At-least-once delivery to listeners over **two delivery modes**:
  - **SSE pull**: one HTTP connection per listener, listener-managed cursor; ideal for dev laptops and ephemeral environments.
  - **HTTP push**: relay POSTs to a registered URL with a per-subscription HMAC, server-managed cursor; ideal for long-lived consumer services.
- A first-class developer experience: `hooks init` to bootstrap, a web inspector to browse events and manage subscriptions, and `hooksctl forward` / `hooksctl push add` so a dev can wire a consumer in one command.
- Pluggable provider model: adding a new source (Stripe, GitHub, etc.) is an `internal/sources/<name>` file implementing a small `Verifier` interface.

**Non-Goals:**
- Unsigned inbound providers. Every source must declare a registered `Verifier` at startup; v1 has no opt-in for unsigned receive.
- Multi-tenant SaaS features. This is a self-hosted tool; one deployment serves one team.
- Exactly-once delivery. Listeners must be idempotent on `delivery_id`; the relay guarantees at-least-once and emits the `delivery_id` to enable client-side dedupe.
- Horizontal scale-out in v1. The default deployment is a single process with SQLite. The storage interface is shaped to allow a Postgres-backed multi-process deployment later, but we will not write that code yet.
- Transformations or routing rules. Events are stored and delivered verbatim.
- Built-in TLS / autocert. The relay speaks plain HTTP and is expected to live behind a TLS-terminating reverse proxy (Caddy, nginx, Cloudflare, Render itself).
- Dead-letter handling for push. A pathological subscription queues forever; surfacing queue depth + last error in the inspector is the operator's signal to act.

## Decisions

### Storage: SQLite (`modernc.org/sqlite`) by default, interface-bounded for Postgres later

We need durability with an `fsync` discipline strong enough that a `200 OK` to the provider is honest. SQLite in WAL mode with `PRAGMA synchronous=NORMAL` gives us crash-safe writes with single-digit-millisecond latency on a laptop SSD, no daemon to operate, and the inspector-friendly property that any developer can `sqlite3 hooks.db` to look around. We use `modernc.org/sqlite` (pure Go, no CGO) so cross-compilation stays trivial.

**Alternatives considered:**
- Postgres-only: better for multi-process, but we'd require every dev to run Postgres or point at a shared instance. Rejected for v1 — the storage interface (`EventStore`, plus token and push-subscription stores) is small enough that adding a Postgres impl later is mechanical.
- An append-only file format (e.g. one JSON-lines log): simpler write path but loses indexed reads, dedupe queries, and the ability to use the file as the inspector's data source.
- Embedded BoltDB / Pebble: faster writes but worse for ad-hoc inspection and SQL tooling.

### Dual delivery: SSE pull + HTTP push

We support both modes because they cover non-overlapping consumer types:
- **SSE pull** is right for dev laptops, ephemeral preview environments, and any consumer that prefers to dial out (no need to expose a public endpoint, no SSRF surface). The listener manages its own cursor by passing `since=<seq>` on reconnect, and the standard SSE `Last-Event-ID` mechanism makes browser-side reconnect free.
- **HTTP push** is right for long-lived consumer services that already accept webhooks. The relay POSTs to a registered URL, signs the body with a per-subscription HMAC (so the consumer can verify origin), and tracks the cursor server-side so the consumer is fully passive — even if it goes down for hours, the relay catches it up in order on recovery.

Both modes read from the same `EventStore`, so adding a third delivery mode later (a Kafka producer, say) is a new package next to `internal/subscribe` and `internal/push` rather than a refactor.

**Alternatives considered:**
- SSE only: covered the dev-laptop case but excluded service-to-service integrators.
- Push only: excluded ephemeral dev environments which are exactly the case we set out to solve.

### Push subscription model

Push subscriptions live in `push_subscriptions` (SQLite), keyed by id, with a per-row signing secret (Argon2id-hashed for storage; plaintext returned exactly once at registration). Each row pins a single `source` and tracks its own `cursor`, `last_attempt_at`, `last_success_at`, `last_error`, `consecutive_failures`, and `paused_at`. The dispatcher is a single goroutine per active subscription that:

1. Reads up to N events with `sequence > cursor` from the store.
2. POSTs each event to `target_url` with `X-Hooks-Signature: t=<unix>,v1=<hmac-sha256(secret, "<unix>.<body>")>`, `X-Hooks-Delivery-Id`, `X-Hooks-Sequence`, and the original headers preserved (excluding hop-by-hop).
3. On 2xx → atomically advance cursor + record success, reset `consecutive_failures`, loop.
4. On non-2xx, network error, or per-attempt timeout (default 30s) → record error, increment `consecutive_failures`, sleep `min(60s, 2^failures * 100ms)` with full jitter, do not advance cursor, loop.
5. On `Notifier` signal (new event for that source), wake immediately if currently sleeping in step 4 with no events to dispatch.

A new subscription cold-starts at `since=latest` (the highest current sequence at registration time) so brand-new consumers don't get flooded by historical backlog. Adding `--since=0` at registration overrides this for migration scenarios.

**Why retry forever and no dead-letter**: the whole point is "never lose a webhook." A subscription that's been failing for hours surfaces in the inspector with queue depth, last error, and `consecutive_failures`; that's the human's signal to fix it (or `hooksctl push pause/rm`). Silently advancing the cursor past failures defeats the contract.

**Why one source per subscription**: mirrors SSE's per-source semantics, keeps the schema flat (one cursor per row), and means the dispatcher loop has nothing to fan out internally. A consumer that wants two sources registers two subscriptions.

### Live fan-out: in-process per-source pub/sub, polling fallback

Inside one process, ingestion writes to SQLite then publishes the new sequence to a per-source channel that subscribe and push goroutines read. If the publish channel is full (slow listener, slow push target), we drop the *signal*, not the event — the consumer's next read will pull the missed sequences from the store. This makes every consumer poll-correct: even if the live signal is missed entirely, it will catch up on the next event or on a timer tick. A consumer is therefore either current or strictly behind by a bounded amount; it is never permanently desynced.

### Authentication

- **Inbound (per source)**: HMAC-SHA256 over the provider's documented signing string (for Render: `<timestamp>.<body>`) using a per-source secret loaded from config. Constant-time compare. Reject if the timestamp is more than 5 minutes off the server clock. Reject if the signature header is missing or malformed. Persist a hash of the body and the `delivery_id` to detect duplicates within a 24-hour window. Strict: every configured source must reference a registered `Verifier`; an unsigned source is not allowed in v1.
- **Outbound subscriber identity (SSE pull and admin)**: opaque bearer tokens stored in SQLite, hashed with Argon2id, scoped to a list of source identifiers and/or the special scope `admin`. Tokens are issued via `hooksctl token add --scopes <list>` and printed in plaintext exactly once. The inspector and the token/push management APIs require `admin` scope; an SSE subscribe call requires the source identifier to be in the token's scopes.
- **Outbound push delivery (relay → consumer)**: each push subscription has its own HMAC signing secret. The relay sets `X-Hooks-Signature: t=<unix>,v1=<hex>` on every outbound POST; consumers verify by recomputing HMAC-SHA256 over `<unix>.<body>` with their stored copy of the secret. Signing-secret rotation is supported via `hooksctl push rotate-secret <id>` and takes effect on the very next attempt.

All hashed-secret comparisons use `subtle.ConstantTimeCompare`. Plaintext tokens and signing secrets are never logged; the logging package has a typed `secret.String` that redacts on `String()` and `MarshalJSON`.

### Token & subscription storage: all in SQLite, none in YAML

`hooks.yaml` carries source secrets, per-source retention, and runtime knobs (listen addr, body size limit, dedupe window) only. Listener tokens, push subscriptions, and their cursors are runtime-mutable state and live in the database. `hooksctl token` and `hooksctl push` are the supported management surfaces; the inspector renders the same data with action buttons. This means tokens and push subscriptions cannot be diff-reviewed in version control, but it also means rotating either does not require a config reload, and ad-hoc dev push targets do not require editing YAML.

### Retention: auto-prune after 30 days, configurable per source

The store runs a pruner goroutine that wakes every hour and deletes events whose `received_at` is older than the source's configured retention. Default retention is **30 days**. Setting a source's retention to `0` (or the literal `forever` in YAML) disables auto-prune for that source. Retention is per-source so a noisy provider can be capped tighter without affecting a low-volume one. `hooks prune --older-than=<duration>` remains as a manual one-shot for ad-hoc cleanup.

**Why not row-count-based**: a chatty source could evict a quiet source's history, which is a worse failure mode than "disk grows." Time-based, per-source preserves reasoning.

### TLS posture: behind a reverse proxy

The relay binds plain HTTP on a configurable address and is expected to live behind a TLS-terminating proxy. Webhook providers reject plain HTTP, so the deployment guide specifies the proxy step. We chose this over autocert/built-in TLS because reverse proxies are universal in 2026, single-binary deploys typically already involve one (Render itself is one), and adding ACME logic would meaningfully expand the failure surface for a tool whose first job is to be a boring durable buffer.

### Configuration: YAML file + env overrides (smaller surface)

A single `hooks.yaml` carries `sources:` (name, verifier, secret, retention, optional skew override, optional body-size override) plus runtime defaults; env vars override runtime knobs (`HOOKS_LISTEN_ADDR`, `HOOKS_DATABASE_URL`, `HOOKS_LOG_LEVEL`). Secrets in the YAML can be `${VAR}` interpolated so the file itself is checkable into version control alongside a `.env`. **Listener tokens and push subscriptions are not in this file** — they are mutable runtime state, managed via the CLI and inspector.

### Project layout

```
cmd/hooks/         # main server binary
cmd/hooksctl/      # developer CLI
internal/config/   # YAML + env loading, validation
internal/secret/   # secret.String type, redaction helpers
internal/sources/  # provider plugins (render.go, …) implementing Verifier
internal/store/    # EventStore, TokenStore, PushSubscriptionStore — interfaces + sqlite impls
internal/tokens/   # listener token mgmt: issue, hash, scopes, lookup, last-used updates
internal/ingest/   # HTTP handler that runs Verifier → EventStore
internal/subscribe/# SSE handler, in-process pub/sub
internal/push/     # outbound dispatcher, HMAC signing, retry/backoff, subscription CRUD API
internal/prune/    # retention pruner goroutine
internal/inspector/# embedded HTML/htmx for the web UI; admin-scope auth
```

### Developer experience choices

- `hooks init` is interactive (with `--non-interactive` flag): writes `hooks.yaml`, creates the database, generates a strong `admin`-scoped token, and prints the path to the config, the token (exactly once), the URL to register with Render, and copy-paste-ready `hooksctl forward` and `hooksctl push add` invocations.
- `hooksctl forward --source render --to http://localhost:3000/webhooks/render` subscribes via SSE, replays missed events from a local cursor file, then pipes live events to the local URL with the original headers preserved. Default behavior on local-target 5xx is exponential backoff (capped 60s) for parity with push delivery; `--exit-on-error` flips this for CI use. The cursor file lives at `${XDG_STATE_HOME:-$HOME/.local/state}/hooks/cursor-<server-host>-<source>`.
- `hooksctl push add --source render --to https://my-svc.example.com/hooks` registers a server-side push subscription, prints the plaintext signing secret exactly once, and starts dispatching.
- The web inspector at `/inspector` is intentionally low-tech: server-rendered HTML, htmx-driven event list with body preview, push-subscription table with queue depth + last error, token-management form, and "Replay to listeners" actions. No build step, no SPA. This keeps the binary self-contained and the UI debuggable.
- A `--dev` mode runs the server, opens the inspector in the browser, and prints a localhost ingestion URL plus a sample provider-side curl command — answering "how do I see this work end-to-end" in under 60 seconds.

### Defaults table

| Knob | Default | Override |
|---|---|---|
| Listen addr | `:8080` | `HOOKS_LISTEN_ADDR` env / flag |
| Database | `./hooks.db` | `HOOKS_DATABASE_URL` env / flag |
| Body size limit | 1 MiB | `body_size_limit` (yaml, per-source override) |
| Dedupe window | 24h | `dedupe_window` (yaml) |
| Replay-attack skew | 5 min | `skew_window` (yaml, per-source override) |
| Retention (per source) | 30 days | `retention` (yaml, per-source) |
| Push per-attempt timeout | 30s | per-subscription |
| Push backoff cap | 60s | n/a |
| SSE keepalive | 30s | n/a |
| SSE replay batch | 1000 events | n/a |

## Risks / Trade-offs

- **SQLite write contention under high webhook burst** → Mitigation: WAL mode + a single ingest goroutine per source serializes writes naturally; Render's webhook volumes are well within SQLite's 10k+ writes/sec ceiling. We log p99 ingest latency and surface it on `/healthz`.
- **At-least-once means listeners can see duplicates** → Mitigation: every event carries `delivery_id`; both SSE and push docs demonstrate idempotent consumption; `X-Hooks-Signature` on push lets consumers verify origin even if duplicates flow in.
- **A misconfigured push subscription floods a target on first connect** → Mitigation: default cold-start cursor is `since=latest`, so a freshly-registered consumer gets only events from registration onward; opt-in `--since=0` is documented as "you really want this only if migrating from another system."
- **Pathological push target queues backlog forever** → Mitigation: inspector surfaces queue depth and last error per subscription; `hooksctl push pause/resume/rm` are the safety valves; dispatcher logs a WARN when `consecutive_failures` first crosses 100. We accept that "alerting" is the operator's responsibility — this is a self-hosted tool.
- **Plaintext signing secret leaked at registration** → Mitigation: secret is printed exactly once, persisted Argon2id-hashed, and rotatable via `hooksctl push rotate-secret <id>` which takes effect on the very next attempt. Tests assert that no path returns the plaintext after issuance.
- **Secret leakage in error logs** → Mitigation: typed `secret.String` redacts on `String()`/`MarshalJSON`; we forbid logging raw request bodies and headers at info level. Tests assert that signature mismatches log only the source name and a hash prefix.
- **Pure-Go SQLite is slower than CGO SQLite** → Acceptable for our volumes; we benchmark in CI and revisit only if p99 ingest crosses 50ms.
- **Single-binary deployment cannot be load-balanced** → Acceptable for v1; the `EventStore` interface and SSE design do not preclude a future Postgres + Redis-pubsub deployment, but we will not build it speculatively.
- **DB-only token storage prevents version-controlled review** → Mitigation: `hooksctl token list` and the inspector both expose the token catalog; we recommend ops keep a checked-in note of which tokens exist (id, name, scopes) without the secret.

## Migration Plan

There is no existing system to migrate from. The deployment steps are:

1. Build/download the binary, copy it to the host.
2. Run `hooks init` to generate `hooks.yaml`, create the database, and print an admin-scoped token (exactly once).
3. Stand up a TLS-terminating reverse proxy in front of the relay (or deploy on Render itself, which provides TLS).
4. Add a Render webhook pointing at `https://<host>/ingest/render` with the secret from `hooks.yaml`.
5. On the developer machine, run `hooksctl forward --source render --to http://localhost:3000/webhooks/render` (SSE pull). Or, for a long-lived service consumer, run `hooksctl push add --source render --to https://service.example.com/hooks` and configure the service to verify `X-Hooks-Signature`.

Rollback is "stop the binary"; the SQLite file is the only state and is easy to back up.

## Open Questions

The previously-open questions are resolved. Remaining smaller defaults to validate during implementation:

- 30s default per-attempt push timeout — revisit if real consumers need longer.
- One-in-flight POST per subscription — cross-subscription concurrency is unbounded by the dispatcher; only the per-target HTTP cap matters.
- Per-source HMAC key rotation flow for *inbound* (provider) secrets is manual (edit YAML, restart) in v1; we will revisit if rotation cadence becomes painful.
