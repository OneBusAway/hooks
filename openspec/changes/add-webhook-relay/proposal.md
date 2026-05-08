## Why

Inbound webhooks (e.g. Render service events) are fire-and-forget: if your local dev tunnel is down, your laptop is asleep, or your service is mid-restart, the message is gone. Render does not retry indefinitely, and there is no built-in way to inspect, audit, or replay what was delivered. We need a small, self-hosted relay that durably captures every webhook, verifies it cryptographically, and lets one or more developer environments subscribe — pulling a stream over SSE or being POSTed at a registered URL — including replaying anything they missed while disconnected.

## What Changes

- New Go service (module path `github.com/onebusaway/hooks`) that exposes a per-source inbound endpoint (e.g. `/ingest/render`), verifies the provider's signature + timestamp, and persists the raw request to a durable event log.
- Append-only event store with a monotonic per-source sequence number, content hash for deduplication, and full request capture (headers, body, received-at). Events auto-prune after 30 days by default; retention is configurable per source (set to `0` to disable auto-prune).
- **Dual delivery**:
  - **Pull (SSE)**: authenticated subscribers open `GET /subscribe/<source>` and receive a replay-then-live stream with a `since=<seq|latest>` cursor.
  - **Push (HTTP POST)**: registered subscriptions are delivered to a target URL, signed with a per-subscription HMAC. Cursor is tracked server-side; if a target is unreachable the dispatcher retries with exponential backoff (capped at 60s) forever, and replays every missed event in order when the target recovers.
- Provider plugin model with Render as the first concrete implementation (HMAC-SHA256 over `timestamp.body` per Render's webhook spec, with a 5-minute clock-skew window). Strict: every configured source must declare a registered `Verifier`; unsigned providers are not supported in v1.
- All listener identity (SSE bearer tokens, push subscriptions, inspector access) lives in SQLite and is managed via `hooksctl`. Bearer tokens are scoped (e.g. `["render", "admin"]`) and hashed at rest with Argon2id; push subscriptions carry their own per-row HMAC signing secret hashed the same way.
- Developer inspector at `/inspector` (gated by `admin` scope) for browsing events, replaying to live subscribers, and managing tokens and push subscriptions; companion CLI `hooksctl` for `tail`, `forward`, `replay`, `token`, `push`.
- First-run developer experience: single binary, SQLite default, `hooks init` generates an admin-scoped token and prints the exact provider-side curl to register a Render webhook plus the exact `hooksctl forward` and `hooksctl push add` invocations.

## Capabilities

### New Capabilities

- `webhook-ingestion`: HTTP receive surface with provider-pluggable signature verification, replay-attack rejection, and durable accept-or-reject semantics. Strict: no unsigned sources.
- `event-store`: Append-only, per-source sequenced event log with deduplication, configurable per-source auto-prune (30-day default), durable token and push-subscription state, and cursor-based reads.
- `event-subscription`: Authenticated SSE pull delivery with replay-from-cursor and live tailing in a single stream; unified DB-backed listener-token model with scopes (sources + `admin`).
- `push-delivery`: Outbound HTTP POST delivery to registered subscriptions, with per-subscription HMAC signing, server-side cursor tracking, automatic catch-up on recovery, and bounded-rate retry-forever semantics.
- `dev-inspector`: Admin-scoped web UI and `hooksctl` CLI for browsing events, replaying, forwarding to local targets, and managing tokens and push subscriptions.

### Modified Capabilities

<!-- None — this is the initial change in a fresh repo. -->

## Impact

- New Go module at the repo root: `github.com/onebusaway/hooks`, with internal packages for ingestion, storage, subscription, push delivery, tokens, prune, and the inspector.
- New runtime dependency: SQLite (via `modernc.org/sqlite`, pure-Go, no CGO) for the default deployment; storage layer is interface-bounded so a Postgres backend can land later without touching the API surface.
- New configuration surface: env vars (`HOOKS_DATABASE_URL`, `HOOKS_LISTEN_ADDR`, `HOOKS_LOG_LEVEL`) plus a YAML file for per-source secrets, per-source retention, and runtime knobs only — listener tokens and push subscriptions live in the database, not in YAML.
- TLS is expected to be terminated by a reverse proxy (Caddy, nginx, Cloudflare, Render's built-in HTTPS, etc.); the relay speaks plain HTTP on its bound address.
- No existing code is affected — the repo is empty apart from this OpenSpec setup.
- Operational footprint: one HTTP service plus background goroutines for push dispatch (one per active subscription) and retention pruning (one). One on-disk SQLite file; no external services required by default.
