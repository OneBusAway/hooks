# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`hooks` is a single-binary, self-hosted webhook relay. It receives HMAC-signed inbound webhooks (Render is the only built-in provider so far), persists them durably to SQLite, and re-delivers to developer environments either via SSE pull (`hooksctl forward`) or HTTP push subscriptions. Replay of anything missed while a consumer was disconnected is a first-class feature.

There are two binaries:

- `cmd/hooks` — the server. Also exposes subcommands: `init` (scaffold `hooks.yaml` + DB + admin token), `prune --older-than <dur>`, `verify` (recompute body sha256 across the store).
- `cmd/hooksctl` — operator/developer CLI. Subcommands: `tail`, `forward`, `replay`, `token {add,list,revoke}`, `push {add,list,get,pause,resume,rotate-secret,rm,test}`. Honors `HOOKS_SERVER` and `HOOKS_TOKEN` env vars.

## Common commands

```sh
make build          # builds ./bin/hooks and ./bin/hooksctl
make test           # go test ./...
make lint           # golangci-lint run ./... (config in .golangci.yml)
make tidy           # go mod tidy
make dev            # builds and runs `hooks --dev` (verbose, opens inspector)
go test ./internal/store/...                          # one package
go test ./internal/push -run TestDispatcher_Backoff   # one test
```

CI (`.github/workflows/ci.yml`) runs `go vet ./...`, `go test ./...`, and `golangci-lint`. Match it locally before pushing.

Go toolchain: `go.mod` pins `go 1.25.9`. SQLite driver is `modernc.org/sqlite` (pure Go — no cgo).

## Architecture

`internal/server.Build` is the wiring root. Reading it end-to-end is the fastest way to understand the system; everything below is mounted from there onto a single `http.ServeMux`.

```
inbound webhook ──► /ingest/<source> ──► verifier ──► store.Append ──┐
                                                                      ▼
                          notifier.Publish(source, sequence) ◄────────┘
                                          │
                       ┌──────────────────┼─────────────────────┐
                       ▼                  ▼                     ▼
                 SSE subscribers    push workers         (inspector live UI)
                 (subscribe.New)    (push.Manager)
```

### Layers

- **`internal/store`** — `EventStore`, `TokenStore`, `PushSubscriptionStore` interfaces with a SQLite impl in `sqlite.go`. The SQLite handle uses `MaxOpenConns=1` (single writer) plus WAL mode; do not raise this. `Append` returns `ErrDuplicate` on `(source, delivery_id)` collisions inside the dedupe window — callers MUST translate that to HTTP 200, not 5xx. Adapters (`adapters.go`) exist because `TokenStore` and `PushSubscriptionStore` both define `Insert`/`List`. The interfaces are intentionally minimal so a Postgres backend can land later without rippling.

- **`internal/sources`** — `Verifier` interface + a global `Registry`. Providers self-register from `init()` (see `render.go` and `docs/sources.md` for the Stripe example). Adding a new provider is: write `internal/sources/<name>.go` implementing `Verifier`, call `Default.Register("<name>", factory)` in `init()`, reference it in `hooks.yaml`. Zero changes to ingest.

- **`internal/ingest`** — one handler mounted per source at `POST /ingest/<source>`. Pipeline: body-size cap (413) → resolve verifier (404) → `Verify` (401 on signature OR stale timestamp) → `store.Append` (200 on duplicate, 503 on other errors, 202 on success) → `notifier.Publish`.

- **`internal/pubsub`** — in-process `Notifier` with buffer-1 channels. **Publishers never block. If a subscriber's buffer is full the SIGNAL is dropped, never the event.** Every subscriber must backfill from the store on wake — that invariant is what makes signal loss safe. Do not change the buffer size or add blocking sends without rethinking that contract.

- **`internal/subscribe`** — SSE handler at `GET /subscribe/{source}`. Replays from `?since=<seq>` then tails via the notifier.

- **`internal/push`** — `Manager` runs one worker goroutine per non-paused subscription. Workers POST events one at a time, advancing cursor only on 2xx. Backoff is `min(60s, 2^failures*100ms)` with full jitter. Outbound delivery signature: `X-Hooks-Signature: t=<unix>,v1=<hex>` where `v1 = HMAC-SHA256(secret, "<unix>.<body>")` (see `signing.go`). **The plaintext signing secret only lives in memory** — after a restart, push delivery for each subscription is paused until `hooksctl push rotate-secret <id>` re-arms it. This is a deliberate trade-off (don't try to "fix" by persisting plaintext).

- **`internal/tokens`** — listener bearer tokens, Argon2id-hashed at rest. The store package can't import argon2 directly, so `tokens.AttachVerifier(st)` injects the hash-compare function at startup. `LookupByPlaintext` is O(N) per request (re-hashes per row); fine for operator-token volumes. The special scope `admin` grants access to `/inspector` and the management APIs but does NOT implicitly grant subscribe — admin tokens MUST also list source names in scopes to use `/subscribe/<source>`.

- **`internal/secret`** — `secret.String` is a typed credential that returns `[REDACTED]` on `String()`, `GoString()`, and `MarshalJSON`. Always use it for secrets crossing config/log boundaries. Convert to plaintext only at the consumption site via `.Reveal()`. Use `secret.Equal` / `secret.EqualString` for constant-time comparison.

- **`internal/config`** — loads `hooks.yaml`, applies env interpolation (`${VAR}` and `${VAR:-default}`), then env-var overrides (`HOOKS_LISTEN_ADDR`, `HOOKS_DATABASE_URL`, `HOOKS_LOG_LEVEL`). **A `tokens:` field is rejected at load time** — listener tokens live in the database, not YAML. `verifier:` is required for every source; unsigned sources are not supported. Defaults: `BodySizeLimit=1MiB`, `DedupeWindow=24h`, `SkewWindow=5m`, source `Retention=30d`. Retention `0` / `forever` / `never` disables auto-prune for that source.

- **`internal/inspector`** — admin-only web UI under `/inspector`. Templates and static assets are `//go:embed`-ed; the binary is fully self-contained. Auth is a cookie carrying the same plaintext bearer token the API uses (server-side lookup is identical Argon2id constant-time compare).

- **`internal/prune`** — hourly per-source pruner that respects each source's configured retention. The `hooks prune --older-than <dur>` CLI bypasses configured retention for ad-hoc cleanup.

## Conventions

- **Single process, SQLite only.** Running two `hooks` processes against the same DB is unsafe. The interfaces are shaped for a future Postgres + Redis/NATS backend, but that code does not exist; do not assume cross-process notification works.
- **Constant-time compare for any HMAC or token check.** Use `hmac.Equal` or `subtle.ConstantTimeCompare` (`secret.Equal*` wraps the latter). Never `==` on signature bytes.
- **Body bytes are sacred.** Verifiers and push workers must not re-encode JSON, normalize whitespace, or otherwise touch the captured body — the stored bytes are what was signed and what gets re-delivered byte-for-byte.
- **Logs must never contain plaintext secrets, tokens, or full webhook bodies.** On signature mismatch we log only the source name and a 4-byte hex prefix of the body's sha256 (`docs/security.md` has the full policy). Existing tests assert this; keep it that way.
- **`render-webhook-relay`-style providers must reject stale timestamps** outside the configured skew window (default 5m). Return `sources.ErrStaleTimestamp` so the ingest layer maps it to 401.
- **HTTP status discipline at `/ingest`:** 200 for duplicate (we already have it), 202 for newly accepted, 401 for verification failure, 413 for oversize, 404 for unknown source, 503 only for genuine store/transient failures so the provider retries.
- **Health endpoints:** `/healthz` is liveness (always 200 when the listener is up). `/readyz` requires a successful SQLite ping — wire load balancers to `/readyz`.
- **OpenSpec workflow** lives in `openspec/` and the `opsx:*` skills (propose / explore / apply / archive). Use it for non-trivial change planning.
- **Linting** via golangci-lint v2 (`.golangci.yml`): `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, `gosec`, `misspell`, `bodyclose`, `errorlint`, `nilerr`, `revive`, plus `gofmt` + `goimports` formatters. `revive`'s `exported` and `package-comments` rules are disabled. `errorlint` is on, so wrap with `%w` and use `errors.Is`/`errors.As` rather than equality or type assertions.
