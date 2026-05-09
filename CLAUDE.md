# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`hooks` is a single-binary, self-hosted webhook relay. It receives HMAC-signed inbound webhooks (Render is the only built-in provider so far), persists them durably to SQLite, and re-delivers to developer environments either via SSE pull (`hooksctl forward`) or HTTP push subscriptions. Replay of anything missed while a consumer was disconnected is a first-class feature.

There are two binaries:

- `cmd/hooks` — the server. Also exposes subcommands: `init` (scaffold `hooks.yaml` + DB + admin token + bootstrap signup URL), `invite` (mint an admin invite from the local admin token and print a signup URL), `prune --older-than <dur>`, `verify` (recompute body sha256 across the store).
- `cmd/hooksctl` — operator/developer CLI. Subcommands: `tail`, `forward`, `replay`, `login`, `logout`, `whoami`, `me {token {add,list,revoke}, sub {add,list,get,pause,resume,rotate-secret,rm,test}}`, `token {add,list,revoke}`, `push {add,list,get,pause,resume,rotate-secret,rm,test}`, `invite {create,list,revoke}` (admin-only). Auth resolution is `--token` > `HOOKS_TOKEN` > `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>` (written by `hooksctl login`) > unauthenticated. Honors `HOOKS_SERVER` and `HOOKS_TOKEN`.

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

- **`internal/inspector`** — admin-only web UI under `/inspector`. Templates and static assets are `//go:embed`-ed; the binary is fully self-contained. Auth is either a `hooks_session=<id>.<plaintext>` cookie (post-login, server-side `user_sessions` row, SHA-256 hashed) or — legacy — a cookie carrying the plaintext bearer token (Argon2id-hashed lookup, identical to API auth). New logins always create a `user_sessions` row; the legacy path is accept-on-read only.

- **`internal/prune`** — hourly per-source pruner that respects each source's configured retention. The `hooks prune --older-than <dur>` CLI bypasses configured retention for ad-hoc cleanup. Also reaps `ephemeral=true` listener tokens whose `last_used_at` is more than 24h in the past (forward crash-safety net) and `device_pairings` rows 24h after terminal state.

- **`internal/users`** — `users` table (id, email, name, role, password_hash Argon2id, default_scopes, deactivated_at). Owns signup-time password policy enforcement (length ≥ 12, no email substring; failed-policy reason logged, never the plaintext). `Deactivate` is the cascading-revoke path: in one tx it sets `deactivated_at`, revokes every PAT/listener token, and pauses every push subscription owned by the user. A last-admin guard refuses with HTTP 409 if zero admins would remain (checked before AND inside the tx). Reactivation flips `deactivated_at` to NULL and **does not** restore tokens or unpause subscriptions — the user must reissue. Matches GitHub's UX; documented in `docs/security.md`.

- **`internal/audit`** — append-only `audit_events` table surfaced at `/inspector/audit` (admin). Recorder hangs off mutating handlers (invites, users, tokens, sessions, device pairings). Prune loop does not touch this table; metadata is small (operator-action volume, not webhook volume).

- **`internal/ratelimit`** — in-process token-bucket-per-IP (and per-user, for device-approve) middleware. Wired onto auth surfaces in `internal/server.registerAuthRoutes`. Buckets live in process memory and reset on restart — acceptable for the single-process SQLite posture. Limits live next to the route registration; check `internal/server/server.go` for current values.

- **`internal/auth`** — `Manager` plus session middleware and `/api/auth/login` + `/api/auth/logout` JSON handlers. Sessions are 32 random bytes hashed SHA-256, **not** Argon2id (random secrets have no offline-attack surface; per-request Argon2 here is pure cost). 30-day sliding TTL.

- **`internal/invites`** — invite issuance + lifecycle, plus the `/api/auth/signup` JSON handler. Bootstrap invite ensure runs on `hooks init` against an empty users table and inserts a single `bootstrap=true`, role `admin`, `expires_at = now + 24h` row. The bootstrap invite is consumed automatically the first time **any** user is created. Once any account exists, signup via the bootstrap URL returns 409.

- **`internal/devicepair`** — CLI device-pairing flow (`/api/auth/device/{start,poll,approve,deny}` + the server-rendered `/device` page in `internal/webpages`). Approval requires re-entering the password (live session is not enough). Default scope on approval is `account` only; `--scopes`/`--admin` opt-in. Plaintext is briefly persisted on the device row between approval and the CLI's first poll, then NULL'd in a deferred update on handler return. Sweeper transitions stale pendings to `expired`. Phishing defenses (narrow-by-default scope, approver context display, password re-entry) are layered; documented in `docs/security.md`.

- **`internal/me`** — self-service `/api/me/*` JSON handlers (profile, tokens, push subscriptions). Token creation enforces scope rules: a non-admin user can only request scopes they hold (default_scopes ∪ {account}); admins implicitly hold every source scope and `admin`; empty scope arrays on `kind='pat'` are normalized to `["account"]` rather than minting an unprivileged ghost.

- **`internal/admin`** — admin-only `/api/users/*`, `/api/invites/*`, `/api/audit` JSON handlers and admin filters (`?owner=...`) on the existing `/api/tokens` and `/api/push-subscriptions` endpoints.

- **`internal/web`** — CSRF middleware (Origin/Referer match + per-session double-submit token cookie). Bearer-only requests skip CSRF (no cookie → can't be CSRF'd). Wired around every cookie-authenticated mutation in `registerAuthRoutes`.

- **`internal/webpages`** — server-rendered `/login`, `/signup`, `/device` HTML pages. Templates `//go:embed`-ed alongside the inspector. `/device` is where the device-pairing approval form lives; the JSON `/api/auth/device/*` endpoints exist for hooksctl + SPA callers.

### Token kinds

Listener tokens and PATs share a row schema (`listener_tokens`) but are routed by `kind` at lookup time:

- **`kind='listener'`** — authorizes `/subscribe/<source>` and (when admin-scoped) the inspector. Cannot reach `/api/me/*`.
- **`kind='pat'`** — owned by a user; authorizes `/api/me/*` and the inspector. Cannot subscribe to event traffic.

Setting `owner_user_id=NULL` is reserved for system tokens minted by `hooks init` or `hooksctl token add` against an empty DB. NULL ownership does not mutate scopes — system tokens retain whatever scopes they were minted with.

### Cookie session model vs token Argon2id

Cookie session secrets are 32 random bytes, hashed **SHA-256**. Bearer-token plaintexts (PATs and listener tokens) and passwords are hashed **Argon2id**. The asymmetry is deliberate — Argon2id buys nothing for high-entropy random secrets, costs CPU per request, and would produce a slowdown under sustained inspector load with no security benefit. See `docs/security.md` for the rationale.

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
