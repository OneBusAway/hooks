## 1. Project scaffolding

- [x] 1.1 Initialize Go module: `go mod init github.com/onebusaway/hooks`
- [x] 1.2 Create directory layout: `cmd/{hooks,hooksctl}`, `internal/{config,secret,sources,store,tokens,ingest,subscribe,push,prune,inspector}`
- [x] 1.3 Add `.golangci.yml` with the project's linter ruleset and a `make lint` target
- [x] 1.4 Add `Makefile` with `build`, `test`, `lint`, `run`, `dev` targets
- [x] 1.5 Add `.github/workflows/ci.yml` running `go test ./...`, `go vet ./...`, and golangci-lint on push/PR
- [x] 1.6 Write top-level `README.md` with one-paragraph description and pointer to `hooks init`

## 2. Configuration loader

- [x] 2.1 Define `Config` struct in `internal/config` (sources with verifier+secret+retention+per-source overrides; runtime knobs: listen addr, db url, dedupe window, body size limit, skew window, log level)
- [x] 2.2 Implement YAML loader with `${ENV}` interpolation
- [x] 2.3 Implement env-var overrides (`HOOKS_LISTEN_ADDR`, `HOOKS_DATABASE_URL`, `HOOKS_LOG_LEVEL`)
- [x] 2.4 Implement strict validation: every source declares a registered verifier; secrets are non-empty after interpolation; YAML may NOT contain a `tokens:` field (loader fails with explicit message if present)
- [x] 2.5 Add `secret.String` type in `internal/secret` that redacts on `String()` and `MarshalJSON`; `subtle.ConstantTimeCompare` helpers
- [x] 2.6 Unit tests for loader and validation, including round-trip with interpolation, missing-verifier rejection, empty-secret rejection, tokens-in-yaml rejection

## 3. Event store interface and SQLite implementation

- [x] 3.1 Define `EventStore` interface (`Append`, `ReadSince`, `Get`, `LatestSequence`, `Prune`) and `Event` struct in `internal/store`
- [x] 3.2 Define `ErrDuplicate` sentinel error
- [x] 3.3 Implement SQLite backend using `modernc.org/sqlite` with WAL mode and `synchronous=NORMAL`
- [x] 3.4 Write idempotent schema migration for `events` (PK on `(source, sequence)`, index on `(source, delivery_id)`, index on `received_at` for prune)
- [x] 3.5 Implement per-source monotonic sequence assignment under transaction
- [x] 3.6 Implement dedupe lookup that returns `ErrDuplicate` on `(source, delivery_id)` collision within the configured window
- [x] 3.7 Implement `Prune` with parameterized cutoff (used by both auto-prune and manual)
- [x] 3.8 Write contract tests that any `EventStore` impl must pass (gapless sequences, durability after process kill via subprocess test, dedupe behavior, cursor reads)
- [x] 3.9 Wire SQLite impl through the contract tests

## 4. Token store + listener-token management

- [x] 4.1 Define `TokenStore` interface in `internal/store` (`Insert`, `LookupByPlaintext`, `TouchLastUsed`, `List`, `Revoke`)
- [x] 4.2 Schema migration for `listener_tokens` (id, name, scopes, secret_hash, created_at, last_used_at, revoked_at)
- [x] 4.3 Implement SQLite TokenStore
- [x] 4.4 Implement `internal/tokens` package: token generation (32 random bytes, base64url), Argon2id hashing, scope parsing, prefix-indexed lookup for performance
- [x] 4.5 Bearer-token middleware: parse `Authorization: Bearer …`, look up, constant-time verify, check scope (incl. `admin`), update `last_used_at`
- [x] 4.6 Unit tests covering: plaintext never persisted, revoked tokens rejected within 1s, admin scope alone cannot subscribe to a source, tokens-in-yaml rejected by loader

## 5. Push-subscription store

- [x] 5.1 Define `PushSubscriptionStore` interface (`Insert`, `List`, `Get`, `UpdateCursorAndSuccess`, `RecordFailure`, `Pause`, `Resume`, `RotateSecret`, `Delete`)
- [x] 5.2 Schema migration for `push_subscriptions` (id, source NOT NULL, target_url, signing_secret_hash, name, cursor, paused_at, created_at, last_attempt_at, last_success_at, last_error, consecutive_failures)
- [x] 5.3 Implement SQLite store with atomic cursor+success update in one transaction; atomic failure record
- [x] 5.4 Contract tests: cursor monotonic, single-source enforcement, paused subs excluded from default `List`, `RotateSecret` invalidates old hash

## 6. Provider plugin model and Render verifier

- [x] 6.1 Define `Verifier` interface in `internal/sources` (`Verify(headers, body) (timestamp, deliveryID, error)`; `RequiredHeaders() []string`)
- [x] 6.2 Implement provider registry with `Register(name string, factory func(secret string) Verifier)`; resolved at config-load time so unknown verifiers fail startup
- [x] 6.3 Implement Render verifier per https://render.com/docs/webhooks: parse `Render-Webhook-Signature` (`t=…,v1=…`), HMAC-SHA256 over `<t>.<body>`, constant-time compare, extract timestamp from `t`, extract `delivery_id` from `Render-Webhook-Id`
- [x] 6.4 Unit tests for Render verifier: valid signature, tampered body, wrong secret, malformed header, missing header, future-dated timestamp, stale timestamp, configurable skew override
- [x] 6.5 Documentation comment on `Verifier` interface showing how to add a new source

## 7. Ingestion HTTP handler

- [x] 7.1 Implement `POST /ingest/<source>` handler in `internal/ingest`
- [x] 7.2 Enforce body size limit before reading (default 1 MiB, per-source override) → HTTP 413
- [x] 7.3 Look up source verifier from registry; HTTP 404 if source unknown
- [x] 7.4 Run verifier against headers + body; HTTP 401 on signature failure or out-of-window timestamp; log only source name + hash prefix on mismatch
- [x] 7.5 Append to store; on `ErrDuplicate` return HTTP 200 with no further side effects; on other error HTTP 503
- [x] 7.6 On success return HTTP 202 and publish `(source, sequence)` to in-process notify channel
- [x] 7.7 Integration tests using `httptest.Server` covering every scenario in `webhook-ingestion/spec.md`

## 8. SSE subscription / pull delivery

- [x] 8.1 Implement in-process per-source pub/sub: `Notifier.Publish(source, sequence)` and `Notifier.Subscribe(source) chan int64` with non-blocking send + drop-signal-not-event semantics
- [x] 8.2 Implement `GET /subscribe/<source>` SSE handler in `internal/subscribe`
- [x] 8.3 Parse `since` query param (`<int>` | `latest` | absent → 0); fold in `Last-Event-ID` (max wins)
- [x] 8.4 Replay loop: read from store in batches of ≤1000, flush each batch, advance cursor
- [x] 8.5 Live loop: select on notify channel + 30s keepalive ticker; on signal, drain newer events from store
- [x] 8.6 Honor request context cancellation; release subscription registration within 1s of disconnect
- [x] 8.7 Format SSE message: `id:<seq>\nevent:<source>\ndata:<json>\n\n` with base64 body
- [x] 8.8 Integration tests covering each scenario in `event-subscription/spec.md` (replay-then-live continuity, slow-listener catch-up, idle keepalive, scope enforcement incl. admin-alone-cannot-subscribe, 100 concurrent subscribers)

## 9. Listener-token CLI and HTTP API

- [x] 9.1 Implement `hooksctl token add --name --scopes`: generate token, store hash, print plaintext exactly once
- [x] 9.2 Implement `hooksctl token list` (no plaintext; supports `--include-revoked`)
- [x] 9.3 Implement `hooksctl token revoke <id>`
- [x] 9.4 Implement `/api/tokens` HTTP routes (admin-scope-required) for the inspector UI
- [x] 9.5 Tests: each subcommand round-trips against an in-memory store; `/api/tokens` rejects non-admin

## 10. Push-delivery dispatcher

- [x] 10.1 Implement push dispatcher in `internal/push`: one goroutine per non-paused subscription, started/stopped on `Insert`/`Pause`/`Resume`/`Delete`
- [x] 10.2 Implement HMAC signing helper: `X-Hooks-Signature: t=<unix>,v1=<hex>` over `<unix>.<body>`
- [x] 10.3 Implement outbound POST builder: preserve original headers, strip hop-by-hop, set `X-Hooks-Delivery-Id`, `X-Hooks-Sequence`, `X-Hooks-Source`
- [x] 10.4 Implement attempt loop: read batch from store > cursor → POST first → on 2xx update cursor+success → on failure record + sleep `min(60s, 2^failures*100ms)` with full jitter → no cursor advance
- [x] 10.5 Wire `Notifier.Subscribe` to wake idle dispatchers (no-shorten if currently in active backoff with pending events)
- [x] 10.6 Per-attempt 30s timeout (configurable per subscription); WARN log when `consecutive_failures` first crosses 100 in a streak
- [x] 10.7 Integration tests covering each scenario in `push-delivery/spec.md`: out-of-order is impossible, 2xx advances cursor, non-2xx does not, multi-hour outage produces full catch-up in order, backoff bounded, recovery resets, hop-by-hop stripped, replay-from-inspector does not advance cursor

## 11. Push-subscription HTTP API + `hooksctl push` CLI

- [x] 11.1 Implement `POST /api/push-subscriptions` (admin scope): create subscription, return id+cursor+plaintext signing_secret exactly once
- [x] 11.2 Implement `GET /api/push-subscriptions` (list) and `GET /api/push-subscriptions/<id>` (detail)
- [x] 11.3 Implement `POST /api/push-subscriptions/<id>/{pause,resume,rotate-secret,test}` and `DELETE /api/push-subscriptions/<id>`
- [x] 11.4 Implement `hooksctl push {add,list,get,pause,resume,rotate-secret,rm,test}` against those endpoints
- [x] 11.5 Cold-start cursor defaults to `latest` (highest current sequence at registration); `--since 0` opts into backfill
- [x] 11.6 Tests: registration with unknown source → 400; multi-source registration → 400; rotate-secret takes effect on next attempt; test does not advance cursor

## 12. Auto-prune retention

- [x] 12.1 Implement pruner goroutine in `internal/prune`: hourly tick, per-source pass using configured retention, single transaction per source
- [x] 12.2 Honor retention `0`/`forever` as "no auto-prune"
- [x] 12.3 Log row counts deleted per source per pass
- [x] 12.4 Implement `hooks prune --older-than=<duration>` manual one-shot
- [x] 12.5 Tests: 31-day-old event pruned at default 30d; `forever` keeps everything; per-source independence

## 13. Inspector web UI

- [x] 13.1 Embed HTML/CSS/htmx assets via `embed.FS` in `internal/inspector`
- [x] 13.2 Implement admin-scope cookie flow + token-entry form at `/inspector/login`
- [x] 13.3 Implement `/inspector` index: 50 most recent events, source filter, htmx swap on filter change
- [x] 13.4 Implement `/inspector/events/<source>/<sequence>` detail view: headers table, pretty-printed body for JSON, raw bytes hex preview otherwise, `body_sha256`, "Copy as curl"
- [x] 13.5 Implement "Replay to listeners" button: fans out to SSE + non-paused push subs (push gets `X-Hooks-Replay: 1` and does NOT advance cursor)
- [x] 13.6 Implement `/inspector/tokens` page: list, add (plaintext shown once on result page), revoke
- [x] 13.7 Implement `/inspector/push` page: list with cursor+queue-depth+failure stats, inline `pause/resume/rotate-secret/delete/test` actions, rotate-secret confirmation page shows plaintext once
- [x] 13.8 End-to-end test using `net/http/httptest` and `goquery` (or similar) for index, detail, replay, token mgmt, push mgmt flows; assert plaintext secrets appear in HTML at most once and never on list views

## 14. `hooks` server binary

- [x] 14.1 Implement `cmd/hooks` main: parse flags, load config, open store, build router, start HTTP listener, start dispatchers + pruner
- [x] 14.2 Implement `hooks init`: refuse if `hooks.yaml` exists without `--force`; generate admin-scoped token; create `hooks.yaml` and `hooks.db`; print quickstart (config path, token once, register-with-Render URL, sample `hooksctl forward` + `hooksctl push add` commands)
- [x] 14.3 Implement `hooks prune --older-than <duration>`
- [x] 14.4 Implement `hooks verify` (recompute body hashes, exit non-zero on mismatch)
- [x] 14.5 Implement `--dev` flag: verbose logging, open browser to inspector, print quickstart commands to stderr
- [x] 14.6 Implement `/healthz` and `/readyz` with the documented semantics
- [x] 14.7 Graceful shutdown on SIGTERM/SIGINT (drain in-flight requests, stop dispatchers, close store)

## 15. `hooksctl` CLI shell

- [x] 15.1 Scaffold `cmd/hooksctl` with subcommand router (`tail`, `forward`, `replay`, `token`, `push`)
- [x] 15.2 Add global flags `--server` (default `http://localhost:8080`) and `--token` (default from `HOOKS_TOKEN`)
- [x] 15.3 Implement `hooksctl tail <source>` consuming SSE; pretty/JSON output modes; SIGINT handler that prints `last-acked: <seq>` to stderr and exits 0
- [x] 15.4 Implement `hooksctl forward <source> --to <url>`: cursor file at `${XDG_STATE_HOME:-$HOME/.local/state}/hooks/cursor-<server-host>-<source>`, replay-then-live, advance cursor only on 2xx, exponential backoff capped at 60s, `--exit-on-error` flag
- [x] 15.5 Implement `hooksctl replay <source> <sequence> --to <url>` for one-shot replay
- [x] 15.6 Integration test using a live `hooks` server in a temp dir: `hooksctl forward` against an `httptest` target, simulate target 5xx and assert cursor file does not advance

## 16. Documentation

- [x] 16.1 Write `docs/quickstart.md`: install, `hooks init`, set up TLS-terminating proxy, register a Render webhook, run `hooksctl forward`, then walk through `hooksctl push add`
- [x] 16.2 Write `docs/sources.md`: how to add a new provider plugin, with Render as the worked example
- [x] 16.3 Write `docs/security.md`: HMAC details (inbound + outbound), token storage, replay-window rationale, what is and is not protected (not protected: TLS — handled by the proxy)
- [x] 16.4 Write `docs/operations.md`: backup the SQLite file, retention/prune cadence, observability (structured JSON logs in v1), multi-process limitations, push-subscription health monitoring via inspector
- [x] 16.5 Write `docs/consumer-verification.md`: how a push-target service should verify `X-Hooks-Signature` (with sample Go and curl snippets)

## 17. Acceptance and release

- [ ] 17.1 Manual end-to-end smoke test: real Render webhook → server → `hooksctl forward` → local app, verify body bytes match
- [ ] 17.2 Manual end-to-end smoke test: Render webhook → server → `hooksctl push add` → real consumer service that verifies `X-Hooks-Signature`
- [x] 17.3 Verify every spec scenario maps to a passing automated test (or a documented manual-only test for `--dev`-mode browser opening)
- [x] 17.4 Run `openspec validate add-webhook-relay --strict` and resolve any findings
- [ ] 17.5 Tag a `v0.1.0` release with prebuilt binaries for darwin/arm64, darwin/amd64, linux/amd64
