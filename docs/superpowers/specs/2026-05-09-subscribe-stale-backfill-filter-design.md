# Skip stale events on `/subscribe` initial backfill

**Status:** approved, pending implementation
**Date:** 2026-05-09
**Affects:** `internal/subscribe`, `internal/server` (handler wiring)

## Problem

`/subscribe/<source>` opens an SSE stream that first replays every event since the caller's cursor and then tails live. The replay is byte-for-byte: each event carries the original provider headers (Render's Standard Webhooks set: `webhook-id`, `webhook-timestamp`, `webhook-signature`).

Standard Webhooks consumers reject messages whose `webhook-timestamp` is older than a tolerance window (5 minutes by default; hardcoded in the `standard-webhooks` Ruby gem and several other implementations). Any event sitting in the relay's store longer than that window will be rejected by a verifying consumer when replayed — verification fails with `"Message timestamp too old"` even though the HMAC is valid.

The conflict is structural. The relay durably stores webhooks; consumers verify timestamps strictly. As soon as automatic replay crosses the consumer's tolerance, every redelivery 401s. The Rails app behind `hooksctl forward` is exhibiting exactly this:

```
Render webhook: signature verification failed: Message timestamp too old
Filter chain halted as :verify_render_signature rendered or redirected
Completed 401 Unauthorized
```

## Decision

Stop automatic catch-up of stale events. Manual replay is unaffected.

A fresh `/subscribe/<source>` connection's **initial backfill** filters out events whose `provider_timestamp` is older than the source's existing `SkewWindow` (default 5 minutes, configurable per source in `hooks.yaml`). The cursor advances past skipped events so reconnects do not re-evaluate them. **Live tail is unaffected** — drains triggered by the notifier or the keepalive ticker do not filter.

This is a deliberate inversion of the relay's documented "replay anything missed while disconnected" promise. A consumer offline for longer than `SkewWindow` will silently miss events that landed during the gap. The trade-off is accepted because:

- Standard Webhooks consumers cannot accept stale messages without weakening their own replay-attack defense.
- The relay still owns the events. Operators can recover any specific delivery via the inspector's "Replay to listeners" action, `hooksctl replay`, or direct DB inspection — those paths are unchanged.

## Behavior in detail

### What changes

`/subscribe/<source>` initial backfill — the first `drain` call before the live select loop — filters events by age.

| Field used for the age check | `provider_timestamp` (the original webhook timestamp; matches what the consumer will check) |
| Threshold | the source's `SkewWindow` from config (default 5m) |
| Comparison | `now - provider_timestamp > SkewWindow` skips; equal-to-window passes (matches `render.go:102` `delta > skew` semantics) |
| Cursor on skip | advances to the skipped event's sequence so future reconnects with `?since=<seq>` start past it |
| Skipped event in the store | unchanged; remains queryable, replayable, and pruneable per existing retention rules |
| Logging | one `slog.Debug` line per skip with `source`, `seq`, `delivery_id`, `age`, `skew_window` |

### What does not change

- **Live tail.** Once initial backfill returns, drains triggered by `Notifier.Publish` or the keepalive ticker do **not** filter. Live ingest events are fresh by definition (they just passed the same `SkewWindow` check at ingest), and the inspector "Replay to listeners" button uses `Notifier.Publish` to wake currently-connected SSE subscribers — that path stays open.
- **Push subscriptions.** `internal/push.Manager` workers and `Push.ReplayOne` operate on a separate code path with a separate cursor model. Untouched.
- **Manual inspector replay** (`POST /events/{source}/{sequence}/replay`). Untouched. `Push.ReplayOne` continues to deliver to push subscribers regardless of age. The SSE side of manual replay (which uses `Notifier.Publish`) keeps working for already-connected subscribers because live tail is unfiltered. Edge case: if a fresh SSE subscriber happens to be inside its initial-backfill drain at the moment a stale event is manually replayed, that subscriber will skip the event during backfill (initial backfill filters). This is consistent with the design — initial backfill is the catch-up path the design suppresses — and recovers via reconnect (live-tail) plus the relay's other replay surfaces.
- **`hooksctl forward`.** No client change. The server change is sufficient.
- **Ingest-time skew check.** Existing behavior in `internal/sources/render.go` is correct and unchanged.
- **Retention / pruning.** Stale events live in the store under each source's configured retention; only their automatic redelivery is suppressed.

## Architecture

### Plumbing

`subscribe.Handler` currently holds:

```go
type Handler struct {
    Sources map[string]bool
    // ...
}
```

It needs the per-source `SkewWindow` to apply the filter. Replace with:

```go
type Handler struct {
    Sources map[string]time.Duration  // skew window per allowed source; zero = source not allowed
    // ...
}
```

`internal/server.Build` constructs the handler and already has the per-source config in scope (it reads `hooks.yaml` into a `config.Config` whose `Source` entries carry `SkewWindow`). Wiring change is local to `Build`.

`subscribe.New`'s signature changes from `sources []string` to `sources map[string]time.Duration`. The package is internal and the production caller is a single line in `internal/server.Build`; tests are updated alongside the change. No backward-compat shim.

### Filter location

The age filter lives in `subscribe.Handler.drain`, gated by a parameter that says "this is the initial backfill" vs "this is a live drain." Implementation sketch:

```go
// Initial backfill: filter by age.
cursor, err := h.drain(ctx, w, flusher, source, cursor, batchLimit, h.Sources[source]) // pass skew
// Live drains: no filter.
cursor, err := h.drain(ctx, w, flusher, source, cursor, batchLimit, 0) // 0 = no filter
```

Inside `drain`, when `maxAge > 0`, events older than `now - maxAge` are skipped and the cursor is advanced past them; otherwise emit unconditionally (current behavior).

The `now` source is injected for testability — Handler gains a `Now func() time.Time` field defaulting to `time.Now`, mirroring the pattern already used in `internal/sources/render.go`.

## TDD outline

Tests live in `internal/subscribe/handler_test.go` alongside the existing suite.

1. **Initial backfill skips a stale event.** Seed one event with `provider_timestamp = now - 10m`, source `SkewWindow = 5m`. Connect; read SSE stream until live transition. Assert no SSE message was emitted for the stale seq.
2. **Initial backfill delivers a fresh event.** Same shape, `provider_timestamp = now - 1m`. Assert the event is emitted.
3. **Mixed batch, cursor advances past skipped events.** Seed `[stale, fresh, stale, fresh]`. Assert only the two fresh events are emitted. Reconnect with `?since=0`; assert the same two fresh events emit and stale ones remain suppressed (idempotent).
4. **Live tail does not filter.** Connect, finish initial backfill, then ingest a stale-timestamped event directly into the store and call `Notifier.Publish(source, seq)`. Assert it is emitted via the live drain. (Models the manual-replay-of-stale-event-to-live-SSE-subscriber path.)
5. **Boundary case at exactly `SkewWindow`.** Event with `provider_timestamp = now - SkewWindow` (delta == skew): emit. Matches `delta > skew` in `render.go:102`.
6. **Skip is observable.** Capture the handler's logger; assert one debug-level entry per skipped event with `source`, `seq`, `delivery_id`, `age`, `skew_window` keys. Plaintext body / signature do not appear.
7. **Default when source is missing from the map.** Direct construction with an unknown source returns 404 (existing behavior). Reasserted to guard the map shape change.

Test injection points:

- `Handler.Now` for clock control (defaults to `time.Now`).
- `Handler.Sources` carrying per-source `SkewWindow` values.
- Existing `httptest`-based handler harness reused.

## Out of scope

- A query-parameter override (`?max_age=...`) for client-side tuning. The server policy is uniform.
- Push-side mirror behavior. Push delivery already cursors per-subscription independently and has different replay semantics; revisiting it is its own design.
- A new YAML field, env var, or CLI flag. The change reuses `SkewWindow`.
- Notifying the consumer that events were skipped (e.g. an SSE comment with the skipped count). Operators have the inspector and `hooksctl replay`; the SSE protocol stays minimal.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Operator surprise — events present in the store but never replayed. | Debug log on every skip; `/audit` and inspector remain authoritative views; CLAUDE.md and `docs/quickstart.md` updated to describe the new behavior. (Doc updates are scoped into the implementation plan, not this design.) |
| Source with `SkewWindow = 0` (operator opted out of skew enforcement at ingest). | Treat `0` as "no filter" on the backfill side too. Consistent with the ingest-side meaning of zero. |
| Test clock divergence — `time.Now` vs injected `Now`. | Single source of truth via `Handler.Now`; production wiring leaves it nil and falls back to `time.Now`. |

## Done when

- All seven tests above pass.
- Existing `internal/subscribe` tests remain green.
- `make lint && make test` clean.
- A short note added to `internal/subscribe/handler.go` package doc and `CLAUDE.md` `internal/subscribe` bullet describing the new policy. (Implementation-plan item; not part of this design.)
