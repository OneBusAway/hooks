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

A fresh `/subscribe/<source>` connection's **initial backfill** filters out events whose `provider_timestamp` is older than the source's effective `SkewWindow` (the per-source value from `hooks.yaml`, falling back to the verifier's 5-minute default — the same `effective_skew` ingest already enforces). The cursor advances past skipped events so reconnects do not re-evaluate them. **Live tail is unaffected** — drains triggered by the notifier or the keepalive ticker do not filter.

This is a deliberate inversion of the relay's documented "replay anything missed while disconnected" promise. A consumer offline for longer than `effective_skew` will silently miss events that landed during the gap. The trade-off is accepted because:

- Standard Webhooks consumers cannot accept stale messages without weakening their own replay-attack defense.
- The relay still owns the events. Operators recover any specific delivery via the inspector's "Replay to listeners" action, `hooksctl replay`, or direct DB inspection — those paths are unchanged.

(Note: `/audit` is **not** part of this recovery surface. `internal/audit` records operator-action volume, not webhook volume; skipped events do not produce audit rows.)

## Behavior in detail

### What changes

`/subscribe/<source>` initial backfill — the first drain call before the live select loop — filters events by age.

| Aspect | Behavior |
|---|---|
| Age field | `provider_timestamp` (the original webhook timestamp; matches what the consumer's signature-verifier will check). Filter is one-sided. |
| Threshold | `effective_skew(source)` — the same value ingest uses. If `hooks.yaml` sets a non-zero `skew_window`, that value; otherwise the verifier's 5-minute default. **Zero is not a disable switch** — it propagates to the same default ingest already applies. |
| Comparison | `now - provider_timestamp > effective_skew` skips; equal-to-window passes (matches `delta > skew` at `internal/sources/render.go:102`). |
| Future timestamps | Always pass. A producer-clock-fast event that admitted at ingest (delta inside `[-skew, +skew]`) yields a negative `now - provider_timestamp` on backfill and emits unconditionally. |
| Zero `provider_timestamp` | Always emit. Failing open: a future verifier that omits the field shouldn't silently swallow events. Render's verifier always populates it today (`internal/sources/render.go:84`), so this is a forward-compat guard. |
| Cursor on skip | Advances to the skipped event's sequence so future reconnects with `?since=<seq>` start past it, and so a follow-up live drain does not re-emit the skipped events. **Load-bearing** — see TDD case 4. |
| Skipped event in store | Unchanged. Remains queryable, replayable, and pruneable per existing retention rules. |
| Logging | One `slog.Debug` line per skip: `slog.String("source", ...)`, `slog.Int64("seq", ...)`, `slog.String("delivery_id", ...)`, `slog.Duration("age", ...)`, `slog.Duration("skew_window", ...)`. No body, signature, or token bytes. |

### What does not change

- **Live tail.** Once initial backfill returns, drains triggered by `Notifier.Publish` or the keepalive ticker do **not** filter. Live ingest events are fresh by definition (they just passed the same `effective_skew` check at ingest), and the inspector "Replay to listeners" button uses `Notifier.Publish` to wake currently-connected SSE subscribers — that path stays open. The keepalive ticker is started after the initial drain returns (`internal/subscribe/handler.go:138` is after the initial drain call), so the ticker cannot fire mid-initial-drain.

- **Push subscriptions.** `internal/push.Manager` workers and `Push.ReplayOne` operate on a separate code path with a separate cursor model. Untouched.

- **Manual inspector replay** (`POST /events/{source}/{sequence}/replay`). Untouched. `Push.ReplayOne` continues to deliver to push subscribers regardless of age. The SSE side of manual replay relies on `Notifier.Publish(source, seq)` waking any current subscriber's live drain, which then `ReadSince(cursor, ...)`. That delivers the replayed event only when `subscriber.cursor < replayed.seq` — i.e. the subscriber hadn't seen it yet. If `subscriber.cursor >= replayed.seq` (the common case after a successful initial backfill), `ReadSince` returns nothing and the replay is a no-op for that SSE subscriber. This is existing behavior, not a regression. Edge case: a fresh SSE subscriber whose initial backfill is in flight when a stale event is manually replayed will skip it during backfill, since initial backfill filters. Operator recovers via reconnect (live tail) or `hooksctl replay`.

- **`hooksctl forward`.** No client change. The server change is sufficient. No new CLI flags, no parsed log messages, no new wire fields.

- **`?since=latest`.** Cursor jumps to `LatestSequence(source)`; initial drain reads zero events; the filter never fires. No behavior change.

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

It needs the per-source `effective_skew` to apply the filter. Replace with:

```go
type Handler struct {
    // Allowed sources mapped to the effective skew window for that source
    // (= configured SkewWindow, or verifier default if zero/unset). Source
    // membership is determined by key presence (`d, ok := h.Sources[s]`),
    // not by value — the value is a real duration that may legitimately
    // be any non-negative number including zero (zero treated as "use
    // verifier default" upstream of this map; the map only ever sees the
    // resolved effective value).
    Sources map[string]time.Duration
    Now     func() time.Time // injected for tests; defaults to time.Now
    // ...
}
```

`internal/server.Build` constructs the handler and reads `hooks.yaml` into a `config.Config` whose `Source` entries carry `SkewWindow`. Build is responsible for resolving zero/unset to the verifier default before populating the map; `subscribe.Handler` itself never sees zero. (Resolving at the seam keeps the verifier-default constant in `internal/sources` where it already lives.)

`subscribe.New`'s signature changes from `sources []string` to `sources map[string]time.Duration`. The package is internal and the production caller is a single line in `internal/server.Build`; tests are updated alongside the change. No backward-compat shim.

### Filter location: split into `initialDrain` + `liveDrain`

The current single `drain` becomes two functions. The type system, not a comment, enforces "live tail does not filter."

```go
// stream():
cursor, err := h.initialDrain(ctx, w, flusher, source, cursor) // filters by age
...
for {
  select {
  case <-ctx.Done(): ...
  case <-ch:
    cursor, err = h.liveDrain(ctx, w, flusher, source, cursor) // unfiltered
  case <-ticker.C:
    if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil { ... }
    flusher.Flush()
    cursor, err = h.liveDrain(ctx, w, flusher, source, cursor) // unfiltered
  }
}
```

Both call a shared inner `readBatchAndEmit(...)` helper that does the SQL + SSE write loop; only `initialDrain` consults `h.Sources[source]` and `h.Now()` to compute `cutoff = h.Now().Add(-effectiveSkew)` per drain pass and skip events whose `provider_timestamp.Before(cutoff)`. `cutoff` is computed once per drain pass, not per event, so a single drain doesn't shift its decision midstream.

When `initialDrain` skips an event, it advances `cursor = ev.Sequence` *without* writing to the wire. This is the load-bearing invariant: if cursor isn't advanced, subsequent live drains call `ReadSince(oldCursor)` and re-emit the skipped events on the *unfiltered* path.

## TDD outline

Tests live in `internal/subscribe/handler_test.go` alongside the existing suite. `Handler.Now` is the clock-control seam.

1. **Initial backfill skips a stale event.** Seed one event with `provider_timestamp = now - 10m`, source effective skew = 5m. Connect; read SSE stream until live transition (e.g. observe a keepalive comment, or assert no payload after a short read). Assert no SSE message was emitted for the stale seq.

2. **Initial backfill delivers a fresh event.** Same shape, `provider_timestamp = now - 1m`. Assert the event is emitted.

3. **Mixed batch, only fresh emitted; idempotent on reconnect.** Seed `[stale, fresh, stale, fresh]`. Connect with `?since=0`; assert only the two fresh events are emitted. Reconnect with `?since=0`; assert the same two fresh events emit and the stale ones remain suppressed.

4. **All-stale batch still advances cursor (regression guard for the load-bearing invariant).** Seed `[stale, stale]`. Connect; finish initial backfill; while still connected, ingest one fresh event and `Notifier.Publish(source, freshSeq)`. Assert the live drain emits **only** the fresh event — not the two stale ones. (If `initialDrain` failed to advance cursor on skip, `liveDrain`'s `ReadSince(0)` would re-pick the stale events on the unfiltered path.)

5. **Live tail does not filter.** Connect, finish initial backfill, then write a stale-`provider_timestamp` event directly to the store and `Notifier.Publish(source, seq)`. Assert it is emitted via the live drain. (Models manual-replay-of-stale-event-to-live-SSE-subscriber.)

6. **Boundary at exactly `effective_skew`.** Event with `provider_timestamp = now - effective_skew` (delta == skew): emit. Matches `delta > skew` at `internal/sources/render.go:102`.

7. **Future-timestamp event passes.** `provider_timestamp = now + 1m`. Emit. Documents the one-sided filter.

8. **Zero `provider_timestamp` passes.** Insert event with `time.Time{}`. Emit. Forward-compat guard.

9. **Skip is observable.** Capture the handler's logger (use a `slog.Handler` test double); seed one stale event; assert one debug-level entry with attrs `source` (string), `seq` (int64), `delivery_id` (string), `age` (duration), `skew_window` (duration). Plaintext body / signature do not appear.

10. **Unknown source still 404s after map shape change.** Direct construction with a `map[string]time.Duration{"render": 5m}`; request `/subscribe/stripe`. 404. (Renames the previous "default when missing" case and exercises the key-presence-not-value-zero membership rule.)

Test fixtures: existing `setup()` helper updated to construct `Handler.Sources = map[string]time.Duration{"render": 5 * time.Minute}` so all pre-existing tests remain valid (events stamped with `time.Now()` are always within 5m by construction).

## Out of scope

- A query-parameter override (`?max_age=...`) for client-side tuning. The server policy is uniform.
- Push-side mirror behavior. Push delivery already cursors per-subscription independently and has different replay semantics; revisiting it is its own design.
- A new YAML field, env var, or CLI flag. The change reuses `SkewWindow`.
- Notifying the consumer that events were skipped (SSE comment, response header, `hooksctl forward` log line). If demand emerges, the SSE comment surface is the lowest-impact follow-up; not designed here.
- Audit emission for skipped events. `/audit` is operator-action volume, not webhook volume.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Operator surprise — events present in the store but never replayed. | Debug log on every skip (per spec, observable via `--dev` or `HOOKS_LOG_LEVEL=debug`). Inspector and `hooksctl replay` remain authoritative recovery surfaces. README, `docs/quickstart.md`, and CLAUDE.md updated to describe the new policy (see "Done when"). |
| Cursor not advanced past skipped events → live drain re-emits stale events on the unfiltered path. | TDD case 4 (all-stale batch + live emit) exercises this directly. Implementation contract: every skip in `initialDrain` updates `cursor`. |
| Test clock divergence — `time.Now` vs injected `Now`. | Single source of truth via `Handler.Now`; production wiring leaves it nil and falls back to `time.Now`. |
| Operator sets `skew_window: "0s"` expecting no enforcement, gets 5m default everywhere. | Pre-existing ingest behavior; this spec preserves it consistently rather than introducing a second convention. Documented in the Threshold table row. |

## Done when

- All ten TDD cases pass.
- Existing `internal/subscribe` tests remain green.
- `make lint && make test` clean.
- Documentation strings updated to reflect that automatic catch-up is bounded by the skew window:
  - `README.md:3` — "including replay of anything missed while disconnected" (qualify with the new policy).
  - `README.md:107` — "`forward` first replays any events you missed (none on first run), then tails live."
  - `docs/quickstart.md:138` — "replays anything missed since the last cursor, then tails live."
  - `internal/subscribe/handler.go` package doc — describe `initialDrain` filter behavior.
  - `CLAUDE.md` `internal/subscribe` bullet — one sentence on the new policy and where the threshold comes from.
