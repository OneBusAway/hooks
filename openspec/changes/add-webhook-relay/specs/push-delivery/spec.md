## ADDED Requirements

### Requirement: Push subscription registration

The service SHALL allow `admin`-scoped clients to register push subscriptions via `POST /api/push-subscriptions`. The request body SHALL include `source` (string, must be a configured source), `target_url` (http or https URL), and optionally `name` (label) and `since` (initial cursor: integer or `latest`, default `latest`). On success the service SHALL respond with HTTP 201 and a JSON body containing the subscription's `id`, `cursor`, and a one-time-only plaintext `signing_secret`. Subsequent reads of the subscription SHALL NOT return the plaintext.

#### Scenario: Successful registration returns id and signing secret
- **WHEN** an admin POSTs `{"source":"render","target_url":"https://x/y","since":"latest"}`
- **THEN** the response is HTTP 201 with body containing `id`, `cursor`, and `signing_secret`, and the secret appears nowhere in subsequent GET responses for that subscription

#### Scenario: Default cold-start cursor is `latest`
- **WHEN** a subscription is registered without a `since` field, and the highest stored sequence for the source is 42
- **THEN** the subscription's stored cursor is 42 and only events with sequence > 42 will be delivered

#### Scenario: Backfill is opt-in via `since=0`
- **WHEN** a subscription is registered with `since=0`
- **THEN** the dispatcher delivers every stored event for that source in ascending sequence order before transitioning to live

#### Scenario: Unknown source is rejected
- **WHEN** a registration request names a `source` that is not in the configuration
- **THEN** the service responds with HTTP 400

### Requirement: One source per subscription

A push subscription SHALL be scoped to exactly one source. To consume two sources, two subscriptions SHALL be registered. The schema SHALL enforce a `NOT NULL` `source` column.

#### Scenario: Multi-source registration is rejected
- **WHEN** a registration request supplies a list (`"sources":[...]`) instead of a single `source`
- **THEN** the service responds with HTTP 400

### Requirement: Outbound HMAC signing

For every push delivery the relay SHALL set the request header `X-Hooks-Signature: t=<unix>,v1=<hex>` where `<unix>` is the current Unix timestamp at attempt time and `<hex>` is the lowercase-hex HMAC-SHA256 of the byte string `<unix>.<body>` using the subscription's signing secret. The relay SHALL also set `X-Hooks-Delivery-Id` to the event's `delivery_id`, `X-Hooks-Sequence` to the event's sequence number (decimal), and `X-Hooks-Source` to the source identifier. Original captured headers SHALL be preserved on the outbound POST except for hop-by-hop headers, which SHALL be stripped.

#### Scenario: Consumer can verify body integrity
- **WHEN** a consumer receives a push and recomputes HMAC-SHA256 over the byte string `<X-Hooks-Signature.t>.<body>` with its stored copy of the signing secret
- **THEN** the result equals the `X-Hooks-Signature.v1` value

#### Scenario: Tampered body fails consumer verification
- **WHEN** a man-in-the-middle alters the body en route
- **THEN** the consumer's recomputed HMAC does not match the header

#### Scenario: Per-attempt timestamp prevents replay
- **WHEN** a delivery is retried 30 seconds later
- **THEN** the `t` and `v1` values are recomputed; the consumer can reject signatures with timestamps outside its own configured skew window

#### Scenario: Hop-by-hop headers are stripped
- **WHEN** a captured event has `Connection: keep-alive` and is delivered to a push target
- **THEN** the outbound POST has no `Connection` header copied from the original

### Requirement: Server-side cursor and ordering

For each push subscription the service SHALL persist a `cursor` (int64, last successfully-2xx-delivered sequence). Deliveries SHALL occur in strictly ascending sequence order. The cursor SHALL advance only after the consumer returns a 2xx response, in the same transaction that records `last_success_at` and resets `consecutive_failures`.

#### Scenario: Cursor advances on 2xx
- **WHEN** the consumer returns 200 for a delivery of sequence 17
- **THEN** the row's cursor becomes 17, `last_success_at` is set, and `consecutive_failures` is 0

#### Scenario: Cursor does not advance on non-2xx
- **WHEN** the consumer returns 500 for a delivery of sequence 17
- **THEN** the row's cursor remains at 16

#### Scenario: Out-of-order delivery is impossible per subscription
- **WHEN** the dispatcher has 100 unsent events for a subscription
- **THEN** the consumer receives them in strictly ascending sequence order, with no parallel deliveries to the same subscription

### Requirement: Catch-up on recovery

When a subscription's target is unreachable for a period and then becomes reachable again, the dispatcher SHALL deliver every event with `sequence > cursor` in order, without operator intervention.

#### Scenario: Multi-hour outage produces full catch-up
- **WHEN** a subscription's target is down for 6 hours during which 240 events arrive, and then the target becomes reachable
- **THEN** all 240 events are delivered in ascending sequence order before any newer events

### Requirement: Retry policy

On non-2xx response, network error, or per-attempt timeout (default 30s, configurable per subscription), the dispatcher SHALL:
1. Atomically record `last_attempt_at`, `last_error` (truncated to 1 KB), and increment `consecutive_failures`.
2. Sleep for `min(60s, 2^consecutive_failures * 100ms)` with full jitter before the next attempt.
3. NOT advance the cursor.
4. Retry indefinitely; there SHALL be no automatic give-up or dead-lettering.

The dispatcher SHALL log a WARN the first time `consecutive_failures` crosses 100 for a given subscription within a single failure streak.

#### Scenario: Backoff is bounded
- **WHEN** a subscription has failed 20 times in a row
- **THEN** the next sleep is at most 60 seconds

#### Scenario: Recovery resets backoff
- **WHEN** a subscription with 50 consecutive failures finally returns 200
- **THEN** `consecutive_failures` is reset to 0 and the next failure's backoff base is 100ms

### Requirement: Dispatcher reactivity

When a new event is ingested for a source that has any non-paused push subscriptions, those subscriptions' dispatchers SHALL be notified within 100ms via the in-process pub/sub channel. A dispatcher currently sleeping in backoff with no pending events SHALL wake immediately on a new-event signal and re-attempt; a dispatcher currently sleeping in backoff with a pending event SHALL continue its current sleep schedule (the new signal does not shorten an active backoff).

#### Scenario: Live event triggers prompt delivery
- **WHEN** a subscription's cursor is current (no backlog) and a new event arrives
- **THEN** the consumer receives a POST within 200ms of ingest under nominal conditions

### Requirement: Operational controls

The service SHALL expose `admin`-scoped HTTP routes under `/api/push-subscriptions` and matching `hooksctl push` subcommands for:
- `list` — id, source, target_url, cursor, queue depth (highest source sequence − cursor), `consecutive_failures`, `last_error` (truncated to 200 chars on the list view), `last_attempt_at`, `last_success_at`, `paused_at`.
- `get <id>` — full row except plaintext secret.
- `pause <id>` — sets `paused_at`; stops dispatch without deleting state; cursor preserved.
- `resume <id>` — clears `paused_at`; restarts dispatch.
- `rotate-secret <id>` — issues a new signing secret (printed once via CLI / shown once via UI), invalidates the old one immediately, and the dispatcher signs the very next attempt with the new secret.
- `delete <id>` — removes the subscription and its row.
- `test <id>` — sends a synthetic ping event with header `X-Hooks-Test: 1` and a non-real `delivery_id`, signed with the subscription's secret, to confirm reachability without consuming a real event or advancing the cursor.

#### Scenario: Pause stops outbound traffic immediately
- **WHEN** an admin pauses a subscription with a backlog of 100 events
- **THEN** no further POSTs are issued to that target until resumed; the cursor is unchanged

#### Scenario: Rotated secret takes effect on the next attempt
- **WHEN** an admin rotates the secret while a delivery is queued for the subscription
- **THEN** the next outbound POST is signed with the new secret; the old plaintext no longer verifies any subsequent push

#### Scenario: Test does not advance cursor
- **WHEN** an admin runs `hooksctl push test <id>` against a reachable target
- **THEN** the target receives a synthetic POST and the subscription's cursor is unchanged

### Requirement: Inspector visibility

The web inspector SHALL render a push-subscription view at `/inspector/push` showing each subscription's source, `target_url`, cursor, queue depth, `consecutive_failures`, `last_error`, `last_attempt_at`, and `last_success_at`, with `pause`/`resume`/`rotate-secret`/`delete`/`test` actions inline. The signing-secret plaintext SHALL never appear on the list view; rotate-secret SHALL show the new plaintext exactly once on the resulting confirmation page.

#### Scenario: Inspector reflects dispatcher state within 5 seconds
- **WHEN** a subscription's `consecutive_failures` increments from 5 to 6
- **THEN** a refresh of `/inspector/push` within 5 seconds shows the new value

#### Scenario: Inspector never shows plaintext signing secret on list
- **WHEN** an admin loads `/inspector/push`
- **THEN** no row's HTML contains the plaintext signing secret

### Requirement: Replay-from-inspector does not mutate cursor

When the inspector's "Replay to listeners" action is taken on an event, eligible push subscriptions SHALL receive a one-shot dispatch of that event with the additional header `X-Hooks-Replay: 1`, and the dispatch SHALL NOT advance the subscription's cursor.

#### Scenario: Replay dispatch is marked and idempotent on cursor
- **WHEN** an admin replays event `(render, 17)` from the inspector while a push subscription on `render` has cursor=20
- **THEN** the target receives a POST for sequence 17 with `X-Hooks-Replay: 1`, and the subscription's cursor remains 20
