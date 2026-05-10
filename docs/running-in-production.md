# Running hooks in production

Day-2 ops: backups, retention, observability, push-subscription health, restarts, and graceful shutdown. For one-time deployment setup (env vars, `hooks init`, container internals, Render Blueprint), see [`deployment.md`](deployment.md).

## Backup

The whole system state lives in `hooks.db` (SQLite, WAL-mode). For backups:

```sh
sqlite3 hooks.db ".backup /backups/hooks-$(date +%F).db"
```

This is the SQLite-blessed online-backup form: it cooperates with WAL and is safe while the server is running. Avoid raw `cp` while the server is live unless you also copy the `-wal` and `-shm` files atomically.

## Retention and pruning

- Default retention is **30 days per source**, configurable via `retention:` per source in `hooks.yaml`.
- Special values: `0` and `forever` disable auto-prune for that source.
- The pruner wakes once an hour and logs the row count it deleted per source per pass. Log lines look like:

  ```
  level=INFO msg="prune: deleted events" source=render rows=128 retention=720h0m0s
  ```

- For an aggressive ad-hoc cleanup independent of configured retention:

  ```sh
  hooks prune --older-than 7d
  ```

The same loop also reaps `ephemeral=true` listener tokens whose `last_used_at` is more than 24h in the past (forward crash-safety net) and `device_pairings` rows 24h after terminal state. The audit log is never pruned — growth is bounded by operator actions, not webhook traffic.

## Observability

In v1 the only observability primitive is structured JSON logs to stderr. Notable events:

- `level=INFO msg="hooks: listening"` on startup.
- `level=WARN msg="ingest: verification failed"` on a 401. Includes `source` and `body_sha256_prefix`.
- `level=WARN msg="push: subscription has crossed 100 consecutive failures"` once per failure streak per subscription.
- `level=INFO msg="prune: deleted events"` on every prune pass that deleted at least one row.

`/healthz` returns 200 once the listener is open. `/readyz` returns 200 only when the SQLite store can complete a round-trip ping; use this for load-balancer health checks.

## Push-subscription health

`hooksctl` exposes two parallel command trees for push subscriptions: `hooksctl me sub *` operates only on subscriptions the calling user owns (self-service), and `hooksctl push *` is the admin/operator form that operates on every subscription on the relay (admin scope required). The commands below use `push *` because day-2 ops typically means triaging across the whole relay.

Open the inspector's `/push` page (or run `hooksctl push list`) to monitor:

- **Queue depth**: `latest_sequence_for_source - cursor`. Grows during outages; should return to 0 within seconds after recovery.
- **`consecutive_failures`**: resets to 0 on the next 2xx.
- **`last_error` / `last_attempt_at` / `last_success_at`**: last attempt's result and recency.

A subscription that stays in a failing state with `consecutive_failures > 100` produces a single WARN log line on the streak's first crossing of 100. There is no built-in alerting; operators are expected to wire whatever they have (logs to Loki/Datadog, etc.).

To smoke-test a consumer end-to-end without waiting for a real provider event, send a synthetic delivery:

```sh
hooksctl push test <id>
```

The relay POSTs a small probe payload to the subscription's URL, signed with the live secret, and reports the consumer's status code. A healthy consumer should: return 2xx within a few seconds, log the `X-Hooks-Delivery-Id`, and validate `X-Hooks-Signature.t` against its current clock. `consecutive_failures` should sit at 0 in steady state — any non-zero baseline means the consumer is dropping deliveries and silently retrying isn't fixing it.

If a target is permanently broken, the safe pause-or-delete commands are:

```sh
hooksctl push pause <id>   # stops dispatch; cursor preserved
hooksctl push rm <id>      # deletes; cursor lost; secret no longer accepted
```

## Restarts and signing-secret state

The push dispatcher needs the per-subscription plaintext signing secret in memory to sign deliveries. It is generated at registration and held in process. On a clean restart, plaintexts are not on disk, so push delivery is paused (no signature can be computed) until each subscription is re-armed via:

```sh
hooksctl push rotate-secret <id>
```

This generates a fresh secret, re-hashes it on disk, and feeds the dispatcher the new plaintext. The new secret takes effect on the very next attempt; the consumer must be updated with the new secret before that attempt lands.

This is a deliberate trade-off: storing a recoverable plaintext on disk would defeat the Argon2id-hashed-at-rest property for the on-disk database. If you find restarts painful, schedule them rarely or pre-stage the rotate as part of your deploy.

## Graceful shutdown

`hooks` shuts down on SIGINT or SIGTERM:

1. HTTP listener stops accepting new connections; in-flight requests get up to 30 seconds to finish.
2. Push dispatchers cancel their per-subscription contexts.
3. The pruner goroutine returns.
4. The SQLite handle closes.
