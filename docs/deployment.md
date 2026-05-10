# Deployment reference

The [README](../README.md) covers the recipe for the three supported deployment paths (Render Blueprint, `docker run`, bare binary). This doc is the reference: env vars, init flags, container internals, what each path does and doesn't set up.

## TLS termination

The relay binds plain HTTP. Stand any TLS-terminating reverse proxy in front of it. Providers refuse non-HTTPS endpoints, so this is enforced by the outside world either way.

- **Caddy** — `webhooks.example.com { reverse_proxy localhost:8080 }`. Caddy obtains a Let's Encrypt cert automatically.
- **nginx** — standard `proxy_pass http://127.0.0.1:8080;` block, plus your existing TLS config.
- **Cloudflare Tunnel / Render / fly.io** — any platform that gives you HTTPS in front of an HTTP origin.

Wire your load balancer's health check to `/readyz` (it pings SQLite end-to-end). `/healthz` is liveness-only.

## `hooks init`

`hooks init` is the bootstrap command. It writes `hooks.yaml`, creates `hooks.db`, mints a one-time **admin token** (the legacy system credential), and — when the users table is empty — prints a one-time **bootstrap signup URL** (24-hour TTL, single-use, auto-disables once any user exists):

```text
admin token (shown ONCE): <long base64 string>
signup: https://webhooks.example.com/signup?code=ABCDEFGH...
        (single-use; expires in 24h; auto-disables once any account exists)
```

Save both. The admin token has no recovery path; the signup URL is how the first human creates their admin account. If the bootstrap link expires before it's used, re-run `hooks init --force` against the still-userless DB to mint a fresh 24-hour invite.

Notable flags:

- `--server-url <url>` (or `HOOKS_PUBLIC_URL`) — host to use when printing the signup URL. Skip it and the URL prints with a `localhost` placeholder you'll have to swap by hand.
- `--dir <path>` — directory for `hooks.yaml` and `hooks.db`. Used by the container entrypoint (`--dir /data`).
- `--force` — re-mint the bootstrap signup URL on a still-userless DB. Once any user exists, the bootstrap path is closed and `--force` does nothing useful.
- `--token-name <name>` — name for the generated admin token (default `operator`). Cosmetic only — surfaced in `hooksctl token list`.

What `hooks init` does **not** do:

- Stand up your reverse proxy. That's on you.
- Register the provider-side webhook. That's a step in the provider's dashboard.
- Persist the admin token plaintext or the bootstrap signup URL anywhere except standard out. Save them — neither is recoverable. (The token's Argon2id hash lives in the database, but the plaintext is shown only once.)

## Env vars and config precedence

Listen-address precedence: `HOOKS_LISTEN_ADDR` > yaml `listen_addr` > `:$PORT` (when `$PORT` is a valid port — for Render/Heroku/Fly/Cloud Run) > `:8080`.

Other env vars:

- `HOOKS_DATABASE_URL` — SQLite path. Defaults to `./hooks.db`; the Docker image overrides to `/data/hooks.db`.
- `HOOKS_LOG_LEVEL` — `debug`, `info`, `warn`, `error`. Default `info`.
- `HOOKS_PUBLIC_URL` *(optional)* — host used when printing the bootstrap signup URL.
- Provider secrets (e.g. `RENDER_WEBHOOK_SECRET`) — referenced from `hooks.yaml` via `${VAR}` interpolation.

`hooks.yaml` supports `${VAR}` and `${VAR:-default}` interpolation. A `tokens:` field is rejected at load time — listener tokens live in the database, not in YAML. Every source must declare a `verifier:`; unsigned sources are not supported.

Defaults: body size limit 1 MiB, dedupe window 24h, skew window 5m, retention 30d per source. Retention `0` / `forever` / `never` disables auto-prune for that source.

## The container image

The `Dockerfile` is a multi-stage build (Go builder → small Alpine runtime). It runs as UID 65532, mounts `/data` as a volume for the SQLite database, and ships both `hooks` and `hooksctl` so you can `docker exec` to manage tokens, push subscriptions, and pruning.

Image defaults:

- `HOOKS_DATABASE_URL=/data/hooks.db`
- Listens on `:8080` (or `$PORT` if set)
- A Dockerfile-level `HEALTHCHECK` polls `/healthz`. Behind a load balancer, prefer `/readyz`.

The image's entrypoint (`docker-entrypoint.sh`) detects an empty `/data` (no `hooks.yaml` and no `hooks.db`) on first boot and runs `hooks init --dir /data` automatically. Without this, Render Blueprint deploys would crash-loop on first boot — the volume is empty, the server can't read `hooks.yaml`, and Render's Shell tab is gated on a running instance, so the documented recovery path would be unreachable. The auto-init prints the one-time admin token and bootstrap signup URL to stdout (which lands in the platform's log stream — treat both as secrets).

Subcommands (`init`, `invite`, `prune`, `verify`, `help`) bypass the bootstrap.

## Render Blueprint specifics

The repo includes a `render.yaml` Blueprint:

- Single instance only. The SQLite store is a single-writer design; two pods against the same disk corrupt it. `numInstances: 1` is intentional.
- 1 GiB persistent disk mounted at `/data`.
- `HOOKS_DATABASE_URL=/data/hooks.db` is set in the Blueprint.
- `HOOKS_PUBLIC_URL` and `RENDER_WEBHOOK_SECRET` are declared `sync: false` — set them in the service's **Environment** tab before the first deploy.
- No `HOOKS_LISTEN_ADDR`. The server honors `$PORT` (which Render injects) automatically.
- `/readyz` is the health check.

Both `hooks` and `hooksctl` are on `$PATH` in the Render Shell, so token rotation, push-subscription management, and pruning all work without leaving the platform.

## Single-process / SQLite limitation

The default deployment is one process with SQLite. There is **no** built-in coordination for multi-process; SSE delivery and push dispatch assume a single in-process notifier. The storage interface is shaped to accept a Postgres backend later (and a Redis/NATS pub/sub for cross-process notifications), but that code isn't written yet — running two `hooks` processes against the same SQLite file is unsafe.

## Skew-window semantics on initial backfill

`hooksctl forward` replays from the cursor on connect, then tails live. **Initial backfill is bounded by the source's signature-verification skew window** (`skew_window` per source in `hooks.yaml`, or 5 minutes when unset). Events older than that window are skipped on the initial drain so a verifying consumer doesn't 401 on a stale `webhook-timestamp`. The cursor still advances past skipped events, so reconnects don't reconsider them.

Skipped events remain in the store. Redeliver them via the inspector ("Replay to listeners") or `hooksctl replay`.

This filter is **only on the initial backfill**. Live tail (notifier-triggered or keepalive-triggered drains) is unfiltered, so manual replays via the inspector still reach currently-connected subscribers.
