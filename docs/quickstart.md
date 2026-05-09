# Quickstart

Get from "fresh checkout" to "real Render webhook landing in a developer environment" in about ten minutes. This is the production-deployment shape (deploy once, log in from laptops). For a fully-local end-to-end demo, see the [README](../README.md).

## 1. Install

```sh
go install github.com/onebusaway/hooks/cmd/hooks@latest
go install github.com/onebusaway/hooks/cmd/hooksctl@latest
```

Or build from source:

```sh
git clone https://github.com/onebusaway/hooks
cd hooks
make build              # produces ./bin/hooks and ./bin/hooksctl
```

## 2. Scaffold a deployment

On the server (or wherever you'll run `hooks`):

```sh
hooks init --server-url https://webhooks.example.com
```

This writes `hooks.yaml`, creates `hooks.db`, mints a one-time **admin token** (the legacy system credential), and — because the users table is empty — prints a one-time **bootstrap signup URL** (24-hour TTL):

```text
admin token (shown ONCE): <long base64 string>
signup: https://webhooks.example.com/signup?code=ABCDEFGH...
        (single-use; expires in 24h; auto-disables once any account exists)
```

Save both. The admin token has no recovery path; the signup URL is how the first human creates their admin account. If you skip `--server-url` (or `HOOKS_PUBLIC_URL`), the URL prints with a `localhost` placeholder you'll have to swap by hand.

Edit `hooks.yaml` to point at your real provider secret(s):

```yaml
sources:
  render:
    verifier: render
    secret: ${RENDER_WEBHOOK_SECRET}
    retention: 30d
```

Then export `RENDER_WEBHOOK_SECRET` (the per-webhook signing secret Render gave you when you created the webhook) in the environment that will run `hooks`.

## 3. Stand up TLS termination

The relay speaks plain HTTP. Stand any TLS-terminating reverse proxy in front of it:

- **Caddy:** add a site like `webhooks.example.com { reverse_proxy localhost:8080 }`. Caddy obtains a Let's Encrypt cert automatically.
- **nginx:** standard `proxy_pass http://127.0.0.1:8080;` block, plus your existing TLS config.
- **Cloudflare Tunnel / Render itself / fly.io:** any platform that gives you HTTPS in front of an HTTP origin works.

Start the relay:

```sh
hooks                # production
hooks --dev          # verbose logs + opens the inspector locally
```

Wire your load balancer's health check to `/readyz` (which pings SQLite); `/healthz` is liveness-only.

## 4. Claim the first admin account

Open the bootstrap signup URL from step 2 in a browser. Pick an email, name, and password (≥ 12 characters; must not contain your email or its local-part). Submitting the form consumes the bootstrap invite, signs you into the inspector at `/inspector`, and the URL returns 409 from then on.

If the link expires before you use it, re-run `hooks init` against the still-empty DB to mint a fresh 24-hour invite. Once any user exists, the bootstrap path is closed — invite teammates from `/inspector/users` (or `POST /api/invites`) instead.

## 5. Register the webhook with Render

In Render, create (or edit) the webhook so its URL points at:

```text
https://webhooks.example.com/ingest/render
```

with the same secret you set in `RENDER_WEBHOOK_SECRET`.

## 6. Connect a laptop with `hooksctl login`

On your dev laptop:

```sh
hooksctl login --server https://webhooks.example.com --scopes render
```

The CLI prints a `Visit:` URL and a `Code:` to type into the relay's `/device` page. Open the URL in a browser where you're logged in (or sign up via an invite from another admin first), enter the code, and re-enter your password to approve the pairing. The CLI then writes a personal access token to `~/.config/hooks/credentials.default` (mode `0600`). Default scope on approval is `account` only, so pass `--scopes` (comma-separated source names) to also subscribe, or `--admin` for admin scope.

Verify:

```sh
hooksctl whoami
```

## 7. Forward to a local app (SSE pull)

```sh
hooksctl forward render --to http://localhost:3000/webhooks/render
```

Against a logged-in profile, `forward` auto-mints an ephemeral `kind='listener'` token, replays anything missed since the last cursor, then tails live. The token is revoked on clean exit; the server's prune loop reaps any ephemeral token whose `last_used_at` falls 24h behind. Bytes hitting your local app are byte-for-byte identical to what Render sent. Original headers (other than hop-by-hop) are preserved.

For a long-lived listener (skip the mint/revoke dance every run), see [`docs/accounts.md`](accounts.md#power-user-long-lived-listener-token).

## 8. Or, register a long-lived consumer (HTTP push)

For a production service that's always up:

```sh
hooksctl me sub add --source render --to https://my-svc.example.com/hooks --name production
```

`me sub add` prints a per-subscription **signing secret** exactly once. Store it on the consumer. The relay will POST every event to that URL with `X-Hooks-Signature: t=<unix>,v1=<hmac-sha256(secret, "<unix>.<body>")>`. See [`docs/consumer-verification.md`](consumer-verification.md) for verification snippets.

The plaintext signing secret only lives in memory, so push delivery for each subscription is paused after a server restart until you re-arm it with `hooksctl me sub rotate-secret <id>` (or `hooksctl push rotate-secret <id>` for admin-owned subscriptions).

## 9. Browse

Open `https://webhooks.example.com/inspector` and sign in with the email/password from step 4. You can browse every captured event, replay any of them to live listeners, manage tokens and push subscriptions, invite teammates, and review the audit log at `/inspector/audit`.

## What `hooks init` does NOT do

- Set up your reverse proxy. That's step 3.
- Register the Render-side webhook. That's step 5.
- Persist the admin token or bootstrap signup URL anywhere except standard out. Save them.

## Where to next

- [`docs/accounts.md`](accounts.md) — invites, scopes, multiple profiles, ephemeral vs long-lived listener tokens, deactivation semantics.
- [`docs/security.md`](security.md) — token kinds, hashing posture, signature verification, secret-handling policy.
- [`docs/sources.md`](sources.md) — how to add a new webhook provider.
- [`docs/operations.md`](operations.md) — pruning, retention, body-integrity verification.
