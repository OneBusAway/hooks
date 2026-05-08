# Quickstart

Get from "fresh checkout" to "real Render webhook landing in a local app" in about five minutes.

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

```sh
hooks init
```

This generates `hooks.yaml`, creates `hooks.db`, and prints an admin token **once**. Save the token — there is no way to recover it later. Edit `hooks.yaml` to point at your real provider secret(s):

```yaml
sources:
  render:
    verifier: render
    secret: ${RENDER_WEBHOOK_SECRET}
    retention: 30d
```

Then export `RENDER_WEBHOOK_SECRET` (this is the per-webhook signing secret Render gave you when you created the webhook).

## 3. Stand up TLS termination

The relay speaks plain HTTP. Stand any TLS-terminating reverse proxy in front of it:

- **Caddy:** add a site like `webhooks.example.com { reverse_proxy localhost:8080 }`. Caddy obtains a Let's Encrypt cert automatically.
- **nginx:** standard `proxy_pass http://127.0.0.1:8080;` block, plus your existing TLS config.
- **Cloudflare Tunnel / Render itself / fly.io:** any platform that gives you HTTPS in front of an HTTP origin works.

Start the relay:

```sh
hooks --dev      # or just `hooks` for production
```

## 4. Register with Render

In Render, create a webhook pointing at:

```
https://webhooks.example.com/ingest/render
```

with the secret you set in `hooks.yaml`.

## 5. Forward to a local app (SSE pull)

On your dev laptop:

```sh
export HOOKS_TOKEN=<the admin token from step 2>
hooksctl forward render --to http://localhost:3000/webhooks/render --server https://webhooks.example.com
```

`forward` replays anything missed since the last cursor and then tails live. Bytes are byte-for-byte identical to what Render sent. Original headers (other than hop-by-hop) are preserved.

## 6. Or, register a long-lived consumer (HTTP push)

For a production service that's always up:

```sh
hooksctl push add --source render --to https://my-svc.example.com/hooks --name production
```

`push add` prints a per-subscription **signing secret** exactly once. Store it on the consumer. The relay will POST every event to that URL with `X-Hooks-Signature: t=<unix>,v1=<hmac-sha256(secret, "<unix>.<body>")>`. See `docs/consumer-verification.md` for verification snippets.

## 7. Browse

Open `https://webhooks.example.com/inspector` and paste your admin token. You can browse every captured event, replay any of them to live listeners, manage tokens, and manage push subscriptions.

## What `hooks init` does NOT do

- Set up your reverse proxy. That's step 3.
- Register the Render-side webhook. That's step 4.
- Persist the admin token outside of standard out. Save it.
