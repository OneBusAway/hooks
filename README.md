## hooks

A small, self-hosted relay that durably captures inbound webhooks (Render to start), verifies their signatures, and re-delivers them to one or more developer environments — either pulled over Server-Sent Events or pushed to a registered URL — including replay of anything missed while disconnected.

To get started: `hooks init`.

## Test it end-to-end with Render

Walks you from a fresh checkout to a real Render webhook landing on your laptop. About ten minutes. For the production-deployment version of this flow, see [`docs/quickstart.md`](docs/quickstart.md).

### Prerequisites

- Go 1.25+ (for `make build`).
- A Render account with a service or other resource that emits webhooks (a deploy is the easiest trigger).
- A tunnel that gives you a public HTTPS URL pointing at `localhost:8080`. Render refuses plain HTTP and will not POST to a non-public address. Pick one:
  - `cloudflared tunnel --url http://localhost:8080`
  - `ngrok http 8080`
  - any reverse proxy you already have on a real domain

### 1. Build the binaries

```sh
git clone https://github.com/onebusaway/hooks
cd hooks
make build
```

You now have `./bin/hooks` (the relay) and `./bin/hooksctl` (the developer CLI).

### 2. Scaffold a deployment

```sh
./bin/hooks init
```

This writes `hooks.yaml`, creates `hooks.db`, and prints an admin token **once**. Copy it now — there is no way to recover it later. On a fresh DB it also prints a one-time **signup URL** (24-hour TTL) so the first human can claim an admin account through `/signup`.

```
admin token (shown ONCE): <long base64 string>
signup: http://localhost:8080/signup?code=<code>   (24h, single-use)
```

Export it for `hooksctl`:

```sh
export HOOKS_TOKEN=<paste the admin token>
```

### 3. Create the webhook in Render

In the Render dashboard, create a new webhook. For the URL, put a placeholder for now (e.g. `https://example.invalid/ingest/render`) — you will update it in step 5 once the tunnel is running. Render will display a **signing secret**; copy it.

```sh
export RENDER_WEBHOOK_SECRET=<the signing secret Render showed you>
```

The default `hooks.yaml` already references this env var:

```yaml
sources:
  render:
    verifier: render
    secret: ${RENDER_WEBHOOK_SECRET}
    retention: 30d
```

### 4. Start the relay

```sh
./bin/hooks --dev
```

`--dev` enables verbose logging, opens the inspector in your browser, and prints the URLs you'll need:

```
inspector: http://localhost:8080/inspector
ingest:    http://localhost:8080/ingest/render
forward:   hooksctl forward render --to http://localhost:3000/webhooks/render
```

Leave it running.

### 5. Open a public HTTPS tunnel to it

In a second terminal:

```sh
cloudflared tunnel --url http://localhost:8080
```

Copy the `https://<random>.trycloudflare.com` URL it prints. Back in the Render dashboard, edit your webhook and set its URL to:

```
https://<random>.trycloudflare.com/ingest/render
```

### 6. Forward events to a local app

In a third terminal, point `hooksctl forward` at whichever local service you're developing:

```sh
./bin/hooksctl forward render --to http://localhost:3000/webhooks/render
```

`forward` first replays any events you missed (none on first run), then tails live. Bytes hitting your local app are byte-for-byte identical to what Render sent — original headers preserved.

### 7. Trigger a webhook from Render

The fastest trigger is a redeploy of any Render service: `Manual Deploy → Deploy latest commit`. Other event types (suspends, scaling) work too.

You should see, in order:

- A `POST /ingest/render` log line in the `hooks --dev` terminal.
- A new row in the inspector at `http://localhost:8080/inspector` (paste the admin token to log in).
- A `POST /webhooks/render` arriving at your local app via the `hooksctl forward` terminal.

### 8. (Optional) Register a long-lived push subscription

If you want a permanent consumer instead of an SSE pull session:

```sh
./bin/hooksctl push add --source render --to https://my-svc.example.com/hooks --name production
```

This prints a per-subscription signing secret **once** — store it on your consumer. The relay will sign every push with `X-Hooks-Signature: t=<unix>,v1=<hmac-sha256(secret, "<unix>.<body>")>`. See [`docs/consumer-verification.md`](docs/consumer-verification.md) for verification snippets in several languages.

### Running it under Docker

A `Dockerfile` and `render.yaml` Blueprint are checked into the repo. The image is a multi-stage build (Go builder → small Alpine runtime), runs as a non-root user, and exposes `/data` as a volume for the SQLite database.

```sh
make docker-build                      # builds hooks:dev locally
mkdir -p ./hooks-data
docker run --rm -v $(pwd)/hooks-data:/data hooks:dev init
docker run --rm -p 8080:8080 \
  -v $(pwd)/hooks-data:/data \
  -e RENDER_WEBHOOK_SECRET \
  hooks:dev
```

For a Render Blueprint deploy, push the repo and point Render at `render.yaml` — it provisions a 1 GiB persistent disk at `/data` and wires `/readyz` as the health check. See [`docs/quickstart.md`](docs/quickstart.md) for the full container walkthrough.

### For developers joining a deployed relay

If your team already runs a `hooks` instance (Render or anywhere else) and you just need a CLI on your laptop, skip the first six steps. Either an admin sends you a signup URL (`https://hooks.example.com/signup?code=...`), or your relay was just deployed and an admin used the bootstrap link to create their account first. Then:

```sh
hooksctl login --server https://hooks.example.com
hooksctl forward render --to http://localhost:3000/webhooks/render
```

`login` prints a short user code, opens the relay's `/device` page in your browser, asks you to log in and re-enter your password to approve the pairing, then writes a PAT to `~/.config/hooks/credentials.default`. `forward` uses that PAT — no further token plumbing.

See [`docs/accounts.md`](docs/accounts.md) for the full walkthrough (scopes, admin operations, multiple profiles, ephemeral vs long-lived listener tokens, deactivation semantics).

### Troubleshooting

- **HTTP 401 in the relay logs** — secret mismatch between `RENDER_WEBHOOK_SECRET` and what Render is signing with. Re-copy the signing secret from the Render dashboard.
- **HTTP 404** — the URL path is wrong; it must end in `/ingest/render`.
- **No request reaches the relay at all** — confirm the tunnel URL works in your browser (`/healthz` should return `ok`), and that you saved the updated URL in the Render dashboard.
- **The `--dev` browser tab won't authenticate** — paste the admin token printed by `hooks init`, not your Render secret.

# LICENSE

(c) Open Transit Software Foundation and made available under the [Apache 2.0 license](./LICENSE).