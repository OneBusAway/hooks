# Security model

## Inbound HMAC verification

Every configured source MUST declare a registered `Verifier`. There is no opt-in for unsigned providers; the loader fails startup if a source has no verifier or names one that is not registered.

For Render specifically:

- The relay computes `HMAC-SHA256(secret, "<timestamp>.<body>")` and compares it with the value carried in the `Render-Webhook-Signature` header (`t=…,v1=…`).
- Comparison is constant-time (`hmac.Equal`).
- Any timestamp more than 5 minutes from the server's current UTC time is rejected (default; `skew_window` overrides per source).
- The captured `delivery_id` is the `Render-Webhook-Id` header.

Failed verification produces HTTP 401 with no body. Logs include only the source name and a 4-byte hex prefix of the body's sha256 — never the body, never the signature, never the secret.

## Listener tokens (SSE pull, inspector, management API)

- Stored in SQLite as Argon2id hashes of 32-byte URL-safe base64 plaintexts.
- Lookup re-hashes the supplied plaintext per row and compares with constant time. (O(N) per request; fine for operator-token volumes; we'd revisit only at thousands of tokens.)
- `hooksctl token list` and `/api/tokens` GET return only metadata (id, name, scopes, timestamps). No path returns the plaintext after issuance.
- Revoked tokens are rejected within one round-trip; `last_used_at` is updated best-effort.

The special scope `admin` grants access to `/inspector`, `/api/tokens`, and `/api/push-subscriptions`. It does **not** implicitly grant subscribe access — an admin token MUST also include the source name in its scopes to subscribe.

## Outbound HMAC signing (push delivery)

Every push delivery sets:

- `X-Hooks-Signature: t=<unix>,v1=<hex>` where `<hex>` is `HMAC-SHA256(secret, "<unix>.<body>")`. `<unix>` is recomputed per attempt.
- `X-Hooks-Delivery-Id`, `X-Hooks-Sequence`, `X-Hooks-Source` for visibility/dedupe at the consumer.

The signing secret is stored Argon2id-hashed at rest. The dispatcher holds the plaintext **in memory** after registration (or `rotate-secret`) for HMAC computation. Consequence: after a server restart, plaintext is no longer in memory and the consumer must be re-armed via `hooksctl push rotate-secret <id>`. This is the documented trade-off of refusing to keep a recoverable plaintext on disk; rotate-secret takes effect on the very next attempt.

## Replay-window enforcement

Both inbound and outbound timestamps live inside a 5-minute window relative to the verifier's clock. Outbound is per-attempt: a retried delivery gets a fresh `t`/`v1` so consumers can verify freshness without buffering the original timestamp.

## What is NOT protected

- **TLS** — the relay binds plain HTTP. Run it behind a TLS-terminating reverse proxy (Caddy, nginx, Cloudflare, etc.). Webhook providers will reject plain HTTP, so this is enforced by Render itself in practice.
- **Replay attacks against the consumer** if the consumer ignores `X-Hooks-Signature.t`. Consumers MUST validate the timestamp window themselves.
- **At-most-once delivery** — listeners may see duplicates on retry. Idempotency is the consumer's responsibility; the relay emits `delivery_id` to make dedup trivial.

## Logging and secret hygiene

- Plaintext tokens, signing secrets, and provider secrets are typed as `secret.String`; they redact themselves on `String()`/`MarshalJSON`.
- The ingest layer logs only the source name and a body-sha256 prefix on signature mismatch.
- Test coverage asserts that no log line contains the plaintext after issuance.
