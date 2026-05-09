# Security model

## Inbound HMAC verification

Every configured source MUST declare a registered `Verifier`. There is no opt-in for unsigned providers; the loader fails startup if a source has no verifier or names one that is not registered.

For Render specifically (per the [Standard Webhooks](https://www.standardwebhooks.com/) spec Render adopted):

- The relay computes `HMAC-SHA256(secret, "<id>.<timestamp>.<body>")` over the raw values of the `webhook-id` and `webhook-timestamp` headers and the request body.
- The `webhook-signature` header carries a space-separated list of `v1,<base64>` tokens (multiple entries support key rotation). We match against any v1 entry, base64-decoded, with `hmac.Equal` for constant-time compare.
- Any timestamp more than 5 minutes from the server's current UTC time is rejected (default; `skew_window` overrides per source).
- The captured `delivery_id` is the `webhook-id` header value.
- Secrets in the canonical Standard Webhooks `whsec_<base64>` form are decoded to raw bytes before HMAC; bare strings are used verbatim.

Failed verification produces HTTP 401 with no body. Logs include only the source name and a 4-byte hex prefix of the body's sha256 — never the body, never the signature, never the secret.

## Listener tokens (SSE pull, inspector, management API)

- Stored in SQLite as Argon2id hashes of 32-byte URL-safe base64 plaintexts.
- Lookup re-hashes the supplied plaintext per row and compares with constant time. (O(N) per request; fine for operator-token volumes; we'd revisit only at thousands of tokens.)
- `hooksctl token list` and `/api/tokens` GET return only metadata (id, name, scopes, timestamps). No path returns the plaintext after issuance.
- Revoked tokens are rejected within one round-trip; `last_used_at` is updated best-effort.

The special scope `admin` grants access to `/inspector`, `/api/tokens`, and `/api/push-subscriptions`. It does **not** implicitly grant subscribe access — an admin token MUST also include the source name in its scopes to subscribe.

### Ephemeral listener tokens

`hooksctl forward` running against a logged-in profile auto-mints a `kind='listener'` token with `ephemeral=true` for the lifetime of the SSE session and revokes it on clean exit. If the CLI is killed (SIGKILL, OOM, network partition) the token row stays unrevoked locally; the server's hourly prune loop covers that case. **Any `ephemeral=true` listener token whose `last_used_at` is more than 24h in the past — or whose `created_at` is more than 24h in the past with no `last_used_at` recorded — is auto-revoked**. The 24h window is large enough that intentional reconnects are unaffected and short enough that an unattended `hooksctl forward` cannot leave a long-tail credential.

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

## User identity and sessions

The relay supports developer accounts on top of the existing token model. See [`docs/accounts.md`](accounts.md) for the operator-facing walkthrough; this section captures the security surface.

### Three credential kinds, one row schema

Listener tokens and personal access tokens (PATs) share a row schema (`listener_tokens`) but are routed by `kind` at lookup time:

- **`kind='listener'`** — authorizes `/subscribe/<source>` and (when admin-scoped) the inspector. Cannot reach `/api/me/*`.
- **`kind='pat'`** — owned by a user; authorizes `/api/me/*` and the inspector. Cannot subscribe to events even when the scope set includes a source name.
- **Web session cookies** — opaque server-side rows in `user_sessions`; carry `Cookie: hooks_session=<id>.<plaintext>`.

Splitting at the kind boundary means a stolen PAT can't silently subscribe to event traffic and a stolen listener token can't mint new credentials.

### Argon2id vs SHA-256

Bearer-token plaintexts (PATs, listener tokens) are hashed with **Argon2id** because the device-pairing window briefly exposes plaintext to the wire and the attacker partially controls the input space at issuance.

Session cookie secrets are 32 random bytes from `crypto/rand` and hashed with **SHA-256**. Argon2's slowness exists to defend against offline attacks on low-entropy passwords; a 256-bit random secret has no offline-attack surface, so the per-request CPU tax buys nothing. The session lookup still does a constant-time compare on the SHA-256 digest.

Passwords use Argon2id.

### Device pairing — plaintext window

`hooksctl login` mints a PAT through a device-pairing flow. The plaintext is briefly persisted in `device_pairings.plaintext_token` between approval and the CLI's first poll — on the order of seconds, hard-capped at 15 minutes by the device-pairing TTL. The plaintext is NULL'd in a deferred update after the response handler returns. If the response write fails partway, the row stays `approved_unfetched` and the next poll succeeds (idempotent retry). The window is acceptable because:

- The plaintext is only fetchable by a client that knows the `device_code` (one of two opaque server-generated tokens; never sent over the user-visible UX path).
- After 24h post-terminal-state, the row is purged.
- This mirrors the existing reveal-once UX of `hooksctl token add`.

### Phishing defenses on device-pairing approval

A logged-in user could be socially engineered into approving an attacker-started pairing. Three layered mitigations:

1. **Narrow-by-default scope.** Approval defaults to `account` only — even a successful phish yields a PAT that can't subscribe to events or mint further tokens beyond what the user holds. The CLI explicitly opts in to broader scope via `--scopes` and `--admin`. The `/device` page surfaces the requested scopes prominently and lets the approver narrow them.
2. **Approver context display.** The `/device` page shows the requesting client's user-agent, IP, and human-readable scope list, with the warning **"Approve only if you started this on this machine."**
3. **Password re-entry.** Approval requires the user to type their password into a CSRF-protected form. A live session alone is insufficient. An attacker now needs the password and the user code in the same session, which is materially harder.

### Cascading revoke and reactivation friction

`POST /api/users/{id}/deactivate` is atomic:

- sets `deactivated_at` on the user row
- revokes every PAT and listener token they own (including ephemeral ones — no special case)
- pauses every push subscription they own

The API requires a `confirm=<email>` body field. A **last-admin guard** refuses with HTTP 409 if it would leave zero active admins; the guard runs both before and inside the transaction so two admins concurrently deactivating each other can't both succeed.

**Reactivation does not auto-restore tokens or unpause subscriptions.** Flipping `deactivated_at` back to NULL is the only thing it does; the user must reissue tokens via `hooksctl login` and unpause their subscriptions themselves. This matches GitHub's account-disable UX. The friction is intentional — reactivation is a deliberate, observable action, not a silent restoration of prior privilege.

### CSRF strategy

Every cookie-authenticated mutation is protected by **two** independent checks:

- **Origin/Referer match.** The `Origin` header (or `Referer` if `Origin` is absent) must match the request host. `Origin: null` is rejected. Absent both, the request is rejected.
- **Server-rendered double-submit token.** Inspector forms embed a per-session random token in a hidden field; the server reads the matching token from a `hooks_csrf` cookie and constant-time compares.

Bearer-only API calls (no cookie present) skip CSRF — they can't be cross-site-forged. Endpoints covered: `/api/auth/*`, `/api/me/*` mutations, `/api/users/*` mutations, `/api/invites/*` mutations, `/api/tokens` mutations, `/api/push-subscriptions` mutations, and the `/device` approval form.

### Rate limiting

In-process token-bucket-per-IP middleware (`internal/ratelimit`) on every authentication surface:

| Endpoint                          | Limits                          |
|-----------------------------------|---------------------------------|
| `POST /api/auth/login`            | 5/min/IP, 30/hour/IP            |
| `POST /api/auth/signup`           | 3/min/IP, 10/hour/IP            |
| `POST /api/auth/device/start`     | 10/min/IP                       |
| `POST /api/auth/device/poll`      | 60/min/IP                       |
| `POST /api/auth/device/approve`   | 10/min/user                     |

Excess requests return HTTP 429 with `Retry-After: <seconds>`. Buckets live in process memory and reset on restart — acceptable for a single-process SQLite deployment. A future Redis-backed backend can swap the implementation without changing the middleware contract.

### Audit log

Every admin-meaningful action is recorded in the append-only `audit_events` table. Surfaced at `/inspector/audit` (admin only). Tracked actions:

- `invite.create`, `invite.revoke`, `invite.consume`
- `user.create`, `user.deactivate`, `user.reactivate`, `user.role_change`, `user.update`, `user.password_reset`
- `token.transfer_owner`, `subscription.transfer_owner`
- `session.create`, `session.delete`
- `device_pairing.start`, `device_pairing.approve`, `device_pairing.deny`

Each row carries `actor_user_id`, `actor_token_id`, `target_type`, `target_id`, and a JSON `metadata` blob (e.g. counts of revoked tokens on a deactivate). The prune loop never touches this table; v1 declines to define a retention policy because growth is bounded by operator actions, not webhook traffic.

### Password policy

Enforced on signup and password reset by `internal/users`:

- Length ≥ 12 Unicode codepoints.
- Case-folded password does not contain the user's email local-part or full email.

Rejections return HTTP 400 with a generic message; the server logs the failed-policy reason (length / contains-email) but never the attempted plaintext. v1 deliberately skips HIBP-style breach-corpus checks — the goal is "block obvious mistakes", not "block all known-breached passwords".
