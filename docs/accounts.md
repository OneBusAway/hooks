# Developer accounts

This walkthrough covers a deployed `hooks` relay (Render or any other host you don't shell into). For the deployment recipe and a local-only path, see the [README](../README.md). For the security-focused breakdown, see [`docs/security.md`](security.md).

The mental model: one relay deployment per team. Each developer has their own account. Listener tokens, push subscriptions, and PATs (personal access tokens) are owned by users. Deactivating a user revokes their tokens and pauses their push subscriptions in one move.

## 1. Deploy the relay

Build the binaries and bring up the server behind TLS (the [README](../README.md) has the recipe; [`deployment.md`](deployment.md) has the reference). Whatever the host, the URL the rest of this doc uses is `https://webhooks.example.com`.

## 2. Bootstrap the first admin

On a freshly initialized database `hooks init` prints a one-time signup URL:

```
admin token (shown ONCE): <legacy system token, copy if you want one>
signup: https://webhooks.example.com/signup?code=ABCDEFGH...
        (single-use; expires in 24h; auto-disables once any account exists)
```

Open the signup URL in a browser. Pick an email, name, and password (≥ 12 characters; must not contain your full email — or its local-part, when the local-part is at least three characters long). The first signup consumes the bootstrap invite; once any user exists, that URL returns 409 even if someone else copies it.

The `admin token` printed alongside the signup URL is the legacy system credential. You can keep it for break-glass access or revoke it with `hooksctl token revoke <id>` once your PAT is working (see step 4). It is **not** tied to any user account.

If the bootstrap link expires before it's used, re-run `hooks init` against the still-userless DB to regenerate it; a fresh 24-hour window starts.

## 3. Invite teammates

After login, the inspector at `/users` exposes an "Issue invite" form. Pick a role (`user` or `admin`) and a default scope set; the page shows the resulting `https://webhooks.example.com/signup?code=...` URL once. Send it to your teammate. Invites are single-use.

The same surface is available over JSON at `POST /api/invites` for any tool you'd rather drive programmatically:

```sh
curl -X POST https://webhooks.example.com/api/invites \
  -H "Authorization: Bearer $ADMIN_PAT" \
  -H "Content-Type: application/json" \
  -d '{"role": "user", "default_scopes": ["render"]}'
```

## 4. Get a CLI on your laptop

```sh
hooksctl login --server https://webhooks.example.com
```

The CLI prints a short user code (`ABCD-EFGH`) and a verification URL, and tries to open the URL in your browser. The page asks you to log in if you aren't already, then shows you the requesting client's user-agent, IP, and requested scopes. **Approval requires you to re-enter your password**, even if you're already logged in — a live session alone is not sufficient.

Default scope on approval is `account` only — enough to manage your own tokens but not enough to subscribe to webhook events. Pass `--scopes` (comma-separated source names) to request more, and `--admin` to request admin scope:

```sh
hooksctl login --server https://webhooks.example.com --scopes render,stripe
hooksctl login --server https://webhooks.example.com --admin
```

You may also narrow the scopes from the approval page itself — the CLI's request is the upper bound. Approval mints a personal access token (PAT), writes it to `${XDG_CONFIG_HOME:-$HOME/.config}/hooks/credentials.<profile>` (mode `0600`), and the next CLI call uses it automatically.

`--profile <name>` lets you keep multiple servers configured side-by-side; `default` is the default profile.

Verify the login worked:

```sh
hooksctl whoami
```

## 5. Forward events to your local app

```sh
hooksctl forward render --to http://localhost:3000/webhooks/render
```

This is the day-to-day developer flow. Two paths:

### Default: ephemeral listener token

When `forward` runs against a logged-in profile (no `--token`), the CLI auto-mints a `kind='listener'` token with `ephemeral=true`, opens an SSE stream, and revokes the token on clean exit. If the CLI is killed, the server's prune loop revokes any `ephemeral` token whose `last_used_at` is more than 24h in the past — so a crashed `forward` doesn't leave credential debris.

### Power-user: long-lived listener token

If you run `forward` all day every day and want to skip the mint/revoke dance:

```sh
# Mint once.
hooksctl me token add --name forward-laptop --kind listener --scopes render
# (copy the printed token)

# Then point forward at it.
hooksctl forward render --to http://localhost:3000/webhooks/render --token <long-lived token>
```

Long-lived listener tokens live until you revoke them with `hooksctl me token revoke <id>` or `hooksctl token revoke <id>`.

## 6. Push subscriptions (optional)

If you want a permanent consumer URL instead of an SSE pull:

```sh
hooksctl me sub add --source render --to https://my-svc.example.com/hooks --name production
```

The relay prints a per-subscription signing secret **once** — store it on your consumer. Verify each delivery via `X-Hooks-Signature: t=<unix>,v1=<hex>` (see [`docs/consumer-verification.md`](consumer-verification.md)).

## Admin operations

The inspector exposes admin-only pages at `/users` (user list + issue-invite form + deactivate / reactivate / reset-password actions) and `/audit` (audit-log table). The matching JSON endpoints are under `/api/users/*`, `/api/invites/*`, `/api/audit`. v1 ships no `hooksctl` subcommands for these surfaces — drive them via the inspector or `curl` against the JSON API.

### Deactivating a user

`POST /api/users/{id}/deactivate` (and the inspector form) **atomically**:

- sets `deactivated_at` on the user row
- revokes every PAT and listener token they own (including ephemeral)
- pauses every push subscription they own

The API requires a `confirm=<email>` body field; the inspector form requires you to type the email in. A **last-admin guard** refuses with HTTP 409 if the action would leave zero active admins.

**Reactivation is intentionally lossy.** Setting `deactivated_at` back to NULL does not auto-restore tokens or unpause subscriptions. The deactivated user must reissue tokens via `hooksctl login` and unpause their subscriptions themselves. This matches GitHub's account-disable UX. Documented friction, not a bug.

### Transferring ownership

```sh
# Move a token to a different user.
curl -X PATCH https://webhooks.example.com/api/tokens/<id> \
  -H "Authorization: Bearer $ADMIN_PAT" \
  -d '{"owner_user_id": "<new owner id>"}'
```

Same shape for `/api/push-subscriptions/{id}`. Useful for "departed admin handed off their listener token" scenarios.

### Audit log

Every admin-meaningful action lands in `audit_events`:

- `invite.create`, `invite.revoke`, `invite.consume`
- `user.create`, `user.deactivate`, `user.reactivate`, `user.role_change`, `user.update`, `user.password_reset`
- `token.transfer_owner`, `subscription.transfer_owner`
- `session.create`, `session.delete`
- `device_pairing.start`, `device_pairing.approve`, `device_pairing.deny`

Surfaced at `/audit` (admin only). The table is **append-only** — no API or UI deletes entries. Size is small (~few hundred bytes per row, growth driven by operator actions, not webhook traffic).

## Logging out

```sh
hooksctl logout
```

Revokes the local PAT against the server, then deletes the credentials file. If the revoke fails (server down, network partition) the file is still deleted but `logout` exits non-zero so you know the token is still live server-side; revoke it from another machine via `hooksctl me token revoke <id>`.
