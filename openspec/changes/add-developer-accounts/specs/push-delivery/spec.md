## ADDED Requirements

### Requirement: Self-service push subscription endpoints

The service SHALL expose `POST /api/me/subscriptions`, `GET /api/me/subscriptions`, `GET /api/me/subscriptions/{id}`, `POST /api/me/subscriptions/{id}/pause`, `POST /api/me/subscriptions/{id}/resume`, `POST /api/me/subscriptions/{id}/rotate-secret`, `DELETE /api/me/subscriptions/{id}`, and `POST /api/me/subscriptions/{id}/test`. These endpoints SHALL operate exclusively on rows whose `owner_user_id` matches the calling user, returning HTTP 404 for any subscription owned by another user. The wire format, request bodies, response shapes, signing semantics, retry, cursor, and replay behavior SHALL be identical to the corresponding admin endpoints — only ownership scoping changes. Mutations against `/api/me/subscriptions/*` accepted via cookie session SHALL be CSRF-checked per the developer-accounts CSRF requirement; bearer-only requests are exempt. Plaintext signing secrets SHALL never appear in any log line; the `internal/secret.String` typed credential SHALL be used at log boundaries.

#### Scenario: User registers a subscription under their account
- **WHEN** an authenticated user POSTs `/api/me/subscriptions` with `{source: "render", target_url: "https://x/y"}`
- **THEN** a row is created with `owner_user_id` equal to that user, the response includes the subscription id and a one-time `signing_secret`, and a subsequent `GET /api/me/subscriptions/{id}` returns the metadata without the plaintext

#### Scenario: User cannot enumerate other users' subscriptions
- **WHEN** a user calls `GET /api/me/subscriptions/{id}` for a subscription owned by another user
- **THEN** the response is HTTP 404

#### Scenario: Mutations on /api/me/subscriptions require account scope
- **WHEN** a token whose scopes do not include `account` is used against `/api/me/subscriptions`
- **THEN** the service responds with HTTP 401 if the request is anonymous, or HTTP 403 otherwise

#### Scenario: Cookie-authenticated mutation without CSRF token is rejected
- **WHEN** a user POSTs `/api/me/subscriptions` with a valid session cookie but no `csrf_token` field matching the `hooks_csrf` cookie
- **THEN** the response is HTTP 403 and no subscription is created

## MODIFIED Requirements

### Requirement: Push subscription registration

The service SHALL allow registration of push subscriptions via two URL surfaces with identical request bodies:
- `POST /api/push-subscriptions` (admin only, CSRF-checked when cookie-authenticated) — registers a subscription with no required `owner_user_id`. Admins MAY pass an explicit `owner_user_id` to register on behalf of a user; omitting it produces a system-owned subscription.
- `POST /api/me/subscriptions` (any authenticated user with `account` scope, CSRF-checked when cookie-authenticated) — registers a subscription whose `owner_user_id` is the calling user; any explicit `owner_user_id` field in the body SHALL be ignored.

The request body SHALL include `source` (string, must be a configured source), `target_url` (http or https URL), and optionally `name` (label) and `since` (initial cursor: integer or `latest`, default `latest`). On success the service SHALL respond with HTTP 201 and a JSON body containing the subscription's `id`, `cursor`, and a one-time-only plaintext `signing_secret`. Subsequent reads of the subscription SHALL NOT return the plaintext.

#### Scenario: Admin registration produces a system-owned subscription
- **WHEN** an admin POSTs `/api/push-subscriptions` with no `owner_user_id`
- **THEN** the resulting row's `owner_user_id` is NULL

#### Scenario: Admin registration on behalf of a user
- **WHEN** an admin POSTs `/api/push-subscriptions` with `{owner_user_id: <user_id>, ...}`
- **THEN** the resulting row's `owner_user_id` matches the supplied id, and the user can subsequently see and manage that subscription via `/api/me/subscriptions`

#### Scenario: Self-service registration ignores owner override
- **WHEN** a non-admin user POSTs `/api/me/subscriptions` with a body that contains `{owner_user_id: <other_user_id>, ...}`
- **THEN** the resulting row's `owner_user_id` is the calling user, not the supplied value

#### Scenario: Default cold-start cursor is `latest`
- **WHEN** a subscription is registered without a `since` field, and the highest stored sequence for the source is 42
- **THEN** the subscription's stored cursor is 42 and only events with sequence > 42 will be delivered

#### Scenario: Backfill is opt-in via `since=0`
- **WHEN** a subscription is registered with `since=0`
- **THEN** the dispatcher delivers every stored event for that source in ascending sequence order before transitioning to live

#### Scenario: Unknown source is rejected
- **WHEN** a registration request names a `source` that is not in the configuration
- **THEN** the service responds with HTTP 400

### Requirement: Operational controls

The service SHALL expose admin HTTP routes under `/api/push-subscriptions` for full-fleet management and per-user routes under `/api/me/subscriptions` (covered by its own requirement) for self-service. The admin routes SHALL accept `?owner=<user_id>` (or the literal `?owner=system` for system-owned rows) on `list` and `get` to filter by ownership, and `PATCH /api/push-subscriptions/{id} {"owner_user_id": "..."}` to transfer ownership. Admin mutations accepted via cookie session SHALL be CSRF-checked. Ownership transfer SHALL record an `audit_events` row with action `subscription.transfer_owner`. The matching `hooksctl push` subcommands continue to require an `admin`-scoped token. Both surfaces support:
- `list` — id, source, target_url, owner, cursor, queue depth (highest source sequence − cursor), `consecutive_failures`, `last_error` (truncated to 200 chars on the list view), `last_attempt_at`, `last_success_at`, `paused_at`.
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

#### Scenario: Owner filter narrows the admin list
- **WHEN** an admin calls `GET /api/push-subscriptions?owner=<user_id>`
- **THEN** the response includes only subscriptions whose `owner_user_id` matches that id

#### Scenario: Admin transfers ownership
- **WHEN** an admin PATCHes `/api/push-subscriptions/{id}` with `{"owner_user_id": "<new_user_id>"}` and a valid CSRF token
- **THEN** subsequent `GET /api/me/subscriptions` calls by the new owner include the subscription, and an `audit_events` row with action `subscription.transfer_owner` is recorded

#### Scenario: Cookie-authenticated PATCH without CSRF token rejected
- **WHEN** an admin PATCHes `/api/push-subscriptions/{id}` from the inspector with a valid session cookie but no matching `csrf_token`
- **THEN** the response is HTTP 403 and no state changes

### Requirement: Inspector visibility

The web inspector SHALL render a push-subscription view at `/inspector/push` (admin only) showing every subscription regardless of owner, and a `/inspector/me/push` view (any active user) showing only subscriptions owned by the calling user. Both views SHALL render each row's source, `target_url`, owner (admin view only), cursor, queue depth, `consecutive_failures`, `last_error`, `last_attempt_at`, and `last_success_at`, with `pause`/`resume`/`rotate-secret`/`delete`/`test` actions inline. The signing-secret plaintext SHALL never appear on a list view; rotate-secret SHALL show the new plaintext exactly once on the resulting confirmation page. Every mutation form SHALL embed a CSRF token tied to the `hooks_csrf` cookie.

#### Scenario: Inspector reflects dispatcher state within 5 seconds
- **WHEN** a subscription's `consecutive_failures` increments from 5 to 6
- **THEN** a refresh of `/inspector/push` (admin) or `/inspector/me/push` (owner) within 5 seconds shows the new value

#### Scenario: Inspector never shows plaintext signing secret on list
- **WHEN** an admin loads `/inspector/push` or a user loads `/inspector/me/push`
- **THEN** no row's HTML contains the plaintext signing secret

#### Scenario: Per-user view excludes other users' subscriptions
- **WHEN** a non-admin user loads `/inspector/me/push`
- **THEN** the rendered list contains only subscriptions whose `owner_user_id` matches that user
