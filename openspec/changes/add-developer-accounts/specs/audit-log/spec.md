## ADDED Requirements

### Requirement: Append-only audit log of admin-meaningful actions

The service SHALL record an immutable audit event for every admin-meaningful action in an `audit_events` table with columns `(id, at, actor_user_id, actor_token_id, action, target_type, target_id, metadata)`. The recorded actions SHALL include at minimum:

- `invite.create`, `invite.revoke`, `invite.consume`
- `user.create`, `user.deactivate`, `user.reactivate`, `user.role_change`, `user.update`
- `user.password_reset`
- `token.transfer_owner`, `subscription.transfer_owner`
- `session.create`, `session.delete`
- `device_pairing.start`, `device_pairing.approve`, `device_pairing.deny`

The `audit_events` table SHALL be append-only: production code paths SHALL NOT issue UPDATE or DELETE against it; the prune loop SHALL NOT touch it. The `metadata` JSON column SHALL NOT contain plaintext secrets, plaintext passwords, or full webhook bodies; any persisted values that would contain such data SHALL flow through `internal/secret.String` at log boundaries and be elided.

#### Scenario: Invite creation produces an audit event
- **WHEN** an admin POSTs `/api/invites` with valid input
- **THEN** an `audit_events` row is inserted with `action="invite.create"`, `actor_user_id` set to the admin, `target_type="invite"`, `target_id` equal to the invite code, and metadata describing role and TTL

#### Scenario: Cascading deactivation produces a single user.deactivate event
- **WHEN** an admin deactivates a user that owns multiple tokens and subscriptions
- **THEN** exactly one `audit_events` row is inserted for the deactivation action; the cascading revokes are not separately audited (the user.deactivate row's metadata SHALL summarize counts)

#### Scenario: No plaintext secret in audit metadata
- **WHEN** any auditable action involves a password, token plaintext, or webhook body
- **THEN** the corresponding `audit_events` row's `metadata` column does not contain that plaintext

### Requirement: Admin audit-log read surface

The service SHALL expose `GET /api/audit?actor=<user_id>&since=<rfc3339>&until=<rfc3339>&limit=<n>` (admin only) returning `audit_events` rows ordered by `at DESC`. The service SHALL also serve `/inspector/audit` (admin only) rendering the same data with actor email resolution and a simple time-range filter. Non-admin requests to either surface SHALL receive HTTP 403.

#### Scenario: Admin filters audit events by actor and time
- **WHEN** an admin GETs `/api/audit?actor=<id>&since=2026-05-01T00:00:00Z&limit=50`
- **THEN** the response contains at most 50 rows matching `actor_user_id=<id>` with `at >= 2026-05-01T00:00:00Z`, ordered by `at DESC`

#### Scenario: Non-admin denied
- **WHEN** a non-admin user calls `GET /api/audit` or loads `/inspector/audit`
- **THEN** the response is HTTP 403
