-- name: InsertInvite :exec
INSERT INTO invites
  (code, role, default_scopes, created_by_user_id, bootstrap,
   created_at, expires_at, consumed_at, consumed_by_user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetInviteByCode :one
SELECT code, role, default_scopes, created_by_user_id, bootstrap,
       created_at, expires_at, consumed_at, consumed_by_user_id
  FROM invites WHERE code = ?;

-- name: MarkInviteConsumed :execrows
UPDATE invites
   SET consumed_at = ?, consumed_by_user_id = ?
 WHERE code = ? AND consumed_at IS NULL;

-- name: ListInvites :many
SELECT code, role, default_scopes, created_by_user_id, bootstrap,
       created_at, expires_at, consumed_at, consumed_by_user_id
  FROM invites
 ORDER BY created_at DESC;

-- name: ListInvitesByConsumed :many
SELECT code, role, default_scopes, created_by_user_id, bootstrap,
       created_at, expires_at, consumed_at, consumed_by_user_id
  FROM invites
 WHERE (sqlc.arg(consumed) = 1 AND consumed_at IS NOT NULL)
    OR (sqlc.arg(consumed) = 0 AND consumed_at IS NULL)
 ORDER BY created_at DESC;

-- name: DeleteInvite :execrows
DELETE FROM invites WHERE code = ? AND consumed_at IS NULL;

-- name: GetBootstrapInvite :one
SELECT code, role, default_scopes, created_by_user_id, bootstrap,
       created_at, expires_at, consumed_at, consumed_by_user_id
  FROM invites
 WHERE bootstrap = 1
 LIMIT 1;

-- name: DeleteBootstrapInvite :exec
DELETE FROM invites WHERE bootstrap = 1;

-- name: MarkBootstrapInvitesConsumed :execrows
UPDATE invites
   SET consumed_at = ?, consumed_by_user_id = ?
 WHERE bootstrap = 1 AND consumed_at IS NULL;
