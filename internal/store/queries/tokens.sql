-- name: InsertToken :exec
INSERT INTO listener_tokens
  (id, name, scopes, secret_hash, created_at,
   owner_user_id, kind, ephemeral, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListActiveTokens :many
SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at,
       owner_user_id, kind, ephemeral, expires_at
  FROM listener_tokens
 WHERE revoked_at IS NULL;

-- name: TouchTokenLastUsed :exec
UPDATE listener_tokens SET last_used_at = ? WHERE id = ?;

-- name: ListTokens :many
SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at,
       owner_user_id, kind, ephemeral, expires_at
  FROM listener_tokens
 WHERE (sqlc.arg(include_revoked) = 1 OR revoked_at IS NULL)
 ORDER BY created_at DESC;

-- name: GetToken :one
SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at,
       owner_user_id, kind, ephemeral, expires_at
  FROM listener_tokens WHERE id = ?;

-- name: RevokeToken :execrows
UPDATE listener_tokens SET revoked_at = ?
 WHERE id = ? AND revoked_at IS NULL;

-- name: ListTokensByOwner :many
SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at,
       owner_user_id, kind, ephemeral, expires_at
  FROM listener_tokens
 WHERE owner_user_id = ?
   AND (sqlc.arg(include_revoked) = 1 OR revoked_at IS NULL)
 ORDER BY created_at DESC;

-- name: ListSystemTokens :many
SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at,
       owner_user_id, kind, ephemeral, expires_at
  FROM listener_tokens
 WHERE owner_user_id IS NULL
   AND (sqlc.arg(include_revoked) = 1 OR revoked_at IS NULL)
 ORDER BY created_at DESC;

-- name: RevokeTokensByOwner :execrows
UPDATE listener_tokens
   SET revoked_at = ?
 WHERE owner_user_id = ? AND revoked_at IS NULL;

-- name: ExpireEphemeralTokensIdle :execrows
UPDATE listener_tokens
   SET revoked_at = ?
 WHERE ephemeral = 1
   AND revoked_at IS NULL
   AND ((last_used_at IS NOT NULL AND last_used_at < ?)
     OR (last_used_at IS NULL  AND created_at < ?));

-- name: UpdateTokenOwner :execrows
UPDATE listener_tokens SET owner_user_id = ? WHERE id = ?;
