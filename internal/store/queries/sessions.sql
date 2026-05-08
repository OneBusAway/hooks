-- name: InsertSession :exec
INSERT INTO user_sessions
  (id, user_id, secret_hash, created_at, last_used_at, expires_at, user_agent, ip)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT id, user_id, secret_hash, created_at, last_used_at, expires_at, user_agent, ip
  FROM user_sessions WHERE id = ?;

-- name: TouchSession :exec
UPDATE user_sessions
   SET last_used_at = ?,
       expires_at = ?
 WHERE id = ?;

-- name: DeleteSession :execrows
DELETE FROM user_sessions WHERE id = ?;

-- name: DeleteSessionsByUser :execrows
DELETE FROM user_sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :execrows
DELETE FROM user_sessions WHERE expires_at < ?;
