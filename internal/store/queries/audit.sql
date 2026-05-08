-- name: InsertAuditEvent :exec
INSERT INTO audit_events
  (id, at, actor_user_id, actor_token_id, action, target_type, target_id, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditEvents :many
SELECT id, at, actor_user_id, actor_token_id, action, target_type, target_id, metadata
  FROM audit_events
 WHERE (sqlc.arg(filter_actor) = 0 OR actor_user_id = sqlc.arg(actor_id))
   AND (sqlc.arg(filter_since) = 0 OR at >= sqlc.arg(since))
   AND (sqlc.arg(filter_until) = 0 OR at <= sqlc.arg(until))
 ORDER BY at DESC
 LIMIT ?;
