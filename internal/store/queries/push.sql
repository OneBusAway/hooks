-- name: InsertPushSubscription :exec
INSERT INTO push_subscriptions
  (id, source, target_url, signing_secret_hash, name, cursor,
   paused_at, created_at, last_error, consecutive_failures, owner_user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', 0, ?);

-- name: ListPushSubscriptions :many
SELECT id, source, target_url, signing_secret_hash, name, cursor,
       paused_at, created_at, last_attempt_at, last_success_at, last_error,
       consecutive_failures, owner_user_id
  FROM push_subscriptions
 WHERE (sqlc.arg(include_paused) = 1 OR paused_at IS NULL)
 ORDER BY created_at ASC;

-- name: ListPushSubscriptionsBySource :many
SELECT id, source, target_url, signing_secret_hash, name, cursor,
       paused_at, created_at, last_attempt_at, last_success_at, last_error,
       consecutive_failures, owner_user_id
  FROM push_subscriptions
 WHERE source = ?
   AND (sqlc.arg(include_paused) = 1 OR paused_at IS NULL)
 ORDER BY created_at ASC;

-- name: ListPushSubscriptionsByOwner :many
SELECT id, source, target_url, signing_secret_hash, name, cursor,
       paused_at, created_at, last_attempt_at, last_success_at, last_error,
       consecutive_failures, owner_user_id
  FROM push_subscriptions
 WHERE owner_user_id = ?
   AND (sqlc.arg(include_paused) = 1 OR paused_at IS NULL)
 ORDER BY created_at ASC;

-- name: ListSystemPushSubscriptions :many
SELECT id, source, target_url, signing_secret_hash, name, cursor,
       paused_at, created_at, last_attempt_at, last_success_at, last_error,
       consecutive_failures, owner_user_id
  FROM push_subscriptions
 WHERE owner_user_id IS NULL
   AND (sqlc.arg(include_paused) = 1 OR paused_at IS NULL)
 ORDER BY created_at ASC;

-- name: GetPushSubscription :one
SELECT id, source, target_url, signing_secret_hash, name, cursor,
       paused_at, created_at, last_attempt_at, last_success_at, last_error,
       consecutive_failures, owner_user_id
  FROM push_subscriptions WHERE id = ?;

-- name: UpdatePushCursorSuccess :execrows
UPDATE push_subscriptions
   SET cursor = ?,
       last_attempt_at = ?,
       last_success_at = ?,
       last_error = '',
       consecutive_failures = 0
 WHERE id = ?;

-- name: RecordPushFailure :execrows
UPDATE push_subscriptions
   SET last_attempt_at = ?,
       last_error = ?,
       consecutive_failures = consecutive_failures + 1
 WHERE id = ?;

-- name: PausePushSubscription :execrows
UPDATE push_subscriptions
   SET paused_at = ?
 WHERE id = ? AND paused_at IS NULL;

-- name: ResumePushSubscription :execrows
UPDATE push_subscriptions SET paused_at = NULL WHERE id = ?;

-- name: RotatePushSecret :execrows
UPDATE push_subscriptions SET signing_secret_hash = ? WHERE id = ?;

-- name: DeletePushSubscription :execrows
DELETE FROM push_subscriptions WHERE id = ?;

-- name: PausePushSubscriptionsByOwner :execrows
UPDATE push_subscriptions
   SET paused_at = ?
 WHERE owner_user_id = ? AND paused_at IS NULL;

-- name: UpdatePushOwner :execrows
UPDATE push_subscriptions SET owner_user_id = ? WHERE id = ?;
