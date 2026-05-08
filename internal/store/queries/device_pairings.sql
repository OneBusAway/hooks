-- name: InsertDevicePairing :exec
INSERT INTO device_pairings
  (device_code, user_code, status, created_at, expires_at, user_id,
   requesting_ip, requesting_user_agent, requested_scopes,
   plaintext_token, token_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDevicePairingByDeviceCode :one
SELECT device_code, user_code, status, created_at, expires_at, user_id,
       requesting_ip, requesting_user_agent, requested_scopes,
       plaintext_token, token_id
  FROM device_pairings WHERE device_code = ?;

-- name: GetDevicePairingByUserCode :one
SELECT device_code, user_code, status, created_at, expires_at, user_id,
       requesting_ip, requesting_user_agent, requested_scopes,
       plaintext_token, token_id
  FROM device_pairings WHERE user_code = ?;

-- name: UpdateDevicePairingApproved :execrows
UPDATE device_pairings
   SET status = 'approved_unfetched',
       user_id = ?,
       plaintext_token = ?,
       token_id = ?
 WHERE user_code = ? AND status = 'pending';

-- name: UpdateDevicePairingDenied :execrows
UPDATE device_pairings
   SET status = 'denied',
       user_id = ?
 WHERE user_code = ? AND status = 'pending';

-- name: MarkDevicePairingFetched :execrows
UPDATE device_pairings
   SET status = 'done',
       plaintext_token = NULL
 WHERE device_code = ? AND status = 'approved_unfetched';

-- name: ExpirePendingDevicePairings :execrows
UPDATE device_pairings
   SET status = 'expired'
 WHERE status = 'pending' AND expires_at < ?;

-- name: DeleteOldDevicePairings :execrows
DELETE FROM device_pairings
 WHERE status IN ('done','denied','expired')
   AND created_at < ?;
