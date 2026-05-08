-- name: InsertUser :exec
INSERT INTO users
  (id, email, name, role, password_hash, default_scopes,
   created_at, deactivated_at, external_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetUserByID :one
SELECT id, email, name, role, password_hash, default_scopes,
       created_at, deactivated_at, external_id
  FROM users WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, email, name, role, password_hash, default_scopes,
       created_at, deactivated_at, external_id
  FROM users WHERE email = ? COLLATE NOCASE;

-- name: ListUsers :many
SELECT id, email, name, role, password_hash, default_scopes,
       created_at, deactivated_at, external_id
  FROM users
 ORDER BY created_at ASC;

-- name: ListUsersByRole :many
SELECT id, email, name, role, password_hash, default_scopes,
       created_at, deactivated_at, external_id
  FROM users
 WHERE role = ?
 ORDER BY created_at ASC;

-- name: UpdateUserProfile :execrows
UPDATE users
   SET name = ?, default_scopes = ?
 WHERE id = ?;

-- name: DeactivateUser :execrows
UPDATE users SET deactivated_at = ? WHERE id = ? AND deactivated_at IS NULL;

-- name: ReactivateUser :execrows
UPDATE users SET deactivated_at = NULL WHERE id = ?;

-- name: SetUserPasswordHash :execrows
UPDATE users SET password_hash = ? WHERE id = ?;

-- name: CountActiveAdmins :one
SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND deactivated_at IS NULL;

-- name: CountActiveAdminsExcluding :one
SELECT COUNT(*) AS n FROM users
 WHERE role = 'admin' AND deactivated_at IS NULL AND id != ?;
