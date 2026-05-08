-- name: CheckEventDuplicate :one
SELECT 1 FROM events
 WHERE source = ? AND delivery_id = ? AND received_at >= ?
 LIMIT 1;

-- name: NextEventSequence :one
SELECT COALESCE(MAX(sequence), 0) + 1 AS next_seq FROM events WHERE source = ?;

-- name: InsertEvent :exec
INSERT INTO events
  (source, sequence, delivery_id, provider_timestamp, received_at,
   headers_json, body, body_sha256)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ReadEventsSince :many
SELECT source, sequence, delivery_id, provider_timestamp, received_at,
       headers_json, body, body_sha256
  FROM events
 WHERE source = ? AND sequence > ?
 ORDER BY sequence ASC
 LIMIT ?;

-- name: GetEvent :one
SELECT source, sequence, delivery_id, provider_timestamp, received_at,
       headers_json, body, body_sha256
  FROM events WHERE source = ? AND sequence = ?;

-- name: LatestEventSequence :one
SELECT CAST(COALESCE(MAX(sequence), 0) AS INTEGER) AS latest FROM events WHERE source = ?;

-- name: PruneEventsBySource :execrows
DELETE FROM events WHERE source = ? AND received_at < ?;

-- name: PruneAllEvents :execrows
DELETE FROM events WHERE received_at < ?;

-- name: ListEventSources :many
SELECT DISTINCT source FROM events ORDER BY source;
