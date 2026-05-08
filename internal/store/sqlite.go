package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLite is the default backend. It implements EventStore directly; the
// TokenStore and PushSubscriptionStore interfaces are exposed via thin
// adapters returned by Tokens() and PushSubscriptions() respectively (the
// adapters exist because TokenStore and PushSubscriptionStore both define
// methods named `Insert` and `List`).
type SQLite struct {
	db           *sql.DB
	dedupeWindow time.Duration
	tokenHash    HashLookup
}

// SQLiteOptions configures a SQLite store.
type SQLiteOptions struct {
	// DedupeWindow controls how far back the (source, delivery_id) check
	// considers a row a duplicate.
	DedupeWindow time.Duration
}

// OpenSQLite opens (and migrates) a SQLite database at dsn. dsn may be a bare
// path like "./hooks.db" or a sqlite URL (sqlite:foo.db). WAL mode and
// synchronous=NORMAL are configured automatically.
func OpenSQLite(dsn string, opts SQLiteOptions) (*SQLite, error) {
	if opts.DedupeWindow == 0 {
		opts.DedupeWindow = 24 * time.Hour
	}

	db, err := sql.Open("sqlite", normalizeDSN(dsn))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite supports concurrent readers but only one writer; serializing
	// writers via a single connection avoids "database is locked" surprises.
	db.SetMaxOpenConns(1)

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}

	s := &SQLite{db: db, dedupeWindow: opts.DedupeWindow}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func normalizeDSN(in string) string {
	// Accept "sqlite:foo.db", "file:foo.db?...", or bare paths.
	if strings.HasPrefix(in, "sqlite:") {
		return strings.TrimPrefix(in, "sqlite:")
	}
	if strings.HasPrefix(in, "file:") {
		return in
	}
	// Bare path. Use a file: URL so options can be appended later if needed.
	return "file:" + url.PathEscape(in) + "?cache=shared"
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Ping(ctx context.Context) error {
	row := s.db.QueryRowContext(ctx, "SELECT 1")
	var n int
	return row.Scan(&n)
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS events (
  source              TEXT    NOT NULL,
  sequence            INTEGER NOT NULL,
  delivery_id         TEXT    NOT NULL,
  provider_timestamp  INTEGER NOT NULL,
  received_at         INTEGER NOT NULL,
  headers_json        TEXT    NOT NULL,
  body                BLOB    NOT NULL,
  body_sha256         TEXT    NOT NULL,
  PRIMARY KEY (source, sequence)
);
CREATE INDEX IF NOT EXISTS idx_events_dedupe   ON events(source, delivery_id);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);

CREATE TABLE IF NOT EXISTS listener_tokens (
  id            TEXT    PRIMARY KEY,
  name          TEXT    NOT NULL,
  scopes        TEXT    NOT NULL,
  secret_hash   TEXT    NOT NULL,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER,
  revoked_at    INTEGER
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id                    TEXT    PRIMARY KEY,
  source                TEXT    NOT NULL,
  target_url            TEXT    NOT NULL,
  signing_secret_hash   TEXT    NOT NULL,
  name                  TEXT    NOT NULL DEFAULT '',
  cursor                INTEGER NOT NULL DEFAULT 0,
  paused_at             INTEGER,
  created_at            INTEGER NOT NULL,
  last_attempt_at       INTEGER,
  last_success_at       INTEGER,
  last_error            TEXT    NOT NULL DEFAULT '',
  consecutive_failures  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_push_source ON push_subscriptions(source);
`

func (s *SQLite) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// --- EventStore --------------------------------------------------------------

func (s *SQLite) Append(ctx context.Context, in AppendInput) (Event, error) {
	if in.Source == "" {
		return Event{}, errors.New("Append: empty source")
	}
	if in.DeliveryID == "" {
		return Event{}, errors.New("Append: empty delivery_id")
	}

	headersJSON, err := json.Marshal(in.Headers)
	if err != nil {
		return Event{}, fmt.Errorf("marshal headers: %w", err)
	}
	sum := sha256.Sum256(in.Body)
	bodyHex := hex.EncodeToString(sum[:])
	receivedAt := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// Dedupe within the configured window. We treat any prior row with the
	// same (source, delivery_id) as a duplicate; the dedupe window is enforced
	// at the application layer rather than by deleting old rows from the
	// dedupe index — the events table itself is the index.
	cutoff := receivedAt.Add(-s.dedupeWindow).UnixNano()
	var existing int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM events WHERE source=? AND delivery_id=? AND received_at>=? LIMIT 1`,
		in.Source, in.DeliveryID, cutoff,
	).Scan(&existing)
	switch {
	case err == nil:
		return Event{}, ErrDuplicate
	case errors.Is(err, sql.ErrNoRows):
		// fall through
	default:
		return Event{}, err
	}

	// Assign next per-source sequence: max(seq)+1, default 1.
	var nextSeq int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE source=?`,
		in.Source,
	).Scan(&nextSeq); err != nil {
		return Event{}, fmt.Errorf("next sequence: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO events
		   (source, sequence, delivery_id, provider_timestamp, received_at,
		    headers_json, body, body_sha256)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Source, nextSeq, in.DeliveryID,
		in.ProviderTimestamp.UTC().UnixNano(),
		receivedAt.UnixNano(),
		string(headersJSON),
		in.Body,
		bodyHex,
	); err != nil {
		return Event{}, fmt.Errorf("insert event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Event{}, err
	}

	return Event{
		Source:            in.Source,
		Sequence:          nextSeq,
		DeliveryID:        in.DeliveryID,
		ProviderTimestamp: in.ProviderTimestamp.UTC(),
		ReceivedAt:        receivedAt,
		Headers:           cloneHeaders(in.Headers),
		Body:              in.Body,
		BodySHA256:        bodyHex,
	}, nil
}

func (s *SQLite) ReadSince(ctx context.Context, source string, cursor int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT source, sequence, delivery_id, provider_timestamp, received_at,
		        headers_json, body, body_sha256
		   FROM events
		  WHERE source=? AND sequence>?
		  ORDER BY sequence ASC
		  LIMIT ?`,
		source, cursor, limit,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *SQLite) Get(ctx context.Context, source string, sequence int64) (Event, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT source, sequence, delivery_id, provider_timestamp, received_at,
		        headers_json, body, body_sha256
		   FROM events WHERE source=? AND sequence=?`,
		source, sequence,
	)
	ev, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	return ev, err
}

func (s *SQLite) LatestSequence(ctx context.Context, source string) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(sequence), 0) FROM events WHERE source=?`,
		source,
	).Scan(&seq)
	return seq, err
}

func (s *SQLite) Prune(ctx context.Context, source string, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE source=? AND received_at < ?`,
		source, cutoff.UTC().UnixNano(),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLite) PruneAll(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE received_at < ?`,
		cutoff.UTC().UnixNano(),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLite) Sources(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT source FROM events ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// --- TokenStore --------------------------------------------------------------

// HashLookup is the hash function used by LookupByPlaintext to recompute the
// per-row hash for constant-time comparison. It is set by the tokens package
// at process start so the store package doesn't depend on argon2.
type HashLookup func(plaintext, encoded string) (bool, error)

// SetTokenHashCompare wires a verifier function for LookupByPlaintext.
func (s *SQLite) SetTokenHashCompare(fn HashLookup) {
	s.tokenHash = fn
}

// tokenHash is package state set at process start; nil means LookupByPlaintext
// always returns ErrNotFound (used in tests that exercise other code paths).
//
// (We make it a struct field rather than a global so multiple SQLite instances
// in tests can have independent verifiers.)
//

func (s *SQLite) Insert(ctx context.Context, t Token) error {
	scopes := strings.Join(t.Scopes, ",")
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO listener_tokens (id, name, scopes, secret_hash, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Name, scopes, t.SecretHash, t.CreatedAt.UTC().UnixNano(),
	)
	return err
}

func (s *SQLite) LookupByPlaintext(ctx context.Context, plaintext string) (Token, error) {
	if s.tokenHash == nil {
		return Token{}, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at
		   FROM listener_tokens
		  WHERE revoked_at IS NULL`,
	)
	if err != nil {
		return Token{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return Token{}, err
		}
		ok, err := s.tokenHash(plaintext, t.SecretHash)
		if err != nil {
			continue
		}
		if ok {
			return t, nil
		}
	}
	if err := rows.Err(); err != nil {
		return Token{}, err
	}
	return Token{}, ErrNotFound
}

func (s *SQLite) TouchLastUsed(ctx context.Context, id string, when time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE listener_tokens SET last_used_at=? WHERE id=?`,
		when.UTC().UnixNano(), id,
	)
	return err
}

func (s *SQLite) List(ctx context.Context, includeRevoked bool) ([]Token, error) {
	q := `SELECT id, name, scopes, secret_hash, created_at, last_used_at, revoked_at
	        FROM listener_tokens`
	if !includeRevoked {
		q += ` WHERE revoked_at IS NULL`
	}
	q += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLite) Revoke(ctx context.Context, id string, when time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE listener_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		when.UTC().UnixNano(), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- PushSubscriptionStore ---------------------------------------------------

func (s *SQLite) InsertPush(ctx context.Context, sub PushSubscription) error {
	var pausedAt any
	if sub.PausedAt != nil {
		pausedAt = sub.PausedAt.UTC().UnixNano()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO push_subscriptions
		   (id, source, target_url, signing_secret_hash, name, cursor,
		    paused_at, created_at, last_error, consecutive_failures)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', 0)`,
		sub.ID, sub.Source, sub.TargetURL, sub.SigningSecretHash, sub.Name,
		sub.Cursor, pausedAt, sub.CreatedAt.UTC().UnixNano(),
	)
	return err
}

func (s *SQLite) ListPush(ctx context.Context, includePaused bool) ([]PushSubscription, error) {
	q := pushSelect
	if !includePaused {
		q += ` WHERE paused_at IS NULL`
	}
	q += ` ORDER BY created_at ASC`
	return s.queryPushList(ctx, q)
}

func (s *SQLite) ListPushBySource(ctx context.Context, source string, includePaused bool) ([]PushSubscription, error) {
	q := pushSelect + ` WHERE source=?`
	args := []any{source}
	if !includePaused {
		q += ` AND paused_at IS NULL`
	}
	q += ` ORDER BY created_at ASC`
	return s.queryPushList(ctx, q, args...)
}

func (s *SQLite) queryPushList(ctx context.Context, q string, args ...any) ([]PushSubscription, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PushSubscription
	for rows.Next() {
		sub, err := scanPush(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

func (s *SQLite) GetPush(ctx context.Context, id string) (PushSubscription, error) {
	row := s.db.QueryRowContext(ctx, pushSelect+` WHERE id=?`, id)
	sub, err := scanPush(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PushSubscription{}, ErrNotFound
	}
	return sub, err
}

func (s *SQLite) UpdateCursorAndSuccess(ctx context.Context, id string, cursor int64, when time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE push_subscriptions
		    SET cursor=?,
		        last_attempt_at=?,
		        last_success_at=?,
		        last_error='',
		        consecutive_failures=0
		  WHERE id=?`,
		cursor, when.UTC().UnixNano(), when.UTC().UnixNano(), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RecordFailure(ctx context.Context, id string, when time.Time, errMsg string) error {
	if len(errMsg) > 1024 {
		errMsg = errMsg[:1024]
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE push_subscriptions
		    SET last_attempt_at=?,
		        last_error=?,
		        consecutive_failures = consecutive_failures + 1
		  WHERE id=?`,
		when.UTC().UnixNano(), errMsg, id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) PausePush(ctx context.Context, id string, when time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE push_subscriptions SET paused_at=? WHERE id=? AND paused_at IS NULL`,
		when.UTC().UnixNano(), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) ResumePush(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE push_subscriptions SET paused_at=NULL WHERE id=?`,
		id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RotatePushSecret(ctx context.Context, id, newHash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE push_subscriptions SET signing_secret_hash=? WHERE id=?`,
		newHash, id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeletePush(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM push_subscriptions WHERE id=?`,
		id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- helpers -----------------------------------------------------------------

const pushSelect = `SELECT id, source, target_url, signing_secret_hash, name, cursor,
       paused_at, created_at, last_attempt_at, last_success_at, last_error,
       consecutive_failures
  FROM push_subscriptions`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(r rowScanner) (Event, error) {
	var (
		ev          Event
		providerNs  int64
		receivedNs  int64
		headersJSON string
	)
	if err := r.Scan(
		&ev.Source, &ev.Sequence, &ev.DeliveryID,
		&providerNs, &receivedNs,
		&headersJSON, &ev.Body, &ev.BodySHA256,
	); err != nil {
		return Event{}, err
	}
	ev.ProviderTimestamp = time.Unix(0, providerNs).UTC()
	ev.ReceivedAt = time.Unix(0, receivedNs).UTC()
	if err := json.Unmarshal([]byte(headersJSON), &ev.Headers); err != nil {
		return Event{}, fmt.Errorf("decode headers: %w", err)
	}
	return ev, nil
}

func scanToken(r rowScanner) (Token, error) {
	var (
		t            Token
		scopesStr    string
		createdNs    int64
		lastUsedNs   sql.NullInt64
		revokedNs    sql.NullInt64
	)
	if err := r.Scan(&t.ID, &t.Name, &scopesStr, &t.SecretHash, &createdNs, &lastUsedNs, &revokedNs); err != nil {
		return Token{}, err
	}
	t.Scopes = splitScopes(scopesStr)
	t.CreatedAt = time.Unix(0, createdNs).UTC()
	if lastUsedNs.Valid {
		v := time.Unix(0, lastUsedNs.Int64).UTC()
		t.LastUsedAt = &v
	}
	if revokedNs.Valid {
		v := time.Unix(0, revokedNs.Int64).UTC()
		t.RevokedAt = &v
	}
	return t, nil
}

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func scanPush(r rowScanner) (PushSubscription, error) {
	var (
		sub          PushSubscription
		pausedNs     sql.NullInt64
		createdNs    int64
		lastAttemptNs sql.NullInt64
		lastSuccessNs sql.NullInt64
	)
	if err := r.Scan(
		&sub.ID, &sub.Source, &sub.TargetURL, &sub.SigningSecretHash,
		&sub.Name, &sub.Cursor,
		&pausedNs, &createdNs, &lastAttemptNs, &lastSuccessNs,
		&sub.LastError, &sub.ConsecutiveFailures,
	); err != nil {
		return PushSubscription{}, err
	}
	sub.CreatedAt = time.Unix(0, createdNs).UTC()
	if pausedNs.Valid {
		v := time.Unix(0, pausedNs.Int64).UTC()
		sub.PausedAt = &v
	}
	if lastAttemptNs.Valid {
		v := time.Unix(0, lastAttemptNs.Int64).UTC()
		sub.LastAttemptAt = &v
	}
	if lastSuccessNs.Valid {
		v := time.Unix(0, lastSuccessNs.Int64).UTC()
		sub.LastSuccessAt = &v
	}
	return sub, nil
}

func cloneHeaders(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// tokenHash is held on the SQLite struct via a method-set field declared
// inline below to avoid forward-declaration; placed here to satisfy methods
// above that reference s.tokenHash.

// (Compile-time assertion that SQLite implements all three interfaces lives
// in adapters.go to avoid clutter here.)
