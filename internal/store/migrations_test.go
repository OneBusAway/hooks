package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// v1SchemaSQL is the schema as it shipped before add-developer-accounts.
// It is the regression baseline for the v1 → v2 upgrade path: this test
// applies it to a fresh DB then runs migrate() and asserts every column
// declared in schema.sql is present in the upgraded DB.
const v1SchemaSQL = `
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

// expectedColumns mirrors schema.sql; if a new column is added there, add it
// here so the regression test guards the upgrade path.
var expectedColumns = map[string][]string{
	"listener_tokens": {
		"id", "name", "scopes", "secret_hash", "created_at",
		"last_used_at", "revoked_at",
		"owner_user_id", "kind", "ephemeral", "expires_at",
	},
	"push_subscriptions": {
		"id", "source", "target_url", "signing_secret_hash", "name", "cursor",
		"paused_at", "created_at", "last_attempt_at", "last_success_at",
		"last_error", "consecutive_failures",
		"owner_user_id",
	},
}

func TestMigrate_V1ToV2(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v1.db")

	// Open a fresh DB and apply the v1 schema verbatim, simulating a deployed
	// instance pre-add-developer-accounts.
	db, err := sql.Open("sqlite", normalizeDSN(dbPath))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), v1SchemaSQL); err != nil {
		t.Fatalf("apply v1 schema: %v", err)
	}

	// Insert one row each into the pre-existing tables so we can assert the
	// upgrade leaves them unchanged.
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO listener_tokens(id,name,scopes,secret_hash,created_at) VALUES (?,?,?,?,?)`,
		"tok1", "operator", "admin", "hash1", int64(1),
	); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO push_subscriptions(id,source,target_url,signing_secret_hash,created_at)
		 VALUES (?,?,?,?,?)`,
		"sub1", "render", "http://localhost", "h", int64(1),
	); err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	_ = db.Close()

	// Now open via OpenSQLite, which applies schema.sql and the deltas.
	s, err := OpenSQLite(dbPath, SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer func() { _ = s.Close() }()

	for table, cols := range expectedColumns {
		actual, err := tableColumns(context.Background(), s.db, table)
		if err != nil {
			t.Fatalf("inspect %s: %v", table, err)
		}
		for _, c := range cols {
			if _, ok := actual[c]; !ok {
				t.Errorf("table %q missing column %q after migrate (have %v)", table, c, actual)
			}
		}
	}

	// Existing rows preserved verbatim.
	var (
		name, scopes, hash string
		createdAt          int64
	)
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT name, scopes, secret_hash, created_at FROM listener_tokens WHERE id=?`,
		"tok1",
	).Scan(&name, &scopes, &hash, &createdAt); err != nil {
		t.Fatalf("preserved-row scan: %v", err)
	}
	if name != "operator" || scopes != "admin" || hash != "hash1" || createdAt != 1 {
		t.Errorf("listener_tokens row was mutated by migration: %v %v %v %v", name, scopes, hash, createdAt)
	}

	// New columns default-backfilled correctly.
	var kind string
	var eph int64
	var owner sql.NullString
	var expires sql.NullInt64
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT kind, ephemeral, owner_user_id, expires_at FROM listener_tokens WHERE id=?`,
		"tok1",
	).Scan(&kind, &eph, &owner, &expires); err != nil {
		t.Fatalf("new-col scan: %v", err)
	}
	if kind != "listener" {
		t.Errorf("kind backfill: got %q, want %q", kind, "listener")
	}
	if eph != 0 {
		t.Errorf("ephemeral backfill: got %d, want 0", eph)
	}
	if owner.Valid {
		t.Errorf("owner_user_id should be NULL on backfill, got %q", owner.String)
	}
	if expires.Valid {
		t.Errorf("expires_at should be NULL on backfill, got %d", expires.Int64)
	}

	// All new tables exist (a missing CREATE TABLE in schema.sql would surface
	// as a syntax error here).
	for _, tbl := range []string{"users", "user_sessions", "invites", "device_pairings", "audit_events"} {
		var n int
		if err := s.db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&n); err != nil {
			t.Fatalf("check %s: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("expected table %s to exist, sqlite_master count=%d", tbl, n)
		}
	}

	// Re-running OpenSQLite (i.e. another boot) is idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := OpenSQLite(dbPath, SQLiteOptions{})
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	_ = s2.Close()
}
