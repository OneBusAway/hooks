package store

import (
	"context"
	"database/sql"
	"fmt"
)

// applyMigrations runs idempotent ALTER deltas needed to bring an existing
// v1 database forward to the current schema. Every CREATE in schema.sql is
// idempotent (`IF NOT EXISTS`), so a fresh DB sees these probe-and-ALTER
// statements as no-ops; an existing v1 DB sees them add the new columns to
// listener_tokens and push_subscriptions. SQLite has no
// `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, so we probe the table_info
// pragma per table and only issue the ALTER when a column is missing.
func applyMigrations(ctx context.Context, db *sql.DB) error {
	for _, t := range tableMigrations {
		exists, err := tableExists(ctx, db, t.table)
		if err != nil {
			return fmt.Errorf("check %s exists: %w", t.table, err)
		}
		if !exists {
			// Fresh DB — schema.sql will CREATE the table with the
			// post-migration column set; nothing to ALTER.
			continue
		}
		existing, err := tableColumns(ctx, db, t.table)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", t.table, err)
		}
		for _, c := range t.columns {
			if _, ok := existing[c.name]; ok {
				continue
			}
			stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", t.table, c.name, c.def)
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("alter %s add %s: %w", t.table, c.name, err)
			}
		}
	}
	return nil
}

func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

type columnDelta struct {
	name string
	// def is the SQL fragment that follows the column name in ADD COLUMN.
	// It MUST match the canonical declaration in schema.sql so re-running
	// either path converges. Defaults are required so existing rows are
	// backfilled with valid values; the CHECK constraint on `kind`, for
	// example, fires only on NULL inserts, and the DEFAULT 'listener'
	// keeps existing rows valid.
	def string
}

type tableDelta struct {
	table   string
	columns []columnDelta
}

var tableMigrations = []tableDelta{
	{
		table: "listener_tokens",
		columns: []columnDelta{
			{name: "owner_user_id", def: "TEXT REFERENCES users(id)"},
			{name: "kind", def: "TEXT NOT NULL DEFAULT 'listener' CHECK (kind IN ('pat','listener'))"},
			{name: "ephemeral", def: "INTEGER NOT NULL DEFAULT 0"},
			{name: "expires_at", def: "INTEGER"},
		},
	},
	{
		table: "push_subscriptions",
		columns: []columnDelta{
			{name: "owner_user_id", def: "TEXT REFERENCES users(id)"},
		},
	},
}

func tableColumns(ctx context.Context, db *sql.DB, table string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = struct{}{}
	}
	return out, rows.Err()
}
