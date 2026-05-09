package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
)

// Crash-safety subprocess test (tasks.md §2.13). Verifies that a
// process killed mid-transaction leaves no half-applied state on
// disk. The test re-execs itself as a subprocess via os.Args[0]; the
// subprocess opens the DB, begins a transaction, inserts a user, and
// calls os.Exit(2) BEFORE committing — modeling a SIGKILL or panic
// between Insert and Commit. The parent then re-opens the same DB
// and asserts the user is NOT present (rollback semantics hold
// across process boundaries thanks to SQLite's WAL + atomic commit).
//
// We also assert that data committed by an earlier transaction
// survives the crash, so the test catches a regression where the
// wrapper accidentally drops committed work.
const crashTestEnv = "HOOKS_STORE_CRASHTEST_DB"

// TestCrashSafety_TxRollback is the parent-mode entry point. When
// the sentinel env var is set, control is handed to the subprocess
// body — that branch is what the parent re-execs.
func TestCrashSafety_TxRollback(t *testing.T) {
	if dsn := os.Getenv(crashTestEnv); dsn != "" {
		runCrashSubprocess(dsn)
		// runCrashSubprocess always exits; never returns.
		return
	}

	dir := t.TempDir()
	dsn := filepath.Join(dir, "crash.db")

	// Seed a "survivor" user via a fully-committed insert so we can
	// assert later that committed work is preserved across the crash.
	parent, err := OpenSQLite(dsn, SQLiteOptions{})
	if err != nil {
		t.Fatalf("open parent: %v", err)
	}
	survivor := User{
		ID: "survivor-1", Email: "survivor@example.com", Name: "S",
		Role: RoleUser, PasswordHash: "h", DefaultScopes: []string{},
		CreatedAt: time.Now().UTC(),
	}
	if err := parent.InsertUser(context.Background(), survivor); err != nil {
		t.Fatalf("seed survivor: %v", err)
	}
	if err := parent.Close(); err != nil {
		t.Fatalf("close parent: %v", err)
	}

	// Re-exec ourselves; the child runs runCrashSubprocess, opens
	// the DB, inserts the "ghost" user inside an open tx, and exits 2
	// without committing. We expect that exit code.
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashSafety_TxRollback$", "-test.v")
	cmd.Env = append(os.Environ(), crashTestEnv+"="+dsn)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("subprocess unexpectedly succeeded; output:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error type %T: %v\noutput:\n%s", err, err, out)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("subprocess exit = %d, want 2; output:\n%s", exitErr.ExitCode(), out)
	}

	// Re-open the same DB and verify state.
	resumed, err := OpenSQLite(dsn, SQLiteOptions{})
	if err != nil {
		t.Fatalf("reopen after crash: %v", err)
	}
	t.Cleanup(func() { _ = resumed.Close() })

	got, err := resumed.GetUserByID(context.Background(), survivor.ID)
	if err != nil {
		t.Fatalf("survivor lookup: %v\nsubprocess output:\n%s", err, out)
	}
	if got.Email != survivor.Email {
		t.Fatalf("survivor email = %q, want %q", got.Email, survivor.Email)
	}

	if _, err := resumed.GetUserByID(context.Background(), "ghost-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ghost user must not exist after mid-tx crash; got err=%v\nsubprocess output:\n%s", err, out)
	}
	if _, err := resumed.GetUserByEmail(context.Background(), "ghost@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ghost email must not exist after mid-tx crash; got err=%v", err)
	}

	// Sanity: DB is fully writable post-recovery.
	if err := resumed.InsertUser(context.Background(), User{
		ID: "post-crash-1", Email: "post@example.com", Name: "P",
		Role: RoleUser, PasswordHash: "h", DefaultScopes: []string{},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("post-crash insert: %v", err)
	}
}

// runCrashSubprocess is the body executed by the re-exec'd test
// binary. It must NOT use *testing.T — it runs before the test
// runner reports anything, and any failure is signaled via os.Exit
// codes that the parent inspects. Diagnostics go to stderr so the
// parent's CombinedOutput captures them.
func runCrashSubprocess(dsn string) {
	s, err := OpenSQLite(dsn, SQLiteOptions{})
	if err != nil {
		_, _ = os.Stderr.WriteString("subprocess open: " + err.Error() + "\n")
		os.Exit(10)
	}

	// Begin a tx, insert the ghost user, then exit WITHOUT committing.
	// We deliberately skip both tx.Rollback() and s.Close() to model
	// an abrupt termination where deferred cleanup never runs.
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		_, _ = os.Stderr.WriteString("subprocess begin tx: " + err.Error() + "\n")
		os.Exit(11)
	}
	q := s.q.WithTx(tx)
	if err := q.InsertUser(context.Background(), sqlcgen.InsertUserParams{
		ID:            "ghost-1",
		Email:         "ghost@example.com",
		Name:          "ghost",
		Role:          string(RoleUser),
		PasswordHash:  "h",
		DefaultScopes: "[]",
		CreatedAt:     time.Now().UTC().UnixNano(),
	}); err != nil {
		_, _ = os.Stderr.WriteString("subprocess insert: " + err.Error() + "\n")
		os.Exit(12)
	}

	// Defensive: confirm the row IS visible inside the open tx.
	// If this read fails, the test would not be exercising what it
	// claims (a row inside an uncommitted tx).
	row := tx.QueryRowContext(context.Background(),
		"SELECT 1 FROM users WHERE id = ?", "ghost-1")
	var n int
	if err := row.Scan(&n); err != nil || n != 1 {
		_, _ = os.Stderr.WriteString("subprocess intra-tx visibility check failed\n")
		os.Exit(13)
	}

	_, _ = os.Stderr.WriteString("subprocess crashing mid-tx (expected)\n")
	os.Exit(2)
}
