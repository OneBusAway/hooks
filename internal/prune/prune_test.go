package prune

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

func newStore(t *testing.T) *store.SQLite {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func appendAt(t *testing.T, st *store.SQLite, source, deliveryID string) {
	t.Helper()
	_, err := st.Append(context.Background(), store.AppendInput{
		Source:            source,
		DeliveryID:        deliveryID,
		ProviderTimestamp: time.Now(),
		Body:              []byte("body"),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunOnce_DefaultRetention(t *testing.T) {
	st := newStore(t)
	appendAt(t, st, "render", "old")

	// Move "now" 31 days into the future so the existing event becomes "old".
	future := time.Now().Add(31 * 24 * time.Hour)
	p := New(st, map[string]time.Duration{"render": 30 * 24 * time.Hour}, slog.New(slog.DiscardHandler))
	p.Now = func() time.Time { return future }
	p.RunOnce(context.Background())

	latest, _ := st.LatestSequence(context.Background(), "render")
	if latest != 0 {
		t.Fatalf("event not pruned (latest=%d)", latest)
	}
}

func TestRunOnce_ForeverKeepsAll(t *testing.T) {
	st := newStore(t)
	appendAt(t, st, "render", "old")
	future := time.Now().Add(365 * 24 * time.Hour)
	p := New(st, map[string]time.Duration{"render": 0}, slog.New(slog.DiscardHandler))
	p.Now = func() time.Time { return future }
	p.RunOnce(context.Background())

	latest, _ := st.LatestSequence(context.Background(), "render")
	if latest != 1 {
		t.Fatalf("forever should keep events (latest=%d)", latest)
	}
}

func TestRunOnce_PerSourceIndependent(t *testing.T) {
	st := newStore(t)
	appendAt(t, st, "render", "r-old")
	appendAt(t, st, "stripe", "s-old")
	future := time.Now().Add(8 * 24 * time.Hour)
	p := New(st, map[string]time.Duration{
		"render": 30 * 24 * time.Hour,
		"stripe": 7 * 24 * time.Hour,
	}, slog.New(slog.DiscardHandler))
	p.Now = func() time.Time { return future }
	p.RunOnce(context.Background())

	r, _ := st.LatestSequence(context.Background(), "render")
	if r != 1 {
		t.Fatalf("render pruned despite 30d retention")
	}
	s, _ := st.LatestSequence(context.Background(), "stripe")
	if s != 0 {
		t.Fatalf("stripe not pruned at 7d retention (latest=%d)", s)
	}
}

func TestPruneOlderThan(t *testing.T) {
	st := newStore(t)
	appendAt(t, st, "render", "r")
	appendAt(t, st, "stripe", "s")
	future := time.Now().Add(time.Hour)
	n, err := PruneOlderThan(context.Background(), st, 30*time.Minute, func() time.Time { return future }, slog.New(slog.DiscardHandler))
	if err != nil || n != 2 {
		t.Fatalf("got n=%d err=%v", n, err)
	}
}

// TestRunOnce_EphemeralTokenIdleSweep covers tasks.md §12.7. The
// pruner is configured with the SQLite store as its TokenStore. An
// ephemeral token whose last_used_at was over 24h ago is revoked; an
// ephemeral token that was used recently survives; a non-ephemeral
// token is never touched.
func TestRunOnce_EphemeralTokenIdleSweep(t *testing.T) {
	st := newStore(t)

	now := time.Now().UTC()

	mustInsert := func(t *testing.T, tok store.Token) {
		t.Helper()
		if err := st.Insert(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	}

	// Idle ephemeral — created 48h ago, last used 30h ago. Should be
	// revoked.
	idleLast := now.Add(-30 * time.Hour)
	mustInsert(t, store.Token{
		ID: "idle-ephemeral", Name: "idle", Scopes: []string{"render"},
		SecretHash: "x", CreatedAt: now.Add(-48 * time.Hour),
		LastUsedAt: &idleLast,
		Kind:       store.TokenKindListener, Ephemeral: true,
	})

	// Fresh ephemeral — used within the last hour. Should survive.
	freshLast := now.Add(-time.Hour)
	mustInsert(t, store.Token{
		ID: "fresh-ephemeral", Name: "fresh", Scopes: []string{"render"},
		SecretHash: "x", CreatedAt: now.Add(-2 * time.Hour),
		LastUsedAt: &freshLast,
		Kind:       store.TokenKindListener, Ephemeral: true,
	})

	// Never-used ephemeral, created 25h ago. Should be revoked
	// (last_used_at IS NULL, created_at < cutoff).
	mustInsert(t, store.Token{
		ID: "never-used-old-ephemeral", Name: "old", Scopes: []string{"render"},
		SecretHash: "x", CreatedAt: now.Add(-25 * time.Hour),
		Kind: store.TokenKindListener, Ephemeral: true,
	})

	// Non-ephemeral, idle for ages. Must NOT be revoked.
	mustInsert(t, store.Token{
		ID: "long-lived", Name: "long", Scopes: []string{"render"},
		SecretHash: "x", CreatedAt: now.Add(-90 * 24 * time.Hour),
		LastUsedAt: &idleLast,
		Kind:       store.TokenKindListener, Ephemeral: false,
	})

	p := New(st, map[string]time.Duration{}, slog.New(slog.DiscardHandler))
	p.Tokens = st
	p.Now = func() time.Time { return now }
	p.RunOnce(context.Background())

	// Inspect each row. We pull all (incl revoked) by leaning on the
	// admin-shape ListSystemTokens — these tokens have nil owner.
	check := func(t *testing.T, id string, wantRevoked bool) {
		t.Helper()
		tok, err := st.GetToken(context.Background(), id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		got := tok.RevokedAt != nil
		if got != wantRevoked {
			t.Errorf("token %s revoked=%v want %v", id, got, wantRevoked)
		}
	}
	check(t, "idle-ephemeral", true)
	check(t, "fresh-ephemeral", false)
	check(t, "never-used-old-ephemeral", true)
	check(t, "long-lived", false)
}

func TestRunBlocksUntilCancel(t *testing.T) {
	st := newStore(t)
	p := New(st, map[string]time.Duration{}, slog.New(slog.DiscardHandler))
	p.Interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
