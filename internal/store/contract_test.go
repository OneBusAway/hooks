package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// EventStoreContract is the suite every EventStore implementation must pass.
// Tests in this package run it against the SQLite backend.
func EventStoreContract(t *testing.T, makeStore func(t *testing.T) EventStore) {
	t.Helper()
	t.Run("GaplessSequencesPerSource", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		for i := 0; i < 5; i++ {
			ev, err := s.Append(ctx, AppendInput{
				Source:            "render",
				DeliveryID:        idFor(i),
				ProviderTimestamp: time.Now(),
				Headers:           map[string]string{"X-Test": "1"},
				Body:              []byte("payload"),
			})
			if err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
			if ev.Sequence != int64(i+1) {
				t.Fatalf("append %d: seq=%d, want %d", i, ev.Sequence, i+1)
			}
		}
	})

	t.Run("SequencesIndependentAcrossSources", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		a, _ := s.Append(ctx, sampleInput("render", "a"))
		b, _ := s.Append(ctx, sampleInput("stripe", "b"))
		if a.Sequence != 1 || b.Sequence != 1 {
			t.Fatalf("got %d, %d; want 1, 1", a.Sequence, b.Sequence)
		}
	})

	t.Run("DuplicateReturnsSentinel", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		in := sampleInput("render", "dup")
		if _, err := s.Append(ctx, in); err != nil {
			t.Fatal(err)
		}
		_, err := s.Append(ctx, in)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("want ErrDuplicate, got %v", err)
		}
		latest, _ := s.LatestSequence(ctx, "render")
		if latest != 1 {
			t.Fatalf("dup should not advance sequence; got %d", latest)
		}
	})

	t.Run("DistinctDeliveryIDsBothStored", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		_, err := s.Append(ctx, sampleInput("render", "x"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Append(ctx, sampleInput("render", "y"))
		if err != nil {
			t.Fatal(err)
		}
		latest, _ := s.LatestSequence(ctx, "render")
		if latest != 2 {
			t.Fatalf("latest = %d, want 2", latest)
		}
	})

	t.Run("ReadSinceCursor", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		for i := 0; i < 5; i++ {
			if _, err := s.Append(ctx, sampleInput("render", idFor(i))); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.ReadSince(ctx, "render", 2, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("len = %d, want 3", len(got))
		}
		for i, ev := range got {
			if ev.Sequence != int64(i+3) {
				t.Fatalf("got seq %d at idx %d, want %d", ev.Sequence, i, i+3)
			}
		}
	})

	t.Run("ReadFromLatestEmpty", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			_, _ = s.Append(ctx, sampleInput("render", idFor(i)))
		}
		latest, _ := s.LatestSequence(ctx, "render")
		got, err := s.ReadSince(ctx, "render", latest, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("len = %d, want 0", len(got))
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		ev, _ := s.Append(ctx, AppendInput{
			Source: "render", DeliveryID: "abc",
			ProviderTimestamp: time.Now(),
			Headers:           map[string]string{"H": "v"},
			Body:              []byte("hello"),
		})
		got, err := s.Get(ctx, "render", ev.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Body) != "hello" || got.Headers["H"] != "v" {
			t.Fatalf("Get round-trip failed: %+v", got)
		}
	})

	t.Run("PrunePerSource", func(t *testing.T) {
		s := makeStore(t)
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			_, _ = s.Append(ctx, sampleInput("render", idFor(i)))
		}
		// Future cutoff prunes everything.
		n, err := s.Prune(ctx, "render", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if n != 3 {
			t.Fatalf("pruned %d, want 3", n)
		}
	})
}

func sampleInput(source, deliveryID string) AppendInput {
	return AppendInput{
		Source:            source,
		DeliveryID:        deliveryID,
		ProviderTimestamp: time.Now(),
		Headers:           map[string]string{"X-Test": "1"},
		Body:              []byte("payload"),
	}
}

func idFor(i int) string { return "delivery-" + string(rune('a'+i)) }

func TestSQLite_EventStoreContract(t *testing.T) {
	EventStoreContract(t, func(t *testing.T) EventStore {
		dir := t.TempDir()
		s, err := OpenSQLite(filepath.Join(dir, "x.db"), SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func TestSQLite_DurabilityAcrossClose(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "x.db")
	s1, err := OpenSQLite(dbPath, SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := s1.Append(context.Background(), sampleInput("render", "abc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenSQLite(dbPath, SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()

	got, err := s2.Get(context.Background(), "render", ev.Sequence)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if string(got.Body) != "payload" {
		t.Fatalf("body lost across close: %q", got.Body)
	}
	// Sequences continue.
	ev2, err := s2.Append(context.Background(), sampleInput("render", "xyz"))
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Sequence != 2 {
		t.Fatalf("after reopen, next seq = %d, want 2", ev2.Sequence)
	}
}

func TestSQLite_PushAdapterRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSQLite(filepath.Join(dir, "x.db"), SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ps := s.PushSubscriptions()
	ctx := context.Background()
	now := time.Now().UTC()
	sub := PushSubscription{
		ID:                "sub1",
		Source:            "render",
		TargetURL:         "http://example.test/hook",
		SigningSecretHash: "argon2id$fake",
		Name:              "staging",
		Cursor:            5,
		CreatedAt:         now,
	}
	if err := ps.Insert(ctx, sub); err != nil {
		t.Fatal(err)
	}
	got, err := ps.Get(ctx, "sub1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cursor != 5 || got.Source != "render" {
		t.Fatalf("got %+v", got)
	}
	// Pause excludes from default list.
	if err := ps.Pause(ctx, "sub1", time.Now()); err != nil {
		t.Fatal(err)
	}
	active, _ := ps.List(ctx, false)
	if len(active) != 0 {
		t.Fatalf("paused sub leaked into active list")
	}
	all, _ := ps.List(ctx, true)
	if len(all) != 1 {
		t.Fatalf("includePaused=true missed sub")
	}
	if err := ps.Resume(ctx, "sub1"); err != nil {
		t.Fatal(err)
	}

	// Cursor advances on success.
	if err := ps.UpdateCursorAndSuccess(ctx, "sub1", 10, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ = ps.Get(ctx, "sub1")
	if got.Cursor != 10 || got.LastSuccessAt == nil || got.ConsecutiveFailures != 0 {
		t.Fatalf("update failed: %+v", got)
	}
	// Failure increments without advancing cursor.
	if err := ps.RecordFailure(ctx, "sub1", time.Now(), "boom"); err != nil {
		t.Fatal(err)
	}
	got, _ = ps.Get(ctx, "sub1")
	if got.Cursor != 10 || got.ConsecutiveFailures != 1 || got.LastError != "boom" {
		t.Fatalf("failure record wrong: %+v", got)
	}
	// Rotate secret invalidates old hash.
	if err := ps.RotateSecret(ctx, "sub1", "argon2id$new"); err != nil {
		t.Fatal(err)
	}
	got, _ = ps.Get(ctx, "sub1")
	if got.SigningSecretHash != "argon2id$new" {
		t.Fatalf("rotate didn't update hash: %q", got.SigningSecretHash)
	}
	if err := ps.Delete(ctx, "sub1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.Get(ctx, "sub1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
}
