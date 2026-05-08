package store

import (
	"context"
	"errors"
	"testing"
)

type stubLatest struct {
	calls map[string]int
	err   error
	value int64
}

func (s *stubLatest) LatestSequence(ctx context.Context, source string) (int64, error) {
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[source]++
	return s.value, s.err
}

func TestLatestByCursorMemoizes(t *testing.T) {
	s := &stubLatest{value: 42}
	c := NewLatestByCursor(s)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if got := c.Get(ctx, "render"); got != 42 {
			t.Fatalf("call %d: got %d", i, got)
		}
	}
	if got := c.Get(ctx, "stripe"); got != 42 {
		t.Fatalf("stripe: got %d", got)
	}

	if s.calls["render"] != 1 {
		t.Fatalf("render fetched %d times, want 1", s.calls["render"])
	}
	if s.calls["stripe"] != 1 {
		t.Fatalf("stripe fetched %d times, want 1", s.calls["stripe"])
	}
	if c.Err() != nil {
		t.Fatalf("Err = %v, want nil", c.Err())
	}
}

func TestLatestByCursorErrPropagates(t *testing.T) {
	want := errors.New("db down")
	s := &stubLatest{err: want}
	c := NewLatestByCursor(s)

	if got := c.Get(context.Background(), "render"); got != 0 {
		t.Fatalf("got %d, want 0 on error", got)
	}
	if !errors.Is(c.Err(), want) {
		t.Fatalf("Err = %v, want %v", c.Err(), want)
	}
}

func TestQueueDepth(t *testing.T) {
	cases := []struct {
		latest, cursor, want int64
	}{
		{0, 0, 0},
		{10, 0, 10},
		{10, 5, 5},
		{10, 10, 0},
		{5, 10, 0}, // cursor ahead of latest (replay/test scenarios) clamps to 0
	}
	for _, c := range cases {
		if got := QueueDepth(c.latest, c.cursor); got != c.want {
			t.Errorf("QueueDepth(%d,%d) = %d, want %d", c.latest, c.cursor, got, c.want)
		}
	}
}
