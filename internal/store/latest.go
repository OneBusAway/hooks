package store

import "context"

// LatestByCursor wraps an EventStore-like reader and memoizes LatestSequence
// per source for the lifetime of a single request, so a list view rendering
// many subscriptions across a few sources doesn't re-issue MAX(sequence)
// queries per row.
//
// Not safe for concurrent use; instantiate one per request.
type LatestByCursor struct {
	events interface {
		LatestSequence(ctx context.Context, source string) (int64, error)
	}
	seen   map[string]int64
	firstErr error
}

// NewLatestByCursor returns a fresh memoizer.
func NewLatestByCursor(events interface {
	LatestSequence(ctx context.Context, source string) (int64, error)
}) *LatestByCursor {
	return &LatestByCursor{events: events, seen: map[string]int64{}}
}

// Get returns the cached or freshly-fetched latest sequence for source.
// Errors from the underlying store are stored and accessible via Err(); the
// returned int64 is 0 in that case so callers may render best-effort views
// while still being able to fail loudly afterwards.
func (c *LatestByCursor) Get(ctx context.Context, source string) int64 {
	if v, ok := c.seen[source]; ok {
		return v
	}
	v, err := c.events.LatestSequence(ctx, source)
	if err != nil && c.firstErr == nil {
		c.firstErr = err
	}
	c.seen[source] = v
	return v
}

// Err returns the first error encountered by Get, or nil. Callers that want
// to fail a request on a DB error should check this after rendering.
func (c *LatestByCursor) Err() error { return c.firstErr }

// QueueDepth computes max(0, latest-cursor) for a subscription. Helper used
// by both push API list views and the inspector.
func QueueDepth(latest, cursor int64) int64 {
	if latest <= cursor {
		return 0
	}
	return latest - cursor
}
