// Package prune runs the periodic auto-prune goroutine that deletes events
// older than the configured per-source retention.
package prune

import (
	"context"
	"log/slog"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// Defaults documented in design.md.
const DefaultInterval = time.Hour

// Pruner is one process-wide goroutine that periodically removes expired
// events per source.
type Pruner struct {
	Store      store.EventStore
	Now        func() time.Time
	Interval   time.Duration
	Retentions map[string]time.Duration // source -> retention; 0 means "no auto-prune"
	Logger     *slog.Logger
}

// New constructs a Pruner.
func New(st store.EventStore, retentions map[string]time.Duration, logger *slog.Logger) *Pruner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pruner{
		Store:      st,
		Now:        time.Now,
		Interval:   DefaultInterval,
		Retentions: retentions,
		Logger:     logger,
	}
}

// Run blocks until ctx is cancelled, ticking on Interval and pruning on each
// tick.
func (p *Pruner) Run(ctx context.Context) {
	if p.Interval <= 0 {
		p.Interval = DefaultInterval
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	// Initial pass on startup so we don't wait an hour to converge.
	p.RunOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.RunOnce(ctx)
		}
	}
}

// RunOnce executes a single per-source prune pass.
func (p *Pruner) RunOnce(ctx context.Context) {
	for source, retention := range p.Retentions {
		if retention <= 0 {
			continue
		}
		cutoff := p.Now().UTC().Add(-retention)
		n, err := p.Store.Prune(ctx, source, cutoff)
		if err != nil {
			p.Logger.Error("prune: source pass failed",
				slog.String("source", source),
				slog.String("error", err.Error()),
			)
			continue
		}
		if n > 0 {
			p.Logger.Info("prune: deleted events",
				slog.String("source", source),
				slog.Int64("rows", n),
				slog.Duration("retention", retention),
			)
		}
	}
}

// PruneOlderThan is the helper used by the manual `hooks prune` CLI subcommand.
// It is independent of the configured per-source retention.
func PruneOlderThan(ctx context.Context, st store.EventStore, older time.Duration, now func() time.Time, logger *slog.Logger) (int64, error) {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	cutoff := now().UTC().Add(-older)
	n, err := st.PruneAll(ctx, cutoff)
	if err == nil && n > 0 {
		logger.Info("prune: manual delete", slog.Int64("rows", n), slog.Duration("older_than", older))
	}
	return n, err
}
