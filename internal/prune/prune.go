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

// EphemeralTokenIdle is the inactivity window after which an
// ephemeral=true listener token is auto-revoked. Documented in
// `docs/security.md` as the 24h window described by add-developer-
// accounts §12.7.
const EphemeralTokenIdle = 24 * time.Hour

// EphemeralTokenExpirer is the slice of TokenStore the pruner needs.
// Implemented by *store.SQLite. Modeled as a tiny interface so the
// prune package does not depend on the full TokenStore surface.
type EphemeralTokenExpirer interface {
	ExpireEphemeralTokensIdle(ctx context.Context, when time.Time, idleCutoff time.Time) (int64, error)
}

// Pruner is one process-wide goroutine that periodically removes expired
// events per source.
type Pruner struct {
	Store      store.EventStore
	Tokens     EphemeralTokenExpirer
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

// RunOnce executes a single per-source prune pass plus the ephemeral
// token sweep when a token expirer was wired in.
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
	if p.Tokens != nil {
		now := p.Now().UTC()
		idleCutoff := now.Add(-EphemeralTokenIdle)
		n, err := p.Tokens.ExpireEphemeralTokensIdle(ctx, now, idleCutoff)
		if err != nil {
			p.Logger.Error("prune: ephemeral token sweep failed",
				slog.String("error", err.Error()),
			)
		} else if n > 0 {
			p.Logger.Info("prune: revoked ephemeral tokens",
				slog.Int64("rows", n),
				slog.Duration("idle", EphemeralTokenIdle),
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
