package auth

import (
	"context"
	"log/slog"
	"time"
)

// SweeperInterval is how often the background goroutine reaps expired
// user_sessions rows.
const SweeperInterval = 15 * time.Minute

// RunSweeper blocks until ctx is cancelled, periodically calling
// SessionStore.DeleteExpired. Errors are logged and the sweeper continues;
// this is best-effort cleanup.
func (m *Manager) RunSweeper(ctx context.Context, logger *slog.Logger) {
	t := time.NewTicker(SweeperInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := m.Sessions.DeleteExpired(ctx, m.Now().UTC())
			if err != nil {
				if logger != nil {
					logger.WarnContext(ctx, "session sweeper error", slog.Any("err", err))
				}
				continue
			}
			if n > 0 && logger != nil {
				logger.DebugContext(ctx, "session sweeper reaped", slog.Int64("rows", n))
			}
		}
	}
}
