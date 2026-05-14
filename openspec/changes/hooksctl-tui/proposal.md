## Why

`hooksctl forward` currently produces no real-time feedback — operators have no visibility into webhook delivery status, latency, or errors while forwarding is active. This adds a full-screen TUI (terminal user interface) to the `forward` subcommand, bringing ngrok-style live observability to webhook relay sessions.

## What Changes

- **New `internal/tui` package** — Bubble Tea model + update + view for the `forward` session dashboard.
- **`hooksctl forward` gains a TUI mode** — the command boots into the full-screen dashboard instead of logging to stdout when stdout is a TTY.
- **Ring-buffered delivery log** — up to 500 deliveries displayed with timestamp, method, path, source, status, latency, size, and optional suffix (retry N/M, error label).
- **Live session header** — shows session state (online/reconnecting/paused/offline), reconnect count, uptime, account email, forwarding route, and token fingerprint.
- **Keybind bar** — persistent footer: copy forwarding URL, pause/resume, help overlay, quit.
- **Quit** — `q`/`^C` cancels the SSE consumer and exits immediately.
- **Responsive layout** — columns drop right-to-left (suffix → size → latency) below 80 cols; identity block collapses to two lines below 24 rows.

## Capabilities

### New Capabilities

- `forward-tui`: Full-screen Bubble Tea dashboard for the `hooksctl forward` session — live delivery tail, session header, keybind bar, help overlay, clipboard integration, and resize handling.

### Modified Capabilities

_(none — the existing `forward` HTTP/SSE logic is unchanged; the TUI is wired on top)_

## Impact

- **New dependency**: `github.com/charmbracelet/bubbletea` (v2), `github.com/charmbracelet/bubbles`, `github.com/charmbracelet/lipgloss`, `github.com/atotto/clipboard`.
- **`cmd/hooksctl`** — `forward` command detects TTY and hands off to the TUI model.
- **`internal/tui`** — new package; no changes to existing packages.
- **No server-side changes** — the TUI consumes the existing SSE `/subscribe` stream.
