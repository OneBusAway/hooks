## Context

`hooksctl forward` runs an SSE loop against `/subscribe/<source>`, deserializes events, and pushes them to a local HTTP target. Today the command emits structured log lines to stdout. Operators have no live view of delivery success/failure, latency, or retry state.

The design spec (`hooksctl-tui-spec.html`) defines a single full-screen status-dashboard TUI: identity header, scrollable delivery tail, persistent keybind bar. Framework mandated: Bubble Tea + Bubbles + Lip Gloss. Minimum terminal: 80×24.

Constraints:
- No server-side changes. The TUI is a presentation layer over the existing SSE stream.
- golangci-lint + `go test -race` must stay green.
- The new `internal/tui` package must not import any existing `internal/*` package that itself imports the store or token machinery (keep the dependency graph clean).

## Goals / Non-Goals

**Goals:**
- Live, full-screen TUI for `hooksctl forward` when stdout is a TTY.
- Ring-buffered delivery log (cap 500) with per-row: timestamp, method, path, source, status, latency, size, suffix.
- Session header: online/reconnecting/paused/offline pill, reconnect count, uptime ticker, account email, forwarding route, token fingerprint.
- Responsive layout: column dropping below 80 cols; identity collapse below 24 rows.
- Keybinds: copy URL (`c`), open web UI (`w`), replay last (`r`), pause/resume (`p`), help overlay (`?`), graceful quit (`q`/`^C`).
- Graceful quit: first press drains in-flight; second force-quits.

**Non-Goals:**
- Per-delivery detail pane (body, headers, JSON view) — out of scope for v1.
- Filtering beyond pause.
- Multi-route sessions.
- Persistent scrollback across restarts.
- Non-TTY fallback changes (existing log output stays as-is).

## Decisions

### 1. New `internal/tui` package, not inlined in `cmd/hooksctl`

Keeps the model/update/view testable without pulling in CLI flag parsing. The `cmd/hooksctl/forward.go` command detects `term.IsTerminal(os.Stdout.Fd())` and hands a channel of `tui.DeliveryEvent` to `tui.New(...)`, then runs `tea.NewProgram(model, tea.WithAltScreen())`.

Alternatives considered: inlining in `cmd/hooksctl` (harder to unit-test), making it a sub-package of `cmd` (circular with shared types).

### 2. Bubble Tea message types bridge the SSE goroutine

The existing SSE consumer goroutine sends `tui.DeliveryReceivedMsg` and `tui.DeliveryCompletedMsg` via `tea.Program.Send(msg)`. This keeps the SSE loop outside the Bubble Tea event loop and avoids blocking the update cycle on network I/O.

Alternatives considered: running SSE inside a `tea.Cmd` — awkward because SSE is a long-lived connection, not a one-shot command.

### 3. Ring buffer in the model, `tea/viewport` for scrolling

`deliveries []Delivery` is capped at 500 via modular append. `viewport.Model` from `github.com/charmbracelet/bubbles` owns scroll position and is fed a pre-rendered string on every update. Sticky-to-bottom flag (`atBottom bool`) is set to false on any manual scroll key and restored on `G`/end.

Alternatives considered: rendering directly from a slice without viewport (manual scroll math, more error-prone).

### 4. Lip Gloss styles defined at package init, not per-render

`var styles = newStyles()` is called once at startup using `lipgloss.HasDarkBackground`. On `tea.BackgroundColorMsg` the styles are rebuilt. This avoids re-allocating `lipgloss.Style` objects on every frame.

Alternatives considered: passing renderer to each function (Lip Gloss v2 encourages this but Lip Gloss v1 is simpler and already in the ecosystem; pin v1 for now).

### 5. `github.com/atotto/clipboard` for copy-URL

Cross-platform clipboard access. Wrapped in a `tea.Cmd` so it doesn't block the update loop. On success fires `clipboardCopiedMsg` which shows a 1.5 s toast.

### 6. TTY detection gates TUI entry

`cmd/hooksctl/forward.go` checks `golang.org/x/term`.`IsTerminal(int(os.Stdout.Fd()))`. If false, falls back to existing structured-log output unchanged. This means CI/pipe usage is unaffected.

## Risks / Trade-offs

- **Terminal color support variance** → Mitigation: use `lipgloss.AdaptiveColor` with both light and dark hex values; Lip Gloss negotiates the color profile automatically.
- **Clipboard unavailable in some environments (headless, WSL without clip.exe)** → Mitigation: wrap clipboard write in error check; on failure, show toast "copy failed — no clipboard" instead of crashing.
- **Viewport height calculation off-by-one on resize** → Mitigation: derive height formula once in a named function `viewportHeight(termH int) int` and test it independently.
- **SSE reconnect during TUI session** → The existing SSE consumer already reconnects; it fires `sessionStateMsg{State: Reconnecting}` so the header pill updates. Deliveries during reconnect gap are missed (same as current behavior).
- **`tea.WithAltScreen()` leaves alternate screen on panic** → Mitigation: `defer p.RestoreTerminal()` in the command handler; same pattern used by k9s, lazygit.

## Migration Plan

1. Add dependencies to `go.mod` / `go.sum` (`go get`).
2. Implement `internal/tui` package (model, styles, messages).
3. Wire `cmd/hooksctl/forward.go` to detect TTY and launch TUI.
4. Manual smoke test: `make dev` + `hooksctl forward render` in a real terminal.
5. `make lint && make test` must pass before merge.

Rollback: revert the TTY-detection branch in `forward.go`; the rest of the code is additive.

## Open Questions

- **Should `hooksctl tail` also get TUI treatment?** Tail is read-only and simpler — leave for v2.
- **Lip Gloss v1 vs v2?** v2 is in beta; stick with stable v1 (`v0.x`) for now and migrate after GA.
