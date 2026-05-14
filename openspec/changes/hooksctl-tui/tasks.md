## 1. Dependencies & Module Setup

- [x] 1.1 Add `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/bubbles`, `github.com/charmbracelet/lipgloss`, and `github.com/atotto/clipboard` to `go.mod` via `go get`
- [x] 1.2 Run `make tidy` and commit updated `go.mod` / `go.sum`
- [x] 1.3 Create `internal/tui/` package directory with a stub `doc.go`

## 2. Message Types & Domain Types

- [x] 2.1 Define `SessionState` type (online / reconnecting / paused / offline) and `SessionInfo` struct (state, reconnect count, uptime start, account email, forwarding route, token prefix/suffix, scopes)
- [x] 2.2 Define `Delivery` struct (id, recv_at, method, path, source, status, duration_ms, size_bytes, suffix, in_flight bool)
- [x] 2.3 Define Bubble Tea message types: `DeliveryReceivedMsg`, `DeliveryCompletedMsg`, `SessionStateMsg`, `tickMsg`, `clipboardCopiedMsg`

## 3. Lip Gloss Style Definitions

- [x] 3.1 Define color token constants matching the spec (`termGreen`, `termAmber`, `termRed`, `termBlue`, `termMagenta`, `termCyan`, `termFg`, `termDim`) using `lipgloss.Color` with `AdaptiveColor` light/dark pairs
- [x] 3.2 Define named styles: `styleTitle`, `styleDim`, `styleStatusOnline`, `styleStatusReconnecting`, `styleStatusPaused`, `styleForwardURL`, `styleTargetURL`, `styleTokenHighlight`, `styleDivider`, `styleKeybind`, `styleToast`
- [x] 3.3 Define status-code color function `statusStyle(code int) lipgloss.Style`

## 4. Core Model

- [x] 4.1 Define `Model` struct with fields: `session SessionInfo`, `deliveries []Delivery` (ring buffer), `viewport viewport.Model`, `help help.Model`, `showHelp bool`, `atBottom bool`, `toastMsg string`, `toastExpiry time.Time`, `termW int`, `termH int`, `keys keyMap`
- [x] 4.2 Implement `New(session SessionInfo) Model` constructor that initialises the viewport and help model
- [x] 4.3 Implement `Init() tea.Cmd` — returns `tea.Batch(tickCmd(), tea.RequestBackgroundColor)`
- [x] 4.4 Implement ring-buffer append helper `appendDelivery(m *Model, d Delivery)` that evicts oldest when len >= 500

## 5. Key Bindings

- [x] 5.1 Define `keyMap` struct with `key.Binding` fields: `copyURL`, `pause`, `help`, `quit`
- [x] 5.2 Implement `ShortHelp()` and `FullHelp()` on `keyMap` for the bubbles `help.Model`
- [x] 5.3 Wire key bindings in `Update()` — `c`, `p`, `?`, `q`, `ctrl+c`

## 6. Update Logic

- [x] 6.1 Handle `tea.WindowSizeMsg` — recompute `termW`, `termH`, viewport height via `viewportHeight()`, re-render content
- [x] 6.2 Handle `tea.BackgroundColorMsg` — rebuild Lip Gloss styles for light/dark
- [x] 6.3 Handle `DeliveryReceivedMsg` — append to ring buffer, scroll to bottom if `atBottom`, rebuild viewport content
- [x] 6.4 Handle `DeliveryCompletedMsg` — find matching in-flight row by ID, update status/latency/suffix, rebuild viewport content
- [x] 6.5 Handle `SessionStateMsg` — update `m.session`, re-render header
- [x] 6.6 Handle `tickMsg` — refresh uptime display, expire toast if past `toastExpiry`, return next tick command
- [x] 6.7 Handle `clipboardCopiedMsg` — set `toastMsg` and `toastExpiry = time.Now().Add(1.5s)`
- [x] 6.8 Implement quit: `q`/`^C` cancels the SSE consumer context and calls `tea.Quit` immediately
- [x] 6.9 Implement visual-only pause/resume: toggle `m.session.State` between paused and online; no back-channel to the SSE goroutine

## 7. View / Rendering

- [x] 7.1 Implement `renderTitle(m Model) string` — `hooksctl <version>` left cyan-bold, right-aligned dim help hint
- [x] 7.2 Implement `renderIdentity(m Model) string` — 4-row key/value block (session pill, account, forwarding route, token); collapse to 2 rows when `termH < 24`
- [x] 7.3 Implement `renderDivider(w int) string` — `strings.Repeat("─", w)` in dim style
- [x] 7.4 Implement `renderDeliveriesHeader() string` — "DELIVERIES" small-caps left, "newest ↓" dim right
- [x] 7.5 Implement `renderDeliveryRow(d Delivery, termW int) string` — fixed-width columns with column-drop thresholds: suffix dropped below 80 cols, size also dropped below 73, latency also dropped below 65
- [x] 7.6 Implement `renderKeybindBar(m Model) string` — inverted key chips + labels; when toast is active, render toast text in place of keybind labels for 1.5 s, then restore
- [x] 7.7 Implement `renderHelpOverlay(m Model) string` — modal box listing all bindings + version info
- [x] 7.8 Implement `View() string` — compose title + identity + divider + deliveries header + viewport + divider + keybind bar; overlay help modal when `showHelp`
- [x] 7.9 Implement `viewportHeight(termH, headerRows int) int` and verify off-by-one with a unit test

## 8. Commands

- [x] 8.1 Implement `tickCmd() tea.Cmd` — fires `tickMsg{time.Now()}` after 1 s using `tea.Tick`
- [x] 8.2 Implement `copyURLCmd(url string) tea.Cmd` — calls `clipboard.WriteAll(url)`, returns `clipboardCopiedMsg` or error toast msg

## 9. TTY Detection & `forward` Command Wiring

- [x] 9.1 Add `golang.org/x/term` import to `cmd/hooksctl/forward.go` (already likely available transitively; confirm in `go.mod`)
- [x] 9.2 In `forward.go` run loop: detect `term.IsTerminal(int(os.Stdout.Fd()))` before starting SSE consumer
- [x] 9.3 If TTY: create `tui.Model`, create `tea.NewProgram(model, tea.WithAltScreen())`, run SSE consumer in a goroutine that calls `p.Send(tui.DeliveryReceivedMsg{...})` and `p.Send(tui.SessionStateMsg{...})` on events
- [x] 9.4 If not TTY: keep existing structured-log path unchanged
- [x] 9.5 Wire `defer p.RestoreTerminal()` for panic safety

## 10. Tests

- [x] 10.1 Unit test `viewportHeight()` for standard, short-terminal, and edge-case inputs
- [x] 10.2 Unit test `renderDeliveryRow()` for 2xx/4xx/5xx color paths and column-drop at < 80 cols
- [x] 10.3 Unit test `appendDelivery()` ring-buffer eviction at cap 500
- [x] 10.4 Unit test `Update()` for `DeliveryReceivedMsg` (appends, scroll behavior) and `DeliveryCompletedMsg` (patches in-flight row)
- [x] 10.5 Unit test quit: `q`/`^C` produces `tea.Quit` immediately regardless of in-flight state
- [x] 10.6 Run `make lint && make test` to confirm no regressions

## 11. Smoke Test & Cleanup

- [ ] 11.1 Run `make dev` and `hooksctl forward render` in a real terminal; verify all regions render correctly
- [ ] 11.2 Test resize by dragging terminal window; confirm column drop and identity collapse
- [ ] 11.3 Test `c` (copy URL + toast), `p` (pause/resume pill), `?` (help overlay), `q` (quit)
- [x] 11.4 Remove stub `doc.go` if package has real files; ensure no dead code
