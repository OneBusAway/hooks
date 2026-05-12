## ADDED Requirements

### Requirement: TUI launches on TTY
When `hooksctl forward` is invoked and stdout is a TTY, the command SHALL launch the full-screen Bubble Tea dashboard instead of emitting structured log lines. When stdout is not a TTY (pipe, redirect, CI), the existing log output SHALL be used unchanged.

#### Scenario: TTY detected
- **WHEN** `hooksctl forward <source> <target>` is run in an interactive terminal
- **THEN** the alternate screen activates and the full-screen TUI renders

#### Scenario: Non-TTY stdout
- **WHEN** `hooksctl forward <source> <target>` is run with stdout piped or redirected
- **THEN** structured log lines are emitted as before with no TUI

---

### Requirement: Session header displays connection state
The TUI header SHALL display four rows of session metadata: (1) session state pill + reconnect count + uptime, (2) account email, (3) forwarding route, (4) token display.

#### Scenario: Online state
- **WHEN** the SSE connection is established
- **THEN** the session pill reads `● online` in green and uptime ticks every second

#### Scenario: Reconnecting state
- **WHEN** the SSE connection drops and reconnect is in progress
- **THEN** the session pill reads `● reconnecting` in amber and reconnect count increments

#### Scenario: Paused state
- **WHEN** the user presses `p`
- **THEN** the session pill reads `● paused` in amber and inbound forwarding is queued

#### Scenario: Token fingerprint display
- **WHEN** the TUI renders the token row
- **THEN** the token is shown as prefix + `…` + last 3 chars with scopes listed

---

### Requirement: Live delivery tail
The TUI SHALL maintain a ring buffer of up to 500 delivery rows, newest at the bottom, auto-scrolling unless the user has manually scrolled up.

#### Scenario: New delivery appended
- **WHEN** a `deliveryReceivedMsg` arrives
- **THEN** a new row is appended to the bottom of the delivery list and the viewport scrolls to bottom if `atBottom` is true

#### Scenario: In-flight row updated
- **WHEN** a `deliveryCompletedMsg` arrives matching a pending in-flight row
- **THEN** the row's status, latency, and suffix fields are updated in-place and the `⇡ in flight` indicator is replaced with the final status code

#### Scenario: Ring buffer cap
- **WHEN** the delivery buffer reaches 500 rows and a new delivery arrives
- **THEN** the oldest row is evicted and the new row is appended

#### Scenario: User scrolls up
- **WHEN** the user presses an up/page-up scroll key
- **THEN** `atBottom` is set to false and new deliveries are appended without auto-scrolling

---

### Requirement: Delivery row columns
Each delivery row SHALL render fixed-width columns in this order: timestamp (12), method (6), path (flex, min 12), source (18), status (4), latency (7), size (7), suffix (flex). Columns SHALL be color-coded per the design spec color tokens.

#### Scenario: 2xx status color
- **WHEN** a delivery row has a 2xx HTTP status code
- **THEN** the status column renders in green (`#9FC26A`)

#### Scenario: 4xx status color
- **WHEN** a delivery row has a 4xx HTTP status code
- **THEN** the status column renders in amber (`#E3B341`)

#### Scenario: 5xx status color
- **WHEN** a delivery row has a 5xx HTTP status code
- **THEN** the status column renders in red (`#E07B6B`)

#### Scenario: In-flight indicator
- **WHEN** a delivery row has `in_flight = true`
- **THEN** the status column renders `⇡ in flight` in magenta (`#C98EC9`)

#### Scenario: Column drop below 80 cols
- **WHEN** terminal width drops below 80 columns
- **THEN** suffix, then size, then latency columns are dropped right-to-left

---

### Requirement: Responsive layout
The TUI SHALL recompute layout on every `tea.WindowSizeMsg`. Below 24 rows the identity block SHALL collapse to two lines (status + forwarding).

#### Scenario: Viewport height recalculation
- **WHEN** a `tea.WindowSizeMsg` is received
- **THEN** viewport height is set to `termHeight − (headerRows + 2 dividers + 1 footer + 2 blank lines)`

#### Scenario: Identity collapse
- **WHEN** terminal height is below 24 rows
- **THEN** the identity block renders only the session state pill and the forwarding route (2 lines instead of 4)

---

### Requirement: Keybind bar
A persistent single-row footer SHALL always be visible and SHALL render inverted key chips followed by action labels: `c` copy URL, `w` web UI, `r` replay last, `p` pause/resume, `?` help, `q` quit.

#### Scenario: Footer always rendered
- **WHEN** the TUI is active regardless of scroll position
- **THEN** the keybind bar is pinned to the last row of the terminal

---

### Requirement: Copy forwarding URL
Pressing `c` SHALL write the public forwarding URL to the system clipboard and show a 1.5 s toast.

#### Scenario: Clipboard success
- **WHEN** the user presses `c` and clipboard write succeeds
- **THEN** a toast "URL copied" appears below the keybind bar for 1.5 seconds then disappears

#### Scenario: Clipboard failure
- **WHEN** the user presses `c` and clipboard write fails
- **THEN** a toast "copy failed — no clipboard" appears for 1.5 seconds

---

### Requirement: Open web UI
Pressing `w` SHALL open the hooks server web dashboard URL in the system default browser.

#### Scenario: Open browser
- **WHEN** the user presses `w`
- **THEN** the OS default browser opens to the hooks server URL

---

### Requirement: Replay last delivery
Pressing `r` SHALL re-send the most recent completed delivery to the local target via the existing replay API.

#### Scenario: Replay triggered
- **WHEN** the user presses `r` and at least one delivery exists
- **THEN** the replay API is called for the most recent delivery ID

#### Scenario: No deliveries
- **WHEN** the user presses `r` and the delivery buffer is empty
- **THEN** the key press is a no-op

---

### Requirement: Help overlay
Pressing `?` SHALL show a modal overlay listing all keybindings plus version and build info. Pressing `?` again or `Esc` SHALL dismiss it.

#### Scenario: Help shown
- **WHEN** the user presses `?`
- **THEN** a modal overlay appears listing all keybindings

#### Scenario: Help dismissed
- **WHEN** the help overlay is visible and the user presses `?` or `Esc`
- **THEN** the overlay is hidden and the delivery tail is visible again

---

### Requirement: Graceful quit
Pressing `q` or `^C` SHALL initiate graceful shutdown: in-flight deliveries are drained before exit. A second press SHALL force-quit immediately.

#### Scenario: First quit key — graceful drain
- **WHEN** the user presses `q` or `^C` with in-flight deliveries
- **THEN** the TUI shows a "draining…" indicator and waits for in-flight rows to complete before exiting

#### Scenario: Second quit key — force quit
- **WHEN** the user presses `q` or `^C` a second time while draining
- **THEN** the program exits immediately without waiting for in-flight deliveries

#### Scenario: Quit with no in-flight
- **WHEN** the user presses `q` or `^C` with no in-flight deliveries
- **THEN** the program exits immediately

---

### Requirement: 1-second uptime tick
The TUI SHALL fire a `tickMsg` every second to refresh the uptime display in the session header.

#### Scenario: Uptime increments
- **WHEN** one second elapses
- **THEN** the uptime counter in the session header increments by one second
