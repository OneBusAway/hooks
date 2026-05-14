package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// --- viewportHeight ---

func TestViewportHeight(t *testing.T) {
	tests := []struct {
		termH      int
		headerRows int
		want       int
	}{
		{termH: 40, headerRows: 9, want: 31},
		{termH: 24, headerRows: 9, want: 15},
		{termH: 9, headerRows: 9, want: 0},
		{termH: 5, headerRows: 9, want: 0}, // edge: height < headerRows
		{termH: 0, headerRows: 9, want: 0},
	}
	for _, tc := range tests {
		got := viewportHeight(tc.termH, tc.headerRows)
		if got != tc.want {
			t.Errorf("viewportHeight(%d, %d) = %d; want %d", tc.termH, tc.headerRows, got, tc.want)
		}
	}
}

// --- fixedHeaderRows ---

func TestFixedHeaderRows(t *testing.T) {
	// >= 24 with email: title(1) + identity(4) + divider(1) + deliveries-header(1) + divider(1) + footer(1)
	if got := fixedHeaderRows(40, true); got != 9 {
		t.Errorf("fixedHeaderRows(40, true) = %d; want 9", got)
	}
	if got := fixedHeaderRows(24, true); got != 9 {
		t.Errorf("fixedHeaderRows(24, true) = %d; want 9", got)
	}
	// >= 24 without email: title(1) + identity(3) + divider(1) + deliveries-header(1) + divider(1) + footer(1)
	if got := fixedHeaderRows(40, false); got != 8 {
		t.Errorf("fixedHeaderRows(40, false) = %d; want 8", got)
	}
	// < 24: title(1) + identity(2) + divider(1) + deliveries-header(1) + divider(1) + footer(1)
	if got := fixedHeaderRows(23, false); got != 7 {
		t.Errorf("fixedHeaderRows(23, false) = %d; want 7", got)
	}
	if got := fixedHeaderRows(10, true); got != 7 {
		t.Errorf("fixedHeaderRows(10, true) = %d; want 7", got)
	}
}

// --- truncate ---

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 4, "hel…"},
		{"hello", 2, "h…"},
		{"hello", 1, "…"},
		{"hello", 0, "…"},
		{"", 5, ""},
	}
	for _, tc := range tests {
		got := truncate(tc.s, tc.max)
		if got != tc.want {
			t.Errorf("truncate(%q, %d) = %q; want %q", tc.s, tc.max, got, tc.want)
		}
	}
}

// --- formatUptime ---

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0m00s"},
		{30 * time.Second, "0m30s"},
		{90 * time.Second, "1m30s"},
		{time.Hour + 2*time.Minute + 3*time.Second, "1h02m03s"},
		{-1 * time.Second, "0m00s"}, // negative clamped to zero
	}
	for _, tc := range tests {
		got := formatUptime(tc.d)
		if got != tc.want {
			t.Errorf("formatUptime(%v) = %q; want %q", tc.d, got, tc.want)
		}
	}
}

// --- renderDeliveryRow ---

func TestRenderDeliveryRow_StatusColors(t *testing.T) {
	st := newStyles(true) // dark mode

	d := func(status int) Delivery {
		return Delivery{
			ID:     "x",
			RecvAt: time.Time{},
			Method: "POST",
			Path:   "/render",
			Source: "render",
			Status: status,
		}
	}

	// 2xx: green style
	row2xx := renderDeliveryRow(d(200), 120, st)
	green := st.statusGreen.Render("200 ")
	if !strings.Contains(row2xx, green) {
		t.Errorf("2xx row should contain green-styled status; got: %q", row2xx)
	}

	// 4xx: amber style
	row4xx := renderDeliveryRow(d(404), 120, st)
	amber := st.statusAmber.Render("404 ")
	if !strings.Contains(row4xx, amber) {
		t.Errorf("4xx row should contain amber-styled status; got: %q", row4xx)
	}

	// 5xx: red style
	row5xx := renderDeliveryRow(d(500), 120, st)
	red := st.statusRed.Render("500 ")
	if !strings.Contains(row5xx, red) {
		t.Errorf("5xx row should contain red-styled status; got: %q", row5xx)
	}
}

func TestRenderDeliveryRow_ColumnDrop(t *testing.T) {
	st := newStyles(true)
	d := Delivery{
		ID:         "x",
		RecvAt:     time.Time{},
		Method:     "POST",
		Path:       "/render",
		Source:     "render",
		Status:     200,
		DurationMS: 42,
		SizeBytes:  1024,
		Suffix:     "retry 1/3",
	}

	// At ≥80: suffix present
	row80 := renderDeliveryRow(d, 80, st)
	if !strings.Contains(row80, "retry 1/3") {
		t.Errorf("at width 80, suffix should be present; row: %q", row80)
	}

	// At <80: suffix dropped
	row79 := renderDeliveryRow(d, 79, st)
	if strings.Contains(row79, "retry 1/3") {
		t.Errorf("at width 79, suffix should be dropped; row: %q", row79)
	}

	// At <73: size dropped (no "1024B" or similar)
	row72 := renderDeliveryRow(d, 72, st)
	if strings.Contains(row72, "1024B") {
		t.Errorf("at width 72, size should be dropped; row: %q", row72)
	}

	// At <65: latency dropped (no "42ms")
	row64 := renderDeliveryRow(d, 64, st)
	if strings.Contains(row64, "42ms") {
		t.Errorf("at width 64, latency should be dropped; row: %q", row64)
	}
}

// --- appendDelivery ---

func TestAppendDelivery_RingBufferEviction(t *testing.T) {
	m := Model{atBottom: true}

	// Fill to capacity with unique IDs.
	for i := range ringCap {
		appendDelivery(&m, Delivery{ID: fmt.Sprintf("d%d", i), RecvAt: time.Now()})
	}
	if len(m.deliveries) != ringCap {
		t.Fatalf("expected %d deliveries, got %d", ringCap, len(m.deliveries))
	}

	// One more should evict the oldest.
	appendDelivery(&m, Delivery{ID: "new", RecvAt: time.Now()})
	if len(m.deliveries) != ringCap {
		t.Fatalf("after eviction expected %d deliveries, got %d", ringCap, len(m.deliveries))
	}
	last := m.deliveries[ringCap-1]
	if last.ID != "new" {
		t.Errorf("expected last delivery to be 'new', got %q", last.ID)
	}
}

func TestAppendDelivery_DeduplicatesID(t *testing.T) {
	m := Model{}
	appendDelivery(&m, Delivery{ID: "d1", InFlight: true})
	appendDelivery(&m, Delivery{ID: "d2", InFlight: true})

	// Re-append d1 with updated fields (simulates reconnect).
	appendDelivery(&m, Delivery{ID: "d1", InFlight: true, Status: 200})

	if len(m.deliveries) != 2 {
		t.Fatalf("expected 2 deliveries after dedup, got %d", len(m.deliveries))
	}
	if m.deliveries[0].Status != 200 {
		t.Errorf("expected d1 status updated to 200, got %d", m.deliveries[0].Status)
	}
}

func TestAppendDelivery_DedupRunsBeforeEviction(t *testing.T) {
	m := Model{}

	// Fill to capacity with unique IDs.
	for i := range ringCap {
		appendDelivery(&m, Delivery{ID: fmt.Sprintf("d%d", i), RecvAt: time.Now()})
	}

	// Re-appending the first entry must update in-place, not evict the oldest.
	appendDelivery(&m, Delivery{ID: "d0", RecvAt: time.Now(), Status: 200})

	if len(m.deliveries) != ringCap {
		t.Fatalf("dedup at capacity: want %d deliveries, got %d", ringCap, len(m.deliveries))
	}
	if m.deliveries[0].Status != 200 {
		t.Errorf("dedup at capacity: want d0 status updated to 200, got %d", m.deliveries[0].Status)
	}
}

// --- helpers ---

func newTestModel() Model {
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, nil)
	m.termW = 120
	m.termH = 40
	return m
}

// --- Update: DeliveryReceivedMsg ---

func TestUpdate_DeliveryReceived(t *testing.T) {
	m := newTestModel()

	d := Delivery{ID: "d1", RecvAt: time.Now(), Method: "POST", Path: "/r", Source: "render", InFlight: true}
	next, _ := m.Update(DeliveryReceivedMsg{Delivery: d})
	nm := next.(Model)

	if len(nm.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(nm.deliveries))
	}
	if nm.deliveries[0].ID != "d1" {
		t.Errorf("expected delivery id d1, got %q", nm.deliveries[0].ID)
	}
}

func TestUpdate_DeliveryCompleted(t *testing.T) {
	m := newTestModel()

	d := Delivery{ID: "d1", RecvAt: time.Now(), Method: "POST", Path: "/r", Source: "render", InFlight: true}
	next, _ := m.Update(DeliveryReceivedMsg{Delivery: d})
	nm := next.(Model)

	next2, _ := nm.Update(DeliveryCompletedMsg{ID: "d1", Status: 200, DurationMS: 50})
	nm2 := next2.(Model)

	if nm2.deliveries[0].InFlight {
		t.Error("delivery should no longer be in-flight after completion")
	}
	if nm2.deliveries[0].Status != 200 {
		t.Errorf("expected status 200, got %d", nm2.deliveries[0].Status)
	}
	if nm2.deliveries[0].DurationMS != 50 {
		t.Errorf("expected DurationMS 50, got %d", nm2.deliveries[0].DurationMS)
	}
}

func TestUpdate_DeliveryCompletedUnknownID(t *testing.T) {
	m := newTestModel()
	d := Delivery{ID: "d1", RecvAt: time.Now(), InFlight: true}
	next, _ := m.Update(DeliveryReceivedMsg{Delivery: d})
	m = next.(Model)

	// Completing with an unknown ID is a no-op — delivery stays in-flight.
	next, _ = m.Update(DeliveryCompletedMsg{ID: "ghost", Status: 200})
	m = next.(Model)

	if len(m.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(m.deliveries))
	}
	if !m.deliveries[0].InFlight {
		t.Error("delivery should still be in-flight — unknown ID should be a no-op")
	}
}

// --- Update: SessionStateMsg ---

func TestUpdate_SessionStateMsg(t *testing.T) {
	m := newTestModel()

	info := SessionInfo{
		State:          StateReconnecting,
		ReconnectCount: 2,
		UptimeStart:    time.Now(),
		ForwardURL:     "https://example.com",
	}
	next, _ := m.Update(SessionStateMsg{Info: info})
	nm := next.(Model)

	if nm.session.State != StateReconnecting {
		t.Errorf("expected StateReconnecting, got %v", nm.session.State)
	}
	if nm.session.ReconnectCount != 2 {
		t.Errorf("expected ReconnectCount 2, got %d", nm.session.ReconnectCount)
	}
}

// --- Update: toast lifecycle ---

func TestUpdate_ToastLifecycle(t *testing.T) {
	m := newTestModel()

	// clipboardCopiedMsg sets toastMsg and schedules expiry.
	next, cmd := m.Update(clipboardCopiedMsg{msg: "URL copied"})
	m = next.(Model)
	if m.toastMsg != "URL copied" {
		t.Errorf("expected toastMsg 'URL copied', got %q", m.toastMsg)
	}
	if cmd == nil {
		t.Fatal("expected toastExpireCmd from clipboardCopiedMsg")
	}

	// toastExpiredMsg with an already-expired expiry clears the toast.
	m.toastExpiry = time.Now().Add(-time.Second)
	next, _ = m.Update(toastExpiredMsg{})
	m = next.(Model)
	if m.toastMsg != "" {
		t.Errorf("toast should be cleared after expiry; got %q", m.toastMsg)
	}
}

func TestUpdate_ToastNotClearedBeforeExpiry(t *testing.T) {
	m := newTestModel()

	next, _ := m.Update(clipboardCopiedMsg{msg: "hello"})
	m = next.(Model)
	// Move expiry into the future so the message hasn't expired.
	m.toastExpiry = time.Now().Add(10 * time.Second)

	next, _ = m.Update(toastExpiredMsg{})
	m = next.(Model)
	if m.toastMsg != "hello" {
		t.Errorf("toast should not be cleared before expiry; got %q", m.toastMsg)
	}
}

// --- Update: help toggle ---

func TestUpdate_HelpKeyTogglesShowHelp(t *testing.T) {
	m := newTestModel()
	if m.showHelp {
		t.Fatal("showHelp should start false")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: '?'})
	m = next.(Model)
	if !m.showHelp {
		t.Error("showHelp should be true after pressing ?")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: '?'})
	m = next.(Model)
	if m.showHelp {
		t.Error("showHelp should be false after pressing ? again")
	}
}

// --- Update: QuitMsg ---

func TestUpdate_QuitMsgCallsCancelAndQuits(t *testing.T) {
	cancelled := false
	cancel := func() { cancelled = true }
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, cancel)

	_, cmd := m.Update(QuitMsg{})
	if cmd == nil {
		t.Fatal("expected a command from QuitMsg")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", msg)
	}
	if !cancelled {
		t.Error("cancel should have been called on QuitMsg")
	}
}

// --- Update: quit key ---

func TestUpdate_QuitProducesQuitCmd(t *testing.T) {
	cancelled := false
	cancel := func() { cancelled = true }

	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, cancel)
	m.termW = 120
	m.termH = 40

	_, cmd := m.Update(tea.KeyPressMsg{Code: 'q'})
	if cmd == nil {
		t.Fatal("expected a command from quit key")
	}

	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("expected QuitMsg, got %T", msg)
	}
	if !cancelled {
		t.Error("cancel should have been called on quit")
	}
}

func TestUpdate_CtrlCProducesQuitCmd(t *testing.T) {
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, nil)
	m.termW = 120
	m.termH = 40

	_, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil {
		t.Fatal("expected a command from ctrl+c")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("expected QuitMsg from ctrl+c, got %T", msg)
	}
}

// --- Update: WindowSizeMsg ---

func TestUpdate_WindowSizeSetsTermDimensions(t *testing.T) {
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, nil)

	next, _ := m.Update(tea.WindowSizeMsg{Width: 150, Height: 50})
	nm := next.(Model)

	if nm.termW != 150 {
		t.Errorf("expected termW 150, got %d", nm.termW)
	}
	if nm.termH != 50 {
		t.Errorf("expected termH 50, got %d", nm.termH)
	}
}

// --- Update: atBottom behavior ---

func TestUpdate_ScrollUpDisablesAutoScroll(t *testing.T) {
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, nil)

	// Size the model so the viewport has real dimensions (height=20 → viewport=13 rows).
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	m = next.(Model)

	// Add 50 deliveries — far more than the 13-row viewport, so content overflows.
	for i := range 50 {
		d := Delivery{
			ID:     fmt.Sprintf("d%d", i),
			RecvAt: time.Now(),
			Method: "POST",
			Path:   "/r",
			Source: "render",
		}
		next, _ := m.Update(DeliveryReceivedMsg{Delivery: d})
		m = next.(Model)
	}
	if !m.atBottom {
		t.Fatal("model should be at bottom after adding deliveries with atBottom=true")
	}

	// Scroll up. The model forwards unhandled keys to the viewport; 'k' is the
	// vim-style line-up binding in charm.land/bubbles/v2/viewport.
	next, _ = m.Update(tea.KeyPressMsg{Code: 'k'})
	m = next.(Model)

	if m.atBottom {
		t.Error("atBottom should be false after scrolling up")
	}
}

// --- Update: copy URL key ---

func TestUpdate_CopyURLKeyReturnsCmd(t *testing.T) {
	m := newTestModel()
	m.session.ForwardURL = "https://hooks.example.com/subscribe/render"

	_, cmd := m.Update(tea.KeyPressMsg{Code: 'c'})
	if cmd == nil {
		t.Fatal("expected a command from copy URL key")
	}
}

// --- Update: esc key ---

func TestUpdate_EscDismissesHelp(t *testing.T) {
	m := newTestModel()
	m.showHelp = true

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	m = next.(Model)
	if m.showHelp {
		t.Error("esc should close the help overlay")
	}
}

func TestUpdate_EscDoesNotOpenHelp(t *testing.T) {
	m := newTestModel()
	if m.showHelp {
		t.Fatal("showHelp should start false")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	m = next.(Model)
	if m.showHelp {
		t.Error("esc should not open the help overlay when it is already closed")
	}
}

// --- Update: atBottom when scrolled up ---

func TestUpdate_ScrollUpDoesNotJumpOnNewDelivery(t *testing.T) {
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, nil)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	m = next.(Model)

	// Fill viewport past capacity so scrolling is possible.
	for i := range 50 {
		d := Delivery{ID: fmt.Sprintf("d%d", i), RecvAt: time.Now(), Method: "POST", Path: "/r", Source: "render"}
		next, _ := m.Update(DeliveryReceivedMsg{Delivery: d})
		m = next.(Model)
	}

	// Scroll up so atBottom becomes false.
	next, _ = m.Update(tea.KeyPressMsg{Code: 'k'})
	m = next.(Model)
	if m.atBottom {
		t.Fatal("expected atBottom=false after scrolling up")
	}

	// A new delivery must not hijack the scroll position.
	d := Delivery{ID: "new", RecvAt: time.Now(), Method: "POST", Path: "/r", Source: "render"}
	next, _ = m.Update(DeliveryReceivedMsg{Delivery: d})
	m = next.(Model)
	if m.atBottom {
		t.Error("atBottom should remain false when a delivery arrives while scrolled up")
	}
}

// --- sessionPill ---

func TestSessionPill_States(t *testing.T) {
	// Online
	m := newTestModel()
	m.session.State = StateOnline
	got := sessionPill(m)
	if !strings.Contains(got, "online") {
		t.Errorf("online pill should contain 'online'; got %q", got)
	}

	// Reconnecting without count — no parenthetical
	m.session.State = StateReconnecting
	m.session.ReconnectCount = 0
	got = sessionPill(m)
	if !strings.Contains(got, "reconnecting") {
		t.Errorf("reconnecting pill should contain 'reconnecting'; got %q", got)
	}
	if strings.Contains(got, "×") {
		t.Errorf("reconnecting pill with count=0 should not contain ×; got %q", got)
	}

	// Reconnecting with count
	m.session.ReconnectCount = 3
	got = sessionPill(m)
	if !strings.Contains(got, "(×3)") {
		t.Errorf("reconnecting pill with count=3 should contain (×3); got %q", got)
	}

	// Offline (default branch)
	m.session.State = StateOffline
	got = sessionPill(m)
	if !strings.Contains(got, "offline") {
		t.Errorf("offline pill should contain 'offline'; got %q", got)
	}
}
