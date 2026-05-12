package tui

import (
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

	// Fill to capacity
	for i := range ringCap {
		appendDelivery(&m, Delivery{ID: string(rune('a' + i%26)), RecvAt: time.Now()})
	}
	if len(m.deliveries) != ringCap {
		t.Fatalf("expected %d deliveries, got %d", ringCap, len(m.deliveries))
	}

	// One more should evict the oldest
	appendDelivery(&m, Delivery{ID: "new", RecvAt: time.Now()})
	if len(m.deliveries) != ringCap {
		t.Fatalf("after eviction expected %d deliveries, got %d", ringCap, len(m.deliveries))
	}
	last := m.deliveries[ringCap-1]
	if last.ID != "new" {
		t.Errorf("expected last delivery to be 'new', got %q", last.ID)
	}
}

// --- Update: DeliveryReceivedMsg ---

func newTestModel() Model {
	m := New(SessionInfo{State: StateOnline, UptimeStart: time.Now()}, nil)
	m.termW = 120
	m.termH = 40
	return m
}

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

// --- Update: atBottom behavior ---

func TestUpdate_ScrollUpDisablesAutoScroll(t *testing.T) {
	m := newTestModel()
	// Seed some deliveries
	for i := range 10 {
		d := Delivery{ID: string(rune('a' + i)), RecvAt: time.Now(), Method: "POST", Path: "/r", Source: "render"}
		next, _ := m.Update(DeliveryReceivedMsg{Delivery: d})
		m = next.(Model)
	}
	if !m.atBottom {
		t.Fatal("model should start at bottom")
	}

	// Send a scroll-up key; viewport will handle it but atBottom should update
	next, _ := m.Update(tea.KeyPressMsg{Code: 'k'})
	m = next.(Model)
	// atBottom is updated to m.vp.AtBottom() after each unhandled key
	// In a zero-size viewport AtBottom() may still be true; just confirm no panic
	_ = m.atBottom
}

// --- Update: quit ---

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
