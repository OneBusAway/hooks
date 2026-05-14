package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
)

// Override at build time: -ldflags "-X github.com/onebusaway/hooks/internal/tui.Version=v1.2.3"
var Version = "dev"

// View satisfies tea.Model and returns the full-screen TUI view.
func (m Model) View() tea.View {
	v := tea.NewView(m.renderContent())
	v.AltScreen = true
	return v
}

func (m Model) renderContent() string {
	if m.termW == 0 {
		return ""
	}
	if m.showHelp {
		return m.renderHelpScreen()
	}
	return m.renderMainScreen()
}

func (m Model) renderMainScreen() string {
	var sb strings.Builder
	sb.WriteString(renderTitle(m))
	sb.WriteByte('\n')
	sb.WriteString(renderIdentity(m))
	sb.WriteByte('\n')
	sb.WriteString(renderDivider(m.termW, m.st))
	sb.WriteByte('\n')
	sb.WriteString(renderDeliveriesHeader(m.termW, m.st))
	sb.WriteByte('\n')
	sb.WriteString(m.vp.View())
	sb.WriteByte('\n')
	sb.WriteString(renderDivider(m.termW, m.st))
	sb.WriteByte('\n')
	sb.WriteString(renderKeybindBar(m))
	return sb.String()
}

func (m Model) renderHelpScreen() string {
	var sb strings.Builder
	sb.WriteString(renderTitle(m))
	sb.WriteByte('\n')
	sb.WriteString(renderHelpOverlay(m))
	sb.WriteByte('\n')
	sb.WriteString(renderDivider(m.termW, m.st))
	sb.WriteByte('\n')
	sb.WriteString(renderKeybindBar(m))
	return sb.String()
}

func renderTitle(m Model) string {
	left := m.st.title.Render("hooksctl " + Version)
	hint := m.st.dim.Render("? help")
	gap := m.termW - lipgloss.Width(left) - lipgloss.Width(hint)
	if gap < 0 {
		gap = 0
	}
	return left + strings.Repeat(" ", gap) + hint
}

func renderIdentity(m Model) string {
	pill := sessionPill(m)
	uptime := formatUptime(time.Since(m.session.UptimeStart))
	statusLine := pill + m.st.dim.Render("  uptime "+uptime)
	route := m.st.forwardURL.Render(m.session.ForwardURL) +
		m.st.dim.Render(" → ") +
		m.st.targetURL.Render(m.session.TargetURL)

	if m.termH < 24 {
		return statusLine + "\n" + route
	}

	scopeStr := strings.Join(m.session.Scopes, ", ")
	token := m.st.dim.Render("token   ") +
		m.st.tokenHighlight.Render(m.session.TokenPrefix+"…"+m.session.TokenSuffix) +
		m.st.dim.Render("  "+scopeStr)

	if m.session.Email == "" {
		return statusLine + "\n" + route + "\n" + token
	}
	email := m.st.dim.Render("account ") + m.session.Email
	return statusLine + "\n" + email + "\n" + route + "\n" + token
}

func sessionPill(m Model) string {
	switch m.session.State {
	case StateOnline:
		return m.st.statusOnline.Render("● online")
	case StateReconnecting:
		rc := ""
		if m.session.ReconnectCount > 0 {
			rc = fmt.Sprintf(" (×%d)", m.session.ReconnectCount)
		}
		return m.st.statusReconnecting.Render("● reconnecting" + rc)
	default:
		return m.st.statusOffline.Render("● offline")
	}
}

func renderDivider(w int, st tuiStyles) string {
	return st.divider.Render(strings.Repeat("─", w))
}

func renderDeliveriesHeader(w int, st tuiStyles) string {
	left := "DELIVERIES"
	right := st.dim.Render("newest ↓")
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}
	return left + strings.Repeat(" ", gap) + right
}

// renderDeliveryRow renders a single delivery row with fixed-width columns.
// Column drop thresholds: suffix <80, size <73, latency <65.
func renderDeliveryRow(d Delivery, termW int, st tuiStyles) string {
	ts := d.RecvAt.Format("15:04:05.000")
	method := fmt.Sprintf("%-6s", truncate(d.Method, 6))
	source := fmt.Sprintf("%-18s", truncate(d.Source, 18))

	var statusStr string
	if d.InFlight {
		statusStr = st.statusMagenta.Render("⇡ in flight")
	} else if d.Status == 0 {
		statusStr = fmt.Sprintf("%-4s", "—")
	} else {
		statusStr = st.statusStyle(d.Status).Render(fmt.Sprintf("%-4d", d.Status))
	}

	// optional right-side columns
	var rightParts []string
	if termW >= 65 {
		rightParts = append(rightParts, st.dim.Render(fmt.Sprintf("%6dms", d.DurationMS)))
	}
	if termW >= 73 {
		rightParts = append(rightParts, st.dim.Render(fmt.Sprintf("%6dB", d.SizeBytes)))
	}
	if termW >= 80 && d.Suffix != "" {
		rightParts = append(rightParts, st.dim.Render(truncate(d.Suffix, 20)))
	}

	rightStr := strings.Join(rightParts, " ")

	// fixed prefix width (without ANSI): ts(12) + sp(1) + method(6) + sp(1) + source(18) + sp(1) + status
	// Keep these widths in sync with the %-6s and %-18s format strings above.
	// status visible width: 4 for code, 11 for "⇡ in flight"
	statusVisW := 4
	if d.InFlight {
		statusVisW = lipgloss.Width(statusStr)
	}
	prefixVisW := 12 + 1 + 6 + 1 + 18 + 1 + statusVisW

	rightVisW := 0
	if rightStr != "" {
		rightVisW = lipgloss.Width(rightStr) + 1 // leading space
	}

	pathWidth := termW - prefixVisW - 1 - rightVisW
	if pathWidth < 12 {
		pathWidth = 12
	}
	path := fmt.Sprintf("%-*s", pathWidth, truncate(d.Path, pathWidth))

	prefix := st.dim.Render(ts) + " " + method + " " + source + " " + statusStr
	if rightStr == "" {
		return prefix + " " + path
	}
	return prefix + " " + path + " " + rightStr
}

func renderKeybindBar(m Model) string {
	if m.toastMsg != "" && time.Now().Before(m.toastExpiry) {
		return m.st.toast.Render(m.toastMsg)
	}
	chip := func(k, label string) string {
		return m.st.keybindChip.Render(" "+k+" ") + " " + label
	}
	parts := []string{
		chip(m.keys.copyURL.Help().Key, m.keys.copyURL.Help().Desc),
		chip(m.keys.help.Help().Key, m.keys.help.Help().Desc),
		chip(m.keys.quit.Help().Key, m.keys.quit.Help().Desc),
	}
	return strings.Join(parts, "  ")
}

// renderHelpOverlay renders the help box. Key strings must stay in sync with defaultKeyMap in keys.go.
func renderHelpOverlay(m Model) string {
	var sb strings.Builder
	sb.WriteString("┌── Help ──────────────────────────────┐\n")
	sb.WriteString("│                                      │\n")
	sb.WriteString("│  c      copy forwarding URL          │\n")
	sb.WriteString("│  ?/esc  toggle help                  │\n")
	sb.WriteString("│  q/^C   quit                         │\n")
	sb.WriteString("│  ↑↓     scroll                       │\n")
	sb.WriteString("│                                      │\n")
	fmt.Fprintf(&sb, "│  hooksctl %-27s │\n", Version)
	sb.WriteString("│                                      │\n")
	sb.WriteString("└──────────────────────────────────────┘")
	return sb.String()
}

// fixedHeaderRows returns the number of rows consumed by non-viewport layout.
// identityRows is 4 when email is present (status+email+route+token), 3 when
// absent (status+route+token), or 2 for compact terminals (termH < 24).
func fixedHeaderRows(termH int, hasEmail bool) int {
	var identityRows int
	switch {
	case termH < 24:
		identityRows = 2
	case hasEmail:
		identityRows = 4
	default:
		identityRows = 3
	}
	// title + identity + divider + deliveries-header + divider + footer
	return 1 + identityRows + 1 + 1 + 1 + 1
}

// viewportHeight returns the number of rows available for the delivery viewport.
func viewportHeight(termH, headerRows int) int {
	h := termH - headerRows
	if h < 0 {
		return 0
	}
	return h
}

// truncate shortens s to at most max runes, replacing the last rune with "…".
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(runes[:max-1]) + "…"
}

func formatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	mn := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, mn, s)
	}
	return fmt.Sprintf("%dm%02ds", mn, s)
}
