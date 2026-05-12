package tui

import lipgloss "charm.land/lipgloss/v2"

type tuiStyles struct {
	title              lipgloss.Style
	dim                lipgloss.Style
	statusOnline       lipgloss.Style
	statusReconnecting lipgloss.Style
	statusOffline      lipgloss.Style
	forwardURL         lipgloss.Style
	targetURL          lipgloss.Style
	tokenHighlight     lipgloss.Style
	divider            lipgloss.Style
	keybindChip        lipgloss.Style
	toast              lipgloss.Style
	statusGreen        lipgloss.Style
	statusAmber        lipgloss.Style
	statusRed          lipgloss.Style
	statusMagenta      lipgloss.Style
}

func newStyles(isDark bool) tuiStyles {
	ld := lipgloss.LightDark(isDark)
	green := ld(lipgloss.Color("#5A7D1A"), lipgloss.Color("#9FC26A"))
	amber := ld(lipgloss.Color("#B07300"), lipgloss.Color("#E3B341"))
	red := ld(lipgloss.Color("#C03030"), lipgloss.Color("#E07B6B"))
	blue := ld(lipgloss.Color("#1060A0"), lipgloss.Color("#6BB5E0"))
	magenta := ld(lipgloss.Color("#8040A0"), lipgloss.Color("#C98EC9"))
	dim := ld(lipgloss.Color("#909090"), lipgloss.Color("#626262"))

	return tuiStyles{
		title:              lipgloss.NewStyle().Foreground(blue).Bold(true),
		dim:                lipgloss.NewStyle().Foreground(dim),
		statusOnline:       lipgloss.NewStyle().Foreground(green).Bold(true),
		statusReconnecting: lipgloss.NewStyle().Foreground(amber).Bold(true),
		statusOffline:      lipgloss.NewStyle().Foreground(dim).Bold(true),
		forwardURL:         lipgloss.NewStyle().Foreground(blue),
		targetURL:          lipgloss.NewStyle().Foreground(dim),
		tokenHighlight:     lipgloss.NewStyle().Foreground(magenta),
		divider:            lipgloss.NewStyle().Foreground(dim),
		keybindChip:        lipgloss.NewStyle().Reverse(true),
		toast:              lipgloss.NewStyle().Foreground(amber).Bold(true),
		statusGreen:        lipgloss.NewStyle().Foreground(green),
		statusAmber:        lipgloss.NewStyle().Foreground(amber),
		statusRed:          lipgloss.NewStyle().Foreground(red),
		statusMagenta:      lipgloss.NewStyle().Foreground(magenta),
	}
}

// statusStyle returns the style for an HTTP status code.
func (s tuiStyles) statusStyle(code int) lipgloss.Style {
	switch {
	case code >= 500:
		return s.statusRed
	case code >= 400:
		return s.statusAmber
	case code >= 200:
		return s.statusGreen
	default:
		return s.dim
	}
}
