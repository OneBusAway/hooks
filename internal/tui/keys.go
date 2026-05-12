package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	copyURL key.Binding
	help    key.Binding
	dismiss key.Binding
	quit    key.Binding
}

var defaultKeyMap = keyMap{
	copyURL: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "copy URL"),
	),
	help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	dismiss: key.NewBinding(
		key.WithKeys("esc"),
	),
	quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.copyURL, k.help, k.quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.copyURL, k.help, k.quit},
	}
}
