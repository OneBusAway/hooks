package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	copyURL key.Binding
	pause   key.Binding
	help    key.Binding
	quit    key.Binding
}

var defaultKeyMap = keyMap{
	copyURL: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "copy URL"),
	),
	pause: key.NewBinding(
		key.WithKeys("p"),
		key.WithHelp("p", "pause/resume"),
	),
	help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.copyURL, k.pause, k.help, k.quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.copyURL, k.pause},
		{k.help, k.quit},
	}
}
