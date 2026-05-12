package tui

import (
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"
)

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg{t: t}
	})
}

func copyURLCmd(url string) tea.Cmd {
	return func() tea.Msg {
		if err := clipboard.WriteAll(url); err != nil {
			return clipboardCopiedMsg{msg: "copy failed — no clipboard"}
		}
		return clipboardCopiedMsg{msg: "URL copied"}
	}
}
