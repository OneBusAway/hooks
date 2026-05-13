package tui

import (
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"
)

func toastExpireCmd() tea.Cmd {
	return tea.Tick(1500*time.Millisecond, func(time.Time) tea.Msg {
		return toastExpiredMsg{}
	})
}

func uptimeTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg {
		return uptimeTickMsg{}
	})
}

func copyURLCmd(url string) tea.Cmd {
	return func() tea.Msg {
		if err := clipboard.WriteAll(url); err != nil {
			return clipboardCopiedMsg{msg: "copy failed — check clipboard access"}
		}
		return clipboardCopiedMsg{msg: "URL copied"}
	}
}
