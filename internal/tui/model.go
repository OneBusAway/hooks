package tui

import (
	"context"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
)

// ringCap bounds the in-memory delivery log; 500 rows balances scrollback depth
// against unbounded memory growth for a long-running session.
const ringCap = 500

type Model struct {
	session     SessionInfo
	deliveries  []Delivery
	vp          viewport.Model
	showHelp    bool
	atBottom    bool
	toastMsg    string
	toastExpiry time.Time
	termW       int
	termH       int
	keys        keyMap
	st          tuiStyles
	cancel      context.CancelFunc
}

func New(session SessionInfo, cancel context.CancelFunc) Model {
	m := Model{
		session:  session,
		atBottom: true,
		keys:     defaultKeyMap,
		st:       newStyles(true),
		cancel:   cancel,
	}
	m.vp = viewport.New()
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.RequestBackgroundColor
}

func appendDelivery(m *Model, d Delivery) {
	if len(m.deliveries) >= ringCap {
		m.deliveries = m.deliveries[1:]
	}
	m.deliveries = append(m.deliveries, d)
}

func rebuildViewport(m *Model) {
	var sb strings.Builder
	for i, d := range m.deliveries {
		sb.WriteString(renderDeliveryRow(d, m.termW, m.st))
		if i < len(m.deliveries)-1 {
			sb.WriteByte('\n')
		}
	}
	m.vp.SetContent(sb.String())
	if m.atBottom {
		m.vp.GotoBottom()
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.termW = msg.Width
		m.termH = msg.Height
		headerRows := fixedHeaderRows(m.termH)
		m.vp.SetWidth(m.termW)
		m.vp.SetHeight(viewportHeight(m.termH, headerRows))
		rebuildViewport(&m)

	case tea.BackgroundColorMsg:
		m.st = newStyles(msg.IsDark())
		rebuildViewport(&m)

	case DeliveryReceivedMsg:
		appendDelivery(&m, msg.Delivery)
		rebuildViewport(&m)

	case DeliveryCompletedMsg:
		for i := range m.deliveries {
			if m.deliveries[i].ID == msg.ID {
				m.deliveries[i].Status = msg.Status
				m.deliveries[i].DurationMS = msg.DurationMS
				m.deliveries[i].Suffix = msg.Suffix
				m.deliveries[i].InFlight = false
				break
			}
		}
		rebuildViewport(&m)

	case QuitMsg:
		if m.cancel != nil {
			m.cancel()
		}
		return m, tea.Quit

	case SessionStateMsg:
		m.session = msg.Info

	case toastExpiredMsg:
		if !m.toastExpiry.IsZero() && time.Now().After(m.toastExpiry) {
			m.toastMsg = ""
			m.toastExpiry = time.Time{}
		}

	case clipboardCopiedMsg:
		m.toastMsg = msg.msg
		m.toastExpiry = time.Now().Add(1500 * time.Millisecond)
		cmds = append(cmds, toastExpireCmd())

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keys.quit):
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case key.Matches(msg, m.keys.copyURL):
			cmds = append(cmds, copyURLCmd(m.session.ForwardURL))
		case key.Matches(msg, m.keys.dismiss):
			m.showHelp = false
		case key.Matches(msg, m.keys.help):
			m.showHelp = !m.showHelp
		default:
			var vpCmd tea.Cmd
			m.vp, vpCmd = m.vp.Update(msg)
			if vpCmd != nil {
				cmds = append(cmds, vpCmd)
			}
			m.atBottom = m.vp.AtBottom()
		}
	}

	return m, tea.Batch(cmds...)
}
