package tui

import "time"

// SessionState describes the connection state of a forward session.
type SessionState int

const (
	StateOnline SessionState = iota
	StateReconnecting
	StateOffline
)

// SessionInfo holds the display data shown in the session header.
type SessionInfo struct {
	State          SessionState
	ReconnectCount int
	UptimeStart    time.Time
	Email          string
	ForwardURL     string
	TargetURL      string
	TokenPrefix    string
	TokenSuffix    string
	Scopes         []string
}

// Delivery represents a single webhook delivery row.
type Delivery struct {
	ID         string
	RecvAt     time.Time
	Method     string
	Path       string
	Source     string
	Status     int
	DurationMS int64
	SizeBytes  int64
	Suffix     string
	InFlight   bool
}

// DeliveryReceivedMsg is sent when a delivery is first received.
type DeliveryReceivedMsg struct{ Delivery Delivery }

// DeliveryCompletedMsg is sent when an in-flight delivery completes.
type DeliveryCompletedMsg struct {
	ID         string
	Status     int
	DurationMS int64
	Suffix     string
}

// SessionStateMsg is sent when the session connection state changes.
type SessionStateMsg struct{ Info SessionInfo }

// QuitMsg tells the model to quit the program. Send it from outside the TUI
// (e.g. the forward goroutine) when the program must exit programmatically.
type QuitMsg struct{}

type toastExpiredMsg struct{}

type clipboardCopiedMsg struct{ msg string }
