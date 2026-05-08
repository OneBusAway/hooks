// Package audit centralises audit-log writes for admin-meaningful actions
// (invite lifecycle, user lifecycle, ownership transfer, password reset,
// session lifecycle, device-pairing transitions). The Recorder writes to
// the audit_events table; the table is append-only — no DELETE/UPDATE
// statements exist in production code paths.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/store"
)

// Recorder is the audit-write interface used by HTTP handlers. Insert
// failures are logged but do not bubble up — auditing must not break the
// underlying action when, e.g., the audit_events insert hits a transient
// disk error. A future hardening pass can promote this to a synchronous
// fail-closed mode if needed.
type Recorder interface {
	Record(ctx context.Context, e store.AuditEvent)
}

// SQLRecorder is the in-process implementation backed by AuditStore.
type SQLRecorder struct {
	Store  store.AuditStore
	Logger *slog.Logger
	Now    func() time.Time
}

// New constructs a SQLRecorder.
func New(s store.AuditStore, logger *slog.Logger) *SQLRecorder {
	return &SQLRecorder{Store: s, Logger: logger, Now: time.Now}
}

// Record persists e. ID and At are populated when zero-valued so callers
// can omit them.
func (r *SQLRecorder) Record(ctx context.Context, e store.AuditEvent) {
	if r == nil || r.Store == nil {
		return
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.At.IsZero() {
		e.At = r.Now().UTC()
	}
	if err := r.Store.Insert(ctx, e); err != nil && r.Logger != nil {
		r.Logger.WarnContext(ctx, "audit recorder insert failed",
			slog.String("action", e.Action),
			slog.String("target_type", e.TargetType),
			slog.String("target_id", e.TargetID),
			slog.Any("err", err),
		)
	}
}

// Action constants — collected here so handlers don't sprinkle string
// literals.
const (
	ActionInviteCreate         = "invite.create"
	ActionInviteRevoke         = "invite.revoke"
	ActionInviteConsume        = "invite.consume"
	ActionUserCreate           = "user.create"
	ActionUserDeactivate       = "user.deactivate"
	ActionUserReactivate       = "user.reactivate"
	ActionUserRoleChange       = "user.role_change"
	ActionUserUpdate           = "user.update"
	ActionUserPasswordReset    = "user.password_reset"
	ActionTokenTransferOwner   = "token.transfer_owner"
	ActionSubscriptionTransferOwner = "subscription.transfer_owner"
	ActionSessionCreate        = "session.create"
	ActionSessionDelete        = "session.delete"
	ActionDevicePairingStart   = "device_pairing.start"
	ActionDevicePairingApprove = "device_pairing.approve"
	ActionDevicePairingDeny    = "device_pairing.deny"
)
