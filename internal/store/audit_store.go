package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
)

func auditEventFromGen(r sqlcgen.AuditEvent) (AuditEvent, error) {
	ev := AuditEvent{
		ID:           r.ID,
		At:           time.Unix(0, r.At).UTC(),
		ActorUserID:  ptrFromNullString(r.ActorUserID),
		ActorTokenID: ptrFromNullString(r.ActorTokenID),
		Action:       AuditAction(r.Action),
		TargetType:   AuditTargetType(r.TargetType),
		TargetID:     r.TargetID,
	}
	if r.Metadata != "" {
		if err := json.Unmarshal([]byte(r.Metadata), &ev.Metadata); err != nil {
			return AuditEvent{}, err
		}
	}
	if ev.Metadata == nil {
		ev.Metadata = map[string]any{}
	}
	return ev, nil
}

func (s *SQLite) InsertAuditEvent(ctx context.Context, e AuditEvent) error {
	if e.ID == "" {
		return errors.New("InsertAuditEvent: empty id")
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return s.q.InsertAuditEvent(ctx, sqlcgen.InsertAuditEventParams{
		ID:           e.ID,
		At:           e.At.UTC().UnixNano(),
		ActorUserID:  nullStringPtr(e.ActorUserID),
		ActorTokenID: nullStringPtr(e.ActorTokenID),
		Action:       string(e.Action),
		TargetType:   string(e.TargetType),
		TargetID:     e.TargetID,
		Metadata:     string(mb),
	})
}

func (s *SQLite) ListAuditEvents(ctx context.Context, q AuditQuery) ([]AuditEvent, error) {
	limit := int64(q.Limit)
	if limit <= 0 {
		limit = 200
	}
	params := sqlcgen.ListAuditEventsParams{
		FilterActor: int64(0),
		FilterSince: int64(0),
		FilterUntil: int64(0),
		Lim:         limit,
	}
	if q.ActorUserID != nil {
		params.FilterActor = int64(1)
		params.ActorID = nullStringPtr(q.ActorUserID)
	}
	if q.Since != nil {
		params.FilterSince = int64(1)
		params.Since = q.Since.UTC().UnixNano()
	}
	if q.Until != nil {
		params.FilterUntil = int64(1)
		params.Until = q.Until.UTC().UnixNano()
	}
	rows, err := s.q.ListAuditEvents(ctx, params)
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev, err := auditEventFromGen(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}
