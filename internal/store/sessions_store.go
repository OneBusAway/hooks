package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
)

func sessionFromGen(r sqlcgen.UserSession) Session {
	return Session{
		ID:         r.ID,
		UserID:     r.UserID,
		SecretHash: r.SecretHash,
		CreatedAt:  time.Unix(0, r.CreatedAt).UTC(),
		LastUsedAt: time.Unix(0, r.LastUsedAt).UTC(),
		ExpiresAt:  time.Unix(0, r.ExpiresAt).UTC(),
		UserAgent:  r.UserAgent,
		IP:         r.Ip,
	}
}

func (s *SQLite) InsertSession(ctx context.Context, sess Session) error {
	if sess.ID == "" {
		return errors.New("InsertSession: empty id")
	}
	return s.q.InsertSession(ctx, sqlcgen.InsertSessionParams{
		ID:         sess.ID,
		UserID:     sess.UserID,
		SecretHash: sess.SecretHash,
		CreatedAt:  sess.CreatedAt.UTC().UnixNano(),
		LastUsedAt: sess.LastUsedAt.UTC().UnixNano(),
		ExpiresAt:  sess.ExpiresAt.UTC().UnixNano(),
		UserAgent:  sess.UserAgent,
		Ip:         sess.IP,
	})
}

func (s *SQLite) GetSession(ctx context.Context, id string) (Session, error) {
	row, err := s.q.GetSession(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	return sessionFromGen(row), nil
}

func (s *SQLite) TouchSession(ctx context.Context, id string, lastUsedAt, expiresAt time.Time) error {
	return s.q.TouchSession(ctx, sqlcgen.TouchSessionParams{
		LastUsedAt: lastUsedAt.UTC().UnixNano(),
		ExpiresAt:  expiresAt.UTC().UnixNano(),
		ID:         id,
	})
}

func (s *SQLite) DeleteSession(ctx context.Context, id string) error {
	n, err := s.q.DeleteSession(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteSessionsByUser(ctx context.Context, userID string) error {
	_, err := s.q.DeleteSessionsByUser(ctx, userID)
	return err
}

func (s *SQLite) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	return s.q.DeleteExpiredSessions(ctx, before.UTC().UnixNano())
}
