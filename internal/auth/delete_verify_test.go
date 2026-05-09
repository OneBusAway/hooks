package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
)

// TestDeleteSession_RejectsForgedCookie is the regression for the security
// fix: anyone holding only the session id (e.g. via a stale log line)
// must not be able to force-logout a victim. DeleteSession must look up
// the row and constant-time verify the secret half before deleting.
func TestDeleteSession_RejectsForgedCookie(t *testing.T) {
	m, s, u := newManagerWithUser(t, "alice@example.com", "supercalifragilistic", store.RoleUser, false)

	// Create a real session as alice.
	plaintext, _ := secret.NewRandom()
	id := uuid.NewString()
	sess := store.Session{
		ID: id, UserID: u.ID, SecretHash: hashSessionSecret(plaintext),
		CreatedAt: m.now().UTC(), LastUsedAt: m.now().UTC(),
		ExpiresAt: m.now().UTC().Add(time.Hour),
	}
	if err := s.InsertSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	// Adversary holds the id but a wrong plaintext (e.g. truncated log line).
	forgedCookie := id + "." + "wrong-plaintext"
	gotID, err := m.DeleteSession(context.Background(), forgedCookie)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("DeleteSession with forged cookie: got err=%v, want ErrInvalid", err)
	}
	if gotID != "" {
		t.Errorf("DeleteSession returned id=%q despite verification failure", gotID)
	}

	// And the row must still exist.
	if _, err := s.GetSession(context.Background(), id); err != nil {
		t.Errorf("victim session was deleted by forged cookie: %v", err)
	}

	// Sanity: legitimate cookie still deletes the row.
	gotID, err = m.DeleteSession(context.Background(), id+"."+plaintext)
	if err != nil {
		t.Fatalf("legitimate DeleteSession: %v", err)
	}
	if gotID != id {
		t.Errorf("legitimate id: got %q, want %q", gotID, id)
	}
	if _, err := s.GetSession(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("legitimate session not deleted: %v", err)
	}
}
