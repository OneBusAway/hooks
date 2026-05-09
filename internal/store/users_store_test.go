package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenSQLite(filepath.Join(dir, "test.db"), SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustInsertUser(t *testing.T, s *SQLite, id, email string, role Role) {
	t.Helper()
	err := s.InsertUser(context.Background(), User{
		ID: id, Email: email, Name: "n", Role: role,
		PasswordHash: "h", DefaultScopes: []string{},
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("InsertUser %s: %v", id, err)
	}
}

func TestUsers_EmailUniqueness_CaseInsensitive(t *testing.T) {
	s := newTestStore(t)
	mustInsertUser(t, s, "u1", "Aaron@Example.COM", RoleUser)
	err := s.InsertUser(context.Background(), User{
		ID: "u2", Email: "AARON@example.com", Name: "n", Role: RoleUser,
		PasswordHash: "h", DefaultScopes: []string{},
		CreatedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("duplicate email should fail")
	}
}

func TestUsers_GetByEmail_CaseInsensitive(t *testing.T) {
	s := newTestStore(t)
	mustInsertUser(t, s, "u1", "Aaron@example.COM", RoleUser)
	u, err := s.GetUserByEmail(context.Background(), "aaron@EXAMPLE.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if u.ID != "u1" {
		t.Fatalf("got %s", u.ID)
	}
}

func TestUsers_DeactivateCascade_RevokesTokensAndPausesSubs(t *testing.T) {
	s := newTestStore(t)
	mustInsertUser(t, s, "u1", "a@example.com", RoleUser)
	owner := "u1"

	// Owned token + sub.
	if err := s.Insert(context.Background(), Token{
		ID: "t1", Name: "x", Scopes: []string{"render"}, SecretHash: "h",
		CreatedAt:   time.Now().UTC(),
		OwnerUserID: &owner, Kind: TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertPush(context.Background(), PushSubscription{
		ID: "p1", Source: "render", TargetURL: "http://x", SigningSecretHash: "h",
		CreatedAt:   time.Now().UTC(),
		OwnerUserID: &owner,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := s.DeactivateUserCascade(context.Background(), "u1", time.Now().UTC())
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if res.TokensRevoked != 1 {
		t.Errorf("TokensRevoked=%d want 1", res.TokensRevoked)
	}
	if res.SubscriptionsPaused != 1 {
		t.Errorf("SubscriptionsPaused=%d want 1", res.SubscriptionsPaused)
	}

	// User row reflects deactivation.
	u, _ := s.GetUserByID(context.Background(), "u1")
	if u.DeactivatedAt == nil {
		t.Errorf("user not marked deactivated")
	}
	// Token revoked.
	tok, _ := s.GetToken(context.Background(), "t1")
	if tok.RevokedAt == nil {
		t.Errorf("token not revoked")
	}
	// Subscription paused.
	sub, _ := s.GetPush(context.Background(), "p1")
	if sub.PausedAt == nil {
		t.Errorf("subscription not paused")
	}
}

func TestUsers_LastAdminGuard(t *testing.T) {
	s := newTestStore(t)
	mustInsertUser(t, s, "a1", "a1@example.com", RoleAdmin)

	_, err := s.DeactivateUserCascade(context.Background(), "a1", time.Now().UTC())
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("want ErrLastAdmin, got %v", err)
	}

	// Add a second admin and now deactivation succeeds.
	mustInsertUser(t, s, "a2", "a2@example.com", RoleAdmin)
	if _, err := s.DeactivateUserCascade(context.Background(), "a1", time.Now().UTC()); err != nil {
		t.Fatalf("deactivate with two admins: %v", err)
	}
}

func TestSessions_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	mustInsertUser(t, s, "u1", "u1@example.com", RoleUser)
	now := time.Now().UTC().Truncate(time.Microsecond)

	in := Session{
		ID: "sess1", UserID: "u1", SecretHash: "h",
		CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour),
		UserAgent: "test", IP: "127.0.0.1",
	}
	if err := s.InsertSession(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(context.Background(), "sess1")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" || got.UserAgent != "test" {
		t.Errorf("roundtrip: %+v", got)
	}

	if err := s.TouchSession(context.Background(), "sess1", now.Add(time.Minute), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(context.Background(), "sess1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(context.Background(), "sess1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestInvites_BootstrapEnsureIdempotent(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	codes := []string{"FRESH1", "FRESH2"}
	idx := 0
	codeFn := func() string {
		c := codes[idx]
		idx++
		return c
	}

	first, err := s.EnsureBootstrapInvite(context.Background(), codeFn, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Code != "FRESH1" {
		t.Fatalf("first code: %s", first.Code)
	}

	// Second call within 24h returns the same code (idempotent).
	second, err := s.EnsureBootstrapInvite(context.Background(), codeFn, 24*time.Hour, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Code != "FRESH1" {
		t.Errorf("second call should return FRESH1, got %s", second.Code)
	}

	// After expiry, the call replaces the row with a fresh code.
	third, err := s.EnsureBootstrapInvite(context.Background(), codeFn, 24*time.Hour, now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if third.Code != "FRESH2" {
		t.Errorf("post-expiry code: %s", third.Code)
	}
}

// TestSignupTx_PrimaryKeyCollision_NotEmailInUse covers §16 review
// finding #4: a UNIQUE-violation on users.id (PK) must NOT be
// classified as ErrEmailInUse. The classifier looks for the email
// constraint specifically; an unrelated PK collision should surface
// the raw error so callers can decide what to do (typically: log and
// 500, since a UUID collision is an internal-state surprise, not a
// user-facing 409).
func TestSignupTx_PrimaryKeyCollision_NotEmailInUse(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()

	// Pre-seed a user occupying ID "fixed-id".
	mustInsertUser(t, s, "fixed-id", "first@example.com", RoleUser)

	// Open a fresh invite for the second signup.
	if err := s.InsertInvite(context.Background(), Invite{
		Code: "INVITE2", Role: RoleUser, DefaultScopes: []string{},
		CreatedAt: now, ExpiresAt: timePtr(now.Add(time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}

	// SignupTx with the *same* user ID but a *different* email. This
	// must trigger a PK collision on users.id, not the email index.
	err := s.SignupTx(context.Background(), "INVITE2", User{
		ID: "fixed-id", Email: "different@example.com",
		Name: "n", Role: RoleUser, PasswordHash: "h",
		DefaultScopes: []string{}, CreatedAt: now,
	}, now)
	if err == nil {
		t.Fatal("expected error on PK collision, got nil")
	}
	if errors.Is(err, ErrEmailInUse) {
		t.Errorf("PK collision misclassified as ErrEmailInUse; got %v", err)
	}
}

func TestInvites_SignupTx_RaceSingleWinner(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	if err := s.InsertInvite(context.Background(), Invite{
		Code: "RACE1", Role: RoleUser, DefaultScopes: []string{},
		CreatedAt: now, ExpiresAt: timePtr(now.Add(7 * 24 * time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}

	const N = 4
	var wg sync.WaitGroup
	wg.Add(N)
	results := make(chan error, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			err := s.SignupTx(context.Background(), "RACE1", User{
				ID:    fmtUser(i),
				Email: fmtEmail(i),
				Name:  "n", Role: RoleUser, PasswordHash: "h",
				DefaultScopes: []string{}, CreatedAt: now,
			}, now)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	var ok, consumed int
	for r := range results {
		switch {
		case r == nil:
			ok++
		case errors.Is(r, ErrInviteConsumed):
			consumed++
		default:
			t.Errorf("unexpected race err: %v", r)
		}
	}
	if ok != 1 {
		t.Errorf("ok=%d, want exactly 1 winner", ok)
	}
	if consumed != N-1 {
		t.Errorf("consumed=%d, want %d losers", consumed, N-1)
	}
}

func timePtr(t time.Time) *time.Time { return &t }
func fmtUser(i int) string           { return "user-" + itoa(i) }
func fmtEmail(i int) string          { return "u" + itoa(i) + "@example.com" }
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for n := i; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}
