package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/audit"
	"github.com/onebusaway/hooks/internal/auth"
	"github.com/onebusaway/hooks/internal/ratelimit"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/users"
)

// TestWrapUserRateLimit_Fires confirms the per-user limiter actually
// rate-limits a session-authenticated caller. An earlier wiring had the
// user-id tag step happen INSIDE the limiter (after KeyByUser had already
// run), so the limiter saw "" and silently bypassed every request.
func TestWrapUserRateLimit_Fires(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "rl.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	hash, err := users.HashPassword(secret.String("supercalifragilistic"))
	if err != nil {
		t.Fatal(err)
	}
	u := store.User{
		ID: uuid.NewString(), Email: "alice@example.com", Name: "Alice",
		Role: store.RoleUser, PasswordHash: hash, CreatedAt: time.Now().UTC(),
	}
	if err := st.InsertUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	rec := audit.New(st.Audit(), nil)
	mgr := auth.NewManager(st.Sessions(), st.Users(), rec, auth.CookieOptions{TTL: time.Hour})

	limiter := ratelimit.New(ratelimit.Limit{Per: time.Hour, Burst: 1})
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	})

	handler := mgr.Middleware(wrapUserRateLimit(mgr, limiter, inner))

	cookieVal, _, err := mgr.CreateSession(context.Background(), u.ID, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	send := func() int {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookieVal})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := send(); got != http.StatusNoContent {
		t.Fatalf("first call: %d (want 204)", got)
	}
	if got := send(); got != http.StatusTooManyRequests {
		t.Fatalf("second call: %d (want 429); per-user limiter is bypassed", got)
	}
	if calls != 1 {
		t.Errorf("inner called %d times, want 1", calls)
	}
}
