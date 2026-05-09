package auth

import (
	"log/slog"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/audit"
)

// TestNewManager_DefaultsAndAccessors confirms the Tier-3 17.1 refactor:
// the only public way to construct a Manager is NewManager, which fills
// the unexported sessions/users/audit/now/cookies fields. The accessors
// Auditor() and TrustProxyHeaders() expose what external packages
// (currently internal/webpages) need without re-exporting the fields.
func TestNewManager_DefaultsAndAccessors(t *testing.T) {
	s := newTestStore(t)
	rec := audit.New(s.Audit(), nil)

	m := NewManager(s.Sessions(), s.Users(), rec, CookieOptions{
		TrustProxyHeaders: true,
	})
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	// Auditor returns the recorder we passed in.
	if m.Auditor() != rec {
		t.Errorf("Auditor() did not round-trip the recorder")
	}
	// TrustProxyHeaders reflects the constructor option.
	if !m.TrustProxyHeaders() {
		t.Errorf("TrustProxyHeaders() = false, want true")
	}
	// Default TTL is applied when the caller passes zero.
	if m.cookies.TTL != DefaultSessionTTL {
		t.Errorf("default TTL not applied: got %v", m.cookies.TTL)
	}
	// Default time source is wired (we just check it's non-nil and
	// returns a sane time).
	if m.now == nil {
		t.Fatal("now is nil")
	}
	if m.now().IsZero() {
		t.Error("now() returned zero time")
	}
}

// TestSetLogger_RoutesIntoWarn confirms that the SetLogger setter is the
// post-construction logger-attachment path used by server.Build. Without
// SetLogger, the warn helper must be a no-op (no nil-deref).
func TestSetLogger_RoutesIntoWarn(t *testing.T) {
	s := newTestStore(t)
	m := NewManager(s.Sessions(), s.Users(), audit.New(s.Audit(), nil),
		CookieOptions{TTL: time.Hour})
	api := NewAPI(m)

	// Without SetLogger, warn must not panic.
	api.warn(t.Context(), "no logger attached")

	// SetLogger attaches a real logger; warn writes through it.
	m.SetLogger(slog.New(slog.DiscardHandler))
	api.warn(t.Context(), "logger attached")
}
