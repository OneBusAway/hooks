package tokens

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/store"
)

// touchCountingStore decorates a real TokenStore but counts TouchLastUsed calls.
type touchCountingStore struct {
	store.TokenStore
	touches atomic.Int64
}

func (c *touchCountingStore) TouchLastUsed(ctx context.Context, id string, when time.Time) error {
	c.touches.Add(1)
	return c.TokenStore.TouchLastUsed(ctx, id, when)
}

func TestMaybeTouchDebounce(t *testing.T) {
	st := newSQLite(t)
	res, err := Issue(context.Background(), st.Tokens(), "x", []string{"render"})
	if err != nil {
		t.Fatal(err)
	}

	counter := &touchCountingStore{TokenStore: st.Tokens()}
	auth := New(counter)

	now := time.Unix(1_700_000_000, 0)
	auth.Now = func() time.Time { return now }

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+res.Plaintext)

	if _, err := auth.Resolve(r); err != nil {
		t.Fatal(err)
	}
	if got := counter.touches.Load(); got != 1 {
		t.Fatalf("first auth: touches=%d, want 1", got)
	}

	// Second auth within the window: no new write.
	now = now.Add(TouchInterval - time.Second)
	if _, err := auth.Resolve(r); err != nil {
		t.Fatal(err)
	}
	if got := counter.touches.Load(); got != 1 {
		t.Fatalf("second auth (within window): touches=%d, want 1", got)
	}

	// Third auth after the window: a new write.
	now = now.Add(2 * TouchInterval)
	if _, err := auth.Resolve(r); err != nil {
		t.Fatal(err)
	}
	if got := counter.touches.Load(); got != 2 {
		t.Fatalf("third auth (past window): touches=%d, want 2", got)
	}
}

func TestResolvePlaintextErrors(t *testing.T) {
	st := newSQLite(t)
	res, _ := Issue(context.Background(), st.Tokens(), "x", []string{"render"})
	auth := New(st.Tokens())

	if _, err := auth.ResolvePlaintext(context.Background(), ""); !errors.Is(err, errMissingToken) {
		t.Fatalf("empty plaintext: got %v, want errMissingToken", err)
	}
	if _, err := auth.ResolvePlaintext(context.Background(), "bogus"); !errors.Is(err, errInvalidToken) {
		t.Fatalf("bogus plaintext: got %v, want errInvalidToken", err)
	}

	// Revoke and confirm subsequent lookup is rejected.
	tok, _ := st.Tokens().LookupByPlaintext(context.Background(), res.Plaintext)
	if err := st.Tokens().Revoke(context.Background(), tok.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ResolvePlaintext(context.Background(), res.Plaintext); !errors.Is(err, errInvalidToken) {
		t.Fatalf("revoked plaintext: got %v", err)
	}
}

func TestResolvePlaintextHappyPath(t *testing.T) {
	st := newSQLite(t)
	res, _ := Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})
	auth := New(st.Tokens())

	tok, err := auth.ResolvePlaintext(context.Background(), res.Plaintext)
	if err != nil {
		t.Fatalf("ResolvePlaintext: %v", err)
	}
	if !store.HasScope(tok.Scopes, store.ScopeAdmin) {
		t.Fatalf("scopes lost: %v", tok.Scopes)
	}
}
