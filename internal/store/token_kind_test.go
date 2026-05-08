package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestInsert_RejectsEmptyTokenKind is the regression for the silent-coercion
// fix: a Token literal that omits Kind must NOT be silently authorized as
// a listener token (which would grant /subscribe/<source> access). Callers
// must explicitly choose a kind.
func TestInsert_RejectsEmptyTokenKind(t *testing.T) {
	s := newTestStore(t)
	err := s.Insert(context.Background(), Token{
		ID: "t1", Name: "x",
		Scopes: []string{"render"}, SecretHash: "h",
		CreatedAt: time.Now().UTC(),
		// Kind deliberately omitted.
	})
	if !errors.Is(err, ErrTokenKindRequired) {
		t.Fatalf("Insert with empty Kind: got err=%v, want ErrTokenKindRequired", err)
	}
}

func TestInsert_AcceptsExplicitListener(t *testing.T) {
	s := newTestStore(t)
	if err := s.Insert(context.Background(), Token{
		ID: "t-listener", Name: "x", Scopes: []string{"render"}, SecretHash: "h",
		CreatedAt: time.Now().UTC(), Kind: TokenKindListener,
	}); err != nil {
		t.Fatalf("explicit listener: %v", err)
	}
}

func TestInsert_AcceptsExplicitPAT(t *testing.T) {
	s := newTestStore(t)
	if err := s.Insert(context.Background(), Token{
		ID: "t-pat", Name: "x", Scopes: []string{"render"}, SecretHash: "h",
		CreatedAt: time.Now().UTC(), Kind: TokenKindPAT,
	}); err != nil {
		t.Fatalf("explicit pat: %v", err)
	}
}
