package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestLookupByPlaintext_WarnsOnHashError ensures LookupByPlaintext logs a
// warn keyed by the row ID when the injected hash comparator returns an
// error (i.e. a corrupted secret_hash column). Otherwise valid plaintexts
// would silently miss against good rows further down the list.
func TestLookupByPlaintext_WarnsOnHashError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Two active tokens. The first will be the corrupted-hash row, the
	// second will be the valid match.
	if err := s.Insert(ctx, Token{
		ID: "tok_corrupt", Name: "corrupt",
		Scopes: []string{"render"}, SecretHash: "BROKEN-HASH",
		CreatedAt: time.Now().UTC(), Kind: TokenKindListener,
	}); err != nil {
		t.Fatalf("insert corrupt: %v", err)
	}
	if err := s.Insert(ctx, Token{
		ID: "tok_good", Name: "good",
		Scopes: []string{"render"}, SecretHash: "GOOD-HASH",
		CreatedAt: time.Now().UTC(), Kind: TokenKindListener,
	}); err != nil {
		t.Fatalf("insert good: %v", err)
	}

	// Comparator: error on corrupted row, match on the good one.
	s.SetTokenHashCompare(func(plaintext, encoded string) (bool, error) {
		if encoded == "BROKEN-HASH" {
			return false, errors.New("malformed encoded hash")
		}
		return encoded == "GOOD-HASH" && plaintext == "secret", nil
	})

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s.SetLogger(logger)

	tok, err := s.LookupByPlaintext(ctx, "secret")
	if err != nil {
		t.Fatalf("LookupByPlaintext: %v", err)
	}
	if tok.ID != "tok_good" {
		t.Fatalf("matched wrong token: %s", tok.ID)
	}

	out := logBuf.String()
	if !strings.Contains(out, "tok_corrupt") {
		t.Errorf("expected warn to mention corrupt row id; got: %s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "WARN") {
		t.Errorf("expected WARN level log; got: %s", out)
	}
}
