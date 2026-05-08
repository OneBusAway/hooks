package users

import (
	"testing"

	"github.com/onebusaway/hooks/internal/secret"
)

func TestPasswordHashAndVerify_Roundtrip(t *testing.T) {
	pw := secret.String("a-strong-passphrase-12345")
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("empty hash")
	}
	ok, err := VerifyPassword(pw, hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("verify returned false for correct password")
	}
}

func TestPasswordVerify_WrongPassword(t *testing.T) {
	hash, err := HashPassword(secret.String("correct-horse-battery-staple"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(secret.String("incorrect-horse-stable-batter"), hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("verify returned true for wrong password")
	}
}

func TestPasswordVerify_MalformedHashReturnsFalseAndNoError(t *testing.T) {
	ok, err := VerifyPassword(secret.String("anything-12345"), "not-a-real-hash")
	if err != nil {
		t.Fatalf("verify on bad hash should not error: %v", err)
	}
	if ok {
		t.Fatal("verify returned true on malformed hash")
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		pw        string
		wantPass  bool
		wantReason string
	}{
		{"too short", "a@b.com", "short", false, ReasonTooShort},
		{"barely long enough", "a@b.com", "abcdefghijkl", true, ""},
		{"contains email", "alice@ex.com", "alice@ex.compass", false, ReasonContainsEmail},
		{"contains email case-insensitive", "Alice@Ex.com", "abcALICE@EX.coMM", false, ReasonContainsEmail},
		{"contains local-part", "alice@ex.com", "abcalice12345xyz", false, ReasonContainsEmail},
		{"good password", "alice@ex.com", "supercalifragilistic", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.email, secret.String(tt.pw))
			if tt.wantPass {
				if err != nil {
					t.Errorf("expected pass, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected fail, got nil")
			}
			if !IsPolicyError(err) {
				t.Errorf("expected PolicyError, got %T", err)
			}
		})
	}
}
