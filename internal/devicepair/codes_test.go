package devicepair

import (
	"strings"
	"testing"
)

// TestUserCodeAlphabet_MatchesSpec is the regression for the alphabet fix.
// design.md and tasks.md §7.1 specify exactly:
//
//	23456789ABCDEFGHJKMNPQRSTUVWXYZ
//
// — 31 chars, base32 minus 0/1/I/L/O. The original implementation dropped
// `U` too (30 chars), diverging from the spec.
func TestUserCodeAlphabet_MatchesSpec(t *testing.T) {
	want := "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	if userCodeAlphabet != want {
		t.Errorf("userCodeAlphabet diverges from spec\n  got:  %q (%d chars)\n  want: %q (%d chars)",
			userCodeAlphabet, len(userCodeAlphabet), want, len(want))
	}
	if len(userCodeAlphabet) != 31 {
		t.Errorf("alphabet length: got %d, want 31", len(userCodeAlphabet))
	}
	// Forbidden chars must be absent.
	for _, c := range "01ILO" {
		if strings.ContainsRune(userCodeAlphabet, c) {
			t.Errorf("alphabet contains forbidden char %q", c)
		}
	}
}

// TestNewUserCode_NoModuloBias generates many codes and checks the
// distribution of each output position. The original implementation used
// `rand_byte % 31` which over [0,256) maps codepoints 0..15 to 9/256
// frequency vs 8/256 for the rest. With rejection sampling, all codepoints
// must be ~equally likely. We use a relative tolerance so the test is
// robust to randomness; with N=31000 samples and 31 buckets the expected
// count is 1000 per bucket and chi-square's 99% threshold for 30 d.o.f.
// is ~50 — i.e. a per-bucket deviation greater than ~150 is suspicious.
func TestNewUserCode_NoModuloBias(t *testing.T) {
	const N = 31000
	counts := make(map[byte]int, len(userCodeAlphabet))
	for c := 0; c < len(userCodeAlphabet); c++ {
		counts[userCodeAlphabet[c]] = 0
	}
	for i := 0; i < N; i++ {
		code, err := NewUserCode()
		if err != nil {
			t.Fatalf("NewUserCode: %v", err)
		}
		// Accumulate every alphabet position (skip the '-').
		for j := 0; j < len(code); j++ {
			if code[j] == '-' {
				continue
			}
			if _, ok := counts[code[j]]; !ok {
				t.Fatalf("code %q contains char %q outside alphabet", code, code[j])
			}
			counts[code[j]]++
		}
	}
	// Each code has 8 alphabet chars; total samples = 8*N. Expected per
	// bucket = 8*N / 31.
	expected := float64(8*N) / float64(len(userCodeAlphabet))
	// Chi-square statistic.
	var chi2 float64
	for _, n := range counts {
		diff := float64(n) - expected
		chi2 += diff * diff / expected
	}
	// 99.9% threshold for 30 d.o.f. is 59.7. Modulo-bias on [0,256)%31
	// produces an excess of ~12.5% for codepoints 0..15 (16/31*256 vs
	// 15/31*256 wraps), giving chi2 well above 100 at this sample size.
	if chi2 > 60 {
		t.Errorf("modulo-bias suspected: chi-square=%.1f over 30 d.o.f. (threshold 60)\n"+
			"distribution: %v", chi2, counts)
	}
}

func TestNewUserCode_ShapeAndAlphabet(t *testing.T) {
	for i := 0; i < 32; i++ {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Errorf("user_code shape: %q", c)
		}
		for j := 0; j < len(c); j++ {
			if c[j] == '-' {
				continue
			}
			if !strings.ContainsRune(userCodeAlphabet, rune(c[j])) {
				t.Errorf("code %q contains char %q outside alphabet", c, c[j])
			}
		}
	}
}
