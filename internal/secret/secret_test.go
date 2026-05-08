package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStringRedactsOnPrintAndJSON(t *testing.T) {
	s := String("super-secret-token")
	if got := s.String(); strings.Contains(got, "super-secret-token") {
		t.Fatalf("String() leaked plaintext: %q", got)
	}
	if got := fmt.Sprintf("%v", s); strings.Contains(got, "super-secret-token") {
		t.Fatalf("%%v leaked plaintext: %q", got)
	}
	if got := fmt.Sprintf("%+v", s); strings.Contains(got, "super-secret-token") {
		t.Fatalf("%%+v leaked plaintext: %q", got)
	}
	if got := fmt.Sprintf("%#v", s); strings.Contains(got, "super-secret-token") {
		t.Fatalf("%%#v leaked plaintext: %q", got)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), "super-secret-token") {
		t.Fatalf("MarshalJSON leaked plaintext: %s", b)
	}
}

func TestRevealReturnsPlaintext(t *testing.T) {
	s := String("plain")
	if s.Reveal() != "plain" {
		t.Fatalf("Reveal() = %q, want %q", s.Reveal(), "plain")
	}
}

func TestEqual(t *testing.T) {
	if !Equal([]byte("abc"), []byte("abc")) {
		t.Fatalf("Equal of equal slices returned false")
	}
	if Equal([]byte("abc"), []byte("abd")) {
		t.Fatalf("Equal of different slices returned true")
	}
	if EqualString("abc", "abc") != true {
		t.Fatalf("EqualString of equal strings returned false")
	}
	if EqualString("abc", "abd") != false {
		t.Fatalf("EqualString of different strings returned true")
	}
}

func TestEmpty(t *testing.T) {
	if !String("").Empty() {
		t.Fatalf("empty String not Empty()")
	}
	if String("x").Empty() {
		t.Fatalf("non-empty String reported Empty()")
	}
}
