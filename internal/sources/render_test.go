package sources

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

// sign builds a Standard Webhooks Webhook-Signature header value over
// "<id>.<ts>.<body>" with the given secret.
func sign(secret, id, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(id))
	m.Write([]byte("."))
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func renderHeaders(id, ts, sig string) http.Header {
	h := http.Header{}
	h.Set(standardwebhooks.HeaderWebhookID, id)
	h.Set(standardwebhooks.HeaderWebhookTimestamp, ts)
	h.Set(standardwebhooks.HeaderWebhookSignature, sig)
	return h
}

func mustVerify(t *testing.T, opts Options) Verifier {
	t.Helper()
	v, ok := Default.Build("render", "shhh", opts)
	if !ok {
		t.Fatal("render not registered")
	}
	return v
}

func TestRenderValidSignature(t *testing.T) {
	body := []byte(`{"event":"deploy"}`)
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := sign("shhh", "delivery-1", ts, body)
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	tsOut, idOut, err := v.Verify(renderHeaders("delivery-1", ts, sig), body)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if idOut != "delivery-1" {
		t.Fatalf("delivery_id = %q", idOut)
	}
	if !tsOut.Equal(now) {
		t.Fatalf("timestamp = %v, want %v", tsOut, now)
	}
}

func TestRenderTamperedBody(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := sign("shhh", "d", ts, []byte("original"))
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	_, _, err := v.Verify(renderHeaders("d", ts, sig), []byte("tampered"))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v, want ErrInvalidSignature", err)
	}
}

func TestRenderWrongSecret(t *testing.T) {
	body := []byte("hi")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := sign("not-the-real-secret", "d", ts, body)
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	_, _, err := v.Verify(renderHeaders("d", ts, sig), body)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v", err)
	}
}

// An unparseable signature value is treated as "no matching signature" by the
// Standard Webhooks library — security-equivalent to a wrong signature, and
// the consumer-visible response is the same HTTP 401 either way.
func TestRenderMalformedSignature(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	_, _, err := v.Verify(renderHeaders("d", ts, "garbage"), []byte("body"))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestRenderMissingHeader(t *testing.T) {
	v := mustVerify(t, Options{})
	cases := []http.Header{
		{},
		renderHeaders("", "1", "v1,ab"),
		renderHeaders("d", "", "v1,ab"),
		renderHeaders("d", "1", ""),
	}
	for i, h := range cases {
		_, _, err := v.Verify(h, []byte(""))
		if !errors.Is(err, ErrMissingHeader) {
			t.Fatalf("case %d: got %v", i, err)
		}
	}
}

func TestRenderStaleTimestamp(t *testing.T) {
	now := time.Now()
	tsTime := now.Add(-10 * time.Minute)
	ts := strconv.FormatInt(tsTime.Unix(), 10)
	body := []byte("hi")
	sig := sign("shhh", "d", ts, body)
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	_, _, err := v.Verify(renderHeaders("d", ts, sig), body)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("got %v", err)
	}
}

func TestRenderFutureTimestamp(t *testing.T) {
	now := time.Now()
	tsTime := now.Add(10 * time.Minute)
	ts := strconv.FormatInt(tsTime.Unix(), 10)
	body := []byte("hi")
	sig := sign("shhh", "d", ts, body)
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	_, _, err := v.Verify(renderHeaders("d", ts, sig), body)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("got %v", err)
	}
}

func TestRenderConfigurableSkew(t *testing.T) {
	now := time.Now()
	tsTime := now.Add(-10 * time.Minute)
	ts := strconv.FormatInt(tsTime.Unix(), 10)
	body := []byte("hi")
	sig := sign("shhh", "d", ts, body)
	v := mustVerify(t, Options{
		Now:        func() time.Time { return now },
		SkewWindow: 30 * time.Minute, // accept 10m old
	})

	if _, _, err := v.Verify(renderHeaders("d", ts, sig), body); err != nil {
		t.Fatalf("with 30m skew, 10m-old should pass: %v", err)
	}
}

// Standard Webhooks supports rotation by listing multiple "v1,<sig>" tokens
// space-separated; any single match must verify.
func TestRenderMultipleSignaturesOneMatches(t *testing.T) {
	body := []byte("hi")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	good := sign("shhh", "d", ts, body)
	bad := sign("nope", "d", ts, body)
	v := mustVerify(t, Options{Now: func() time.Time { return now }})

	if _, _, err := v.Verify(renderHeaders("d", ts, bad+" "+good), body); err != nil {
		t.Fatalf("expected one matching v1 entry to verify: %v", err)
	}
}

// "whsec_<base64>" secrets are decoded to raw bytes before HMAC; passing the
// raw bytes directly should produce the same signature.
func TestRenderWhsecPrefixedSecret(t *testing.T) {
	rawKey := []byte("super-secret-bytes")
	encoded := "whsec_" + base64.StdEncoding.EncodeToString(rawKey)

	body := []byte("hi")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := sign(string(rawKey), "d", ts, body) // sign with the raw bytes

	vEnc, _ := Default.Build("render", encoded, Options{Now: func() time.Time { return now }})
	if _, _, err := vEnc.Verify(renderHeaders("d", ts, sig), body); err != nil {
		t.Fatalf("whsec_-prefixed secret should decode and verify: %v", err)
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic")
		}
	}()
	r := NewRegistry()
	r.Register("x", newRenderVerifier)
	r.Register("x", newRenderVerifier)
}

func TestRegistryHas(t *testing.T) {
	if !Default.Has("render") {
		t.Fatalf("render not in default registry")
	}
}

// stripped down, doc'd example: a custom plugin
func TestNewSourceRegistersCleanly(t *testing.T) {
	reg := NewRegistry()
	called := false
	reg.Register("custom", func(secret string, opts Options) Verifier {
		called = true
		return newRenderVerifier(secret, opts)
	})
	if !reg.Has("custom") {
		t.Fatal("Has() lied")
	}
	if _, ok := reg.Build("custom", "x", Options{}); !ok || !called {
		t.Fatal("Build did not call factory")
	}
	// Sanity check error path on absent name.
	if _, ok := reg.Build("missing", "", Options{}); ok {
		t.Fatal("Build returned ok for unregistered name")
	}
	_ = fmt.Sprintf
}
