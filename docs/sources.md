# Adding a new provider plugin

Provider verification lives behind a small `Verifier` interface in `internal/sources/sources.go`:

```go
type Verifier interface {
    RequiredHeaders() []string
    Verify(headers http.Header, body []byte) (timestamp time.Time, deliveryID string, err error)
}
```

Adding a new source — say, Stripe — is three short steps.

## 1. Create `internal/sources/stripe.go`

Implement HMAC verification per Stripe's docs:

```go
package sources

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net/http"
    "strconv"
    "strings"
    "time"
)

func init() { Default.Register("stripe", newStripeVerifier) }

func newStripeVerifier(secret string, opts Options) Verifier {
    skew := opts.SkewWindow
    if skew == 0 { skew = 5 * time.Minute }
    now := opts.Now
    if now == nil { now = time.Now }
    return &stripeVerifier{secret: secret, skew: skew, now: now}
}

type stripeVerifier struct { secret string; skew time.Duration; now func() time.Time }

func (v *stripeVerifier) RequiredHeaders() []string {
    return []string{"Stripe-Signature"}
}

func (v *stripeVerifier) Verify(h http.Header, body []byte) (time.Time, string, error) {
    sig := h.Get("Stripe-Signature")
    if sig == "" { return time.Time{}, "", fmt.Errorf("%w: Stripe-Signature", ErrMissingHeader) }
    var t string
    var v1 string
    for _, p := range strings.Split(sig, ",") {
        kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
        if len(kv) != 2 { continue }
        switch kv[0] { case "t": t = kv[1]; case "v1": v1 = kv[1] }
    }
    if t == "" || v1 == "" { return time.Time{}, "", fmt.Errorf("%w: Stripe-Signature", ErrMalformedHeader) }

    mac := hmac.New(sha256.New, []byte(v.secret))
    mac.Write([]byte(t)); mac.Write([]byte(".")); mac.Write(body)
    want := hex.EncodeToString(mac.Sum(nil))
    if want != v1 { return time.Time{}, "", ErrInvalidSignature }

    sec, _ := strconv.ParseInt(t, 10, 64)
    ts := time.Unix(sec, 0).UTC()
    if d := v.now().UTC().Sub(ts); d < -v.skew || d > v.skew {
        return time.Time{}, "", ErrStaleTimestamp
    }
    // Stripe doesn't supply a stable per-delivery id in headers; use the
    // sha256 of the canonical signing string.
    sum := sha256.Sum256([]byte(t + "." + string(body)))
    return ts, hex.EncodeToString(sum[:]), nil
}
```

## 2. Add the source to `hooks.yaml`

```yaml
sources:
  stripe:
    verifier: stripe
    secret: ${STRIPE_WEBHOOK_SECRET}
    retention: 30d
```

## 3. Restart the server

The config loader resolves `verifier: stripe` against the registry that the import wired up at process start, so any unknown verifier fails startup with a clear message. After restart, `POST /ingest/stripe` is live.

## Notes for plugin authors

- Use `hmac.Equal` (or `subtle.ConstantTimeCompare`) for signature comparison; never `==` on byte slices.
- Reject any timestamp outside the configured skew window (`Options.SkewWindow`); 5 minutes is the default.
- Treat the body bytes as exact: do not re-encode JSON or normalize whitespace.
- If the provider supplies a stable delivery id, return it. Otherwise return `sha256(<canonical-signing-string>)` so the dedupe index still works.
