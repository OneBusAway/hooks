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

// Render webhook signing per https://render.com/docs/webhooks:
//
//   Render-Webhook-Id:        unique delivery id (used as our delivery_id)
//   Render-Webhook-Timestamp: unix-seconds the signature was computed at
//   Render-Webhook-Signature: HMAC-SHA256(secret, "<timestamp>.<body>"), hex
//
// Render documents a 5-minute replay-window default; we honor that by default
// and allow per-source override via Options.SkewWindow.
const (
	renderHeaderID        = "Render-Webhook-Id"
	renderHeaderTimestamp = "Render-Webhook-Timestamp"
	renderHeaderSignature = "Render-Webhook-Signature"
)

const renderDefaultSkew = 5 * time.Minute

func init() { Default.Register("render", newRenderVerifier) }

func newRenderVerifier(secret string, opts Options) Verifier {
	skew := opts.SkewWindow
	if skew == 0 {
		skew = renderDefaultSkew
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &renderVerifier{secret: secret, skew: skew, now: now}
}

type renderVerifier struct {
	secret string
	skew   time.Duration
	now    func() time.Time
}

func (v *renderVerifier) RequiredHeaders() []string {
	return []string{renderHeaderID, renderHeaderTimestamp, renderHeaderSignature}
}

func (v *renderVerifier) Verify(headers http.Header, body []byte) (time.Time, string, error) {
	deliveryID := headers.Get(renderHeaderID)
	if deliveryID == "" {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrMissingHeader, renderHeaderID)
	}
	tsRaw := headers.Get(renderHeaderTimestamp)
	if tsRaw == "" {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrMissingHeader, renderHeaderTimestamp)
	}
	tsSec, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: %s: %v", ErrMalformedHeader, renderHeaderTimestamp, err)
	}
	tsMillis := tsSec
	// Render historically sent unix milliseconds in some payloads; if the
	// number looks like a millisecond timestamp (>= year 2001 in seconds is
	// fine, but >= 13 digits is conclusively ms), interpret as ms.
	var providerTime time.Time
	if tsRaw != "" && len(tsRaw) >= 13 {
		providerTime = time.Unix(0, tsMillis*int64(time.Millisecond)).UTC()
	} else {
		providerTime = time.Unix(tsSec, 0).UTC()
	}

	sigHeader := headers.Get(renderHeaderSignature)
	if sigHeader == "" {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrMissingHeader, renderHeaderSignature)
	}
	sigBytes, err := parseRenderSignature(sigHeader)
	if err != nil {
		return time.Time{}, "", err
	}

	mac := hmac.New(sha256.New, []byte(v.secret))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	want := mac.Sum(nil)
	if !hmac.Equal(want, sigBytes) {
		return time.Time{}, "", ErrInvalidSignature
	}

	now := v.now().UTC()
	if delta := now.Sub(providerTime); delta < -v.skew || delta > v.skew {
		return time.Time{}, "", fmt.Errorf("%w: delta %s exceeds %s", ErrStaleTimestamp, delta, v.skew)
	}

	return providerTime, deliveryID, nil
}

// parseRenderSignature accepts either the documented Stripe-style format
// `t=<timestamp>,v1=<hex>` (which is what newer Render docs reference) OR a
// bare hex digest. We default to the comma-separated form.
func parseRenderSignature(in string) ([]byte, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, fmt.Errorf("%w: empty signature", ErrMalformedHeader)
	}
	// If the header is a comma-separated list of k=v pairs, look up v1.
	if strings.Contains(in, "=") && strings.Contains(in, "v1") {
		for _, p := range strings.Split(in, ",") {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "v1=") {
				continue
			}
			b, err := hex.DecodeString(strings.TrimPrefix(p, "v1="))
			if err != nil {
				return nil, fmt.Errorf("%w: v1 not hex: %v", ErrMalformedHeader, err)
			}
			return b, nil
		}
		return nil, fmt.Errorf("%w: no v1= in %q", ErrMalformedHeader, in)
	}
	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, fmt.Errorf("%w: not hex: %v", ErrMalformedHeader, err)
	}
	return b, nil
}
