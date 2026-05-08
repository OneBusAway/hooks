package sources

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

// Render webhook signing follows the Standard Webhooks spec
// (https://www.standardwebhooks.com/) per https://render.com/docs/webhooks.
// We delegate the cryptographic verification to the official library and
// keep responsibility only for: header presence/parse errors (so we can
// surface our typed sentinels), per-source SkewWindow override, and pulling
// out the values our store needs (delivery_id, provider timestamp).
//
// The signing secret is accepted in either form:
//   - "whsec_<base64>" (canonical Standard Webhooks form, what Render shows)
//   - bare bytes (handed straight to HMAC; useful for tests)
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

	wh, err := buildWebhook(secret)
	return &renderVerifier{wh: wh, whErr: err, skew: skew, now: now}
}

func buildWebhook(secret string) (*standardwebhooks.Webhook, error) {
	if strings.HasPrefix(secret, "whsec_") {
		return standardwebhooks.NewWebhook(secret)
	}
	return standardwebhooks.NewWebhookRaw([]byte(secret))
}

type renderVerifier struct {
	wh    *standardwebhooks.Webhook
	whErr error
	skew  time.Duration
	now   func() time.Time
}

func (v *renderVerifier) RequiredHeaders() []string {
	return []string{
		standardwebhooks.HeaderWebhookID,
		standardwebhooks.HeaderWebhookTimestamp,
		standardwebhooks.HeaderWebhookSignature,
	}
}

func (v *renderVerifier) Verify(headers http.Header, body []byte) (time.Time, string, error) {
	if v.whErr != nil {
		return time.Time{}, "", fmt.Errorf("verify: build webhook: %w", v.whErr)
	}

	deliveryID := headers.Get(standardwebhooks.HeaderWebhookID)
	if deliveryID == "" {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrMissingHeader, standardwebhooks.HeaderWebhookID)
	}
	tsRaw := headers.Get(standardwebhooks.HeaderWebhookTimestamp)
	if tsRaw == "" {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrMissingHeader, standardwebhooks.HeaderWebhookTimestamp)
	}
	if headers.Get(standardwebhooks.HeaderWebhookSignature) == "" {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrMissingHeader, standardwebhooks.HeaderWebhookSignature)
	}
	tsNum, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: %s: %v", ErrMalformedHeader, standardwebhooks.HeaderWebhookTimestamp, err)
	}
	providerTime := time.Unix(tsNum, 0).UTC()

	// Use the lib for the HMAC + signature-list parsing, but skip its built-in
	// timestamp tolerance so our per-source SkewWindow override applies.
	if err := v.wh.VerifyIgnoringTimestamp(body, headers); err != nil {
		switch {
		case errors.Is(err, standardwebhooks.ErrRequiredHeaders):
			return time.Time{}, "", fmt.Errorf("%w: %v", ErrMissingHeader, err)
		case errors.Is(err, standardwebhooks.ErrInvalidHeaders):
			return time.Time{}, "", fmt.Errorf("%w: %v", ErrMalformedHeader, err)
		case errors.Is(err, standardwebhooks.ErrNoMatchingSignature):
			return time.Time{}, "", ErrInvalidSignature
		default:
			return time.Time{}, "", fmt.Errorf("verify: %w", err)
		}
	}

	now := v.now().UTC()
	if delta := now.Sub(providerTime); delta < -v.skew || delta > v.skew {
		return time.Time{}, "", fmt.Errorf("%w: delta %s exceeds %s", ErrStaleTimestamp, delta, v.skew)
	}

	return providerTime, deliveryID, nil
}
