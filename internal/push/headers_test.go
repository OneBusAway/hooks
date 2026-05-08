package push

import "testing"

// TestIsHopByHop pins the spec contract: ONLY hop-by-hop (and Host/Content-Length,
// which we always recompute) are stripped on outbound. Provider signature
// headers must pass through.
func TestIsHopByHop(t *testing.T) {
	stripped := []string{
		"Connection", "connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade",
		"Host", "Content-Length",
	}
	for _, h := range stripped {
		if !IsHopByHop(h) {
			t.Errorf("IsHopByHop(%q) = false, want true", h)
		}
	}

	preserved := []string{
		"Content-Type",
		"User-Agent",
		"Render-Webhook-Signature",
		"Render-Webhook-Id",
		"Render-Webhook-Timestamp",
		"X-Hooks-Signature",
		"Stripe-Signature",
		"X-Custom",
	}
	for _, h := range preserved {
		if IsHopByHop(h) {
			t.Errorf("IsHopByHop(%q) = true, want false (must pass through per spec)", h)
		}
	}
}
