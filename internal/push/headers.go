package push

import "strings"

// hopByHopHeaders enumerates the RFC 7230 hop-by-hop headers, plus Host /
// Content-Length which we always recompute on outbound. Per the push-delivery
// spec, EVERYTHING ELSE captured from the original delivery must pass through
// — including provider-supplied signature headers, which consumers ignore in
// favor of X-Hooks-Signature but may use for debugging.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"host":                true,
	"content-length":      true,
}

// IsHopByHop reports whether name is a header we should strip from forwarded
// captured headers.
func IsHopByHop(name string) bool {
	return hopByHopHeaders[strings.ToLower(name)]
}
