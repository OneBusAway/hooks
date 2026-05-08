package push

import "strings"

// hopByHopHeaders enumerates the standard hop-by-hop headers we strip from
// captured upstream headers before re-emitting on outbound POSTs.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	// Headers we ALWAYS overwrite on outbound:
	"host":           true,
	"content-length": true,
	// Provider-supplied signature must not leak forward.
	"render-webhook-signature": true,
	"render-webhook-id":        true,
	"render-webhook-timestamp": true,
}

// IsHopByHop reports whether name is a header we should strip from forwarded
// captured headers.
func IsHopByHop(name string) bool {
	return hopByHopHeaders[strings.ToLower(name)]
}
