// Package sources defines the Verifier interface that every inbound webhook
// provider plugin must satisfy, plus a global registry mapping verifier names
// (as written in hooks.yaml) to factories.
//
// Adding a new source provider is three steps:
//
//  1. Create a new file under internal/sources/<name>.go (e.g. stripe.go).
//
//  2. Implement the Verifier interface for that provider's signing scheme:
//
//     - RequiredHeaders should list the headers your verifier reads from
//     so the ingest layer can early-fail before parsing the body.
//     - Verify should return the provider-attested timestamp, the
//     provider-supplied delivery_id (or a sha256 of the canonical signing
//     string if the provider does not provide one), and an error.
//
//  3. Call sources.Register("<name>", factory) from an init() block so the
//     config loader can resolve "verifier: <name>" entries at startup.
//
// Wiring a registered verifier costs zero code change in internal/ingest.
package sources

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// Verifier validates one inbound webhook against the source's signing scheme.
type Verifier interface {
	// RequiredHeaders returns canonical-cased header names the verifier reads.
	RequiredHeaders() []string

	// Verify checks signature and returns the provider-attested timestamp and
	// delivery_id. The body must already be the bytes that were signed; the
	// implementation MUST NOT modify it.
	Verify(headers http.Header, body []byte) (timestamp time.Time, deliveryID string, err error)
}

// Factory builds a Verifier for a source whose secret has just been loaded.
// Optional opts may include per-source overrides such as a non-default
// skew window; pass them via Options on the same call.
type Factory func(secret string, opts Options) Verifier

// Options carry per-source configuration into the Factory.
type Options struct {
	// SkewWindow is the maximum acceptable distance between the provider's
	// timestamp and now(). Zero means "use the verifier's default".
	SkewWindow time.Duration

	// Now is overridable in tests for stable behavior.
	Now func() time.Time
}

// Now returns o.Now() or time.Now() if the option was unset.
func (o Options) NowOrDefault() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// ErrInvalidSignature is returned when the HMAC check fails.
var ErrInvalidSignature = errors.New("verify: invalid signature")

// ErrStaleTimestamp is returned when the provider's timestamp is outside the
// configured skew window.
var ErrStaleTimestamp = errors.New("verify: timestamp outside skew window")

// ErrMissingHeader is returned when a required header is missing.
var ErrMissingHeader = errors.New("verify: required header missing")

// ErrMalformedHeader is returned when a header is present but unparseable.
var ErrMalformedHeader = errors.New("verify: malformed header")

// Registry maps source identifier names to their Factory implementations.
type Registry struct {
	mu    sync.RWMutex
	known map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{known: map[string]Factory{}} }

// Register adds a factory under name. Panics on duplicate registration so
// import-time mistakes are caught at startup.
func (r *Registry) Register(name string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.known[name]; exists {
		panic("sources: duplicate registration for " + name)
	}
	r.known[name] = f
}

// Has reports whether a factory is registered under name. Used by config
// validation.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.known[name]
	return ok
}

// Build returns a Verifier built from the named factory.
func (r *Registry) Build(name, secret string, opts Options) (Verifier, bool) {
	r.mu.RLock()
	f, ok := r.known[name]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return f(secret, opts), true
}

// Default is the process-wide registry that init() functions in source
// plugin files register against.
var Default = NewRegistry()
