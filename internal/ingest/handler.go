// Package ingest implements the inbound webhook receive surface.
//
// One handler is mounted per configured source at POST /ingest/<source>.
// The handler:
//
//  1. Enforces the body-size cap (HTTP 413).
//  2. Resolves the source's verifier (HTTP 404 if unknown).
//  3. Verifies signature + timestamp (HTTP 401 on either failure).
//  4. Appends to the durable event store (HTTP 200 on duplicate, HTTP 503 on
//     other errors, HTTP 202 on success).
//  5. Publishes the new sequence to the in-process notifier so subscribers
//     and push dispatchers wake.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/store"
)

// SourceBinding wires one configured source to its built verifier and per-source
// limits.
type SourceBinding struct {
	Name          string
	Verifier      sources.Verifier
	BodySizeLimit int64
}

// Handler is a single http.Handler that dispatches /ingest/<source> requests
// to the appropriate per-source pipeline. It is mounted at /ingest/ via a
// stdlib mux pattern.
type Handler struct {
	bindings map[string]SourceBinding
	store    store.EventStore
	notifier *pubsub.Notifier
	logger   *slog.Logger
}

// New returns a Handler. bindings maps source name → wiring. The handler is
// safe for concurrent use.
func New(bindings map[string]SourceBinding, st store.EventStore, n *pubsub.Notifier, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{bindings: bindings, store: st, notifier: n, logger: logger}
}

// Register mounts the ingest handler under prefix on mux. The path pattern
// "POST {prefix}{source}" is used so each source gets its own distinct route.
func (h *Handler) Register(mux *http.ServeMux, prefix string) {
	if prefix == "" {
		prefix = "/ingest/"
	}
	for name := range h.bindings {
		// Pattern: POST /ingest/<name>
		mux.Handle("POST "+prefix+name, h.handlerFor(name))
	}
}

func (h *Handler) handlerFor(source string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serveSource(w, r, source)
	})
}

// ServeHTTP allows generic mounting (e.g. with a custom router); it parses
// the source from the URL path's last segment.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	source := lastPathSegment(r.URL.Path)
	h.serveSource(w, r, source)
}

func (h *Handler) serveSource(w http.ResponseWriter, r *http.Request, source string) {
	binding, ok := h.bindings[source]
	if !ok {
		http.Error(w, "unknown source", http.StatusNotFound)
		return
	}

	// Enforce body size cap *before* reading. We honor Content-Length when
	// present, then also wrap the body in MaxBytesReader as a defense in
	// depth (Content-Length lies happen).
	if cl := r.ContentLength; cl > 0 && cl > binding.BodySizeLimit {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, binding.BodySizeLimit)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	providerTime, deliveryID, err := binding.Verifier.Verify(r.Header, body)
	if err != nil {
		// Log only the source name and a short hash prefix of the body — never
		// the body itself, never the secret, never the full signature.
		sum := sha256.Sum256(body)
		h.logger.Warn("ingest: verification failed",
			slog.String("source", source),
			slog.String("body_sha256_prefix", hex.EncodeToString(sum[:4])),
			slog.String("error_kind", classifyVerifyError(err)),
		)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Capture every header verbatim.
	headers := make(map[string]string, len(r.Header))
	for k, vs := range r.Header {
		headers[k] = strings.Join(vs, ", ")
	}

	ev, err := h.store.Append(r.Context(), store.AppendInput{
		Source:            source,
		DeliveryID:        deliveryID,
		ProviderTimestamp: providerTime,
		Headers:           headers,
		Body:              body,
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusAccepted)
		go h.notifier.Publish(source, ev.Sequence)
	case errors.Is(err, store.ErrDuplicate):
		// Already accepted earlier; tell the provider "we got it" without
		// notifying subscribers a second time.
		w.WriteHeader(http.StatusOK)
	default:
		h.logger.Error("ingest: store append failed",
			slog.String("source", source),
			slog.String("error", err.Error()),
		)
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
	}
}

// classifyVerifyError returns a one-word error kind for safe logging.
func classifyVerifyError(err error) string {
	switch {
	case errors.Is(err, sources.ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, sources.ErrStaleTimestamp):
		return "stale_timestamp"
	case errors.Is(err, sources.ErrMissingHeader):
		return "missing_header"
	case errors.Is(err, sources.ErrMalformedHeader):
		return "malformed_header"
	default:
		return "other"
	}
}

func lastPathSegment(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// BuildBindings constructs SourceBindings from a map of source-name →
// (verifier, bodyLimit). Helper for the main wiring code.
type BuildSpec struct {
	Verifier      sources.Verifier
	BodySizeLimit int64
}

// BuildBindings is a small convenience for cmd/hooks to translate config into
// the map handler expects.
func BuildBindings(specs map[string]BuildSpec) map[string]SourceBinding {
	out := make(map[string]SourceBinding, len(specs))
	for name, s := range specs {
		out[name] = SourceBinding{
			Name:          name,
			Verifier:      s.Verifier,
			BodySizeLimit: s.BodySizeLimit,
		}
	}
	return out
}

