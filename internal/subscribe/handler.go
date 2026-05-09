// Package subscribe implements the GET /subscribe/<source> SSE endpoint.
//
// Stream layout:
//
//	id:<seq>
//	event:<source>
//	data:<json>
//	\n
//
// data is a single line of JSON containing delivery_id, provider_timestamp,
// received_at, headers, and a base64-encoded body. Bytes round-trip verbatim.
//
// The handler runs a replay loop (read from the store in batches of ≤1000
// until caught up to the current latest sequence) followed by a live loop
// (select on the per-source notifier channel + a 30s keepalive ticker). On
// any signal the live loop drains all newer events from the store, so a
// dropped notify channel signal still lands the affected events.
package subscribe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

// Defaults documented in design.md.
const (
	DefaultKeepalive  = 30 * time.Second
	DefaultBatchLimit = 1000
)

// Handler serves /subscribe/<source>.
type Handler struct {
	Store      store.EventStore
	Notifier   *pubsub.Notifier
	Auth       *tokens.Authenticator
	Sources    map[string]bool
	Logger     *slog.Logger
	Keepalive  time.Duration
	BatchLimit int
}

// New constructs a Handler with sensible defaults.
func New(st store.EventStore, n *pubsub.Notifier, auth *tokens.Authenticator, sources []string, logger *slog.Logger) *Handler {
	srcSet := map[string]bool{}
	for _, s := range sources {
		srcSet[s] = true
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		Store:      st,
		Notifier:   n,
		Auth:       auth,
		Sources:    srcSet,
		Logger:     logger,
		Keepalive:  DefaultKeepalive,
		BatchLimit: DefaultBatchLimit,
	}
}

// ServeHTTP handles GET /subscribe/<source>.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	source := lastPathSegment(r.URL.Path)
	if !h.Sources[source] {
		http.Error(w, "unknown source", http.StatusNotFound)
		return
	}

	if _, err := h.Auth.AuthorizeSource(r, source); err != nil {
		tokens.WriteAuthError(w, err)
		return
	}

	cursor, err := parseCursor(r, h.Store, source)
	if err != nil {
		http.Error(w, "invalid cursor: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Configure SSE response.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	if err := h.stream(r.Context(), w, flusher, source, cursor); err != nil {
		// Errors here are typically client disconnects; log at debug.
		h.Logger.Debug("subscribe: stream ended", slog.String("source", source), slog.String("error", err.Error()))
	}
}

func (h *Handler) stream(ctx context.Context, w io.Writer, flusher http.Flusher, source string, cursor int64) error {
	batchLimit := h.BatchLimit
	if batchLimit <= 0 {
		batchLimit = DefaultBatchLimit
	}
	keepalive := h.Keepalive
	if keepalive <= 0 {
		keepalive = DefaultKeepalive
	}

	// Subscribe to live signals BEFORE replaying so we don't miss anything
	// that arrives during replay.
	ch := h.Notifier.Subscribe(source)
	defer h.Notifier.Unsubscribe(source, ch)

	// Replay phase.
	cursor, err := h.drain(ctx, w, flusher, source, cursor, batchLimit)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-ch:
			if !ok {
				return errors.New("notifier closed")
			}
			cursor, err = h.drain(ctx, w, flusher, source, cursor, batchLimit)
			if err != nil {
				return err
			}
		case <-ticker.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return err
			}
			flusher.Flush()
			// Belt-and-suspenders: if we missed a signal, drain anyway.
			cursor, err = h.drain(ctx, w, flusher, source, cursor, batchLimit)
			if err != nil {
				return err
			}
		}
	}
}

func (h *Handler) drain(ctx context.Context, w io.Writer, flusher http.Flusher, source string, cursor int64, batchLimit int) (int64, error) {
	for {
		batch, err := h.Store.ReadSince(ctx, source, cursor, batchLimit)
		if err != nil {
			return cursor, err
		}
		if len(batch) == 0 {
			return cursor, nil
		}
		for _, ev := range batch {
			if err := writeEvent(w, ev); err != nil {
				return cursor, err
			}
			cursor = ev.Sequence
		}
		flusher.Flush()
	}
}

// writeEvent renders an Event as a single SSE message.
func writeEvent(w io.Writer, ev store.Event) error {
	payload := ssePayload{
		DeliveryID:        ev.DeliveryID,
		ProviderTimestamp: ev.ProviderTimestamp,
		ReceivedAt:        ev.ReceivedAt,
		Headers:           ev.Headers,
		Body:              base64.StdEncoding.EncodeToString(ev.Body),
		BodySHA256:        ev.BodySHA256,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := fmt.Fprintf(w, "id:%d\nevent:%s\ndata:", ev.Sequence, ev.Source); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\n\n"); err != nil {
		return err
	}
	return nil
}

type ssePayload struct {
	DeliveryID        string            `json:"delivery_id"`
	ProviderTimestamp time.Time         `json:"provider_timestamp"`
	ReceivedAt        time.Time         `json:"received_at"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	BodySHA256        string            `json:"body_sha256"`
}

// parseCursor resolves the effective starting sequence from `since` and
// `Last-Event-ID`. The maximum of the two wins so browser auto-reconnect
// cannot regress.
func parseCursor(r *http.Request, st store.EventStore, source string) (int64, error) {
	cursor := int64(0)

	if v := r.URL.Query().Get("since"); v != "" {
		if v == "latest" {
			latest, err := st.LatestSequence(r.Context(), source)
			if err != nil {
				return 0, err
			}
			cursor = latest
		} else {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("since: %w", err)
			}
			if n < 0 {
				return 0, fmt.Errorf("since: must be non-negative")
			}
			cursor = n
		}
	}

	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("Last-Event-ID: %w", err)
		}
		if n > cursor {
			cursor = n
		}
	}
	return cursor, nil
}

func lastPathSegment(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
