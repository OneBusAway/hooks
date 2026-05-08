package ingest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/store"
)

const renderSecret = "shhh"

func newTestHandler(t *testing.T) (*Handler, *store.SQLite, *pubsub.Notifier) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	v, _ := sources.Default.Build("render", renderSecret, sources.Options{Now: time.Now})
	bindings := map[string]SourceBinding{
		"render": {Name: "render", Verifier: v, BodySizeLimit: 1 << 20},
	}
	notifier := pubsub.New()
	h := New(bindings, st, notifier, slog.New(slog.DiscardHandler))
	return h, st, notifier
}

func renderRequest(method, path string, body []byte, ts time.Time) *http.Request {
	tsRaw := strconv.FormatInt(ts.Unix(), 10)
	id := "delivery-" + tsRaw
	mac := hmac.New(sha256.New, []byte(renderSecret))
	mac.Write([]byte(id))
	mac.Write([]byte("."))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Webhook-Id", id)
	r.Header.Set("Webhook-Timestamp", tsRaw)
	r.Header.Set("Webhook-Signature", sig)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestIngestAccepts202OnSuccess(t *testing.T) {
	h, st, notifier := newTestHandler(t)
	body := []byte(`{"event":"deploy"}`)
	r := renderRequest(http.MethodPost, "/ingest/render", body, time.Now())
	w := httptest.NewRecorder()

	// Subscribe before request to catch the publish.
	sub := notifier.Subscribe("render")
	defer notifier.Unsubscribe("render", sub)

	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	// Verify event landed.
	got, err := st.LatestSequence(context.Background(), "render")
	if err != nil || got != 1 {
		t.Fatalf("LatestSequence = %d, %v", got, err)
	}
	// Notifier was poked.
	select {
	case <-sub:
	case <-time.After(time.Second):
		t.Fatal("notifier did not publish")
	}
}

func TestIngestUnknownSourceIs404(t *testing.T) {
	h, _, _ := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/ingest/stripe", strings.NewReader(""))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

func TestIngestTamperedBodyIs401(t *testing.T) {
	h, _, _ := newTestHandler(t)
	body := []byte(`{"event":"deploy"}`)
	r := renderRequest(http.MethodPost, "/ingest/render", body, time.Now())
	r.Body = io.NopCloser(strings.NewReader(`{"event":"hacked"}`))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestIngestMissingSignatureIs401(t *testing.T) {
	h, _, _ := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/ingest/render", strings.NewReader(""))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestIngestStaleTimestampIs401(t *testing.T) {
	h, _, _ := newTestHandler(t)
	body := []byte("hi")
	r := renderRequest(http.MethodPost, "/ingest/render", body, time.Now().Add(-1*time.Hour))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestIngestDuplicateIs200(t *testing.T) {
	h, _, _ := newTestHandler(t)
	body := []byte("hi")
	now := time.Now()

	r1 := renderRequest(http.MethodPost, "/ingest/render", body, now)
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("first req: %d", w1.Code)
	}

	r2 := renderRequest(http.MethodPost, "/ingest/render", body, now)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("dup req: %d", w2.Code)
	}
}

func TestIngestOversizedIs413(t *testing.T) {
	h, _, _ := newTestHandler(t)
	// SourceBinding sets BodySizeLimit = 1 MiB; send 2 MiB.
	big := make([]byte, 2<<20)
	r := renderRequest(http.MethodPost, "/ingest/render", big, time.Now())
	r.ContentLength = int64(len(big))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", w.Code)
	}
}

func TestIngestStoredBodyMatchesSigned(t *testing.T) {
	h, st, _ := newTestHandler(t)
	body := []byte(`{"hello":"world"}`)
	r := renderRequest(http.MethodPost, "/ingest/render", body, time.Now())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatal(w.Body.String())
	}
	ev, err := st.Get(context.Background(), "render", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.Body, body) {
		t.Fatalf("body diverged")
	}
}

func TestIngestMethodMustBePOST(t *testing.T) {
	h, _, _ := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/ingest/render", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", w.Code)
	}
}

func TestRegisterMountsPerSource(t *testing.T) {
	h, _, _ := newTestHandler(t)
	mux := http.NewServeMux()
	h.Register(mux, "/ingest/")

	body := []byte(`{}`)
	r := renderRequest(http.MethodPost, "/ingest/render", body, time.Now())
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}
