package server

import (
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

	"github.com/onebusaway/hooks/internal/config"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/sources"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:    ":0",
		DatabaseURL:   filepath.Join(dir, "x.db"),
		LogLevel:      "info",
		BodySizeLimit: 1 << 20,
		DedupeWindow:  24 * time.Hour,
		SkewWindow:    5 * time.Minute,
		Sources: map[string]config.Source{
			"render": {
				Name:          "render",
				Verifier:      "render",
				Secret:        secret.String("shhh"),
				Retention:     30 * 24 * time.Hour,
				SkewWindow:    5 * time.Minute,
				BodySizeLimit: 1 << 20,
			},
		},
	}
	srv, err := Build(cfg, sources.Default, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestServerHealthAndReady(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv.Mux)
	t.Cleanup(ts.Close)

	resp, _ := http.Get(ts.URL + "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, _ = http.Get(ts.URL + "/readyz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerIngestEndToEnd(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv.Mux)
	t.Cleanup(ts.Close)

	body := []byte(`{"event":"deploy"}`)
	now := time.Now()
	tsRaw := strconv.FormatInt(now.Unix(), 10)
	id := "delivery-1"
	mac := hmac.New(sha256.New, []byte("shhh"))
	mac.Write([]byte(id))
	mac.Write([]byte("."))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ingest/render", strings.NewReader(string(body)))
	req.Header.Set("Webhook-Id", id)
	req.Header.Set("Webhook-Timestamp", tsRaw)
	req.Header.Set("Webhook-Signature", sig)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}

	latest, err := srv.Store.LatestSequence(context.Background(), "render")
	if err != nil || latest != 1 {
		t.Fatalf("latest = %d, %v", latest, err)
	}
}

func TestServerInspectorRouted(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv.Mux)
	t.Cleanup(ts.Close)

	cli := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cli.Get(ts.URL + "/inspector")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("inspector should redirect to login, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
