package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/config"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/server"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/tokens"
)

func startTestServer(t *testing.T) (string, string, func()) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:    "127.0.0.1:0",
		DatabaseURL:   filepath.Join(dir, "x.db"),
		BodySizeLimit: 1 << 20,
		DedupeWindow:  24 * time.Hour,
		SkewWindow:    5 * time.Minute,
		Sources: map[string]config.Source{
			"render": {
				Name: "render", Verifier: "render",
				Secret:        secret.String("shhh"),
				Retention:     30 * 24 * time.Hour,
				SkewWindow:    5 * time.Minute,
				BodySizeLimit: 1 << 20,
			},
		},
	}
	srv, err := server.Build(cfg, sources.Default, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Mux)

	res, err := tokens.Issue(context.Background(), srv.Store.Tokens(), "ci", []string{"render", "admin"})
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		ts.Close()
		_ = srv.Close()
	}
	return ts.URL, res.Plaintext, cleanup
}

func ingestRender(t *testing.T, base, body string) {
	t.Helper()
	now := time.Now()
	tsRaw := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte("shhh"))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write([]byte(body))
	sig := "t=" + tsRaw + ",v1=" + hex.EncodeToString(mac.Sum(nil))
	req, _ := http.NewRequest(http.MethodPost, base+"/ingest/render", bytes.NewReader([]byte(body)))
	req.Header.Set("Render-Webhook-Id", "delivery-"+tsRaw+"-"+strconv.Itoa(int(time.Now().UnixNano())))
	req.Header.Set("Render-Webhook-Timestamp", tsRaw)
	req.Header.Set("Render-Webhook-Signature", sig)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		bb, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest: %d %s", resp.StatusCode, bb)
	}
	resp.Body.Close()
}

func TestForwardCursorAdvancesOn2xx(t *testing.T) {
	base, token, stop := startTestServer(t)
	t.Cleanup(stop)

	var got int32
	var mu sync.Mutex
	var bodies []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		atomic.AddInt32(&got, 1)
		w.WriteHeader(200)
	}))
	t.Cleanup(target.Close)

	// Set XDG_STATE_HOME so cursor file is in a known temp dir.
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("HOOKS_TOKEN", token)

	ingestRender(t, base, `{"event":"deploy"}`)

	// Run forward in a goroutine; it loops forever, so we cancel via SIGINT
	// — easier: drive run() in-process and stop by closing the target server
	// after we see one delivery.
	done := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwardTestCtx = ctx
	t.Cleanup(func() { forwardTestCtx = nil })
	go func() {
		done <- run([]string{"forward", "render", "--server", base, "--to", target.URL})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&got) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadInt32(&got) < 1 {
		t.Fatal("never received forwarded request")
	}

	// Read cursor file; should be 1.
	data, err := os.ReadFile(filepath.Join(state, "hooks", cursorFileName(base, "render")))
	if err != nil {
		t.Fatalf("cursor file missing: %v", err)
	}
	if string(bytes.TrimSpace(data)) != "1" {
		t.Fatalf("cursor = %q", data)
	}
}

func TestForwardCursorDoesNotAdvanceOn5xx(t *testing.T) {
	base, token, stop := startTestServer(t)
	t.Cleanup(stop)

	var got int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&got, 1)
		w.WriteHeader(500)
	}))
	t.Cleanup(target.Close)

	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("HOOKS_TOKEN", token)

	ingestRender(t, base, `{"event":"deploy"}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwardTestCtx = ctx
	t.Cleanup(func() { forwardTestCtx = nil })
	go run([]string{"forward", "render", "--server", base, "--to", target.URL})

	// Wait until we see at least one attempt + a tiny grace period.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&got) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	cursorPath := filepath.Join(state, "hooks", cursorFileName(base, "render"))
	if data, err := os.ReadFile(cursorPath); err == nil {
		if string(bytes.TrimSpace(data)) == "1" {
			t.Fatalf("cursor advanced despite 5xx: %s", data)
		}
	}
}

func cursorFileName(server, source string) string {
	return "cursor-" + serverHost(server) + "-" + source
}
