package main

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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/config"
	"github.com/onebusaway/hooks/internal/secret"
	"github.com/onebusaway/hooks/internal/server"
	"github.com/onebusaway/hooks/internal/sources"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
	pkgUsers "github.com/onebusaway/hooks/internal/users"
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
	id := "delivery-" + tsRaw + "-" + strconv.Itoa(int(time.Now().UnixNano()))
	mac := hmac.New(sha256.New, []byte("shhh"))
	mac.Write([]byte(id))
	mac.Write([]byte("."))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write([]byte(body))
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req, _ := http.NewRequest(http.MethodPost, base+"/ingest/render", bytes.NewReader([]byte(body)))
	req.Header.Set("Webhook-Id", id)
	req.Header.Set("Webhook-Timestamp", tsRaw)
	req.Header.Set("Webhook-Signature", sig)
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

// startTestServerWithUser is like startTestServer but additionally
// creates a user and a kind='pat' PAT for them, returning the PAT
// plaintext alongside the system bearer. Used by the §12 ephemeral-
// listener tests so we can drive `forward` as a logged-in developer.
func startTestServerWithUser(t *testing.T) (base, systemTok, userPAT, userID string, srv *server.Server, cleanup func()) {
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
	built, err := server.Build(cfg, sources.Default, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(built.Mux)

	sysRes, err := tokens.Issue(context.Background(), built.Store.Tokens(), "ci", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}

	pwHash, err := pkgUsers.HashPassword(secret.String("supercalifragilistic"))
	if err != nil {
		t.Fatal(err)
	}
	user := store.User{
		ID:            uuid.NewString(),
		Email:         "alice@example.com",
		Name:          "Alice",
		Role:          store.RoleUser,
		PasswordHash:  pwHash,
		DefaultScopes: []string{"render"},
		CreatedAt:     time.Now().UTC(),
	}
	if err := built.Store.InsertUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	patRes, err := tokens.Generate("alice-pat", []string{"account"})
	if err != nil {
		t.Fatal(err)
	}
	owner := user.ID
	if err := built.Store.Insert(context.Background(), store.Token{
		ID: patRes.ID, Name: "alice-pat", Scopes: []string{"account"}, SecretHash: patRes.Hash,
		CreatedAt: time.Now().UTC(), OwnerUserID: &owner, Kind: store.TokenKindPAT,
	}); err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		ts.Close()
		_ = built.Close()
	}
	return ts.URL, sysRes.Plaintext, patRes.Plaintext, user.ID, built, cleanup
}

// countOwnedListenerTokens returns the number of unrevoked
// kind='listener' tokens owned by the given user. The §12 tests use
// it to assert ephemeral-mint-and-revoke happened (or did not).
func countOwnedListenerTokens(t *testing.T, srv *server.Server, ownerID string, includeRevoked bool) int {
	t.Helper()
	rows, err := srv.Store.Tokens().ListByOwner(context.Background(), ownerID, includeRevoked)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.Kind == store.TokenKindListener {
			n++
		}
	}
	return n
}

// TestForward_ExplicitToken_NoEphemeralMint asserts that when
// HOOKS_TOKEN is set in the environment, `hooksctl forward` does NOT
// auto-mint an ephemeral listener token — it uses the supplied token
// directly. This preserves the long-standing CI / system-credential
// path.
func TestForward_ExplicitToken_NoEphemeralMint(t *testing.T) {
	base, systemTok, _, userID, srv, stop := startTestServerWithUser(t)
	t.Cleanup(stop)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(target.Close)

	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// Explicit env-supplied token: forward must NOT mint anything.
	t.Setenv("HOOKS_TOKEN", systemTok)

	ingestRender(t, base, `{"event":"deploy"}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwardTestCtx = ctx
	t.Cleanup(func() { forwardTestCtx = nil })

	done := make(chan int, 1)
	go func() {
		done <- run([]string{"forward", "render", "--server", base, "--to", target.URL})
	}()

	// Wait for the cursor to advance so we know subscribe succeeded.
	cursorPath := filepath.Join(state, "hooks", cursorFileName(base, "render"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(cursorPath); err == nil &&
			string(bytes.TrimSpace(data)) == "1" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	// No listener token should ever have been minted for the user.
	if got := countOwnedListenerTokens(t, srv, userID, true); got != 0 {
		t.Fatalf("listener tokens minted for user despite explicit HOOKS_TOKEN: got %d", got)
	}
}

// TestForward_ExplicitTokenFlag_NoEphemeralMint covers the second
// "skip" branch from §12.5: passing `--token <id>` explicitly.
func TestForward_ExplicitTokenFlag_NoEphemeralMint(t *testing.T) {
	base, systemTok, _, userID, srv, stop := startTestServerWithUser(t)
	t.Cleanup(stop)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(target.Close)

	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// Important: clear HOOKS_TOKEN so only --token is in play.
	t.Setenv("HOOKS_TOKEN", "")

	ingestRender(t, base, `{"event":"deploy"}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwardTestCtx = ctx
	t.Cleanup(func() { forwardTestCtx = nil })

	done := make(chan int, 1)
	go func() {
		done <- run([]string{"forward", "render",
			"--server", base, "--token", systemTok, "--to", target.URL})
	}()

	cursorPath := filepath.Join(state, "hooks", cursorFileName(base, "render"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(cursorPath); err == nil &&
			string(bytes.TrimSpace(data)) == "1" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	if got := countOwnedListenerTokens(t, srv, userID, true); got != 0 {
		t.Fatalf("listener tokens minted for user despite --token: got %d", got)
	}
}

// TestForward_LoginAware_MintsAndRevokesEphemeral covers the §12.2-4
// happy path: a profile-loaded user PAT triggers an ephemeral
// kind='listener' mint before SSE, and a revoke on context-cancel.
func TestForward_LoginAware_MintsAndRevokesEphemeral(t *testing.T) {
	base, _, userPAT, userID, srv, stop := startTestServerWithUser(t)
	t.Cleanup(stop)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(target.Close)

	// Write a credentials profile so the CLI loads the user PAT.
	cfgRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	// Ensure HOOKS_TOKEN does NOT shadow the profile.
	t.Setenv("HOOKS_TOKEN", "")

	if err := saveProfile("default", profile{
		ServerURL: base,
		Token:     userPAT,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	ingestRender(t, base, `{"event":"deploy"}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwardTestCtx = ctx
	t.Cleanup(func() { forwardTestCtx = nil })

	done := make(chan int, 1)
	go func() {
		done <- run([]string{"forward", "render", "--to", target.URL})
	}()

	// Wait until forward minted an ephemeral token. We poll the store
	// rather than relying on a sleep because the mint happens before
	// subscribe.
	deadline := time.Now().Add(3 * time.Second)
	saw := 0
	for time.Now().Before(deadline) {
		saw = countOwnedListenerTokens(t, srv, userID, false)
		if saw >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if saw < 1 {
		t.Fatal("forward did not mint an ephemeral listener token")
	}

	// Wait for cursor advance to confirm subscribe with the new token works.
	cursorPath := filepath.Join(state, "hooks", cursorFileName(base, "render"))
	deadline = time.Now().Add(3 * time.Second)
	advanced := false
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(cursorPath); err == nil &&
			string(bytes.TrimSpace(data)) == "1" {
			advanced = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !advanced {
		t.Fatal("cursor did not advance — ephemeral subscribe failed")
	}

	// Cancel and wait for forward to return; the deferred revoke runs.
	cancel()
	<-done

	// After revoke, the active count drops to zero. The token row is
	// retained with revoked_at set.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countOwnedListenerTokens(t, srv, userID, false) == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := countOwnedListenerTokens(t, srv, userID, false); got != 0 {
		t.Fatalf("ephemeral token not revoked on exit: %d still active", got)
	}
	if got := countOwnedListenerTokens(t, srv, userID, true); got != 1 {
		t.Fatalf("ephemeral token row not retained: %d", got)
	}

	// And the row is in fact ephemeral with the right scope.
	rows, err := srv.Store.Tokens().ListByOwner(context.Background(), userID, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Kind != store.TokenKindListener {
			continue
		}
		if !r.Ephemeral {
			t.Errorf("minted listener token is not ephemeral")
		}
		if len(r.Scopes) != 1 || r.Scopes[0] != "render" {
			t.Errorf("minted listener scopes = %v; want [render]", r.Scopes)
		}
	}
}
