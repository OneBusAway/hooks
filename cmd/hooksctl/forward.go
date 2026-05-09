package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/onebusaway/hooks/internal/push"
)

// forwardTestCtx is non-nil only in tests; production paths derive their
// own context from os signals.
var forwardTestCtx context.Context

func cmdForward(g globals, args []string) int {
	fs := newFlagSet("forward")
	to := fs.String("to", "", "local URL to POST every event to")
	exitOnError := fs.Bool("exit-on-error", false, "exit non-zero on the first failed forward")
	timeout := fs.Duration("attempt-timeout", 30*time.Second, "per-attempt POST timeout")
	tail, err := parseInterleaved(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(tail) != 1 || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: hooksctl forward <source> --to <url> [--exit-on-error]")
		return 2
	}
	source := tail[0]
	if g.Token == "" {
		fmt.Fprintln(os.Stderr, "missing --token (or HOOKS_TOKEN)")
		return 2
	}
	cursorPath, perr := cursorFilePath(g.Server, source)
	if perr != nil {
		fmt.Fprintln(os.Stderr, perr)
		return 1
	}
	startCursor := loadCursor(cursorPath)

	var ctx context.Context
	var cancel context.CancelFunc
	if forwardTestCtx != nil {
		ctx, cancel = context.WithCancel(forwardTestCtx)
	} else {
		ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
	defer cancel()

	// If we're running with a profile-loaded user PAT (no explicit
	// --token / HOOKS_TOKEN), mint an ephemeral kind='listener' token
	// scoped to <source> for the SSE handshake. The PAT itself cannot
	// reach /subscribe/<source>; it can mint a listener token via
	// /api/me/tokens. We register a deferred revoke so the token does
	// not survive a normal exit. (Server-side prune handles the
	// not-so-normal exits on a 24h timer.)
	subscribeToken := g.Token
	if !g.TokenExplicit {
		eph, err := mintEphemeralListener(ctx, g, source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forward: mint ephemeral token: %v\n", err)
			return 1
		}
		if eph != nil {
			subscribeToken = eph.Plaintext
			defer revokeEphemeralListener(g, eph.ID)
		}
	}

	cli := &http.Client{Timeout: *timeout}

	for {
		if err := streamFromCursor(ctx, g, subscribeToken, source, &startCursor, cursorPath, *to, cli, *exitOnError); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			if *exitOnError {
				fmt.Fprintln(os.Stderr, "forward:", err)
				return 1
			}
			// Backoff capped at 60s; mirrors push policy.
			delay := backoff()
			fmt.Fprintf(os.Stderr, "forward: %v; reconnecting in %s\n", err, delay)
			select {
			case <-ctx.Done():
				return 0
			case <-time.After(delay):
			}
			continue
		}
		return 0
	}
}

func streamFromCursor(ctx context.Context, g globals, bearer, source string, cursor *int64, cursorPath, to string, cli *http.Client, exitOnError bool) error {
	endpoint := fmt.Sprintf("%s/subscribe/%s?since=%d", strings.TrimRight(g.Server, "/"), source, *cursor)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subscribe returned %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	current := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if len(current) == 0 {
				continue
			}
			seq, err := strconv.ParseInt(current["id"], 10, 64)
			if err != nil {
				current = map[string]string{}
				continue
			}
			if err := forwardOne(ctx, cli, to, current, exitOnError); err != nil {
				return err
			}
			*cursor = seq
			saveCursor(cursorPath, seq)
			current = map[string]string{}
		case strings.HasPrefix(line, ":"):
			// keepalive
		default:
			if i := strings.Index(line, ":"); i >= 0 {
				current[line[:i]] = strings.TrimPrefix(line[i+1:], " ")
			}
		}
	}
	return scanner.Err()
}

func forwardOne(ctx context.Context, cli *http.Client, to string, msg map[string]string, exitOnError bool) error {
	var p struct {
		DeliveryID        string            `json:"delivery_id"`
		ProviderTimestamp time.Time         `json:"provider_timestamp"`
		Headers           map[string]string `json:"headers"`
		Body              string            `json:"body"`
	}
	if err := json.Unmarshal([]byte(msg["data"]), &p); err != nil {
		return fmt.Errorf("parse event: %w", err)
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, to, bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		for k, v := range p.Headers {
			if push.IsHopByHop(k) {
				continue
			}
			req.Header.Set(k, v)
		}
		req.Header.Set("X-Hooks-Delivery-Id", p.DeliveryID)
		req.Header.Set("X-Hooks-Sequence", msg["id"])
		req.Header.Set("X-Hooks-Source", msg["event"])

		resp, err := cli.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if exitOnError {
				return fmt.Errorf("transport: %w", err)
			}
			fmt.Fprintf(os.Stderr, "forward: %v\n", err)
			if !sleepWithCtx(ctx, attemptBackoff(attempt)) {
				return ctx.Err()
			}
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if exitOnError {
			return fmt.Errorf("target returned %d", resp.StatusCode)
		}
		fmt.Fprintf(os.Stderr, "forward: target returned %d\n", resp.StatusCode)
		if !sleepWithCtx(ctx, attemptBackoff(attempt)) {
			return ctx.Err()
		}
	}
}

func attemptBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 30 {
		attempt = 30
	}
	base := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
	if base > 60*time.Second {
		base = 60 * time.Second
	}
	if base <= 0 {
		return 100 * time.Millisecond
	}
	return time.Duration(rand.Int63n(int64(base)))
}

func backoff() time.Duration {
	return time.Duration(rand.Int63n(int64(2*time.Second))) + 500*time.Millisecond
}

func sleepWithCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cursorFilePath(server, source string) (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "hooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	host := serverHost(server)
	return filepath.Join(dir, fmt.Sprintf("cursor-%s-%s", host, source)), nil
}

func serverHost(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ReplaceAll(s, "/", "_")
	}
	return strings.ReplaceAll(u.Host, ":", "_")
}

func loadCursor(path string) int64 {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return n
}

func saveCursor(path string, seq int64) {
	_ = os.WriteFile(path, []byte(strconv.FormatInt(seq, 10)+"\n"), 0o600)
}

// ephemeralListener is the in-memory record of a `kind='listener'`,
// `ephemeral=true` token minted for the lifetime of one `hooksctl
// forward` invocation.
type ephemeralListener struct {
	ID        string
	Plaintext string
}

// mintEphemeralListener calls /api/me/tokens to mint a per-source
// listener token. Returns (nil, nil) if the caller's PAT cannot reach
// /api/me (e.g. system bearer that happens to have only listener
// scope) — in that case forward falls back to using the original
// token, preserving backwards compatibility for power users who hand-
// minted a long-lived listener token. Any unexpected status is
// returned as an error so the caller can abort with a clean message.
func mintEphemeralListener(ctx context.Context, g globals, source string) (*ephemeralListener, error) {
	body, _ := json.Marshal(map[string]any{
		"name":      "hooksctl-forward-" + source,
		"scopes":    []string{source},
		"kind":      "listener",
		"ephemeral": true,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.Server, "/")+"/api/me/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusCreated:
		var out struct {
			ID        string `json:"id"`
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		if out.Plaintext == "" || out.ID == "" {
			return nil, errors.New("server returned empty token")
		}
		return &ephemeralListener{ID: out.ID, Plaintext: out.Plaintext}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The bearer is not a user PAT (e.g. listener token reaching
		// here because /api/me rejected it). Fall back to using the
		// caller-supplied token directly.
		return nil, nil
	default:
		bb, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("/api/me/tokens: %d %s", resp.StatusCode, bb)
	}
}

// revokeEphemeralListener best-effort POSTs the revoke endpoint with
// a 5s timeout so a slow or unreachable server does not block CLI
// teardown. Errors are logged to stderr; the plaintext token never
// appears in any log line.
func revokeEphemeralListener(g globals, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.Server, "/")+"/api/me/tokens/"+id+"/revoke", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forward: revoke ephemeral token: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forward: revoke ephemeral token: %v\n", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		fmt.Fprintf(os.Stderr, "forward: revoke ephemeral token: status %d\n", resp.StatusCode)
	}
}


