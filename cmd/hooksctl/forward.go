package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	cli := &http.Client{Timeout: *timeout}

	for {
		if err := streamFromCursor(ctx, g, source, &startCursor, cursorPath, *to, cli, *exitOnError); err != nil {
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

func streamFromCursor(ctx context.Context, g globals, source string, cursor *int64, cursorPath, to string, cli *http.Client, exitOnError bool) error {
	endpoint := fmt.Sprintf("%s/subscribe/%s?since=%d", strings.TrimRight(g.Server, "/"), source, *cursor)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
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

