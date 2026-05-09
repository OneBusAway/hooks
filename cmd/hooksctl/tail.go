package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func cmdTail(g globals, args []string) int {
	fs := newFlagSet("tail")
	since := fs.String("since", "0", "starting cursor: integer or 'latest'")
	tail, err := parseInterleaved(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(tail) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl tail <source> [--since <seq|latest>]")
		return 2
	}
	source := tail[0]
	if g.Token == "" {
		fmt.Fprintln(os.Stderr, "missing --token (or HOOKS_TOKEN)")
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	url := fmt.Sprintf("%s/subscribe/%s?since=%s", strings.TrimRight(g.Server, "/"), source, *since)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "subscribe returned %d\n", resp.StatusCode)
		return 1
	}

	var lastSeq atomic.Int64
	defer func() {
		fmt.Fprintf(os.Stderr, "last-acked: %d\n", lastSeq.Load())
	}()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	var msg map[string]string
	flush := func() {
		if msg == nil {
			return
		}
		seq := msg["id"]
		if n, err := strconv.ParseInt(seq, 10, 64); err == nil {
			lastSeq.Store(n)
		}
		printEvent(g.JSON, source, msg)
		msg = nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
			// keepalive comment
		default:
			if msg == nil {
				msg = map[string]string{}
			}
			if i := strings.Index(line, ":"); i >= 0 {
				k := line[:i]
				v := strings.TrimPrefix(line[i+1:], " ")
				msg[k] = v
			}
		}
	}
	flush()
	return 0
}

func printEvent(asJSON bool, source string, msg map[string]string) {
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"source":   source,
			"sequence": msg["id"],
			"data":     msg["data"],
		})
		return
	}
	var p struct {
		DeliveryID        string    `json:"delivery_id"`
		ProviderTimestamp time.Time `json:"provider_timestamp"`
		Body              string    `json:"body"`
	}
	_ = json.Unmarshal([]byte(msg["data"]), &p)
	bodyBytes, _ := base64.StdEncoding.DecodeString(p.Body)
	preview := string(bodyBytes)
	if len(preview) > 80 {
		preview = preview[:80] + "…"
	}
	fmt.Printf("%s seq=%s delivery=%s body=%q\n", source, msg["id"], p.DeliveryID, preview)
}
