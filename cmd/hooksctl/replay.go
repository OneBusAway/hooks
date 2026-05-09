package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/onebusaway/hooks/internal/push"
)

func cmdReplay(g globals, args []string) int {
	fs := newFlagSet("replay")
	to := fs.String("to", "", "URL to POST the replayed event to")
	tail, err := parseInterleaved(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(tail) != 2 || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: hooksctl replay <source> <sequence> --to <url>")
		return 2
	}
	source := tail[0]
	seq, err := strconv.ParseInt(tail[1], 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid sequence:", err)
		return 2
	}
	if g.Token == "" {
		fmt.Fprintln(os.Stderr, "missing --token (or HOOKS_TOKEN)")
		return 2
	}

	// Pull the event via subscribe with since=seq-1, limit one.
	url := fmt.Sprintf("%s/subscribe/%s?since=%d", strings.TrimRight(g.Server, "/"), source, seq-1)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+g.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "subscribe:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the first SSE message.
	current := map[string]string{}
	buf := make([]byte, 1<<16)
	n, _ := resp.Body.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			if len(current) > 0 {
				break
			}
			continue
		}
		if i := strings.Index(line, ":"); i >= 0 {
			current[line[:i]] = strings.TrimPrefix(line[i+1:], " ")
		}
	}
	if current["id"] != strconv.FormatInt(seq, 10) {
		fmt.Fprintf(os.Stderr, "replay: did not find sequence %d (got %q)\n", seq, current["id"])
		return 1
	}

	var p struct {
		Headers    map[string]string `json:"headers"`
		Body       string            `json:"body"`
		DeliveryID string            `json:"delivery_id"`
	}
	if err := json.Unmarshal([]byte(current["data"]), &p); err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		return 1
	}
	body, _ := base64.StdEncoding.DecodeString(p.Body)
	out, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, *to, bytes.NewReader(body))
	for k, v := range p.Headers {
		if push.IsHopByHop(k) {
			continue
		}
		out.Header.Set(k, v)
	}
	out.Header.Set("X-Hooks-Delivery-Id", p.DeliveryID)
	out.Header.Set("X-Hooks-Sequence", current["id"])
	out.Header.Set("X-Hooks-Source", source)

	resp2, err := http.DefaultClient.Do(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "POST:", err)
		return 1
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "target returned %d\n", resp2.StatusCode)
		return 1
	}
	fmt.Println("replayed")
	return 0
}
