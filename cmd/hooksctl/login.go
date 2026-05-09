package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// loginPollHardCap is the maximum total time the login command will
// poll for an approval before giving up. design.md §device-pairing TTL
// is 15m; we wrap that as a client-side cap so a stuck terminal doesn't
// poll forever even if the row would notionally still be pending.
const loginPollHardCap = 15 * time.Minute

// loginTestClient is non-nil only in tests; production paths use a
// fresh http.Client with a 30s per-request timeout. Tests inject an
// httptest.Server's client so TLS config matches.
var loginTestClient *http.Client

func cmdLogin(g globals, args []string) int {
	fs := newFlagSet("login")
	scopes := fs.String("scopes", "", "comma-separated scopes to request (e.g. render,stripe)")
	admin := fs.Bool("admin", false, "request the admin scope")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cli := loginTestClient
	if cli == nil {
		cli = &http.Client{Timeout: 30 * time.Second}
	}

	scopeList := splitScopes(*scopes)
	body, _ := json.Marshal(map[string]any{
		"scopes": scopeList,
		"admin":  *admin,
	})
	startResp, err := postJSON(cli, g.Server+"/api/auth/device/start", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login: start:", err)
		return 1
	}
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(startResp.Body)
		fmt.Fprintf(os.Stderr, "login: start: %d %s\n", startResp.StatusCode, bb)
		return 1
	}
	var s struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_uri"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&s); err != nil {
		fmt.Fprintln(os.Stderr, "login: decode start:", err)
		return 1
	}

	// Print a stable, scriptable banner. The user will eyeball user_code
	// and visit the verification URL on a logged-in browser.
	fmt.Printf("Visit: %s\n", s.VerificationURL)
	fmt.Printf("Code:  %s\n", s.UserCode)
	fmt.Printf("(this code expires in %d seconds; polling every %ds)\n",
		s.ExpiresIn, s.Interval)

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()
	deadline := time.Now().Add(loginPollHardCap)
	if s.ExpiresIn > 0 && time.Duration(s.ExpiresIn)*time.Second < loginPollHardCap {
		deadline = time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)
	}
	interval := time.Duration(s.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	pollBody, _ := json.Marshal(map[string]string{"device_code": s.DeviceCode})
	for {
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "login: timed out waiting for approval")
			return 1
		}
		if err := sleepCtx(ctx, interval); err != nil {
			fmt.Fprintln(os.Stderr, "login: cancelled")
			return 130
		}
		pollResp, err := postJSON(cli, g.Server+"/api/auth/device/poll", pollBody)
		if err != nil {
			fmt.Fprintln(os.Stderr, "login: poll:", err)
			continue
		}
		switch pollResp.StatusCode {
		case http.StatusAccepted:
			_ = pollResp.Body.Close()
			continue
		case http.StatusOK:
			var p struct {
				Token  string   `json:"token"`
				UserID string   `json:"user_id"`
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
			}
			err := json.NewDecoder(pollResp.Body).Decode(&p)
			_ = pollResp.Body.Close()
			if err != nil || p.Token == "" {
				fmt.Fprintln(os.Stderr, "login: malformed approval response")
				return 1
			}
			now := time.Now().UTC()
			prof := profile{
				ServerURL: g.Server,
				Token:     p.Token,
				CreatedAt: now,
			}
			if err := saveProfile(g.Profile, prof); err != nil {
				fmt.Fprintln(os.Stderr, "login: save profile:", err)
				return 1
			}
			path, _ := profilePath(g.Profile)
			fmt.Printf("Saved credentials to %s\n", path)
			fmt.Printf("Scopes: %s\n", strings.Join(p.Scopes, ","))
			return 0
		case http.StatusForbidden:
			bb, _ := io.ReadAll(pollResp.Body)
			_ = pollResp.Body.Close()
			fmt.Fprintf(os.Stderr, "login: denied: %s\n", bb)
			return 1
		case http.StatusGone:
			bb, _ := io.ReadAll(pollResp.Body)
			_ = pollResp.Body.Close()
			fmt.Fprintf(os.Stderr, "login: expired: %s\n", bb)
			return 1
		case http.StatusNotFound:
			bb, _ := io.ReadAll(pollResp.Body)
			_ = pollResp.Body.Close()
			fmt.Fprintf(os.Stderr, "login: pairing not found: %s\n", bb)
			return 1
		default:
			bb, _ := io.ReadAll(pollResp.Body)
			_ = pollResp.Body.Close()
			fmt.Fprintf(os.Stderr, "login: poll: %d %s\n", pollResp.StatusCode, bb)
			return 1
		}
	}
}

// splitScopes turns "render,stripe" into ["render","stripe"]; empty or
// whitespace-only entries are dropped. An empty string yields a nil
// slice so the server applies its default ([]string{"account"}).
func splitScopes(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func postJSON(cli *http.Client, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return cli.Do(req)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
