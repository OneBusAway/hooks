package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// cmdMe routes `hooksctl me <subcommand>` against /api/me/*. The two
// subcommand families mirror the operator-side `token` and `push` trees,
// but every request is scoped to the caller's owned tokens / push
// subscriptions via the server-side `OwnerUserID` filter.
func cmdMe(g globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me {token|sub} ...")
		return 2
	}
	switch args[0] {
	case "token":
		return cmdMeToken(g, args[1:])
	case "sub":
		return cmdMeSub(g, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown me subcommand: %s\n", args[0])
		return 2
	}
}

// ---------- me token ----------

func cmdMeToken(g globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me token {add|list|revoke} ...")
		return 2
	}
	switch args[0] {
	case "add":
		return meTokenAdd(g, args[1:])
	case "list":
		return meTokenList(g, args[1:])
	case "revoke":
		return meTokenRevoke(g, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown me token subcommand: %s\n", args[0])
		return 2
	}
}

func meTokenAdd(g globals, args []string) int {
	fs := newFlagSet("me token add")
	name := fs.String("name", "", "human-readable label")
	scopes := fs.String("scopes", "", "comma-separated scopes (must be a subset of the caller's held scopes)")
	kind := fs.String("kind", "pat", "token kind: pat|listener")
	ephemeral := fs.Bool("ephemeral", false, "mark token as ephemeral (subject to the 24h-idle prune policy)")
	expiresIn := fs.String("expires-in", "", "absolute TTL (e.g. 30m, 24h, 30d). Server caps at 1y.")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me token add --name <name> --scopes <list> [--kind pat|listener] [--ephemeral] [--expires-in <dur>]")
		return 2
	}
	scopeList := splitScopes(*scopes)
	body := map[string]any{
		"name":      *name,
		"scopes":    scopeList,
		"kind":      *kind,
		"ephemeral": *ephemeral,
	}
	if *expiresIn != "" {
		dur, err := parseDurationDays(*expiresIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "me token add: --expires-in: %v\n", err)
			return 2
		}
		body["expires_in_seconds"] = int64(dur.Seconds())
	}
	payload, _ := json.Marshal(body)
	resp, err := authedRequest(g, http.MethodPost, "/api/me/tokens", payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "create: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	var out struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		Kind      string   `json:"kind"`
		Ephemeral bool     `json:"ephemeral"`
		Plaintext string   `json:"plaintext"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return 0
	}
	fmt.Printf("id:        %s\n", out.ID)
	fmt.Printf("name:      %s\n", out.Name)
	fmt.Printf("scopes:    %s\n", strings.Join(out.Scopes, ","))
	fmt.Printf("kind:      %s\n", out.Kind)
	if out.Ephemeral {
		fmt.Println("ephemeral: true")
	}
	fmt.Printf("token (shown ONCE): %s\n", out.Plaintext)
	return 0
}

func meTokenList(g globals, args []string) int {
	fs := newFlagSet("me token list")
	includeRevoked := fs.Bool("include-revoked", false, "include revoked tokens")
	kindFilter := fs.String("kind", "", "filter by kind (pat|listener)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	q := url.Values{}
	if *includeRevoked {
		q.Set("include_revoked", "1")
	}
	if *kindFilter != "" {
		q.Set("kind", *kindFilter)
	}
	path := "/api/me/tokens"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	resp, err := authedRequest(g, http.MethodGet, path, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "list: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	if g.JSON {
		_, _ = io.Copy(os.Stdout, resp.Body)
		return 0
	}
	var out struct {
		Tokens []struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			Scopes    []string `json:"scopes"`
			Kind      string   `json:"kind"`
			Ephemeral bool     `json:"ephemeral,omitempty"`
		} `json:"tokens"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("%-36s %-20s %-10s %-5s %s\n", "ID", "NAME", "KIND", "EPHM", "SCOPES")
	for _, t := range out.Tokens {
		eph := ""
		if t.Ephemeral {
			eph = "yes"
		}
		fmt.Printf("%-36s %-20s %-10s %-5s %s\n", t.ID, t.Name, t.Kind, eph, strings.Join(t.Scopes, ","))
	}
	return 0
}

func meTokenRevoke(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me token revoke <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/me/tokens/"+args[0]+"/revoke", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "revoke: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	fmt.Println("revoked")
	return 0
}

// ---------- me sub ----------

func cmdMeSub(g globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me sub {add|list|get|pause|resume|rotate-secret|rm|test} ...")
		return 2
	}
	switch args[0] {
	case "add":
		return meSubAdd(g, args[1:])
	case "list":
		return meSubList(g, args[1:])
	case "get":
		return meSubGet(g, args[1:])
	case "pause":
		return meSubAction(g, args[1:], "pause")
	case "resume":
		return meSubAction(g, args[1:], "resume")
	case "rotate-secret":
		return meSubRotate(g, args[1:])
	case "rm", "delete":
		return meSubDelete(g, args[1:])
	case "test":
		return meSubAction(g, args[1:], "test")
	default:
		fmt.Fprintf(os.Stderr, "unknown me sub subcommand: %s\n", args[0])
		return 2
	}
}

func meSubAdd(g globals, args []string) int {
	fs := newFlagSet("me sub add")
	source := fs.String("source", "", "source name")
	to := fs.String("to", "", "target URL")
	name := fs.String("name", "", "label")
	since := fs.String("since", "", "starting cursor (integer or 'latest', default latest)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *source == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me sub add --source <name> --to <url> [--name <label>] [--since <seq|latest>]")
		return 2
	}
	body, _ := json.Marshal(map[string]any{
		"source":     *source,
		"target_url": *to,
		"name":       *name,
		"since":      *since,
	})
	resp, err := authedRequest(g, http.MethodPost, "/api/me/subscriptions", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "create: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	var out struct {
		Subscription struct {
			ID        string `json:"id"`
			Source    string `json:"source"`
			TargetURL string `json:"target_url"`
			Cursor    int64  `json:"cursor"`
		} `json:"subscription"`
		SigningSecret string `json:"signing_secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return 0
	}
	fmt.Printf("id:             %s\n", out.Subscription.ID)
	fmt.Printf("source:         %s\n", out.Subscription.Source)
	fmt.Printf("target:         %s\n", out.Subscription.TargetURL)
	fmt.Printf("cursor:         %d\n", out.Subscription.Cursor)
	fmt.Printf("signing secret (shown ONCE): %s\n", out.SigningSecret)
	return 0
}

func meSubList(g globals, args []string) int {
	fs := newFlagSet("me sub list")
	includePaused := fs.Bool("include-paused", false, "include paused subscriptions")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	q := ""
	if *includePaused {
		q = "?include_paused=1"
	}
	resp, err := authedRequest(g, http.MethodGet, "/api/me/subscriptions"+q, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "list: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	if g.JSON {
		_, _ = io.Copy(os.Stdout, resp.Body)
		return 0
	}
	var out struct {
		Subscriptions []struct {
			ID                  string `json:"id"`
			Source              string `json:"source"`
			TargetURL           string `json:"target_url"`
			Cursor              int64  `json:"cursor"`
			ConsecutiveFailures int    `json:"consecutive_failures"`
		} `json:"subscriptions"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("%-36s %-12s %-40s %8s %8s\n", "ID", "SOURCE", "TARGET", "CURSOR", "FAIL")
	for _, s := range out.Subscriptions {
		fmt.Printf("%-36s %-12s %-40s %8d %8d\n", s.ID, s.Source, s.TargetURL, s.Cursor, s.ConsecutiveFailures)
	}
	return 0
}

func meSubGet(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me sub get <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodGet, "/api/me/subscriptions/"+args[0], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "get: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	_, _ = io.Copy(os.Stdout, resp.Body)
	fmt.Println()
	return 0
}

func meSubAction(g globals, args []string, action string) int {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: hooksctl me sub %s <id>\n", action)
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/me/subscriptions/"+args[0]+"/"+action, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "%s: %d %s\n", action, resp.StatusCode, bb)
		return 1
	}
	fmt.Println(action)
	return 0
}

func meSubRotate(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me sub rotate-secret <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/me/subscriptions/"+args[0]+"/rotate-secret", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "rotate-secret: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	var out struct {
		ID            string `json:"id"`
		SigningSecret string `json:"signing_secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return 0
	}
	fmt.Printf("id:             %s\n", out.ID)
	fmt.Printf("signing secret (shown ONCE): %s\n", out.SigningSecret)
	return 0
}

func meSubDelete(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl me sub rm <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodDelete, "/api/me/subscriptions/"+args[0], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "rm: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	fmt.Println("removed")
	return 0
}

// parseDurationDays accepts everything `time.ParseDuration` does plus a
// `<N>d` suffix for days. We translate days locally because Go's parser
// does not understand units larger than `h`.
func parseDurationDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseInt(rest, 10, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid days: %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}
	return d, nil
}
