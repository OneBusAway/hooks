package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func cmdToken(g globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl token {add|list|revoke} ...")
		return 2
	}
	switch args[0] {
	case "add":
		return tokenAdd(g, args[1:])
	case "list":
		return tokenList(g, args[1:])
	case "revoke":
		return tokenRevoke(g, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown token subcommand: %s\n", args[0])
		return 2
	}
}

func tokenAdd(g globals, args []string) int {
	fs := newFlagSet("token add")
	name := fs.String("name", "", "human-readable label")
	scopes := fs.String("scopes", "", "comma-separated scopes (e.g. render,admin)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *name == "" || *scopes == "" {
		fmt.Fprintln(os.Stderr, "usage: hooksctl token add --name <name> --scopes <list>")
		return 2
	}
	body, _ := json.Marshal(map[string]any{
		"name":   *name,
		"scopes": []string{*scopes}, // server normalizes
	})
	resp, err := authedRequest(g, http.MethodPost, "/api/tokens", body)
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
		Plaintext string   `json:"plaintext"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		fmt.Printf("id:     %s\n", out.ID)
		fmt.Printf("name:   %s\n", out.Name)
		fmt.Printf("scopes: %s\n", strings.Join(out.Scopes, ","))
		fmt.Printf("token (shown ONCE): %s\n", out.Plaintext)
	}
	return 0
}

func tokenList(g globals, args []string) int {
	fs := newFlagSet("token list")
	includeRevoked := fs.Bool("include-revoked", false, "include revoked tokens")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	q := ""
	if *includeRevoked {
		q = "?include_revoked=1"
	}
	resp, err := authedRequest(g, http.MethodGet, "/api/tokens"+q, nil)
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
			ID, Name string
			Scopes   []string
		} `json:"tokens"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("%-36s %-20s %s\n", "ID", "NAME", "SCOPES")
	for _, t := range out.Tokens {
		fmt.Printf("%-36s %-20s %s\n", t.ID, t.Name, strings.Join(t.Scopes, ","))
	}
	return 0
}

func tokenRevoke(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl token revoke <id>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodPost, "/api/tokens/"+args[0]+"/revoke", nil)
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

func authedRequest(g globals, method, path string, body []byte) (*http.Response, error) {
	if g.Token == "" {
		return nil, fmt.Errorf("missing --token (or HOOKS_TOKEN)")
	}
	url := strings.TrimRight(g.Server, "/") + path
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}
