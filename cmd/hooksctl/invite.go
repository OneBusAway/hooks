package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// cmdInvite routes `hooksctl invite <subcommand>` against /api/invites.
// All three subcommands require an admin PAT (caller-side enforcement is
// the server's; the CLI just passes the bearer through).
func cmdInvite(g globals, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl invite {create|list|revoke} ...")
		return 2
	}
	switch args[0] {
	case "create":
		return inviteCreate(g, args[1:])
	case "list":
		return inviteList(g, args[1:])
	case "revoke":
		return inviteRevoke(g, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown invite subcommand: %s\n", args[0])
		return 2
	}
}

func inviteCreate(g globals, args []string) int {
	fs := newFlagSet("invite create")
	role := fs.String("role", "user", "invite role: user|admin")
	scopes := fs.String("scopes", "", "comma-separated default_scopes (admin invites store but ignore at auth time)")
	ttl := fs.String("ttl", "", "time-to-live (e.g. 7d, 24h). Server default is 7d.")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	body := map[string]any{"role": *role}
	if list := splitScopes(*scopes); len(list) > 0 {
		body["default_scopes"] = list
	}
	if *ttl != "" {
		dur, err := parseDurationDays(*ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invite create: --ttl: %v\n", err)
			return 2
		}
		body["ttl_seconds"] = int64(dur.Seconds())
	}
	payload, _ := json.Marshal(body)
	resp, err := authedRequest(g, http.MethodPost, "/api/invites", payload)
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
		Code          string   `json:"code"`
		Role          string   `json:"role"`
		DefaultScopes []string `json:"default_scopes"`
		ExpiresAt     *string  `json:"expires_at,omitempty"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return 0
	}
	fmt.Printf("code:    %s\n", out.Code)
	fmt.Printf("role:    %s\n", out.Role)
	if len(out.DefaultScopes) > 0 {
		fmt.Printf("scopes:  %s\n", strings.Join(out.DefaultScopes, ","))
	}
	if out.ExpiresAt != nil {
		fmt.Printf("expires: %s\n", *out.ExpiresAt)
	}
	fmt.Printf("signup:  %s/signup?code=%s\n", strings.TrimRight(g.Server, "/"), out.Code)
	return 0
}

func inviteList(g globals, args []string) int {
	fs := newFlagSet("invite list")
	includeConsumed := fs.Bool("include-consumed", false, "include consumed invites in the listing")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	path := "/api/invites?consumed=false"
	if *includeConsumed {
		path = "/api/invites"
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
		Invites []struct {
			Code       string  `json:"code"`
			Role       string  `json:"role"`
			ExpiresAt  *string `json:"expires_at,omitempty"`
			ConsumedAt *string `json:"consumed_at,omitempty"`
		} `json:"invites"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("%-22s %-8s %-25s %-25s\n", "CODE", "ROLE", "EXPIRES", "CONSUMED")
	for _, inv := range out.Invites {
		exp := "-"
		if inv.ExpiresAt != nil {
			exp = *inv.ExpiresAt
		}
		cons := "-"
		if inv.ConsumedAt != nil {
			cons = *inv.ConsumedAt
		}
		fmt.Printf("%-22s %-8s %-25s %-25s\n", inv.Code, inv.Role, exp, cons)
	}
	return 0
}

func inviteRevoke(g globals, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hooksctl invite revoke <code>")
		return 2
	}
	resp, err := authedRequest(g, http.MethodDelete, "/api/invites/"+args[0], nil)
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
