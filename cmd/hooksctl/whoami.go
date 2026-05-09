package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// cmdWhoami GETs /api/me and prints email + role + server URL. Errors
// surface to stderr; exit codes mirror the rest of the CLI (0 success,
// 1 transport/server failure, 2 usage error).
func cmdWhoami(g globals, args []string) int {
	fs := newFlagSet("whoami")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if g.Token == "" {
		fmt.Fprintln(os.Stderr, "missing --token (or HOOKS_TOKEN, or a logged-in profile — try `hooksctl login`)")
		return 1
	}
	resp, err := authedRequest(g, http.MethodGet, "/api/me", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "whoami: %d %s\n", resp.StatusCode, bb)
		return 1
	}
	var out struct {
		UserID        string   `json:"user_id"`
		Email         string   `json:"email"`
		Name          string   `json:"name"`
		Role          string   `json:"role"`
		DefaultScopes []string `json:"default_scopes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if g.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"server": g.Server,
			"user":   out,
		})
		return 0
	}
	fmt.Printf("server: %s\n", g.Server)
	fmt.Printf("email:  %s\n", out.Email)
	fmt.Printf("name:   %s\n", out.Name)
	fmt.Printf("role:   %s\n", out.Role)
	return 0
}
