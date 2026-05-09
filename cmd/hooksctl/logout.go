package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// cmdLogout revokes the locally-stored PAT (if reachable) and deletes
// the credentials file. The local-file delete is unconditional: if the
// network revoke fails, we still scrub the file (so a user can run
// `hooksctl logout` to clean up after a server is decommissioned) but
// exit non-zero with a stderr warning.
//
// design.md "logout" sequence:
//  1. POST /api/me/tokens/{self}/revoke
//  2. POST /api/auth/logout (only if a session cookie is present —
//     the CLI never carries one, so we skip it here)
//  3. Delete the credentials file
//
// design.md is explicit that the plaintext token must not appear in any
// log line.
func cmdLogout(g globals, args []string) int {
	fs := newFlagSet("logout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// Even if there is no profile file (e.g. user never ran login but
	// HOOKS_TOKEN was set), we still try to revoke the bearer they
	// supplied — that's the most useful interpretation of "log this
	// credential out".
	revokeFailed := false
	if g.Token != "" {
		revokeFailed = revokeBearer(g)
	}

	if err := deleteProfile(g.Profile); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "logout: delete profile:", err)
		return 1
	}

	if revokeFailed {
		fmt.Fprintln(os.Stderr,
			"logout: local credentials removed, but server-side revoke failed; "+
				"the token may still be valid until the operator revokes it")
		return 1
	}
	fmt.Println("logged out")
	return 0
}

// revokeBearer POSTs /api/me/tokens/self/revoke. Returns true on
// failure. 204 = revoked; 404 = not owned by the caller (already
// revoked, or a system token — no harm done); anything else is a real
// failure surfaced to stderr.
func revokeBearer(g globals) bool {
	resp, err := authedRequest(g, http.MethodPost, "/api/me/tokens/self/revoke", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logout: revoke:", err)
		return true
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return false
	}
	bb, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(os.Stderr, "logout: revoke: %d %s\n", resp.StatusCode, bb)
	return true
}
