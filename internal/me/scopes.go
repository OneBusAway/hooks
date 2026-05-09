// Package me implements the /api/me/* self-service surface described in
// design.md and add-developer-accounts §8: profile read/edit, token list/
// mint/revoke, and per-user push-subscription management. It accepts
// either a hooks_session cookie (resolved upstream by auth.Manager) or a
// kind='pat' bearer token; listener tokens are rejected with 403 here.
package me

import "github.com/onebusaway/hooks/internal/store"

// adminAllScopes is the sentinel returned by HeldScopes for admin users;
// SubsetOf treats it as "any scope satisfies."
const adminAllScopes = "*"

// HeldScopes returns the scope set caller may use as parents when minting
// tokens or registering subscriptions. Admins implicitly hold every
// scope; non-admin users hold their default_scopes plus the implicit
// account scope.
func HeldScopes(u store.User) []string {
	if u.Role == store.RoleAdmin {
		return []string{adminAllScopes}
	}
	out := append([]string{}, u.DefaultScopes...)
	if !store.HasScope(out, store.ScopeAccount) {
		out = append(out, store.ScopeAccount)
	}
	return out
}

// SubsetOf reports whether every element of need is present in have. The
// "*" sentinel in have grants everything.
func SubsetOf(need, have []string) bool {
	for _, h := range have {
		if h == adminAllScopes {
			return true
		}
	}
	hs := map[string]bool{}
	for _, h := range have {
		hs[h] = true
	}
	for _, n := range need {
		if !hs[n] {
			return false
		}
	}
	return true
}

// Normalize trims duplicates while preserving order; empty entries are
// dropped. The result is suitable for storage.
func Normalize(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// EnsureAccount appends the account scope if absent. Used by PAT mint.
func EnsureAccount(scopes []string) []string {
	if store.HasScope(scopes, store.ScopeAccount) {
		return scopes
	}
	return append(scopes, store.ScopeAccount)
}
