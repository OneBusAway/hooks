// Package me implements the /api/me/* self-service surface described in
// design.md and add-developer-accounts §8: profile read/edit, token list/
// mint/revoke, and per-user push-subscription management. It accepts
// either a hooks_session cookie (resolved upstream by auth.Manager) or a
// kind='pat' bearer token; listener tokens are rejected with 403 here.
package me

import "github.com/onebusaway/hooks/internal/store"

// HeldScopes returns the scope set caller may use as parents when minting
// tokens or registering subscriptions. Admins implicitly hold every
// scope; non-admin users hold their default_scopes plus the implicit
// account scope. Thin wrapper around store.HeldByUser so call sites in
// the me package read consistently.
func HeldScopes(u store.User) []string {
	return []string(store.HeldByUser(u))
}

// SubsetOf reports whether every element of need is present in have. The
// store.ScopeAll sentinel in have grants everything.
func SubsetOf(need, have []string) bool {
	return store.Scopes(need).SubsetOf(store.Scopes(have))
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
	return []string(store.Scopes(scopes).With(store.ScopeAccount))
}
