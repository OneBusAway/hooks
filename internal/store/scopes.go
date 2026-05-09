package store

// ScopeAll is the wildcard sentinel used when expressing the scope set an
// admin user holds: any scope check against a Scopes containing ScopeAll
// passes. It is a runtime sentinel only — it is never persisted.
const ScopeAll = "*"

// Scopes is a list of scope strings with set-like semantics. Equality is
// order- and duplicate-insensitive; Has and SubsetOf treat the ScopeAll
// sentinel as "any scope satisfies."
//
// Two scope-shape concepts are encoded:
//
//   - Persisted scopes (stored on tokens, subscriptions, default_scopes)
//     are concrete source names plus the implicit "account" and "admin"
//     scopes.
//   - Held scopes — the runtime authority of a caller — additionally
//     allow the ScopeAll sentinel for admins, who hold every scope
//     implicitly.
//
// Use HeldByUser to derive a held-scope Scopes from a User. Use With to
// inject the implicit account scope when minting PATs. Use SubsetOf to
// check whether a requested scope set is authorized.
type Scopes []string

// Has reports whether name appears in s. The ScopeAll sentinel matches
// any non-empty name; an empty probe always returns false (callers
// shouldn't be checking for the empty scope, and matching it against a
// wildcard would be surprising).
func (s Scopes) Has(name string) bool {
	if name == "" {
		return false
	}
	for _, x := range s {
		if x == ScopeAll {
			return true
		}
		if x == name {
			return true
		}
	}
	return false
}

// With returns a new Scopes with name appended if absent. It does not
// mutate the receiver. Used at PAT-mint time to force-include the
// account scope.
func (s Scopes) With(name string) Scopes {
	if s.Has(name) {
		// Defensive copy so callers never observe aliasing.
		out := make(Scopes, len(s))
		copy(out, s)
		return out
	}
	out := make(Scopes, len(s), len(s)+1)
	copy(out, s)
	return append(out, name)
}

// Equal reports whether s and other denote the same set, ignoring order
// and duplicates. Two empty (or nil) Scopes are equal.
func (s Scopes) Equal(other Scopes) bool {
	a := s.uniq()
	b := other.uniq()
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// SubsetOf reports whether every element of s is present in have. The
// ScopeAll sentinel in have grants everything.
func (s Scopes) SubsetOf(have Scopes) bool {
	for _, h := range have {
		if h == ScopeAll {
			return true
		}
	}
	hs := have.uniq()
	for _, n := range s {
		if !hs[n] {
			return false
		}
	}
	return true
}

// uniq returns the receiver as a set.
func (s Scopes) uniq() map[string]bool {
	out := make(map[string]bool, len(s))
	for _, x := range s {
		out[x] = true
	}
	return out
}

// HeldByUser returns the runtime authority a user has when minting tokens
// or registering subscriptions. Admins implicitly hold every scope
// (Scopes{ScopeAll}); non-admin users hold their default_scopes plus the
// implicit account scope.
func HeldByUser(u User) Scopes {
	if u.Role == RoleAdmin {
		return Scopes{ScopeAll}
	}
	return Scopes(u.DefaultScopes).With(ScopeAccount)
}
