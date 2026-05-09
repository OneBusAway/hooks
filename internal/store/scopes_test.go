package store

import (
	"slices"
	"testing"
)

func TestScopes_Has(t *testing.T) {
	tests := []struct {
		name   string
		scopes Scopes
		probe  string
		want   bool
	}{
		{"empty does not contain anything", Scopes{}, "render", false},
		{"single match", Scopes{"render"}, "render", true},
		{"single non-match", Scopes{"render"}, "stripe", false},
		{"multiple match", Scopes{"render", "stripe"}, "stripe", true},
		{"wildcard matches anything", Scopes{ScopeAll}, "stripe", true},
		{"empty probe returns false", Scopes{"render"}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scopes.Has(tc.probe); got != tc.want {
				t.Errorf("Has(%q) = %v, want %v", tc.probe, got, tc.want)
			}
		})
	}
}

func TestScopes_With(t *testing.T) {
	tests := []struct {
		name string
		in   Scopes
		add  string
		want Scopes
	}{
		{"appends when absent", Scopes{"render"}, "account", Scopes{"render", "account"}},
		{"no-op when present", Scopes{"render", "account"}, "account", Scopes{"render", "account"}},
		{"appends to empty", Scopes{}, "account", Scopes{"account"}},
		{"appends to nil", nil, "account", Scopes{"account"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.With(tc.add)
			if !slices.Equal(got, tc.want) {
				t.Errorf("With(%q) = %v, want %v", tc.add, got, tc.want)
			}
		})
	}
}

func TestScopes_With_DoesNotMutateInput(t *testing.T) {
	in := Scopes{"render"}
	_ = in.With("account")
	if !slices.Equal(in, Scopes{"render"}) {
		t.Errorf("With mutated receiver: got %v, want [render]", in)
	}
}

func TestScopes_Equal(t *testing.T) {
	tests := []struct {
		name string
		a, b Scopes
		want bool
	}{
		{"both empty", Scopes{}, Scopes{}, true},
		{"nil equals empty", nil, Scopes{}, true},
		{"same single element", Scopes{"render"}, Scopes{"render"}, true},
		{"order-insensitive", Scopes{"render", "stripe"}, Scopes{"stripe", "render"}, true},
		{"duplicates ignored", Scopes{"render", "render"}, Scopes{"render"}, true},
		{"different lengths after dedupe", Scopes{"render"}, Scopes{"render", "stripe"}, false},
		{"different elements", Scopes{"render"}, Scopes{"stripe"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Equal(tc.b); got != tc.want {
				t.Errorf("Equal(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			// Equal is symmetric.
			if got := tc.b.Equal(tc.a); got != tc.want {
				t.Errorf("Equal(%v, %v) = %v (asymmetric), want %v", tc.b, tc.a, got, tc.want)
			}
		})
	}
}

func TestScopes_HeldByUser(t *testing.T) {
	tests := []struct {
		name string
		user User
		want Scopes
	}{
		{
			name: "admin returns wildcard sentinel",
			user: User{Role: RoleAdmin, DefaultScopes: []string{"render"}},
			want: Scopes{ScopeAll},
		},
		{
			name: "non-admin gets default_scopes plus account",
			user: User{Role: RoleUser, DefaultScopes: []string{"render"}},
			want: Scopes{"render", ScopeAccount},
		},
		{
			name: "non-admin already has account does not double-add",
			user: User{Role: RoleUser, DefaultScopes: []string{"render", ScopeAccount}},
			want: Scopes{"render", ScopeAccount},
		},
		{
			name: "non-admin with empty default_scopes still gets account",
			user: User{Role: RoleUser, DefaultScopes: nil},
			want: Scopes{ScopeAccount},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HeldByUser(tc.user)
			if !slices.Equal(got, tc.want) {
				t.Errorf("HeldByUser = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScopes_SubsetOf(t *testing.T) {
	tests := []struct {
		name string
		need Scopes
		have Scopes
		want bool
	}{
		{"empty need is always satisfied", Scopes{}, Scopes{"render"}, true},
		{"need fully present in have", Scopes{"render"}, Scopes{"render", "stripe"}, true},
		{"need missing from have", Scopes{"render"}, Scopes{"stripe"}, false},
		{"wildcard have grants any need", Scopes{"render", "stripe"}, Scopes{ScopeAll}, true},
		{"wildcard have grants empty need", Scopes{}, Scopes{ScopeAll}, true},
		{"non-wildcard have rejects extra need", Scopes{"render", "stripe"}, Scopes{"render"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.need.SubsetOf(tc.have); got != tc.want {
				t.Errorf("SubsetOf(need=%v, have=%v) = %v, want %v", tc.need, tc.have, got, tc.want)
			}
		})
	}
}
