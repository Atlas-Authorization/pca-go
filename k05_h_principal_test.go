package pca

import (
	"errors"
	"slices"
	"testing"
)

// F3 requireVerifiedPrincipal + resolvePrincipal.
func TestF3_RequireVerifiedPrincipal(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	run := func(mut func(in *AuthorizeInput)) AuthorizeResult {
		in := g01DynIn(g)
		mut(&in)
		return Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), in)
	}
	verified := func(string, map[string]any) (*PrincipalInfo, error) {
		return &PrincipalInfo{Pub: "p", SubjectType: "human", Verified: true}, nil
	}
	if r := run(func(in *AuthorizeInput) { in.ResolvePrincipal, in.RequireVerifiedPrincipal = verified, true }); !r.Allow || r.Checks["principal"] != "pass" || r.Principal == nil || !r.Principal.Verified {
		t.Errorf("verified: %+v", r)
	}
	deniedWant := "principal: the grant issuer is not an enrolled, verified principal"
	for name, f := range map[string]func(string, map[string]any) (*PrincipalInfo, error){
		"nil": func(string, map[string]any) (*PrincipalInfo, error) { return nil, nil },
		"unverified": func(string, map[string]any) (*PrincipalInfo, error) {
			return &PrincipalInfo{SubjectType: "unverified"}, nil
		},
	} {
		r := run(func(in *AuthorizeInput) { in.ResolvePrincipal, in.RequireVerifiedPrincipal = f, true })
		if r.Allow || r.Checks["principal"] != "fail" || !slices.Contains(r.Reasons, deniedWant) {
			t.Errorf("%s required: %+v", name, r)
		}
		// not required: allowed, reported not-enforced, the principal is returned
		r = run(func(in *AuthorizeInput) { in.ResolvePrincipal = f })
		if !r.Allow || r.Checks["principal"] != "not-enforced" || r.Principal == nil || r.Principal.Verified {
			t.Errorf("%s optional: %+v", name, r)
		}
	}
	// the resolver receives the grant issuer
	var seen string
	run(func(in *AuthorizeInput) {
		in.ResolvePrincipal = func(pub string, _ map[string]any) (*PrincipalInfo, error) { seen = pub; return nil, nil }
	})
	if seen != g["issuer"] {
		t.Errorf("resolver saw %q, want the grant issuer %v", seen, g["issuer"])
	}
	// no resolver but the requirement: denied
	if r := run(func(in *AuthorizeInput) { in.RequireVerifiedPrincipal = true }); r.Allow || !slices.Contains(r.Reasons, "principal: requireVerifiedPrincipal needs a resolvePrincipal resolver") {
		t.Errorf("no resolver: %+v", r)
	}
	// neither: no principal check at all
	if r := run(func(in *AuthorizeInput) {}); !r.Allow || r.Checks["principal"] != "" || r.Principal != nil {
		t.Errorf("neither: %+v", r)
	}
	// a resolver that errors or panics fails closed
	for name, f := range map[string]func(string, map[string]any) (*PrincipalInfo, error){
		"error": func(string, map[string]any) (*PrincipalInfo, error) { return nil, errors.New("down") },
		"panic": func(string, map[string]any) (*PrincipalInfo, error) { panic("boom") },
	} {
		if r := run(func(in *AuthorizeInput) { in.ResolvePrincipal = f }); r.Allow || r.Checks["principal"] != "fail" {
			t.Errorf("%s: %+v", name, r)
		}
	}
}
