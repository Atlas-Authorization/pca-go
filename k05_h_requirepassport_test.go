package pca

import (
	"slices"
	"testing"
)

// F3 requirePassport: a valid signed passport for the presenting agent (its sub = the PCActn's leaf holder), checked before the counter
// is claimed.
func TestF3_RequirePassport(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	issuer, _ := NewKeyPair()
	mkPassport := func(subject string, hw bool) map[string]any {
		pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": hw, "issued_at": g01Now - 1000})
		if err != nil {
			t.Fatal(err)
		}
		sp, err := SignPassport(pp, issuer, subject, 0, 0, g01Now+3_600_000, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sp
	}
	opts := PassportOptions{TrustedIssuers: []string{issuer.Public}, Revoked: func(string, string, string) (bool, error) { return false, nil }}
	run := func(counter int64, passport any, req *PassportRequirement) (AuthorizeResult, *MemoryStateStore) {
		in := g01DynIn(g)
		store := NewMemoryStateStore()
		in.StateStore, in.RequirePassport, in.Passport = store, req, passport
		return Authorize(g01Act(t, g, chain, k.agent, "", g01Now, counter, nil), in), store
	}
	if r, _ := run(1, nil, nil); !r.Allow || r.Checks["passport"] != "" {
		t.Errorf("not required: %+v", r)
	}
	if r, _ := run(1, mkPassport(k.agent.Public, false), &PassportRequirement{Options: opts}); !r.Allow || r.Checks["passport"] != "pass" {
		t.Errorf("valid: %+v", r)
	}
	for name, c := range map[string]struct {
		passport any
		req      *PassportRequirement
		want     string
	}{
		"absent":         {nil, &PassportRequirement{Options: opts}, "passport: malformed"},
		"another agent":  {mkPassport(k.sub.Public, false), &PassportRequirement{Options: opts}, "passport: subject_mismatch"},
		"hardware asked": {mkPassport(k.agent.Public, false), &PassportRequirement{Options: opts, Hardware: true}, "passport: hardware_evidence_missing"},
		"no issuers":     {mkPassport(k.agent.Public, false), &PassportRequirement{Options: PassportOptions{Revoked: opts.Revoked}}, ""},
	} {
		r, st := run(1, c.passport, c.req)
		if r.Allow || r.Checks["passport"] != "fail" {
			t.Errorf("%s: %+v", name, r)
			continue
		}
		if c.want != "" && !slices.Contains(r.Reasons, c.want) {
			t.Errorf("%s: reasons %v, want %q", name, r.Reasons, c.want)
		}
		// a refusal never consumes the counter
		if last, _ := st.Last(StateKey(g["id"].(string), k.agent.Public)); last != nil {
			t.Errorf("%s: a refused passport consumed the counter", name)
		}
	}
}
