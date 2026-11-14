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
	if r, _ := run(1, mkPassport(k.agent.Public, false), &PassportRequirement{Options: opts}); r.Assurance.ToMap()["passport"].(map[string]any)["level"] != "software" {
		t.Errorf("software passport assurance: %v", r.Assurance.ToMap()["passport"])
	}
	if r, _ := run(1, nil, nil); r.Assurance.ToMap()["passport"] != nil {
		t.Errorf("no passport entry without the gate: %v", r.Assurance.ToMap())
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

// A hardware-rooted passport that passes carries its verifier's label in assurance.passport (level "unknown" when the verifier
// declares none).
func TestF3_RequirePassportHardwareAssurance(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	issuer, _ := NewKeyPair()
	pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": true, "issued_at": g01Now - 1000})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := SignPassport(pp, issuer, k.agent.Public, 0, 0, g01Now+3_600_000, map[string]any{"document": map[string]any{"nonce": "n"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := PassportOptions{TrustedIssuers: []string{issuer.Public}, Revoked: func(string, string, string) (bool, error) { return false, nil },
		Attest: func(map[string]any, PassportBinding) (PassportAttestation, error) {
			return PassportAttestation{OK: true, Bound: true, Measured: map[string]any{"model_id": "m", "operator": "acme"}}, nil
		}}
	in := g01DynIn(g)
	in.RequirePassport, in.Passport = &PassportRequirement{Options: opts, Hardware: true}, sp
	r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), in)
	if !r.Allow {
		t.Fatalf("hardware-rooted: %+v", r)
	}
	e, _ := r.Assurance.Get("passport")
	if e.Outcome != "pass" || e.Level != "unknown" || e.Vendor != "" {
		t.Errorf("assurance.passport = %+v", e)
	}
}

type passportLabelVendor struct{}

func (passportLabelVendor) verify(map[string]any, *AttestationBinding, int64) HardwareResult {
	return HardwareResult{OK: true, Bound: true, Measured: map[string]any{"model_id": "m", "operator": "acme"}}
}

// assurance.passport of an admitted hardware-rooted passport: Attest wins over DefaultHardware, the built-in vendor verifier labels
// itself (hardware + vendor), an integrator Attest func is unlabelled ("unknown"), a software passport is "software".
func TestF3_RequirePassportAssuranceLabels(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	issuer, _ := NewKeyPair()
	mk := func(hw bool) map[string]any {
		pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": hw, "issued_at": g01Now - 1000})
		if err != nil {
			t.Fatal(err)
		}
		var ev map[string]any
		if hw {
			ev = map[string]any{"document": map[string]any{"nonce": "n"}}
		}
		sp, err := SignPassport(pp, issuer, k.agent.Public, 0, 0, g01Now+3_600_000, ev, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sp
	}
	attest := func(map[string]any, PassportBinding) (PassportAttestation, error) {
		return PassportAttestation{OK: true, Bound: true, Measured: map[string]any{"model_id": "m", "operator": "acme"}}, nil
	}
	dh := func() *DefaultHardware {
		return &DefaultHardware{Verifier: &VendorVerifier{vendor: "amd-sev-snp", impl: passportLabelVendor{}}}
	}
	for name, c := range map[string]struct {
		hw            bool
		attest        bool
		dh            bool
		level, vendor string
	}{
		"software":                 {false, true, true, "software", ""},
		"software, no hooks":       {false, false, false, "software", ""},
		"attest only":              {true, true, false, "unknown", ""},
		"default hardware only":    {true, false, true, "hardware", "amd-sev-snp"},
		"attest wins over default": {true, true, true, "unknown", ""},
	} {
		opts := PassportOptions{TrustedIssuers: []string{issuer.Public}, Revoked: func(string, string, string) (bool, error) { return false, nil }}
		if c.attest {
			opts.Attest = attest
		}
		if c.dh {
			opts.DefaultHardware = dh()
		}
		in := g01DynIn(g)
		in.RequirePassport, in.Passport = &PassportRequirement{Options: opts}, mk(c.hw)
		r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), in)
		if !r.Allow {
			t.Errorf("%s: %+v", name, r)
			continue
		}
		e, _ := r.Assurance.Get("passport")
		if e.Outcome != "pass" || e.Level != c.level || e.Vendor != c.vendor {
			t.Errorf("%s: assurance.passport = %+v", name, e)
		}
	}
}

// The guard admits a leaf other than the one the passport was checked for (a resolver rewrites the leaf's holder after the
// up-front passport check): refused with passport: subject_mismatch, never allowed.
func TestF3_RequirePassportLeafChangedAfterCheck(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	issuer, _ := NewKeyPair()
	pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": false, "issued_at": g01Now - 1000})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := SignPassport(pp, issuer, k.agent.Public, 0, 0, g01Now+3_600_000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	act := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	in := g01DynIn(g)
	in.RequirePassport = &PassportRequirement{Options: PassportOptions{TrustedIssuers: []string{issuer.Public},
		Revoked: func(string, string, string) (bool, error) { return false, nil }}}
	in.Passport = sp
	in.ResolvePrincipal = func(_ string, grant map[string]any) (*PrincipalInfo, error) {
		grant["holder"] = "someone-else"
		if ch, ok := act["cap_chain"].([]any); ok && len(ch) > 0 {
			if leaf, ok := ch[len(ch)-1].(map[string]any); ok {
				leaf["holder"] = "someone-else"
			}
		}
		return nil, nil
	}
	r := Authorize(act, in)
	if r.Allow || r.Checks["passport"] != "fail" || !slices.Contains(r.Reasons, "passport: subject_mismatch") {
		t.Errorf("leaf changed after the passport check: %+v", r)
	}
}
