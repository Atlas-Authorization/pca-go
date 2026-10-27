package pca

// Intent Layer M2 unit tests: the `envelope.intent` wire rules and the `intent` check (intent.go).

import (
	"encoding/json"
	"strings"
	"testing"
)

const tSalt = "c2FsdC1pbnRlbnQtdGVzdA"

func tRef() string { return b64.EncodeToString(sha([]byte("intent/ref"))) }
func tMap() string { return b64.EncodeToString(sha([]byte("intent/map"))) }

// newIntentFx is newFx with a 2-hop chain whose root carries an envelope caveat committing to goalCommit.
func newIntentFx(t *testing.T, goalCommit any) *fx {
	f := newFx(t)
	env := map[string]any{"type": "envelope", "goal_commit": goalCommit}
	chain, keys := mkChain(t, 2, func(int) []any { return []any{map[string]any{"type": "c"}, env} })
	f.chain, f.keys = chain, keys
	f.grant = deepM(t, chain[0].(map[string]any))
	f.p["cap_chain"] = chain
	f.p["grant_ref"] = f.grant["id"]
	f.resign()
	return f
}

func boundCommit(t *testing.T) string {
	c, err := IntentGoalCommit(tRef(), tMap(), tSalt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func tIntent() map[string]any {
	return map[string]any{"ref": tRef(), "map_digest": tMap(), "goal_salt": tSalt,
		"fidelity_ppm": jnum(950_000), "residual_risk_ppm": jnum(4_310_000)}
}

func (f *fx) verifyIntent(pol *IntentPolicy) Verdict {
	f.t.Helper()
	v, err := VerifyPCActnCoreWith(f.norm(), f.grant, f.now, f.aud, VerifyOptions{Intent: pol})
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func fp(x float64) *float64 { return &x }

func TestIntentAbsentNoPolicyIsPreM2(t *testing.T) {
	f := newIntentFx(t, boundCommit(t))
	for _, pol := range []*IntentPolicy{nil, {}, {Require: false}} {
		v := f.verifyIntent(pol)
		if !v.Allow || len(v.Checks) != 9 {
			t.Fatalf("pre-M2 verdict expected: %+v", v)
		}
		if _, has := v.Checks["intent"]; has {
			t.Fatal("intent must not be reported")
		}
	}
}

func TestIntentBound(t *testing.T) {
	f := newIntentFx(t, boundCommit(t))
	f.p["intent"] = tIntent()
	f.resign()
	v := f.verifyIntent(&IntentPolicy{Require: true, MinFidelityPpm: fp(950_000), MaxResidualRiskPpm: fp(4_310_000)})
	if !v.Allow || !v.Checks["intent"] || len(v.Checks) != 10 {
		t.Fatalf("bound intent must pass: %+v", v)
	}
	// Reported even without a policy when the PCActn carries the slot.
	if v := f.verifyIntent(nil); !v.Allow || !v.Checks["intent"] {
		t.Fatalf("bound intent, no policy: %+v", v)
	}
}

func TestIntentCheckFailures(t *testing.T) {
	cases := []struct {
		name   string
		commit any
		carry  bool
		mut    func(m map[string]any)
		pol    *IntentPolicy
		reason string
	}{
		{"absent-required", "x", false, nil, &IntentPolicy{Require: true}, "requires an intent"},
		{"threshold-implies-require", "x", false, nil, &IntentPolicy{MinFidelityPpm: fp(1)}, "requires an intent"},
		{"misconfig-negative", "", true, nil, &IntentPolicy{MinFidelityPpm: fp(-1)}, "misconfigured"},
		{"misconfig-fraction", "", true, nil, &IntentPolicy{MaxResidualRiskPpm: fp(0.5)}, "misconfigured"},
		{"salt-mismatch", "", true, func(m map[string]any) { m["goal_salt"] = "wrong" }, nil, "do not open"},
		{"goal-commit-not-string", 7, true, nil, nil, "no envelope goal commitment"},
		{"fidelity-below-min", "", true, nil, &IntentPolicy{MinFidelityPpm: fp(950_001)}, "below the policy minimum"},
		{"residual-above-max", "", true, nil, &IntentPolicy{MaxResidualRiskPpm: fp(4_309_999)}, "exceeds the policy maximum"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			commit := c.commit
			if commit == "" {
				commit = boundCommit(t)
			}
			if n, ok := commit.(int); ok {
				commit = jnum(int64(n))
			}
			f := newIntentFx(t, commit)
			if c.carry {
				m := tIntent()
				if c.mut != nil {
					c.mut(m)
				}
				f.p["intent"] = m
				f.resign()
			}
			v := f.verifyIntent(c.pol)
			if v.Allow || v.Checks["intent"] || !v.Checks["counter_format"] || !v.Checks["leaf_signature"] {
				t.Fatalf("want intent fail only: %+v", v)
			}
			if !strings.HasPrefix(v.Reason, "intent: ") || !strings.Contains(v.Reason, c.reason) {
				t.Fatalf("reason %q", v.Reason)
			}
		})
	}
}

func TestIntentWireRefusals(t *testing.T) {
	cases := map[string]func(m map[string]any) any{
		"string":         func(map[string]any) any { return "x" },
		"null":           func(map[string]any) any { return nil },
		"array":          func(m map[string]any) any { return []any{m} },
		"unknown":        func(m map[string]any) any { m["note"] = "x"; return m },
		"missing-ref":    func(m map[string]any) any { delete(m, "ref"); return m },
		"ref-31":         func(m map[string]any) any { m["ref"] = b64.EncodeToString(make([]byte, 31)); return m },
		"ref-padded":     func(m map[string]any) any { m["ref"] = tRef() + "="; return m },
		"salt-empty":     func(m map[string]any) any { m["goal_salt"] = ""; return m },
		"salt-129":       func(m map[string]any) any { m["goal_salt"] = strings.Repeat("é", 64) + "a"; return m },
		"fid-over":       func(m map[string]any) any { m["fidelity_ppm"] = jnum(1_000_001); return m },
		"fid-negative":   func(m map[string]any) any { m["fidelity_ppm"] = jnum(-1); return m },
		"fid-fraction":   func(m map[string]any) any { m["fidelity_ppm"] = json.Number("1.5"); return m },
		"res-negative":   func(m map[string]any) any { m["residual_risk_ppm"] = jnum(-1); return m },
		"res-bool":       func(m map[string]any) any { m["residual_risk_ppm"] = true; return m },
		"salt-is-number": func(m map[string]any) any { m["goal_salt"] = jnum(5); return m },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newIntentFx(t, boundCommit(t))
			f.p["intent"] = mk(tIntent())
			f.resign()
			v := f.verifyIntent(nil)
			if v.Allow || len(v.Checks) != 1 || v.Checks["wire"] {
				t.Fatalf("want terminal wire failure: %+v", v)
			}
		})
	}
	// 128 UTF-8 bytes is the inclusive edge.
	salt := strings.Repeat("é", 64)
	c, _ := IntentGoalCommit(tRef(), tMap(), salt)
	f := newIntentFx(t, c)
	m := tIntent()
	m["goal_salt"] = salt
	f.p["intent"] = m
	f.resign()
	if v := f.verifyIntent(nil); !v.Allow || !v.Checks["intent"] {
		t.Fatalf("128-byte salt: %+v", v)
	}
}

func TestIntentPolicyFromJSON(t *testing.T) {
	v, _ := StrictParse(`{"require":false,"min_fidelity_ppm":-1,"max_residual_risk_ppm":0.5}`)
	p := IntentPolicyFromJSON(v)
	if p == nil || p.Require || p.MinFidelityPpm == nil || *p.MinFidelityPpm != -1 || *p.MaxResidualRiskPpm != 0.5 {
		t.Fatalf("%+v", p)
	}
	if !p.active() || okThreshold(p.MinFidelityPpm) || okThreshold(p.MaxResidualRiskPpm) {
		t.Fatal("misconfigured policy must be active and invalid")
	}
	if IntentPolicyFromJSON(nil) != nil {
		t.Fatal("absent policy")
	}
}
