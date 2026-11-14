package pca

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// F2: the risk score, trust budget and threshold in Authorize. The g01 grant has all risk weights 0, so only the signed caution (a floor
// on r) moves the risk: theta1 0.5, theta2 0.8, kappa 1, bMax 1000.
func TestF2_AuthorizeRiskBudgetAndThreshold(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	counter := int64(0)
	run := func(caution string, mut func(in *AuthorizeInput)) (AuthorizeResult, *MemoryStateStore) {
		counter++
		var extra map[string]any
		if caution != "" {
			extra = map[string]any{"caution": json.Number(caution)}
		}
		in := g01DynIn(g)
		store := NewMemoryStateStore()
		in.StateStore = store
		if mut != nil {
			mut(&in)
		}
		return Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, extra), in), store
	}
	stream := StateKey(g["id"].(string), k.agent.Public)
	hasReason := func(r AuthorizeResult, sub string) bool {
		for _, why := range r.Reasons {
			if strings.Contains(why, sub) {
				return true
			}
		}
		return false
	}
	// r = 0: t=1, admitted, free: nothing is stored
	if r, st := run("", nil); !r.Allow {
		t.Fatalf("no caution: %+v", r)
	} else if b, _ := st.Budget(stream); b != nil {
		t.Errorf("a free action stored a budget: %v", b)
	}
	// a caution of 0.3 (t=1): admitted and debited 0.3 in the same step as the claim
	r, st := run("0.3", nil)
	if !r.Allow {
		t.Fatalf("caution 0.3: %+v", r)
	}
	b, _ := st.Budget(stream)
	if b == nil || !near(b["B"].(float64), 999.7) {
		t.Errorf("stored budget after a 0.3 spend: %v", b)
	}
	// a replay spends nothing: the counter is consumed once and the budget with it
	in := g01DynIn(g)
	in.StateStore = st
	again := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, map[string]any{"caution": json.Number("0.3")}), in)
	if again.Allow {
		t.Errorf("replay allowed: %+v", again)
	}
	if b2, _ := st.Budget(stream); !near(b2["B"].(float64), 999.7) {
		t.Errorf("a replay changed the budget: %v", b2)
	}
	// t=2 (caution 0.6) and t=3 (0.9) without a threshold verifier fail `threshold`
	for caution, want := range map[string]string{"0.6": "threshold: t=2 (standard) required but no threshold verifier is enforced", "0.9": "threshold: t=3 (strong) required but no threshold verifier is enforced"} {
		r, _ := run(caution, nil)
		if r.Allow || r.Checks["threshold"] != "fail" || !slices.Contains(r.Reasons, want) {
			t.Errorf("caution %s: %+v", caution, r)
		}
		if !hasReason(r, "policy: risk "+caution+"00 exceeds auto threshold") && caution == "0.9" {
			t.Errorf("caution %s: no step-up reason in %v", caution, r.Reasons)
		}
	}
	// the hook contract: it must have enforced at least the server-derived t
	hook := func(res ThresholdResult) func(in *AuthorizeInput) {
		return func(in *AuthorizeInput) {
			in.Threshold = func(_, _ map[string]any) ThresholdResult { return res }
		}
	}
	if r, _ := run("0.9", hook(ThresholdResult{OK: true, Enforced: true, T: 3})); !r.Allow || r.Checks["threshold"] != "pass" {
		t.Errorf("hook enforced t=3: %+v", r)
	}
	if r, _ := run("0.9", hook(ThresholdResult{OK: true, Enforced: true, T: 2})); r.Allow || !hasReason(r, "threshold: threshold hook enforced t=2 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)") {
		t.Errorf("hook enforced t=2: %+v", r)
	}
	if r, _ := run("0.9", hook(ThresholdResult{OK: true})); r.Allow || !hasReason(r, "threshold hook enforced t=unreported but the server requires t=3") {
		t.Errorf("hook silent: %+v", r)
	}
	if r, _ := run("0.9", hook(ThresholdResult{OK: false})); r.Allow || !hasReason(r, "threshold: t=3 required and the threshold proof was rejected") {
		t.Errorf("hook rejected: %+v", r)
	}
	if r, _ := run("0.6", hook(ThresholdResult{OK: true, Enforced: true, T: 3})); !r.Allow {
		t.Errorf("hook enforced more than required: %+v", r)
	}
	if r, _ := run("0.9", func(in *AuthorizeInput) {
		in.Threshold = func(_, _ map[string]any) ThresholdResult { panic("boom") }
	}); r.Allow || !hasReason(r, "the threshold proof was rejected") {
		t.Errorf("hook panics: %+v", r)
	}
	// a depleted carried budget: a machine-only action steps up to a human (t=3), never debited
	r, _ = run("0.3", func(in *AuthorizeInput) {
		in.Context = func(map[string]any) (*AuthorizeContext, error) {
			return &AuthorizeContext{Budget: &TrustBudget{B: 0.2, Tau: float64(g01Now)}}, nil
		}
	})
	if r.Allow || !hasReason(r, "policy: trust budget depleted: human recharge required") {
		t.Errorf("depleted: %+v", r)
	}
	// a carried budget is the host's own: not stored back
	r, st = run("0.3", func(in *AuthorizeInput) {
		in.Context = func(map[string]any) (*AuthorizeContext, error) {
			return &AuthorizeContext{Budget: &TrustBudget{B: 5, Tau: float64(g01Now)}}, nil
		}
	})
	if !r.Allow {
		t.Fatalf("carried budget: %+v", r)
	}
	if b3, _ := st.Budget(stream); b3 != nil {
		t.Errorf("a carried budget was stored: %v", b3)
	}
	// a risk provider that fails denies (fail closed)
	if r, _ := run("", func(in *AuthorizeInput) {
		in.Risk = func(*Operation, map[string]any, map[string]any) (map[string]any, error) { panic("down") }
	}); r.Allow || r.Checks["risk"] != "fail" {
		t.Errorf("risk provider panics: %+v", r)
	}
	// a store that cannot persist budgets refuses a metered action but serves a free one
	if r, _ := run("0.3", func(in *AuthorizeInput) { in.StateStore = unscopedStoreWithLast{} }); r.Allow {
		t.Errorf("no budget store, metered: %+v", r)
	}
}

type unscopedStoreWithLast struct{ unscopedStore }

func (unscopedStoreWithLast) Last(string) (*int64, error) { return nil, nil }

// Without any risk input every input is the worst case; the reasons name them.
func TestF2_DecideRiskMissingInputs(t *testing.T) {
	p := h2DefaultPolicy
	dec := DecideRisk(RiskStep{Policy: p, Risk: map[string]any{}, Budget: TrustBudget{B: 1, Tau: 0}, Now: 0, PrOK: true, CvOK: true, DcvOK: true, ChainOK: true})
	if !near(dec.R, 0.95) || dec.RequiredThreshold.T != 3 || !dec.ReleaseGuardianShare || dec.Admit || dec.Debit {
		t.Errorf("worst case: %+v", dec)
	}
	if len(dec.Reasons) < 1 || dec.Reasons[0] != "risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence" {
		t.Errorf("reasons: %v", dec.Reasons)
	}
	// the plan geodesic fills the semantic distance; age comes from the budget
	plan := []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}}
	dec = DecideRisk(RiskStep{Policy: p, Risk: map[string]any{"reversibility": json.Number("1"), "blastRadius": json.Number("0"), "taint": json.Number("0"), "confidence": json.Number("1")},
		Plan: plan, NodeID: "a", HasNodeID: true, Budget: TrustBudget{B: 1, Tau: 0}, Now: 0, ReversibilityClass: "reversible", PrOK: true, CvOK: true, DcvOK: true, ChainOK: true})
	// semantic distance a -> c (goal = last node) = 2/2 = 1, age 0: r = 0.25
	if !near(dec.R, 0.25) || len(dec.Reasons) != 0 || dec.RequiredThreshold.T != 1 || !dec.Admit || !dec.Debit {
		t.Errorf("geodesic: %+v", dec)
	}
	// an unreleased decision never admits or debits and always needs a step-up
	dec = DecideRisk(RiskStep{Policy: p, Risk: map[string]any{}, Budget: TrustBudget{B: 1}, PrOK: false, CvOK: true, DcvOK: true, ChainOK: true})
	if dec.ReleaseGuardianShare || dec.Admit || dec.Debit || !dec.NeedStepUp {
		t.Errorf("not released: %+v", dec)
	}
	// the signed caution raises r, never lowers it
	calm := map[string]any{"semanticDistance": json.Number("0"), "reversibility": json.Number("1"), "blastRadius": json.Number("0"), "taint": json.Number("0"), "confidence": json.Number("1"), "age": json.Number("0")}
	if dec = DecideRisk(RiskStep{Policy: p, Risk: calm, Budget: TrustBudget{B: 1}, RFloor: 0.7, HasRFloor: true, ReversibilityClass: "reversible", PrOK: true, CvOK: true, DcvOK: true, ChainOK: true}); !near(dec.R, 0.7) || dec.RequiredThreshold.T != 3 {
		t.Errorf("caution floor: %+v", dec)
	}
	if dec = DecideRisk(RiskStep{Policy: p, Risk: calm, Budget: TrustBudget{B: 1}, RFloor: -3, HasRFloor: true, ReversibilityClass: "reversible", PrOK: true, CvOK: true, DcvOK: true, ChainOK: true}); dec.R != 0 {
		t.Errorf("negative caution: %+v", dec)
	}
	// an irreversible or unrecognised class is never optimistic
	for class, opt := range map[string]bool{"reversible": true, "rate_limited": true, "costly": true, "irreversible": false, "": false, "weird": false} {
		d := DecideRisk(RiskStep{Policy: p, Risk: calm, Budget: TrustBudget{B: 1}, ReversibilityClass: class, PrOK: true, CvOK: true, DcvOK: true, ChainOK: true})
		if d.RequiredThreshold.OptimisticAllowed != opt {
			t.Errorf("class %q: optimistic %v", class, d.RequiredThreshold.OptimisticAllowed)
		}
	}
}

func TestF2_PlanGeodesic(t *testing.T) {
	ids := func(ns ...string) []map[string]any {
		out := make([]map[string]any, len(ns))
		for i, n := range ns {
			out[i] = map[string]any{"id": n}
		}
		return out
	}
	if got := PlanGeodesic(ids("a", "b", "c", "d"), "a", "d"); got != 1 {
		t.Errorf("no edges, index distance: %v", got)
	}
	if got := PlanGeodesic(ids("a", "b", "c", "d"), "b", "c"); !near(got, 1.0/3) {
		t.Errorf("no edges, adjacent: %v", got)
	}
	if got := PlanGeodesic(ids("a"), "a", "a"); got != 0 {
		t.Errorf("same node: %v", got)
	}
	if got := PlanGeodesic(ids("a", "b"), "a", "zz"); got != 1 {
		t.Errorf("unknown node: %v", got)
	}
	// edges: a -> b -> c, d unreachable
	plan := ids("a", "b", "c", "d")
	plan[0]["post"] = []any{"b"}
	plan[1]["post"] = "c"
	if got := PlanGeodesic(plan, "a", "c"); !near(got, 2.0/3) {
		t.Errorf("a to c over two hops: %v", got)
	}
	if got := PlanGeodesic(plan, "c", "a"); !near(got, 2.0/3) {
		t.Errorf("undirected: %v", got)
	}
	if got := PlanGeodesic(plan, "a", "d"); got != 1 {
		t.Errorf("unreachable: %v", got)
	}
	// pre references, under the named keys
	plan2 := ids("a", "b", "c")
	plan2[2]["pre"] = map[string]any{"after": []any{"b"}, "depends_on": "a"}
	if got := PlanGeodesic(plan2, "b", "c"); !near(got, 0.5) {
		t.Errorf("pre keys: %v", got)
	}
}

// requireRiskInputs: a named input the server did not supply fails `risk_inputs`; semanticDistance counts as supplied with a plan.
func TestF3_RequireRiskInputs(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	run := func(required []string, risk map[string]any) AuthorizeResult {
		in := g01DynIn(g)
		in.RequireRiskInputs = required
		in.Risk = func(*Operation, map[string]any, map[string]any) (map[string]any, error) { return risk, nil }
		return Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), in)
	}
	if r := run([]string{"taint", "confidence"}, map[string]any{"taint": json.Number("0")}); r.Allow || r.Checks["risk_inputs"] != "fail" ||
		!slices.Contains(r.Reasons, "risk_inputs: required risk input(s) not supplied by the server: confidence") {
		t.Errorf("missing confidence: %+v", r)
	}
	if r := run([]string{"taint"}, map[string]any{"taint": json.Number("0")}); !r.Allow || r.Checks["risk_inputs"] != "pass" {
		t.Errorf("supplied: %+v", r)
	}
	if r := run([]string{"semanticDistance"}, map[string]any{}); !r.Allow || r.Checks["risk_inputs"] != "pass" {
		t.Errorf("semanticDistance with a plan: %+v", r)
	}
	if r := run([]string{"taint"}, map[string]any{"taint": "0"}); r.Allow {
		t.Errorf("a non-number taint counts as missing: %+v", r)
	}
}

// adaptivePolicy can only narrow: it refuses when it needs a higher threshold than the grant's own policy, ignores a looser one,
// and an invalid or failing policy refuses.
func TestF3_AdaptivePolicy(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	run := func(caution string, ap func(int64) *RiskPolicy) AuthorizeResult {
		in := g01DynIn(g)
		in.AdaptivePolicy = ap
		return Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, map[string]any{"caution": json.Number(caution)}), in)
	}
	grantPol := h2DefaultPolicy
	grantPol.Theta1, grantPol.Theta2, grantPol.BMax = 0.5, 0.8, 1000
	tight := func(t1, t2 float64) func(int64) *RiskPolicy {
		return func(int64) *RiskPolicy { p := grantPol; p.Theta1, p.Theta2 = t1, t2; return &p }
	}
	// caution 0.3: the grant's t is 1; a policy with theta1 0.2 needs t=2
	if r := run("0.3", nil); !r.Allow {
		t.Fatalf("no adaptive policy: %+v", r)
	}
	if r := run("0.3", tight(0.2, 0.8)); r.Allow || r.Checks["adaptive"] != "fail" || !slices.Contains(r.Reasons, "adaptive: tightened policy requires threshold t=2 (grant policy: t=1)") {
		t.Errorf("tightened: %+v", r)
	}
	if r := run("0.3", tight(0.9, 0.95)); !r.Allow {
		t.Errorf("a looser policy is ignored: %+v", r)
	}
	if r := run("0.3", func(int64) *RiskPolicy { return nil }); !r.Allow {
		t.Errorf("none: %+v", r)
	}
	if r := run("0.3", tight(0.9, 0.1)); r.Allow || !slices.Contains(r.Reasons, "adaptive: invalid policy (risk_policy requires 0 <= theta1 <= theta2)") {
		t.Errorf("invalid: %+v", r)
	}
	for name, f := range map[string]func(int64) *RiskPolicy{
		"down":    func(int64) *RiskPolicy { panic("down") },
		"boom":    func(int64) *RiskPolicy { panic(errors.New("boom")) },
		"unknown": func(int64) *RiskPolicy { panic(42) },
	} {
		if r := run("0.3", f); r.Allow || r.Status != 403 || r.Reason != "authorize error (fail closed): "+name || r.Checks["authorize"] != "fail" {
			t.Errorf("failing source %s: %+v", name, r)
		}
	}
}
