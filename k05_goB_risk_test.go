package pca

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func goBNear(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestGoB_RiskClampAndFinite(t *testing.T) {
	if !math.Signbit(riskClamp01(math.Copysign(0, -1))) {
		t.Error("negative zero must pass through the clamp unchanged")
	}
	if riskClamp01(1.5) != 1 || riskClamp01(2) != 1 || riskClamp01(-0.5) != 0 || riskClamp01(0.25) != 0.25 || riskClamp01(1) != 1 {
		t.Error("clamp01")
	}
	if riskFinite(math.Inf(-1)) || riskFinite(math.Inf(1)) || riskFinite(math.NaN()) || !riskFinite(0) || !riskFinite(-3) {
		t.Error("riskFinite")
	}
	if math.Signbit(riskWt(math.Copysign(0, -1))) {
		t.Error("a zero weight is positive zero")
	}
	if riskWt(0.5) != 0.5 || riskWt(-1) != 0 || riskWt(math.NaN()) != 0 || riskWt(math.Inf(1)) != 0 {
		t.Error("riskWt")
	}
}

func TestGoB_RiskScoreWorstCaseOfNonFinite(t *testing.T) {
	nan := math.NaN()
	best := RiskInputs{SemanticDistance: 0, Reversibility: 1, BlastRadius: 0, Taint: 0, Confidence: 1, Age: 0}
	cases := []struct {
		name string
		mut  func(*RiskInputs)
		w    RiskWeights
		want float64
	}{
		{"semanticDistance", func(i *RiskInputs) { i.SemanticDistance = nan }, RiskWeights{Alpha: 0.4}, 0.4},
		{"reversibility", func(i *RiskInputs) { i.Reversibility = nan }, RiskWeights{Beta: 0.4}, 0.4},
		{"blastRadius", func(i *RiskInputs) { i.BlastRadius = nan }, RiskWeights{Gamma: 0.4}, 0.4},
		{"taint", func(i *RiskInputs) { i.Taint = nan }, RiskWeights{Delta: 0.4}, 0.4},
		{"confidence", func(i *RiskInputs) { i.Confidence = nan }, RiskWeights{Epsilon: 0.4}, 0.4},
		{"age", func(i *RiskInputs) { i.Age = nan }, RiskWeights{Zeta: 0.4}, 0.4},
	}
	for _, c := range cases {
		in := best
		c.mut(&in)
		if got := RiskScore(in, c.w); !goBNear(got, c.want) {
			t.Errorf("%s: %v want %v", c.name, got, c.want)
		}
	}
	// the worst case of an unbounded weight sum is clamped to 1
	in := best
	in.Taint, in.Age = nan, nan
	if got := RiskScore(in, RiskWeights{Delta: 0.4, Zeta: 0.4}); !goBNear(got, 0.8) {
		t.Errorf("two worst inputs: %v", got)
	}
	if got := RiskScore(RiskInputs{Taint: nan}, RiskWeights{Delta: 0.9}); !goBNear(got, 0.9) {
		t.Errorf("single: %v", got)
	}
}

func TestGoB_RequiredThresholdOfNonFinite(t *testing.T) {
	for _, r := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		rt := RequiredThresholdOf(r, 0.2, 1, false)
		if rt.T != 2 || rt.Proof != "standard" {
			t.Errorf("non-finite %v is treated as risk 1: %+v", r, rt)
		}
	}
	if rt := RequiredThresholdOf(0.2, 0.2, 0.5, false); rt.T != 1 || !rt.OptimisticAllowed {
		t.Errorf("r == theta1 is t=1: %+v", rt)
	}
	if rt := RequiredThresholdOf(0.2, 0.2, 0.5, true); rt.OptimisticAllowed {
		t.Error("irreversible is never optimistic")
	}
	if rt := RequiredThresholdOf(0.5, 0.2, 0.5, false); rt.T != 2 {
		t.Errorf("r == theta2 is t=2: %+v", rt)
	}
	if rt := RequiredThresholdOf(0.51, 0.2, 0.5, false); rt.T != 3 || rt.Proof != "strong" {
		t.Errorf("above theta2: %+v", rt)
	}
}

func TestGoB_EscalateThreshold(t *testing.T) {
	cases := []struct {
		in   RequiredThreshold
		minT int
		want RequiredThreshold
	}{
		{RequiredThreshold{T: 2, Proof: "claim"}, 0, RequiredThreshold{T: 2, Proof: "standard"}},
		{RequiredThreshold{T: 3, Proof: "standard"}, 0, RequiredThreshold{T: 3, Proof: "strong"}},
		{RequiredThreshold{T: 3, Proof: "claim"}, 0, RequiredThreshold{T: 3, Proof: "strong"}},
		{RequiredThreshold{T: 3, Proof: "strong"}, 0, RequiredThreshold{T: 3, Proof: "strong"}},
		{RequiredThreshold{T: 2, Proof: "strong"}, 2, RequiredThreshold{T: 2, Proof: "strong"}},
		{RequiredThreshold{T: 1, Proof: "claim", OptimisticAllowed: true}, 1, RequiredThreshold{T: 1, Proof: "claim", OptimisticAllowed: true}},
		{RequiredThreshold{T: 1, Proof: "claim", OptimisticAllowed: true}, 2, RequiredThreshold{T: 2, Proof: "standard"}},
		{RequiredThreshold{T: 1, Proof: "claim", OptimisticAllowed: true}, 3, RequiredThreshold{T: 3, Proof: "strong"}},
		{RequiredThreshold{T: 3, Proof: "strong"}, 1, RequiredThreshold{T: 3, Proof: "strong"}},
		// a proof the table does not know is kept when it ranks no lower than the level needs
		{RequiredThreshold{T: 1, Proof: "bogus"}, 1, RequiredThreshold{T: 1, Proof: "bogus"}},
	}
	for i, c := range cases {
		if got := EscalateThreshold(c.in, c.minT); got != c.want {
			t.Errorf("case %d: %+v want %+v", i, got, c.want)
		}
	}
}

func TestGoB_RiskCostLeakDebitRecharge(t *testing.T) {
	if got := RiskCost(math.NaN(), 2); got != 2 {
		t.Errorf("non-finite r costs kappa: %v", got)
	}
	if got := RiskCost(0.25, 2); got != 0.5 {
		t.Errorf("cost: %v", got)
	}
	// a non-finite now leaks nothing and keeps the last update time
	b := TrustBudget{B: 5, Tau: 500}
	got := b.Leak(math.NaN(), 1)
	if got.B != 5 || got.Tau != 500 || got.AsOf != 500 || !got.HasAsOf {
		t.Errorf("leak at a non-finite now: %+v", got)
	}
	b2 := TrustBudget{B: 5, Tau: 500, AsOf: 700, HasAsOf: true}
	if got := b2.Leak(math.NaN(), 1); got.AsOf != 700 || got.B != 5 {
		t.Errorf("leak from asOf: %+v", got)
	}
	if got := b.Leak(2500, 1); !goBNear(got.B, 3) || got.AsOf != 2500 {
		t.Errorf("leak two seconds: %+v", got)
	}
}

func TestGoB_AgeSinceTouchHorizon(t *testing.T) {
	b := TrustBudget{Tau: 0}
	if got := b.AgeSinceTouch(0.5, 1); got != 0.5 {
		t.Errorf("a one millisecond horizon: %v", got)
	}
	if got := b.AgeSinceTouch(0.25, 0.5); got != 0.5 {
		t.Errorf("a sub-millisecond horizon: %v", got)
	}
	if got := b.AgeSinceTouch(1800000, 0); got != 0.5 {
		t.Errorf("default horizon: %v", got)
	}
	if got := b.AgeSinceTouch(10, -5); got != 1 {
		t.Errorf("negative horizon: %v", got)
	}
}

func TestGoB_SafetyBound(t *testing.T) {
	if got := SafetyBound(0.5, 0.5); got != 1 {
		t.Errorf("bMax 0.5 / kappa 0.5: %v", got)
	}
	if got := SafetyBound(3, 1); got != 3 {
		t.Errorf("3/1: %v", got)
	}
	if got := SafetyBound(-3, 1); got != 0 {
		t.Errorf("negative bMax: %v", got)
	}
	if got := SafetyBound(3, 0); got != 0 {
		t.Errorf("kappa 0: %v", got)
	}
}

func TestGoB_RiskRefsOf(t *testing.T) {
	if got := riskRefsOf("a", riskPreKeys); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("string: %v", got)
	}
	if got := riskRefsOf([]any{"a", 5, "b", nil}, riskPreKeys); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("array skips non-strings: %v", got)
	}
	m := map[string]any{"after": "x", "nodes": []any{"y", 7}, "unrelated": "z"}
	if got := riskRefsOf(m, riskPreKeys); !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Errorf("map keys: %v", got)
	}
	if got := riskRefsOf(5, riskPreKeys); len(got) != 0 {
		t.Errorf("number: %v", got)
	}
}

func TestGoB_PlanGeodesic(t *testing.T) {
	n := func(id string, kv ...any) map[string]any {
		m := map[string]any{"id": id}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	chain := []map[string]any{n("a", "post", "c"), n("b"), n("c", "post", []any{"d"}), n("d")}
	if got := PlanGeodesic(chain, "a", "d"); !goBNear(got, 2.0/3) {
		t.Errorf("two hops of three: %v", got)
	}
	if got := PlanGeodesic(chain, "d", "a"); !goBNear(got, 2.0/3) {
		t.Errorf("undirected: %v", got)
	}
	pre := []map[string]any{n("a"), n("b"), n("c", "pre", "a")}
	if got := PlanGeodesic(pre, "a", "c"); !goBNear(got, 0.5) {
		t.Errorf("a single pre edge: %v", got)
	}
	preMap := []map[string]any{n("a"), n("b"), n("c", "pre", map[string]any{"after": "a"})}
	if got := PlanGeodesic(preMap, "a", "c"); !goBNear(got, 0.5) {
		t.Errorf("a pre map edge: %v", got)
	}
	// an id outside the plan makes no edge (so the index fallback applies)
	unkPre := []map[string]any{n("a"), n("b"), n("c", "pre", "zzz"), n("d")}
	if got := PlanGeodesic(unkPre, "a", "c"); !goBNear(got, 2.0/3) {
		t.Errorf("unknown pre id: %v", got)
	}
	unkPost := []map[string]any{n("a"), n("b"), n("c", "post", "zzz"), n("d")}
	if got := PlanGeodesic(unkPost, "a", "c"); !goBNear(got, 2.0/3) {
		t.Errorf("unknown post id: %v", got)
	}
	// a node naming itself is no edge
	self := []map[string]any{n("a", "pre", "a", "post", "a"), n("b"), n("c")}
	if got := PlanGeodesic(self, "a", "b"); !goBNear(got, 0.5) {
		t.Errorf("self reference: %v", got)
	}
	// edges that do not connect the two nodes
	apart := []map[string]any{n("a"), n("b"), n("c", "pre", "b"), n("d")}
	if got := PlanGeodesic(apart, "a", "c"); got != 1 {
		t.Errorf("unreachable: %v", got)
	}
	if got := PlanGeodesic(apart, "b", "c"); !goBNear(got, 1.0/3) {
		t.Errorf("reachable: %v", got)
	}
	if PlanGeodesic(chain, "a", "a") != 0 || PlanGeodesic(chain, "a", "zz") != 1 || PlanGeodesic(chain, "zz", "a") != 1 {
		t.Error("same node 0, unknown node 1")
	}
}

func goBValidPolicy() RiskPolicy {
	return RiskPolicy{Weights: RiskWeights{Alpha: 0.5, Beta: 0.5, Gamma: 0.5, Delta: 0.5, Epsilon: 0.5, Zeta: 0.5},
		Theta1: 0.2, Theta2: 0.5, Kappa: 1, Lambda: 0.5, Rho: 0.5, BMax: 0.5}
}

func TestGoB_ValidateRiskPolicy(t *testing.T) {
	if r := ValidateRiskPolicy(goBValidPolicy()); r != "" {
		t.Fatalf("valid policy: %q", r)
	}
	zero := goBValidPolicy()
	zero.Weights = RiskWeights{}
	zero.Theta1, zero.Theta2, zero.Lambda, zero.Rho, zero.BMax = 0, 0, 0, 0, 0
	if r := ValidateRiskPolicy(zero); r != "" {
		t.Errorf("zeros are allowed: %q", r)
	}
	names := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}
	set := func(p *RiskPolicy, i int, v float64) {
		ptrs := []*float64{&p.Weights.Alpha, &p.Weights.Beta, &p.Weights.Gamma, &p.Weights.Delta, &p.Weights.Epsilon, &p.Weights.Zeta}
		*ptrs[i] = v
	}
	for i, nm := range names {
		for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.5} {
			p := goBValidPolicy()
			set(&p, i, v)
			if r, want := ValidateRiskPolicy(p), "risk_policy.weights."+nm+" must be finite and >= 0"; r != want {
				t.Errorf("weight %s=%v: %q", nm, v, r)
			}
		}
	}
	fnames := []string{"theta1", "theta2", "kappa", "lambda", "rho", "bMax"}
	for i, nm := range fnames {
		for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
			p := goBValidPolicy()
			ptrs := []*float64{&p.Theta1, &p.Theta2, &p.Kappa, &p.Lambda, &p.Rho, &p.BMax}
			*ptrs[i] = v
			if r, want := ValidateRiskPolicy(p), "risk_policy."+nm+" must be finite"; r != want {
				t.Errorf("%s=%v: %q", nm, v, r)
			}
		}
	}
	bad := func(mut func(*RiskPolicy), want string) {
		t.Helper()
		p := goBValidPolicy()
		mut(&p)
		if r := ValidateRiskPolicy(p); r != want {
			t.Errorf("got %q want %q", r, want)
		}
	}
	order := "risk_policy requires 0 <= theta1 <= theta2"
	bad(func(p *RiskPolicy) { p.Theta1 = -0.1 }, order)
	bad(func(p *RiskPolicy) { p.Theta1, p.Theta2 = 0.4, 0.3 }, order)
	ok := goBValidPolicy()
	ok.Theta1, ok.Theta2 = 0.3, 0.3
	if r := ValidateRiskPolicy(ok); r != "" {
		t.Errorf("theta1 == theta2: %q", r)
	}
	bad(func(p *RiskPolicy) { p.Kappa = 0 }, "risk_policy.kappa must be > 0")
	bad(func(p *RiskPolicy) { p.Kappa = -1 }, "risk_policy.kappa must be > 0")
	lrb := "risk_policy lambda/rho/bMax must be >= 0"
	bad(func(p *RiskPolicy) { p.Lambda = -0.1 }, lrb)
	bad(func(p *RiskPolicy) { p.Rho = -0.1 }, lrb)
	bad(func(p *RiskPolicy) { p.BMax = -0.1 }, lrb)
	for i := 0; i < 3; i++ {
		p := goBValidPolicy()
		p.Lambda, p.Rho, p.BMax = 0, 0, 0
		ptrs := []*float64{&p.Lambda, &p.Rho, &p.BMax}
		*ptrs[i] = 0.5
		if r := ValidateRiskPolicy(p); r != "" {
			t.Errorf("one of lambda/rho/bMax at 0.5 (%d): %q", i, r)
		}
	}
}

func goBPolicyMap() map[string]any {
	return map[string]any{
		"weights": map[string]any{"alpha": 0.1, "beta": 0.2, "gamma": 0.3, "delta": 0.4, "epsilon": 0.5, "zeta": 0.6},
		"theta1":  0.25, "theta2": 0.75, "kappa": 2.0, "lambda": 0.5, "rho": 0.125, "bMax": 3.0,
	}
}

func TestGoB_RiskPolicyOf(t *testing.T) {
	p, ok := RiskPolicyOf(goBPolicyMap())
	want := RiskPolicy{Weights: RiskWeights{Alpha: 0.1, Beta: 0.2, Gamma: 0.3, Delta: 0.4, Epsilon: 0.5, Zeta: 0.6},
		Theta1: 0.25, Theta2: 0.75, Kappa: 2, Lambda: 0.5, Rho: 0.125, BMax: 3}
	if !ok || p != want {
		t.Fatalf("valid: %+v %v", p, ok)
	}
	refuse := func(name string, v any) {
		t.Helper()
		if p, ok := RiskPolicyOf(v); ok || p != (RiskPolicy{}) {
			t.Errorf("%s: %+v %v", name, p, ok)
		}
	}
	refuse("not a map", "x")
	refuse("nil", nil)
	m := goBPolicyMap()
	m["weights"] = "x"
	refuse("weights not a map", m)
	m = goBPolicyMap()
	delete(m, "weights")
	refuse("no weights", m)
	for _, k := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"} {
		m = goBPolicyMap()
		delete(m["weights"].(map[string]any), k)
		refuse("missing weight "+k, m)
		m = goBPolicyMap()
		m["weights"].(map[string]any)[k] = "x"
		refuse("non-number weight "+k, m)
		m = goBPolicyMap()
		m["weights"].(map[string]any)[k] = math.NaN()
		refuse("NaN weight "+k, m)
	}
	for _, k := range []string{"theta1", "theta2", "kappa", "lambda", "rho", "bMax"} {
		m = goBPolicyMap()
		delete(m, k)
		refuse("missing "+k, m)
		m = goBPolicyMap()
		m[k] = "x"
		refuse("non-number "+k, m)
		m = goBPolicyMap()
		m[k] = math.Inf(1)
		refuse("infinite "+k, m)
	}
}

// ---- DecideRisk ------------------------------------------------------------------------------------------------------

func goBDecidePolicy(w RiskWeights) RiskPolicy {
	return RiskPolicy{Weights: w, Theta1: 0.3, Theta2: 0.6, Kappa: 1, Lambda: 0, Rho: 0.1, BMax: 1}
}

func goBFullRisk(over map[string]any) map[string]any {
	m := map[string]any{"semanticDistance": 0.0, "reversibility": 1.0, "blastRadius": 0.0, "taint": 0.0, "confidence": 1.0, "age": 0.0}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func goBGo(c RiskStep) RiskStep {
	c.PrOK, c.CvOK, c.DcvOK, c.ChainOK = true, true, true, true
	return c
}

func TestGoB_DecideRiskMissingInputsAreWorst(t *testing.T) {
	w := RiskWeights{Alpha: 0.1, Beta: 0.1, Gamma: 0.1, Delta: 0.1, Epsilon: 0.1, Zeta: 0.1}
	d := DecideRisk(goBGo(RiskStep{Policy: goBDecidePolicy(w), Risk: map[string]any{}, Budget: TrustBudget{B: 1}}))
	// every input but age is at its worst; age is derived (0 here)
	if !goBNear(d.R, 0.5) {
		t.Errorf("r = %v", d.R)
	}
	if len(d.Reasons) == 0 || d.Reasons[0] != "risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence" {
		t.Errorf("reasons: %v", d.Reasons)
	}
	// exactly one input missing is reported
	d = DecideRisk(goBGo(RiskStep{Policy: goBDecidePolicy(w), Risk: goBFullRisk(map[string]any{"taint": nil}), Budget: TrustBudget{B: 1}}))
	if len(d.Reasons) != 1 || d.Reasons[0] != "risk input(s) missing, assumed worst case: taint" {
		t.Errorf("one missing: %v", d.Reasons)
	}
	// nothing missing: no reason
	d = DecideRisk(goBGo(RiskStep{Policy: goBDecidePolicy(w), Risk: goBFullRisk(nil), Budget: TrustBudget{B: 1}}))
	if len(d.Reasons) != 0 {
		t.Errorf("none missing: %v", d.Reasons)
	}
}

func TestGoB_DecideRiskInvalidValueIsWorst(t *testing.T) {
	only := func(w RiskWeights, over map[string]any) float64 {
		return DecideRisk(goBGo(RiskStep{Policy: goBDecidePolicy(w), Risk: goBFullRisk(over), Budget: TrustBudget{B: 1}})).R
	}
	// a present key that is not a finite number is the worst case, never the best
	if r := only(RiskWeights{Zeta: 0.1}, map[string]any{"age": "x"}); !goBNear(r, 0.1) {
		t.Errorf("age as a string: %v", r)
	}
	if r := only(RiskWeights{Zeta: 0.1}, map[string]any{"age": math.NaN()}); !goBNear(r, 0.1) {
		t.Errorf("age NaN: %v", r)
	}
	if r := only(RiskWeights{Delta: 0.1}, map[string]any{"taint": "x"}); !goBNear(r, 0.1) {
		t.Errorf("taint as a string: %v", r)
	}
	if r := only(RiskWeights{Delta: 0.1}, map[string]any{"taint": math.Inf(1)}); !goBNear(r, 0.1) {
		t.Errorf("taint infinite: %v", r)
	}
	if r := only(RiskWeights{Beta: 0.1}, map[string]any{"reversibility": "x"}); !goBNear(r, 0.1) {
		t.Errorf("reversibility as a string: %v", r)
	}
}

func goBPlan3() []map[string]any {
	return []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}}
}

func TestGoB_DecideRiskSemanticDistanceFromPlan(t *testing.T) {
	alpha := RiskWeights{Alpha: 1}
	run := func(s RiskStep) RiskDecision {
		s.Policy = goBDecidePolicy(alpha)
		s.Risk = goBFullRisk(map[string]any{"semanticDistance": nil})
		s.Budget = TrustBudget{B: 1}
		return DecideRisk(goBGo(s))
	}
	// the goal defaults to the last node of the plan
	d := run(RiskStep{Plan: goBPlan3(), NodeID: "b", HasNodeID: true})
	if !goBNear(d.R, 0.5) {
		t.Errorf("default goal: %v", d.R)
	}
	// an explicit goal is kept (not replaced by the last node)
	d = run(RiskStep{Plan: goBPlan3(), NodeID: "a", HasNodeID: true, GoalNodeID: "b"})
	if !goBNear(d.R, 0.5) {
		t.Errorf("explicit goal: %v", d.R)
	}
	// no node id given: the worst case, even when a goal is named
	d = run(RiskStep{Plan: goBPlan3(), NodeID: "a", HasNodeID: false, GoalNodeID: "b"})
	if d.R != 1 {
		t.Errorf("no node id: %v", d.R)
	}
	// an empty plan (not nil) has no goal: worst case, and no index panic
	d = run(RiskStep{Plan: []map[string]any{}, NodeID: "a", HasNodeID: true})
	if d.R != 1 {
		t.Errorf("empty plan: %v", d.R)
	}
	// a single-node plan: the goal is that node, distance 0
	d = run(RiskStep{Plan: []map[string]any{{"id": "a"}}, NodeID: "a", HasNodeID: true})
	if d.R != 0 {
		t.Errorf("one-node plan: %v", d.R)
	}
	// no plan: the missing distance stays at the worst case
	d = run(RiskStep{NodeID: "a", HasNodeID: true})
	if d.R != 1 {
		t.Errorf("nil plan: %v", d.R)
	}
	// a supplied distance wins over the plan
	d = DecideRisk(goBGo(RiskStep{Policy: goBDecidePolicy(alpha), Risk: goBFullRisk(map[string]any{"semanticDistance": 0.25}),
		Plan: goBPlan3(), NodeID: "a", HasNodeID: true, GoalNodeID: "c", Budget: TrustBudget{B: 1}}))
	if !goBNear(d.R, 0.25) {
		t.Errorf("supplied distance: %v", d.R)
	}
	// the plan-derived distance is not reported as missing; the others still are
	d = run(RiskStep{Plan: goBPlan3(), NodeID: "b", HasNodeID: true, Risk: nil})
	for _, r := range d.Reasons { // the 0.5 risk steps up; only a missing-input reason would be wrong
		if strings.Contains(r, "missing") {
			t.Errorf("reasons: %v", d.Reasons)
		}
	}
	s := RiskStep{Policy: goBDecidePolicy(alpha), Risk: map[string]any{"age": 0.0}, Plan: goBPlan3(), NodeID: "b", HasNodeID: true, Budget: TrustBudget{B: 1}}
	d = DecideRisk(goBGo(s))
	if len(d.Reasons) == 0 || d.Reasons[0] != "risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence" {
		t.Errorf("reasons: %v", d.Reasons)
	}
}

func TestGoB_DecideRiskFloor(t *testing.T) {
	zero := goBDecidePolicy(RiskWeights{})
	run := func(hasFloor bool, floor float64) float64 {
		return DecideRisk(goBGo(RiskStep{Policy: zero, Risk: goBFullRisk(nil), Budget: TrustBudget{B: 1}, HasRFloor: hasFloor, RFloor: floor})).R
	}
	if r := run(true, 0.4); !goBNear(r, 0.4) {
		t.Errorf("floor applies: %v", r)
	}
	if r := run(true, 1.5); r != 1 {
		t.Errorf("floor above 1 is clamped: %v", r)
	}
	if r := run(true, -0.5); r != 0 {
		t.Errorf("negative floor: %v", r)
	}
	if r := run(false, 0.9); r != 0 {
		t.Errorf("a floor not flagged is ignored: %v", r)
	}
	if r := run(false, math.NaN()); r != 0 {
		t.Errorf("an unflagged NaN floor: %v", r)
	}
	if r := run(true, math.NaN()); r != 0 {
		t.Errorf("a NaN floor is ignored: %v", r)
	}
	if r := run(true, math.Inf(1)); r != 0 {
		t.Errorf("an infinite floor is ignored: %v", r)
	}
}

func TestGoB_DecideRiskStepUpReasons(t *testing.T) {
	alpha := goBDecidePolicy(RiskWeights{Alpha: 1})
	run := func(sd float64, b float64) RiskDecision {
		return DecideRisk(goBGo(RiskStep{Policy: alpha, Risk: goBFullRisk(map[string]any{"semanticDistance": sd}), Budget: TrustBudget{B: b}}))
	}
	d := run(0.2, 0) // t=1 but the budget cannot cover it
	if len(d.Reasons) != 1 || d.Reasons[0] != "trust budget depleted: human recharge required" {
		t.Errorf("depleted: %v", d.Reasons)
	}
	if d.RequiredThreshold.T != 3 || !d.NeedStepUp || d.Admit {
		t.Errorf("depleted decision: %+v", d)
	}
	d = run(0.8, 1)
	if len(d.Reasons) != 1 || d.Reasons[0] != "risk 0.800 exceeds auto threshold: step-up to t=3" {
		t.Errorf("t=3: %v", d.Reasons)
	}
	d = run(0.5, 1)
	if len(d.Reasons) != 1 || d.Reasons[0] != "risk 0.500 exceeds auto threshold: step-up to t=2" {
		t.Errorf("t=2: %v", d.Reasons)
	}
	d = run(0.2, 1)
	if len(d.Reasons) != 0 {
		t.Errorf("t=1 affordable: %v", d.Reasons)
	}
}

func TestGoB_DecideRiskReleaseAndDebit(t *testing.T) {
	alpha := goBDecidePolicy(RiskWeights{Alpha: 1})
	mk := func(sd float64, release bool) RiskStep {
		s := RiskStep{Policy: alpha, Risk: goBFullRisk(map[string]any{"semanticDistance": sd}), Budget: TrustBudget{B: 1}}
		if release {
			s = goBGo(s)
		}
		return s
	}
	d := DecideRisk(mk(0.2, true))
	if d.NeedStepUp || !d.Admit || !d.ReleaseGuardianShare || !d.Debit || !goBNear(d.Budget.B, 0.8) {
		t.Errorf("admitted: %+v", d)
	}
	d = DecideRisk(mk(0.2, false))
	if !d.NeedStepUp || d.Admit || d.ReleaseGuardianShare || d.Debit || d.Budget.B != 1 {
		t.Errorf("no release: %+v", d)
	}
	d = DecideRisk(mk(0.8, true))
	if !d.NeedStepUp || d.Admit || d.Debit || d.Budget.B != 1 {
		t.Errorf("high risk: %+v", d)
	}
	d = DecideRisk(mk(0.8, false))
	if !d.NeedStepUp || d.Debit {
		t.Errorf("high risk and no release: %+v", d)
	}
	// t=2 is metered: released and debited, but needs the step-up
	d = DecideRisk(mk(0.5, true))
	if !d.NeedStepUp || d.Admit || !d.Debit || !goBNear(d.Budget.B, 0.5) {
		t.Errorf("t=2: %+v", d)
	}
}
