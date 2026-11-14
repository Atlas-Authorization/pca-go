package pca

import (
	"math"
	"testing"
)

var h2DefaultPolicy = RiskPolicy{
	Weights: RiskWeights{Alpha: 0.25, Beta: 0.2, Gamma: 0.2, Delta: 0.2, Epsilon: 0.1, Zeta: 0.05},
	Theta1:  0.25, Theta2: 0.6, Kappa: 1, Lambda: 0.0005, Rho: 0.5, BMax: 1,
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestF2_RiskScore(t *testing.T) {
	w := h2DefaultPolicy.Weights
	best := RiskInputs{SemanticDistance: 0, Reversibility: 1, BlastRadius: 0, Taint: 0, Confidence: 1, Age: 0}
	worst := RiskInputs{SemanticDistance: 1, Reversibility: 0, BlastRadius: 1, Taint: 1, Confidence: 0, Age: 1}
	if got := RiskScore(best, w); got != 0 {
		t.Errorf("best: %v", got)
	}
	if got := RiskScore(worst, w); !near(got, 1) {
		t.Errorf("worst: %v", got)
	}
	// each input moves the score by exactly its weight
	for name, c := range map[string]struct {
		in   RiskInputs
		want float64
	}{
		"semantic":      {RiskInputs{SemanticDistance: 1, Reversibility: 1, Confidence: 1}, 0.25},
		"irreversible":  {RiskInputs{Reversibility: 0, Confidence: 1}, 0.2},
		"blast":         {RiskInputs{BlastRadius: 1, Reversibility: 1, Confidence: 1}, 0.2},
		"taint":         {RiskInputs{Taint: 1, Reversibility: 1, Confidence: 1}, 0.2},
		"unconfident":   {RiskInputs{Confidence: 0, Reversibility: 1}, 0.1},
		"age":           {RiskInputs{Age: 1, Reversibility: 1, Confidence: 1}, 0.05},
		"half semantic": {RiskInputs{SemanticDistance: 0.5, Reversibility: 1, Confidence: 1}, 0.125},
	} {
		if got := RiskScore(c.in, w); !near(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	// non-finite inputs are the worst case; out-of-range inputs are clamped
	nan := math.NaN()
	if got := RiskScore(RiskInputs{SemanticDistance: nan, Reversibility: 1, Confidence: 1}, w); !near(got, 0.25) {
		t.Errorf("NaN semantic: %v", got)
	}
	if got := RiskScore(RiskInputs{Reversibility: nan, Confidence: 1}, w); !near(got, 0.2) {
		t.Errorf("NaN reversibility: %v", got)
	}
	if got := RiskScore(RiskInputs{SemanticDistance: 5, Reversibility: 1, Confidence: 1}, w); !near(got, 0.25) {
		t.Errorf("clamped: %v", got)
	}
	// a negative or non-finite weight counts as 0
	if got := RiskScore(worst, RiskWeights{Alpha: -1, Beta: nan, Gamma: math.Inf(1) * 0, Delta: 0.2}); !near(got, 0.2) {
		t.Errorf("bad weights: %v", got)
	}
}

func TestF2_RequiredThresholdAndEscalate(t *testing.T) {
	p := h2DefaultPolicy
	for _, c := range []struct {
		r    float64
		t    int
		opt  bool
		irr  bool
		name string
	}{
		{0, 1, true, false, "zero"}, {0.25, 1, true, false, "theta1"}, {0.25, 1, false, true, "theta1 irreversible"},
		{0.2500001, 2, false, false, "above theta1"}, {0.6, 2, false, false, "theta2"}, {0.6000001, 3, false, false, "above theta2"},
		{1, 3, false, false, "one"}, {math.NaN(), 3, false, false, "NaN"}, {math.Inf(1), 3, false, false, "Inf"},
	} {
		got := RequiredThresholdOf(c.r, p.Theta1, p.Theta2, c.irr)
		if got.T != c.t || got.OptimisticAllowed != c.opt {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if got := RequiredThresholdOf(0.4, p.Theta1, p.Theta2, false); got.Proof != "standard" {
		t.Errorf("proof %q", got.Proof)
	}
	if got := RequiredThresholdOf(0.9, p.Theta1, p.Theta2, false); got.Proof != "strong" {
		t.Errorf("proof %q", got.Proof)
	}
	rt := RequiredThresholdOf(0.1, p.Theta1, p.Theta2, false)
	if got := EscalateThreshold(rt, 2); got.T != 2 || got.Proof != "standard" || got.OptimisticAllowed {
		t.Errorf("escalate to 2: %+v", got)
	}
	if got := EscalateThreshold(rt, 3); got.T != 3 || got.Proof != "strong" || got.OptimisticAllowed {
		t.Errorf("escalate to 3: %+v", got)
	}
	if got := EscalateThreshold(rt, 1); got != rt {
		t.Errorf("escalate to 1 changes %+v", got)
	}
	strong := RequiredThresholdOf(0.9, p.Theta1, p.Theta2, false)
	if got := EscalateThreshold(strong, 1); got != strong {
		t.Errorf("never lowers: %+v", got)
	}
}

func TestF2_TrustBudget(t *testing.T) {
	p := h2DefaultPolicy
	b := TrustBudget{B: 1, Tau: 0}
	l := b.Leak(1000, p.Lambda)
	if !near(l.B, 0.9995) || l.AsOf != 1000 || !l.HasAsOf || l.Tau != 0 {
		t.Errorf("leak: %+v", l)
	}
	if again := l.Leak(1000, p.Lambda); again != l {
		t.Errorf("leak twice at the same now: %+v", again)
	}
	if got := b.Leak(-5, p.Lambda); got.B != 1 { // an earlier now never raises the budget
		t.Errorf("leak into the past: %+v", got)
	}
	if got := b.Leak(math.NaN(), p.Lambda); got.B != 1 {
		t.Errorf("leak NaN: %+v", got)
	}
	if got := (TrustBudget{B: 0.0001}).Leak(1e9, 1); got.B != 0 {
		t.Errorf("leak floors at 0: %+v", got)
	}
	if d := (TrustBudget{B: 1}).Debit(0.4); !near(d.B, 0.6) {
		t.Errorf("debit: %+v", d)
	}
	if d := (TrustBudget{B: 0.3}).Debit(0.4); d.B != 0 {
		t.Errorf("debit floors at 0: %+v", d)
	}
	if d := (TrustBudget{B: 1}).Debit(-1); d.B != 1 {
		t.Errorf("a negative cost never recharges: %+v", d)
	}
	if r := (TrustBudget{B: 0.8}).Recharge(0.5, 1, 99); r.B != 1 || r.Tau != 99 || r.AsOf != 99 {
		t.Errorf("recharge caps at bMax: %+v", r)
	}
	if r := (TrustBudget{B: 0.1}).Recharge(0.5, 1, 99); !near(r.B, 0.6) {
		t.Errorf("recharge: %+v", r)
	}
	if r := RechargeFull(1, 7); r.B != 1 || r.Tau != 7 {
		t.Errorf("full: %+v", r)
	}
	if got := RiskCost(0.5, 2); got != 1 {
		t.Errorf("cost: %v", got)
	}
	if got := RiskCost(math.NaN(), 2); got != 2 {
		t.Errorf("cost of NaN: %v", got)
	}
	if got := RiskCost(0.5, -1); got != 0 {
		t.Errorf("cost with a negative kappa: %v", got)
	}
	if got := (TrustBudget{Tau: 0}).AgeSinceTouch(1_800_000, 0); !near(got, 0.5) {
		t.Errorf("age: %v", got)
	}
	if got := (TrustBudget{Tau: 0}).AgeSinceTouch(math.NaN(), 0); got != 1 {
		t.Errorf("age NaN: %v", got)
	}
	if got := (TrustBudget{Tau: 0}).AgeSinceTouch(10, -1); got != 1 {
		t.Errorf("age with a bad horizon: %v", got)
	}
	if got := (TrustBudget{Tau: 100}).AgeSinceTouch(0, 1000); got != 0 {
		t.Errorf("age before the touch: %v", got)
	}
	if got := SafetyBound(1, 2); got != 0.5 {
		t.Errorf("bound: %v", got)
	}
	if got := SafetyBound(1, 0); got != 0 {
		t.Errorf("bound without a cost scale: %v", got)
	}
}

func TestF2_Admit(t *testing.T) {
	p := h2DefaultPolicy
	full := TrustBudget{B: 1}
	if a := Admit(0.1, full, p); !a.Admit || a.NeedStepUp || a.T != 1 || !a.Metered {
		t.Errorf("t1: %+v", a)
	}
	if a := Admit(0.4, full, p); a.Admit || !a.NeedStepUp || a.T != 2 || !a.Metered {
		t.Errorf("t2: %+v", a)
	}
	if a := Admit(0.8, full, p); a.Admit || !a.NeedStepUp || a.T != 3 || a.Metered {
		t.Errorf("t3: %+v", a)
	}
	// a budget that cannot cover the cost escalates a machine-only action to a human step-up, unmetered
	if a := Admit(0.1, TrustBudget{B: 0.05}, p); a.Admit || !a.NeedStepUp || a.T != 3 || a.Metered {
		t.Errorf("depleted t1: %+v", a)
	}
	if a := Admit(0.4, TrustBudget{B: 0.3}, p); a.T != 3 || a.Metered {
		t.Errorf("depleted t2: %+v", a)
	}
	// B == cost is covered
	if a := Admit(0.1, TrustBudget{B: 0.1}, p); !a.Admit {
		t.Errorf("exactly covered: %+v", a)
	}
	// t=3 needs no budget
	if a := Admit(0.8, TrustBudget{B: 0}, p); a.T != 3 {
		t.Errorf("t3 with no budget: %+v", a)
	}
}
