package pca

import "math"

// The risk decomposition of the replayable policy debugger: the risk functional re-run term by term, so "why is this action risky" has
// a verifiable answer rather than a logged guess. Everything here is deterministic and recomputable from the inputs.

// RiskTermContribution is one term of r = alpha*d + beta*(1-rev) + gamma*bl + delta*taint + epsilon*(1-conf) + zeta*age.
type RiskTermContribution struct {
	// Term is semanticDistance, reversibility, blastRadius, taint, confidence or age.
	Term string `json:"term"`
	// Weight is the policy weight (clamped to >= 0, as the risk functional does).
	Weight float64 `json:"weight"`
	// Input is the clamped [0,1] input value actually used (a non-finite input is the worst case for its term).
	Input float64 `json:"input"`
	// Effective is the value fed into the weighted sum: Input for risk-increasing terms, 1 - Input for reversibility and confidence.
	Effective float64 `json:"effective"`
	// Contribution is Weight * Effective: this term's additive contribution to the pre-clamp sum.
	Contribution float64 `json:"contribution"`
	// Inverted is true for reversibility and confidence, where a higher input LOWERS risk.
	Inverted bool `json:"inverted"`
}

// RiskExplanation is the decomposition of one risk value.
type RiskExplanation struct {
	Inputs  RiskInputs             `json:"inputs"`
	Weights RiskWeights            `json:"weights"`
	Terms   []RiskTermContribution `json:"terms"`
	// RawSum is the sum of the contributions BEFORE the final clamp to [0,1].
	RawSum float64 `json:"rawSum"`
	// RScore is clamp(RawSum, 0, 1): the risk from the functional alone.
	RScore float64 `json:"rScore"`
	// RFloor is the signed caution floor applied: R = max(RScore, RFloor).
	RFloor float64 `json:"rFloor"`
	// R is the final risk, equal to what the admission path computes.
	R float64 `json:"r"`
}

func policyDebugClamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x // NaN passes through, as in the reference
}

func policyDebugTerm(name string, weight, raw, worst float64, inverted bool) RiskTermContribution {
	in := worst
	if !math.IsNaN(raw) && !math.IsInf(raw, 0) {
		in = policyDebugClamp01(raw)
	}
	eff := in
	if inverted {
		eff = 1 - in
	}
	w := riskWt(weight)
	return RiskTermContribution{Term: name, Weight: w, Input: in, Effective: eff, Contribution: w * eff, Inverted: inverted}
}

// ExplainRisk decomposes the risk of inputs under weights into its six additive terms. RawSum and the clamp reproduce the admission
// path's r; rFloor is the signed caution floor (a non-finite one counts as 0).
func ExplainRisk(inputs RiskInputs, weights RiskWeights, rFloor float64) RiskExplanation {
	if math.IsNaN(rFloor) || math.IsInf(rFloor, 0) {
		rFloor = 0
	}
	terms := []RiskTermContribution{
		policyDebugTerm("semanticDistance", weights.Alpha, inputs.SemanticDistance, 1, false),
		policyDebugTerm("reversibility", weights.Beta, inputs.Reversibility, 0, true),
		policyDebugTerm("blastRadius", weights.Gamma, inputs.BlastRadius, 1, false),
		policyDebugTerm("taint", weights.Delta, inputs.Taint, 1, false),
		policyDebugTerm("confidence", weights.Epsilon, inputs.Confidence, 0, true),
		policyDebugTerm("age", weights.Zeta, inputs.Age, 1, false),
	}
	raw := 0.0
	for _, t := range terms {
		raw += t.Contribution
	}
	score := policyDebugClamp01(raw)
	floor := policyDebugClamp01(rFloor)
	return RiskExplanation{Inputs: inputs, Weights: weights, Terms: terms, RawSum: raw, RScore: score, RFloor: floor, R: math.Max(score, floor)}
}
