package pca

import (
	"encoding/json"
	"math"
	"strings"
)

// The decision side of the replayable policy debugger: Decide re-run with its risk decomposed and its budget traced
// (ExplainPolicyDecision), "what if" variations of one input (ApplyDelta, Counterfactual) and the audit of a PCActn next to the
// explanation of its decision (AuditPCActn). Everything is recomputed from the inputs; nothing is read from a log.

// BudgetTrajectory is the trust budget through one decision: as given, after the passive leak, and after the decision (debited
// when the action was admitted); Cost is what the action costs at its risk and SafetyBound the policy's bound on machine-only risk
// between two human recharges.
type BudgetTrajectory struct {
	Before, Leaked, After map[string]any
	Cost, SafetyBound     float64
}

// DecisionExplanation is Decide's result with the reasons behind it. EnvelopeValid false means the grant carried no readable
// envelope: the decision is the fail-closed denial and the risk has no terms.
type DecisionExplanation struct {
	Decision             map[string]any
	Risk                 RiskExplanation
	RequiredThreshold    map[string]any
	T                    int
	AutoAllow            bool
	NeedStepUp           bool
	ReleaseGuardianShare bool
	Budget               BudgetTrajectory
	Reasons              []string
	EnvelopeValid        bool
}

func pdBudgetJSON(b TrustBudget) map[string]any {
	m := map[string]any{"B": payNum(b.B), "tau": payNum(b.Tau)}
	if b.HasAsOf {
		m["asOf"] = payNum(b.AsOf)
	}
	return m
}

func pdPolicy(env map[string]any) RiskPolicy {
	if env != nil {
		if p, ok := RiskPolicyOf(env["risk_policy"]); ok {
			return p
		}
	}
	p, _ := RiskPolicyOf(DefaultRiskPolicy())
	return p
}

// ExplainPolicyDecision (the policy debugger's explainDecision; ExplainDecision is the plain-language explainer) runs Decide on input and explains the result: the risk term by term (with the inputs Decide resolved: worst
// case for a missing one, the plan geodesic for the semantic distance, the time since the last human touch for the age), the
// threshold, and the budget before, after the leak and after the decision.
func ExplainPolicyDecision(input map[string]any) DecisionExplanation {
	decision := Decide(input)
	env := ReadEnvelope(input["grant"])
	pol := pdPolicy(env)
	r := jsF(decision["r"])
	before, _ := input["budget"].(map[string]any)
	leakedJSON := before
	risk := RiskExplanation{Inputs: RiskInputs{SemanticDistance: 1, Reversibility: 0, BlastRadius: 1, Taint: 1, Confidence: 0, Age: 1},
		Terms: []RiskTermContribution{}, RawSum: r, RScore: r, R: r}
	if env != nil {
		now := jsF(input["now"])
		budget, _ := parseBudget(before)
		leaked := budget.Leak(now, pol.Lambda)
		leakedJSON = pdBudgetJSON(leaked)
		given, _ := input["risk"].(map[string]any)
		inputs := risk.Inputs
		for k, dst := range map[string]*float64{"semanticDistance": &inputs.SemanticDistance, "reversibility": &inputs.Reversibility,
			"blastRadius": &inputs.BlastRadius, "taint": &inputs.Taint, "confidence": &inputs.Confidence, "age": &inputs.Age} {
			if f, ok := jsNum(given[k]); ok && riskFinite(f) {
				*dst = f
			}
		}
		if pl, ok := input["plan"].([]any); ok {
			if v, has := given["semanticDistance"]; !has || v == nil {
				plan := make([]map[string]any, len(pl))
				for i, n := range pl {
					plan[i], _ = n.(map[string]any)
				}
				goal, _ := input["goalNodeId"].(string)
				if goal == "" && len(plan) > 0 {
					goal, _ = plan[len(plan)-1]["id"].(string)
				}
				inputs.SemanticDistance = 1
				if node, ok := input["nodeId"].(string); ok && goal != "" {
					inputs.SemanticDistance = PlanGeodesic(plan, node, goal)
				}
			}
		}
		if v, has := given["age"]; !has || v == nil {
			inputs.Age = leaked.AgeSinceTouch(now, jsFOr(input["ageHorizonMs"], 0))
		}
		floor := 0.0
		if f, ok := jsNum(input["rFloor"]); ok && riskFinite(f) {
			floor = math.Min(1, math.Max(0, f))
		}
		risk = ExplainRisk(inputs, pol.Weights, floor)
	}
	rt, _ := decision["requiredThreshold"].(map[string]any)
	after, _ := decision["budget"].(map[string]any)
	reasons := []string{}
	if list, ok := decision["reasons"].([]any); ok {
		for _, x := range list {
			s, _ := x.(string)
			reasons = append(reasons, s)
		}
	}
	return DecisionExplanation{Decision: decision, Risk: risk, RequiredThreshold: rt, T: int(jsFOr(rt["t"], 3)),
		AutoAllow: decision["admit"] == true, NeedStepUp: decision["needStepUp"] == true, ReleaseGuardianShare: decision["releaseGuardianShare"] == true,
		Budget:  BudgetTrajectory{Before: before, Leaked: leakedJSON, After: after, Cost: RiskCost(r, pol.Kappa), SafetyBound: SafetyBound(pol.BMax, pol.Kappa)},
		Reasons: reasons, EnvelopeValid: env != nil}
}

func jsFOr(v any, dflt float64) float64 {
	if f, ok := jsNum(v); ok && riskFinite(f) {
		return f
	}
	return dflt
}

// CounterfactualDelta is one "what if" over a Decide input: other risk inputs, another budget, another caution floor, another
// time, other caveat context, or a human co-sign (HumanCosign recharges the budget by rho; with HumanCosignFull the human
// re-confirms the goal and the budget returns to bMax). Label names it in the report ("" derives a description).
type CounterfactualDelta struct {
	Label           string
	Risk            map[string]any
	Budget          map[string]any
	RFloor          *float64
	Now             *float64
	CaveatContext   map[string]any
	HumanCosign     bool
	HumanCosignFull bool
}

// pdText is the template-literal text of a value: a number as ECMAScript prints it (NaN and Infinity included).
func pdText(v any) string {
	if f, ok := jsNum(v); ok {
		if f == 0 {
			return "0"
		}
		return jsNumberString(f)
	}
	return oaString(oaVal{v, true})
}

func (d CounterfactualDelta) describe() string {
	if d.Label != "" {
		return d.Label
	}
	var parts []string
	if d.HumanCosign || d.HumanCosignFull {
		if d.HumanCosignFull {
			parts = append(parts, "human re-confirms goal (B←Bmax)")
		} else {
			parts = append(parts, "human co-signs (B+ρ)")
		}
	}
	for _, k := range jsKeys(d.Risk) {
		parts = append(parts, k+"="+pdText(d.Risk[k]))
	}
	for _, k := range jsKeys(d.Budget) {
		parts = append(parts, "budget."+k+"="+pdText(d.Budget[k]))
	}
	if d.RFloor != nil {
		parts = append(parts, "caution="+rsNumStr(*d.RFloor))
	}
	if d.Now != nil {
		parts = append(parts, "now="+rsNumStr(*d.Now))
	}
	for _, k := range jsKeys(d.CaveatContext) {
		b, _ := json.Marshal(d.CaveatContext[k])
		parts = append(parts, "ctx."+k+"="+string(b))
	}
	if len(parts) == 0 {
		return "no-op"
	}
	return strings.Join(parts, ", ")
}

func pdMerge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ApplyDelta returns a copy of a Decide input with the delta applied; the input is not changed.
func ApplyDelta(input map[string]any, d CounterfactualDelta) map[string]any {
	next := copyMap(input)
	now := input["now"]
	if d.Now != nil {
		now = payNum(*d.Now)
	}
	base, _ := input["budget"].(map[string]any)
	budget := pdMerge(base, d.Budget)
	if d.HumanCosign || d.HumanCosignFull {
		pol := pdPolicy(ReadEnvelope(input["grant"]))
		t := jsF(now)
		if d.HumanCosignFull {
			budget = pdBudgetJSON(RechargeFull(pol.BMax, t))
		} else {
			b, _ := parseBudget(budget)
			budget = pdBudgetJSON(b.Recharge(pol.Rho, pol.BMax, t))
		}
	}
	risk, _ := input["risk"].(map[string]any)
	cc, _ := input["caveatContext"].(map[string]any)
	next["now"], next["budget"], next["risk"], next["caveatContext"] = now, budget, pdMerge(risk, d.Risk), pdMerge(cc, d.CaveatContext)
	if now == nil {
		delete(next, "now")
	}
	if d.RFloor != nil {
		next["rFloor"] = payNum(*d.RFloor)
	}
	return next
}

// CounterfactualOutcome is the decision under one delta compared with the baseline: whether automatic admission flips, whether
// and in which direction the required threshold moves (raised, lowered or same), and how far the risk moves.
type CounterfactualOutcome struct {
	Label              string
	Delta              CounterfactualDelta
	Explanation        DecisionExplanation
	FlipsAllow         bool
	Allow              bool
	ThresholdDirection string
	ChangesThreshold   bool
	T                  int
	RDelta             float64
}

// CounterfactualReport is the baseline explanation, the outcome of every delta, and the labels of the deltas that flip the
// automatic admission or change the threshold.
type CounterfactualReport struct {
	Baseline          DecisionExplanation
	Outcomes          []CounterfactualOutcome
	Flipping          []string
	ThresholdChanging []string
}

// Counterfactual re-runs the decision under each delta and reports what would change the outcome.
func Counterfactual(input map[string]any, deltas []CounterfactualDelta) CounterfactualReport {
	rep := CounterfactualReport{Baseline: ExplainPolicyDecision(input), Outcomes: []CounterfactualOutcome{}, Flipping: []string{}, ThresholdChanging: []string{}}
	for _, d := range deltas {
		e := ExplainPolicyDecision(ApplyDelta(input, d))
		dir := "same"
		if e.T > rep.Baseline.T {
			dir = "raised"
		} else if e.T < rep.Baseline.T {
			dir = "lowered"
		}
		o := CounterfactualOutcome{Label: d.describe(), Delta: d, Explanation: e, FlipsAllow: e.AutoAllow != rep.Baseline.AutoAllow, Allow: e.AutoAllow,
			ThresholdDirection: dir, ChangesThreshold: dir != "same", T: e.T, RDelta: e.Risk.R - rep.Baseline.Risk.R}
		rep.Outcomes = append(rep.Outcomes, o)
		if o.FlipsAllow {
			rep.Flipping = append(rep.Flipping, o.Label)
		}
		if o.ChangesThreshold {
			rep.ThresholdChanging = append(rep.ThresholdChanging, o.Label)
		}
	}
	return rep
}

// PolicyAudit is the core verification verdict of a PCActn next to the explanation of the decision it claims.
type PolicyAudit struct {
	Verify      Verdict
	Explanation DecisionExplanation
}

// AuditPCActn verifies a PCActn against the verifier's own grant (VerifyPCActnCoreWith) and explains the decision of input, so an
// auditor sees whether the artifact verifies and why the policy decided as it did. The error is the verifier's.
func AuditPCActn(pcactn, input, grant map[string]any, now int64, audience string, opts VerifyOptions) (PolicyAudit, error) {
	v, err := VerifyPCActnCoreWith(pcactn, grant, now, audience, opts)
	return PolicyAudit{Verify: v, Explanation: ExplainPolicyDecision(input)}, err
}

func pdWeightsJSON(w RiskWeights) map[string]any {
	return map[string]any{"alpha": rsN(w.Alpha), "beta": rsN(w.Beta), "gamma": rsN(w.Gamma), "delta": rsN(w.Delta), "epsilon": rsN(w.Epsilon), "zeta": rsN(w.Zeta)}
}

func pdInputsJSON(i RiskInputs) map[string]any {
	return map[string]any{"semanticDistance": rsN(i.SemanticDistance), "reversibility": rsN(i.Reversibility), "blastRadius": rsN(i.BlastRadius),
		"taint": rsN(i.Taint), "confidence": rsN(i.Confidence), "age": rsN(i.Age)}
}

// JSON is the explanation as the reference's object {inputs, weights, terms, rawSum, rScore, rFloor, r}. A non-finite number
// stays a float64 (JSON cannot carry it).
func (e RiskExplanation) JSON() map[string]any {
	terms := make([]any, len(e.Terms))
	for i, t := range e.Terms {
		terms[i] = map[string]any{"term": t.Term, "weight": rsN(t.Weight), "input": rsN(t.Input), "effective": rsN(t.Effective),
			"contribution": rsN(t.Contribution), "inverted": t.Inverted}
	}
	return map[string]any{"inputs": pdInputsJSON(e.Inputs), "weights": pdWeightsJSON(e.Weights), "terms": terms, "rawSum": rsN(e.RawSum),
		"rScore": rsN(e.RScore), "rFloor": rsN(e.RFloor), "r": rsN(e.R)}
}

// JSON is the explanation as the reference's object.
func (e DecisionExplanation) JSON() map[string]any {
	reasons := make([]any, len(e.Reasons))
	for i, r := range e.Reasons {
		reasons[i] = r
	}
	return map[string]any{"decision": e.Decision, "risk": e.Risk.JSON(), "requiredThreshold": e.RequiredThreshold, "t": jsNumber(float64(e.T)),
		"autoAllow": e.AutoAllow, "needStepUp": e.NeedStepUp, "releaseGuardianShare": e.ReleaseGuardianShare,
		"budget": map[string]any{"before": e.Budget.Before, "leaked": e.Budget.Leaked, "after": e.Budget.After, "cost": rsN(e.Budget.Cost),
			"safetyBound": rsN(e.Budget.SafetyBound)},
		"reasons": reasons, "envelopeValid": e.EnvelopeValid}
}

// JSON is the delta as the reference's object (only the members that are set).
func (d CounterfactualDelta) JSON() map[string]any {
	m := map[string]any{}
	if d.Label != "" {
		m["label"] = d.Label
	}
	if d.Risk != nil {
		m["risk"] = d.Risk
	}
	if d.Budget != nil {
		m["budget"] = d.Budget
	}
	if d.RFloor != nil {
		m["rFloor"] = rsN(*d.RFloor)
	}
	if d.Now != nil {
		m["now"] = rsN(*d.Now)
	}
	if d.CaveatContext != nil {
		m["caveatContext"] = d.CaveatContext
	}
	if d.HumanCosignFull {
		m["humanCosign"] = map[string]any{"full": true}
	} else if d.HumanCosign {
		m["humanCosign"] = true
	}
	return m
}

// JSON is the report as the reference's object {baseline, outcomes, flipping, thresholdChanging}.
func (r CounterfactualReport) JSON() map[string]any {
	strs := func(l []string) []any {
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	}
	outcomes := make([]any, len(r.Outcomes))
	for i, o := range r.Outcomes {
		outcomes[i] = map[string]any{"label": o.Label, "delta": o.Delta.JSON(), "explanation": o.Explanation.JSON(), "flipsAllow": o.FlipsAllow,
			"allow": o.Allow, "thresholdDirection": o.ThresholdDirection, "changesThreshold": o.ChangesThreshold, "t": jsNumber(float64(o.T)),
			"rDelta": rsN(o.RDelta)}
	}
	return map[string]any{"baseline": r.Baseline.JSON(), "outcomes": outcomes, "flipping": strs(r.Flipping), "thresholdChanging": strs(r.ThresholdChanging)}
}
