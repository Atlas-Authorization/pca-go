package pca

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Risk functional, threshold map and decaying trust budget (spec section 10, L3). Pure and deterministic; a port of the
// reference risk.ts. Time is epoch milliseconds; Lambda is budget drained PER SECOND. Non-finite inputs fail closed (worst case).

// RiskWeights are the non-negative weights of the risk functional.
type RiskWeights struct {
	Alpha   float64 // semantic distance
	Beta    float64 // irreversibility
	Gamma   float64 // blast radius
	Delta   float64 // taint
	Epsilon float64 // agent uncertainty
	Zeta    float64 // age since human touch
}

// RiskPolicy is a grant's risk policy.
type RiskPolicy struct {
	Weights RiskWeights
	Theta1  float64
	Theta2  float64
	Kappa   float64 // cost scale: c(A) = kappa * r(A)
	Lambda  float64 // passive leak, budget units per second
	Rho     float64 // recharge per human co-sign
	BMax    float64
}

// RiskInputs are all normalized to [0, 1].
type RiskInputs struct {
	SemanticDistance float64
	Reversibility    float64
	BlastRadius      float64
	Taint            float64
	Confidence       float64
	Age              float64
}

func riskClamp01(x float64) float64 {
	switch {
	case x < 0:
		return 0
	case x > 1:
		return 1
	}
	return x
}

func riskFinite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }

// riskUnit: non-finite is the worst case (worst is 1 for risk-increasing inputs, 0 for reversibility and confidence), else clamped.
func riskUnit(x float64, worst float64) float64 {
	if riskFinite(x) {
		return riskClamp01(x)
	}
	return worst
}

func riskWt(x float64) float64 {
	if riskFinite(x) && x > 0 {
		return x
	}
	return 0
}

// RiskScore is r = clamp(a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1). Monotone non-decreasing in d, bl, taint,
// age and non-increasing in rev, conf (weights below 0 count as 0, which is what makes that hold for any policy).
func RiskScore(i RiskInputs, w RiskWeights) float64 {
	r := riskWt(w.Alpha)*riskUnit(i.SemanticDistance, 1) +
		riskWt(w.Beta)*(1-riskUnit(i.Reversibility, 0)) +
		riskWt(w.Gamma)*riskUnit(i.BlastRadius, 1) +
		riskWt(w.Delta)*riskUnit(i.Taint, 1) +
		riskWt(w.Epsilon)*(1-riskUnit(i.Confidence, 0)) +
		riskWt(w.Zeta)*riskUnit(i.Age, 1)
	return riskClamp01(r)
}

// RequiredThreshold is the step-up level a risk needs: T 1 (claim), 2 (standard) or 3 (strong).
type RequiredThreshold struct {
	T                 int
	Proof             string // claim | standard | strong
	OptimisticAllowed bool
}

// RequiredThresholdOf is the piecewise map: r <= theta1 is t=1 (claim, optimistic acceptance allowed unless irreversible),
// theta1 < r <= theta2 is t=2 (standard), above is t=3 (strong). A non-finite r is the worst case.
func RequiredThresholdOf(r, theta1, theta2 float64, irreversible bool) RequiredThreshold {
	x := 1.0
	if riskFinite(r) {
		x = r
	}
	switch {
	case x <= theta1:
		return RequiredThreshold{T: 1, Proof: "claim", OptimisticAllowed: !irreversible}
	case x <= theta2:
		return RequiredThreshold{T: 2, Proof: "standard"}
	}
	return RequiredThreshold{T: 3, Proof: "strong"}
}

var riskProofRank = map[string]int{"claim": 0, "standard": 1, "strong": 2}
var riskProofForT = map[int]string{1: "claim", 2: "standard", 3: "strong"}

// EscalateThreshold raises rt to at least minT and keeps it coherent (t=2 needs a proof of at least standard, t=3 strong, and
// optimistic acceptance is never allowed above t=1). It never lowers anything.
func EscalateThreshold(rt RequiredThreshold, minT int) RequiredThreshold {
	t := rt.T
	if minT > t {
		t = minT
	}
	proof := rt.Proof
	if riskProofRank[proof] < riskProofRank[riskProofForT[t]] {
		proof = riskProofForT[t]
	}
	opt := rt.OptimisticAllowed
	if t > 1 {
		opt = false
	}
	return RequiredThreshold{T: t, Proof: proof, OptimisticAllowed: opt}
}

// TrustBudget is the decaying trust budget. B is in [0, bMax], Tau the last human touch, AsOf the time the budget was last brought
// up to date by Leak (it keeps the budget from leaking twice); HasAsOf false means AsOf = Tau.
type TrustBudget struct {
	B, Tau, AsOf float64
	HasAsOf      bool
}

func riskNz(x float64) float64 {
	if riskFinite(x) && x > 0 {
		return x
	}
	return 0
}

// RiskCost is c(A) = kappa * r(A); a non-finite r costs as r = 1.
func RiskCost(r, kappa float64) float64 {
	if !riskFinite(r) {
		r = 1
	}
	return riskNz(kappa) * riskClamp01(r)
}

// Leak applies the passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same now.
func (b TrustBudget) Leak(now, lambda float64) TrustBudget {
	from := b.Tau
	if b.HasAsOf {
		from = b.AsOf
	}
	dt := 0.0
	if riskFinite(now) && riskFinite(from) {
		dt = math.Max(0, now-from)
	}
	out := TrustBudget{B: math.Max(0, b.B-riskNz(lambda)*(dt/1000)), Tau: b.Tau, HasAsOf: true}
	if riskFinite(now) {
		out.AsOf = math.Max(now, from)
	} else {
		out.AsOf = from
	}
	return out
}

// Debit is B <- max(0, B - cost). Callers must check B >= cost first (Admit does).
func (b TrustBudget) Debit(c float64) TrustBudget {
	b.B = math.Max(0, b.B-riskNz(c))
	return b
}

// Recharge is a human co-sign: B <- min(bMax, B+rho), tau <- now. The only way the budget increases.
func (b TrustBudget) Recharge(rho, bMax, now float64) TrustBudget {
	return TrustBudget{B: math.Min(riskNz(bMax), b.B+riskNz(rho)), Tau: now, AsOf: now, HasAsOf: true}
}

// RechargeFull is a full goal re-confirmation: B <- bMax, tau <- now.
func RechargeFull(bMax, now float64) TrustBudget {
	return TrustBudget{B: riskNz(bMax), Tau: now, AsOf: now, HasAsOf: true}
}

// AgeSinceTouch is the normalized age since the last human touch: clamp((now - tau) / horizonMs, 0, 1). horizonMs <= 0 uses the
// default of one hour.
func (b TrustBudget) AgeSinceTouch(now, horizonMs float64) float64 {
	if horizonMs == 0 {
		horizonMs = 3_600_000
	}
	if !riskFinite(now) || !riskFinite(b.Tau) || !(horizonMs > 0) {
		return 1
	}
	return riskClamp01((now - b.Tau) / horizonMs)
}

// Admission is the budget decision of Admit.
type Admission struct {
	Admit      bool // t=1 auto path: no human and no co-signer needed
	NeedStepUp bool
	T          int
	Metered    bool // the action proceeds without a human co-signature and so MUST be debited kappa * r
}

// Admit: the machine-only band is t=1 and t=2 (at t=2 the guardian auto-cosigns), so BOTH are metered: an action at t < 3 proceeds
// only if B >= c(A), and is then debited. When the budget cannot cover it the action escalates to t=3 (human step-up). t=3 is
// never debited. The budget must already be leaked up to the decision time.
func Admit(r float64, b TrustBudget, p RiskPolicy) Admission {
	t := RequiredThresholdOf(r, p.Theta1, p.Theta2, false).T
	c := RiskCost(r, p.Kappa)
	if t < 3 && !(b.B >= c) {
		return Admission{NeedStepUp: true, T: 3}
	}
	switch t {
	case 1:
		return Admission{Admit: true, T: 1, Metered: true}
	case 2:
		return Admission{NeedStepUp: true, T: 2, Metered: true}
	}
	return Admission{NeedStepUp: true, T: 3}
}

// SafetyBound: between two consecutive human recharges the total risk of machine-only actions is at most bMax / kappa.
func SafetyBound(bMax, kappa float64) float64 {
	if kappa > 0 {
		return math.Max(0, bMax) / kappa
	}
	return 0
}

// ---- plan geodesic and the decision steps of the policy VM --------------------------------------------------------------

var (
	riskPreKeys  = []string{"after", "depends_on", "requires", "nodes"}
	riskPostKeys = []string{"before", "enables", "then", "next"}
)

func riskRefsOf(x any, keys []string) []string {
	var out []string
	add := func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, s := range t {
				if str, ok := s.(string); ok {
					out = append(out, str)
				}
			}
		}
	}
	add(x)
	if m, ok := x.(map[string]any); ok {
		for _, k := range keys {
			add(m[k])
		}
	}
	return out
}

// PlanGeodesic is the normalized geodesic distance in the committed plan DAG, in [0, 1] (an approximation, as in the reference):
// edges come from node references (`pre` ids are predecessors, `post` ids successors; only ids in the plan count); the distance is
// the BFS hop count over the UNDIRECTED graph divided by n-1; unreachable is 1; a plan that declares no edges falls back to
// |i-j|/(n-1); an unknown node id is 1 (fail closed); the same node is 0.
func PlanGeodesic(plan []map[string]any, fromNodeID, toGoalNodeID string) float64 {
	idx := map[string]int{}
	for i, n := range plan {
		id, _ := n["id"].(string)
		idx[id] = i // a later node with the same id wins, as the reference Map does
	}
	a, okA := idx[fromNodeID]
	b, okB := idx[toGoalNodeID]
	if !okA || !okB {
		return 1
	}
	if a == b {
		return 0
	}
	n := len(plan)
	adj := make([]map[int]bool, n)
	for i := range adj {
		adj[i] = map[int]bool{}
	}
	edges := 0
	link := func(i, j int) {
		if i == j {
			return
		}
		if !adj[i][j] {
			edges++
		}
		adj[i][j], adj[j][i] = true, true
	}
	for i, node := range plan {
		for _, id := range riskRefsOf(node["pre"], riskPreKeys) {
			if j, ok := idx[id]; ok {
				link(j, i)
			}
		}
		for _, id := range riskRefsOf(node["post"], riskPostKeys) {
			if j, ok := idx[id]; ok {
				link(i, j)
			}
		}
	}
	if edges == 0 {
		return riskClamp01(math.Abs(float64(a-b)) / float64(n-1))
	}
	dist := make([]int, n)
	for i := range dist {
		dist[i] = -1
	}
	dist[a] = 0
	q := []int{a}
	for h := 0; h < len(q); h++ {
		u := q[h]
		nb := make([]int, 0, len(adj[u]))
		for v := range adj[u] {
			nb = append(nb, v)
		}
		sort.Ints(nb)
		for _, v := range nb {
			if dist[v] == -1 {
				dist[v] = dist[u] + 1
				q = append(q, v)
			}
		}
	}
	if dist[b] < 0 {
		return 1
	}
	return riskClamp01(float64(dist[b]) / float64(n-1))
}

// ValidateRiskPolicy returns the reference's error for a risk policy that is not well formed, else "".
func ValidateRiskPolicy(p RiskPolicy) string {
	for _, w := range []struct {
		name string
		v    float64
	}{{"alpha", p.Weights.Alpha}, {"beta", p.Weights.Beta}, {"gamma", p.Weights.Gamma}, {"delta", p.Weights.Delta}, {"epsilon", p.Weights.Epsilon}, {"zeta", p.Weights.Zeta}} {
		if !riskFinite(w.v) || w.v < 0 {
			return "risk_policy.weights." + w.name + " must be finite and >= 0"
		}
	}
	for _, f := range []struct {
		name string
		v    float64
	}{{"theta1", p.Theta1}, {"theta2", p.Theta2}, {"kappa", p.Kappa}, {"lambda", p.Lambda}, {"rho", p.Rho}, {"bMax", p.BMax}} {
		if !riskFinite(f.v) {
			return "risk_policy." + f.name + " must be finite"
		}
	}
	if p.Theta1 < 0 || p.Theta2 < p.Theta1 {
		return "risk_policy requires 0 <= theta1 <= theta2"
	}
	if p.Kappa <= 0 {
		return "risk_policy.kappa must be > 0"
	}
	if p.Lambda < 0 || p.Rho < 0 || p.BMax < 0 {
		return "risk_policy lambda/rho/bMax must be >= 0"
	}
	return ""
}

// RiskPolicyOf reads the envelope's `risk_policy` (already validated by ReadEnvelope).
func RiskPolicyOf(v any) (RiskPolicy, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return RiskPolicy{}, false
	}
	w, ok := m["weights"].(map[string]any)
	if !ok {
		return RiskPolicy{}, false
	}
	num := func(o map[string]any, k string) (float64, bool) {
		f, ok := jsNum(o[k])
		return f, ok && riskFinite(f)
	}
	var p RiskPolicy
	for k, dst := range map[string]*float64{"alpha": &p.Weights.Alpha, "beta": &p.Weights.Beta, "gamma": &p.Weights.Gamma,
		"delta": &p.Weights.Delta, "epsilon": &p.Weights.Epsilon, "zeta": &p.Weights.Zeta} {
		f, ok := num(w, k)
		if !ok {
			return RiskPolicy{}, false
		}
		*dst = f
	}
	for k, dst := range map[string]*float64{"theta1": &p.Theta1, "theta2": &p.Theta2, "kappa": &p.Kappa, "lambda": &p.Lambda, "rho": &p.Rho, "bMax": &p.BMax} {
		f, ok := num(m, k)
		if !ok {
			return RiskPolicy{}, false
		}
		*dst = f
	}
	return p, true
}

// RiskStep is the input of DecideRisk: steps 3-5 of the reference policy VM's decide().
type RiskStep struct {
	Policy RiskPolicy
	// Risk holds the inputs the server supplied (semanticDistance, reversibility, blastRadius, taint, confidence, age); a key that
	// is absent or not a finite number is the worst case, except age (derived from the budget's last touch) and semanticDistance
	// (derived from the plan geodesic when a plan is given).
	Risk               map[string]any
	Plan               []map[string]any
	NodeID             string
	HasNodeID          bool
	GoalNodeID         string
	Budget             TrustBudget
	Now                float64
	AgeHorizonMs       float64
	RFloor             float64 // the signed caution; ignored unless finite
	HasRFloor          bool
	ReversibilityClass string // "" = none
	// PrOK, CvOK, DcvOK, ChainOK are the caller's verdicts for the predicates, the envelope/root caveats, the delegated caveats and
	// the chain.
	PrOK, CvOK, DcvOK, ChainOK bool
}

// RiskDecision is the outcome of DecideRisk.
type RiskDecision struct {
	ReleaseGuardianShare bool
	RequiredThreshold    RequiredThreshold
	R                    float64
	Admit, NeedStepUp    bool
	Reasons              []string // the informational ones, in reference order
	Budget               TrustBudget
	Debit                bool // the release was metered: the caller stores Budget (the cost was debited)
}

var riskInputKeys = []string{"semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"}

func riskFastPathEligible(class string) bool {
	return class == "reversible" || class == "rate_limited" || class == "costly"
}

// DecideRisk is the risk r, the threshold band, the budget admission, the escalation and the release / admit / debit decision
// (policy-vm.ts steps 3-5; the release rule is the proved DecideCore: policy AND caveats AND delegated caveats AND chain).
func DecideRisk(s RiskStep) RiskDecision {
	p := s.Policy
	leaked := s.Budget.Leak(s.Now, p.Lambda)
	num := func(k string) (float64, bool) {
		v, has := s.Risk[k]
		if !has {
			return 0, false
		}
		f, ok := jsNum(v)
		return f, ok && riskFinite(f)
	}
	inputs := RiskInputs{SemanticDistance: 1, Reversibility: 0, BlastRadius: 1, Taint: 1, Confidence: 0, Age: 1}
	for k, dst := range map[string]*float64{"semanticDistance": &inputs.SemanticDistance, "reversibility": &inputs.Reversibility,
		"blastRadius": &inputs.BlastRadius, "taint": &inputs.Taint, "confidence": &inputs.Confidence, "age": &inputs.Age} {
		if f, ok := num(k); ok {
			*dst = f
		}
	}
	var missing []string
	for _, k := range riskInputKeys {
		if _, ok := num(k); k != "age" && !ok {
			missing = append(missing, k)
		}
	}
	if _, has := s.Risk["semanticDistance"]; s.Plan != nil && !has {
		goal := s.GoalNodeID
		if goal == "" && len(s.Plan) > 0 {
			goal, _ = s.Plan[len(s.Plan)-1]["id"].(string)
		}
		if s.HasNodeID && goal != "" {
			inputs.SemanticDistance = PlanGeodesic(s.Plan, s.NodeID, goal)
		} else {
			inputs.SemanticDistance = 1
		}
		kept := missing[:0]
		for _, k := range missing {
			if k != "semanticDistance" {
				kept = append(kept, k)
			}
		}
		missing = kept
	}
	if _, has := s.Risk["age"]; !has {
		inputs.Age = leaked.AgeSinceTouch(s.Now, s.AgeHorizonMs)
	}
	var reasons []string
	if len(missing) > 0 {
		reasons = append(reasons, "risk input(s) missing, assumed worst case: "+strings.Join(missing, ", "))
	}
	rFloor := 0.0
	if s.HasRFloor && riskFinite(s.RFloor) {
		rFloor = math.Min(1, math.Max(0, s.RFloor))
	}
	r := math.Max(RiskScore(inputs, p.Weights), rFloor)

	// only a RECOGNIZED non-irreversible class is fast-path eligible (a missing or unknown class fails closed)
	rt := RequiredThresholdOf(r, p.Theta1, p.Theta2, !riskFastPathEligible(s.ReversibilityClass))
	adm := Admit(r, leaked, p)
	if adm.NeedStepUp {
		if rt.T < 3 && adm.T == 3 {
			reasons = append(reasons, "trust budget depleted: human recharge required")
		} else {
			reasons = append(reasons, "risk "+strconv.FormatFloat(r, 'f', 3, 64)+" exceeds auto threshold: step-up to t="+strconv.Itoa(adm.T))
		}
	}
	release := s.PrOK && s.CvOK && s.DcvOK && s.ChainOK
	dec := RiskDecision{ReleaseGuardianShare: release, R: r, Reasons: reasons, Budget: leaked}
	dec.Admit = release && adm.Admit
	dec.NeedStepUp = !release || adm.NeedStepUp
	dec.RequiredThreshold = EscalateThreshold(rt, adm.T)
	dec.Debit = release && adm.Metered
	if dec.Debit {
		dec.Budget = leaked.Debit(RiskCost(r, p.Kappa))
	}
	return dec
}

// InsecureCalmRisk supplies every risk input at its best value (risk 0): INSECURE, for tests and demos only. A real server supplies
// the risk it knows through AuthorizeInput.Risk; an input it does not supply is the worst case, which needs the highest threshold.
func InsecureCalmRisk(*Operation, map[string]any, map[string]any) (map[string]any, error) {
	return map[string]any{"semanticDistance": json.Number("0"), "reversibility": json.Number("1"), "blastRadius": json.Number("0"),
		"taint": json.Number("0"), "confidence": json.Number("1"), "age": json.Number("0")}, nil
}
