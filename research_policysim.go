package pca

import (
	"math"
	"sort"
	"strings"
)

// Policy simulation and linting: before a principal enables a grant, replay a batch of historical or hypothetical actions against
// the compiled policy (which auto-admit, which force a human step-up, which are denied) and run static lints for the classic
// mistakes. Pure, offline, and mutating nothing: it composes the compiled policy's predicates and caveats with the trust-budget
// algebra. A planning tool: the resource server's verifier remains the authority at run time.

var policySimReversibilityOrder = []string{"reversible", "rate_limited", "irreversible"}

func policySimNz(x float64) float64 {
	if !math.IsNaN(x) && !math.IsInf(x, 0) && x > 0 {
		return x
	}
	return 0
}

func policySimCost(r, kappa float64) float64 {
	if math.IsNaN(r) || math.IsInf(r, 0) {
		r = 1
	}
	return policySimNz(kappa) * rsClamp01(r)
}

// policySimNumber is Number(params[field]): NaN for an absent member.
func policySimNumber(params map[string]any, field string) float64 {
	v, present := params[field]
	if !present {
		return math.NaN()
	}
	switch t := v.(type) {
	case nil:
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	case string, []any:
		return jsStringToNumber(jsValueString(v))
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func policySimRiskOf(policy *CompiledPolicy, cat *Catalog, verb string, params map[string]any) float64 {
	spec, known := cat.Get(verb)
	kappa := jsF(policy.RiskPolicy["kappa"])
	if policy.BudgetModel == "dollars" && known && spec.AmountField != "" {
		amt := policySimNumber(params, spec.AmountField)
		if !math.IsNaN(amt) && !math.IsInf(amt, 0) && kappa > 0 {
			return rsClamp01(amt / kappa)
		}
	}
	if known {
		return rsClamp01(spec.BlastRadius)
	}
	return rsClamp01(0.8)
}

func policySimResult(action map[string]any, outcome string, t int, r float64, reason string, budgetAfter float64) map[string]any {
	m := map[string]any{"action": action, "outcome": outcome, "r": rsN(r), "budgetAfter": rsN(budgetAfter)}
	if t != 0 {
		m["t"] = jsNumber(float64(t))
	}
	if reason != "" {
		m["reason"] = reason
	}
	return m
}

// policySimDenial is the refusal wording of the predicates for an action ("" when they permit it): the unmet limit when one is in
// scope, else "no predicate permits <verb> on <resource>". Never panics.
func policySimDenial(predicates any, ctx map[string]any) (reason string) {
	if evaluatePredicates(predicates, ctx) {
		return ""
	}
	arr, ok := predicates.([]any)
	if !ok || len(arr) == 0 {
		return "envelope grants no predicates"
	}
	a, _ := ctx["action"].(map[string]any)
	vr := jsMemberString(a, "verb") + " on " + jsMemberString(a, "resource")
	limit, found := "", false
	func() {
		defer func() { _ = recover() }()
		limit, found = firstUnmetLimit(arr, ctx, &regexBudget{})
	}()
	if found {
		return limit + " not satisfied for " + vr
	}
	return "no predicate permits " + vr
}

type policySimTimed struct {
	a  map[string]any
	at float64
}

// SimulatePolicy replays actions in time order against the policy, threading the trust budget as the server would (leak between
// actions; debit kappa*r on every metered admit; step-up when the budget cannot cover a machine-band action). An action with no
// usable time is reported as denied, not skipped or guessed. catalog may be nil (the built-in one); start is the clock the budget
// starts at and the base of untimed actions' order (start + index). An action is {verb, resource, params?, at?}.
func SimulatePolicy(policy *CompiledPolicy, actions []map[string]any, catalog *Catalog, start float64) map[string]any {
	cat := catalog
	if cat == nil {
		cat = DefaultCatalog()
	}
	timed := make([]policySimTimed, 0, len(actions))
	for i, a := range actions {
		at := start + float64(i)
		if raw := a["at"]; raw != nil {
			at = math.NaN()
			if rsFinite(raw) {
				at = jsF(raw)
			}
		}
		timed = append(timed, policySimTimed{a, at})
	}
	rp := policy.RiskPolicy
	bMax, lambda, kappa := jsF(rp["bMax"]), jsF(rp["lambda"]), jsF(rp["kappa"])
	theta1, theta2 := jsF(rp["theta1"]), jsF(rp["theta2"])
	budgetB, asOf := bMax, start
	var ordered []policySimTimed
	for _, x := range timed {
		if !math.IsNaN(x.at) && !math.IsInf(x.at, 0) {
			ordered = append(ordered, x)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].at-ordered[j].at < 0 })
	results := []map[string]any{}
	for _, x := range timed {
		if math.IsNaN(x.at) || math.IsInf(x.at, 0) {
			results = append(results, policySimResult(x.a, "deny", 0, 1, "action has no finite time", budgetB))
		}
	}
	var recent []any
	peakRisk, autonomousRisk := 0.0, 0.0
	for _, x := range ordered {
		a, at := x.a, x.at
		verb, _ := a["verb"].(string)
		spec, known := cat.Get(verb)
		params := rsMap(a["params"])
		pm := params
		if pm == nil {
			pm = map[string]any{}
		}
		rev, blast := "irreversible", 1.0
		if known {
			rev, blast = spec.Reversibility, spec.BlastRadius
		}
		ctx := map[string]any{"action": map[string]any{"verb": a["verb"], "resource": a["resource"], "params": pm, "reversibility_class": rev}}
		r := policySimRiskOf(policy, cat, verb, params)
		peakRisk = math.Max(peakRisk, r)

		denial := policySimDenial(policy.Predicates, ctx)
		var capOK bool
		var failed []string
		if denial == "" {
			cctx := map[string]any{"now": rsN(at), "blast_radius": rsN(blast), "reversibility_class": rev,
				"recent_action_times": append([]any(nil), recent...)}
			capOK, failed = EvaluateCaveats(policy.Caveats, cctx)
		}
		// leak: B falls by lambda per second since the last update (idempotent at the same instant)
		dt := math.Max(0, at-asOf)
		budgetB = math.Max(0, budgetB-policySimNz(lambda)*(dt/1000))
		asOf = math.Max(at, asOf)

		if denial != "" {
			results = append(results, policySimResult(a, "deny", 0, r, denial, budgetB))
			continue
		}
		if !capOK {
			results = append(results, policySimResult(a, "deny", 0, r, "caveat(s) failed: "+strings.Join(failed, ", "), budgetB))
			continue
		}
		t := RequiredThresholdOf(r, theta1, theta2, false).T
		c := policySimCost(r, kappa)
		admit, tOut := false, 3
		switch {
		case t < 3 && !(budgetB >= c):
			tOut = 3
		case t == 1:
			admit, tOut = true, 1
		case t == 2:
			tOut = 2
		}
		if admit {
			budgetB -= c
			autonomousRisk += r
			recent = append(recent, jsNumber(at))
			results = append(results, policySimResult(a, "auto", 1, r, "", budgetB))
		} else {
			// t=2 (guardian auto-cosign) and t=3 (human) both surface as a step-up in the planning view
			results = append(results, policySimResult(a, "step_up", tOut, r, "requires tier "+jsNumberString(float64(tOut)), budgetB))
		}
	}
	var auto, stepUp, deny float64
	out := make([]any, len(results))
	for i, m := range results {
		switch m["outcome"] {
		case "auto":
			auto++
		case "step_up":
			stepUp++
		default:
			deny++
		}
		out[i] = m
	}
	return map[string]any{"results": out, "auto": rsN(auto), "stepUp": rsN(stepUp), "deny": rsN(deny), "endBudget": rsN(budgetB),
		"peakRisk": rsN(peakRisk), "autonomousRisk": rsN(autonomousRisk)}
}

func policySimSev(cls string) int {
	for i, c := range policySimReversibilityOrder {
		if c == cls {
			return i
		}
	}
	return -1
}

func policySimLint(level, code, message string) any {
	return map[string]any{"level": level, "code": code, "message": message}
}

// policySimKeys is Object.keys order: array-index keys ascending, then the rest (sorted, the insertion order being unrecoverable
// from a Go map).
func policySimKeys(m map[string]string) []string {
	var idx, rest []string
	for k := range m {
		if _, ok := arrayIndex(k); ok {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(idx, func(i, j int) bool { a, _ := arrayIndex(idx[i]); b, _ := arrayIndex(idx[j]); return a < b })
	sort.Strings(rest)
	return append(idx, rest...)
}

// LintPolicy runs static lints over a compiled policy: "error" = almost certainly a mistake (a limit that matches no granted
// action), "warn" = a real risk worth a second look, "info" = a notable but intentional property. catalog may be nil.
func LintPolicy(policy *CompiledPolicy, catalog *Catalog) []any {
	cat := catalog
	if cat == nil {
		cat = DefaultCatalog()
	}
	lints := []any{}
	granted := map[string]bool{}
	for _, s := range policy.Actions {
		granted[s.Verb], granted[s.Action] = true, true
		for _, al := range s.Aliases {
			granted[al] = true
		}
	}
	for _, key := range policySimKeys(policy.InputLimits) {
		if !granted[key] {
			lints = append(lints, policySimLint("error", "limit-unmatched", "limit for '"+key+"' matches no granted action"))
		}
	}
	for _, spec := range policy.Actions {
		var pred map[string]any
		for _, p := range policy.Predicates {
			if pm := rsMap(p); pm != nil && pm["verb"] == any(spec.Verb) {
				pred = pm
				break
			}
		}
		broad := pred == nil || !rsTruthy(pred["resource"]) || pred["resource"] == any("*")
		if _, limited := policy.Limits[spec.Verb]; spec.AmountField != "" && !limited {
			lints = append(lints, policySimLint("warn", "money-unbounded", "money action '"+spec.Verb+"' has no per-call limit — spend is bounded only by the trust budget"))
		}
		if broad && policySimSev(spec.Reversibility) >= policySimSev("rate_limited") {
			lints = append(lints, policySimLint("warn", "broad-resource", "'"+spec.Verb+"' ("+spec.Reversibility+") matches ANY resource — consider a resource prefix"))
		}
		if _, ok := cat.Get(spec.Verb); !ok {
			lints = append(lints, policySimLint("info", "uncatalogued", "'"+spec.Verb+"' is not in the catalog — treated conservatively (irreversible, high blast radius)"))
		}
	}
	rp := policy.RiskPolicy
	theta2, bMax, kappa := jsF(rp["theta2"]), jsF(rp["bMax"]), jsF(rp["kappa"])
	if theta2 >= 1 {
		hasIrrev := false
		for _, s := range policy.Actions {
			if policySimSev(s.Reversibility) >= policySimSev("irreversible") {
				hasIrrev = true
			}
		}
		level, tail := "info", ""
		if hasIrrev {
			level, tail = "warn", " — including irreversible actions"
		}
		lints = append(lints, policySimLint(level, "no-step-up-band", "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted"+tail))
	}
	if kappa > 0 && bMax/kappa > 100 {
		lints = append(lints, policySimLint("warn", "large-autonomy", "autonomous bound is "+rsNumStr(rsRound(bMax/kappa))+"× a max-risk action between human co-signs"))
	}
	return lints
}
