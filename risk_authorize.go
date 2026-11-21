package pca

import (
	"math"
	"strconv"
	"strings"
)

// budgetWriteT is the budget a metered release stores atomically with its replay claim.
type budgetWriteT struct{ before, after map[string]any }

func parseBudget(m map[string]any) (TrustBudget, bool) {
	b, okB := jsNum(m["B"])
	tau, okT := jsNum(m["tau"])
	if !okB || !okT || !riskFinite(b) || !riskFinite(tau) {
		return TrustBudget{}, false
	}
	out := TrustBudget{B: b, Tau: tau}
	if v, has := m["asOf"]; has && v != nil {
		as, ok := jsNum(v)
		if !ok || !riskFinite(as) {
			return TrustBudget{}, false
		}
		out.AsOf, out.HasAsOf = as, true
	}
	return out, true
}

func budgetMap(b TrustBudget) map[string]any {
	as := b.Tau
	if b.HasAsOf {
		as = b.AsOf
	}
	return map[string]any{"B": b.B, "tau": b.Tau, "asOf": as}
}

func callRisk(f func(*Operation, map[string]any, map[string]any) (map[string]any, error), op *Operation, grant, p map[string]any) (m map[string]any, failed bool) {
	defer func() {
		if recover() != nil {
			m, failed = nil, true
		}
	}()
	m, err := f(op, grant, p)
	return m, err != nil
}

func callBudgetRead(bs BudgetStore, key string) (m map[string]any, failed bool) {
	defer func() {
		if recover() != nil {
			m, failed = nil, true
		}
	}()
	m, err := bs.Budget(key)
	return m, err != nil
}

// adaptiveFault carries the failure of the AdaptivePolicy callback up to Authorize's catch-all, which refuses with
// `authorize error (fail closed): <message>` on the `authorize` check (the reference lets the exception propagate to its catch-all).
type adaptiveFault struct{ msg string }

func callAdaptive(f func(int64) *RiskPolicy, now int64) *RiskPolicy {
	defer func() {
		if r := recover(); r != nil {
			msg := "unknown"
			switch v := r.(type) {
			case error:
				msg = v.Error()
			case string:
				msg = v
			}
			panic(adaptiveFault{msg})
		}
	}()
	return f(now)
}

func callThreshold(h ThresholdHook, p, grant map[string]any) (r ThresholdResult) {
	defer func() {
		if recover() != nil {
			r = ThresholdResult{} // a hook that panics rejected the proof
		}
	}()
	return h(p, grant)
}

// riskStep runs the decision for one Authorize call and records its checks and reasons. It returns the budget to store with the
// replay claim (nil: none).
func riskStep(in *AuthorizeInput, op *Operation, grant, p map[string]any, chain []any, ctx *AuthorizeContext, rp RiskPolicy, now int64,
	policyWhy []string, planNodes []map[string]any, nodeID any, effective any, st map[string]string,
	mark func(name, status string), fail func(name, why string), reasons *[]string) *budgetWriteT {
	risk := map[string]any{}
	for k, v := range ctx.Risk {
		risk[k] = v
	}
	inputsOK := true
	if in.Risk != nil {
		m, failed := callRisk(in.Risk, op, grant, p)
		if failed {
			fail("risk", "the server risk provider failed (fail closed)")
			inputsOK = false
		} else {
			for k, v := range m {
				risk[k] = v
			}
		}
	}
	if len(in.RequireRiskInputs) > 0 {
		var missing []string
		for _, k := range in.RequireRiskInputs {
			f, ok := jsNum(risk[k])
			if _, has := risk[k]; (!has || !ok || !riskFinite(f)) && !(k == "semanticDistance" && planNodes != nil) {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			fail("risk_inputs", "required risk input(s) not supplied by the server: "+strings.Join(missing, ", "))
		} else {
			mark("risk_inputs", "pass")
		}
	}
	// the budget: the host's own (carried), else the one stored for this counter stream, else the grant's bMax at now
	seed := TrustBudget{B: rp.BMax, Tau: float64(now), AsOf: float64(now), HasAsOf: true}
	budget, persist := seed, false
	var before map[string]any
	if ctx.Budget != nil {
		budget = *ctx.Budget
	} else {
		persist = true
		streamKey := ""
		if len(chain) > 0 {
			leaf, _ := chain[len(chain)-1].(map[string]any)
			h, okH := leaf["holder"].(string)
			g, okG := grant["id"].(string)
			if okH && okG {
				streamKey = StateKey(g, h)
			}
		}
		if bs, isBS := in.StateStore.(BudgetStore); streamKey != "" && isBS {
			m, failed := callBudgetRead(bs, streamKey)
			switch {
			case failed:
				fail("budget", "the trust budget could not be read (fail closed)")
				inputsOK = false
			case m != nil:
				if b, ok := parseBudget(m); ok {
					budget, before = b, m
				} else {
					fail("budget", "the stored trust budget is malformed (fail closed)")
					inputsOK = false
				}
			}
		}
	}
	if !inputsOK {
		return nil
	}
	step := RiskStep{Policy: rp, Risk: risk, Plan: planNodes, GoalNodeID: ctx.GoalNodeID, Budget: budget, Now: float64(now),
		AgeHorizonMs: ctx.AgeHorizonMs, PrOK: len(policyWhy) == 0, CvOK: true, DcvOK: st["delegated_caveats"] != "fail", ChainOK: true}
	if nid, ok := nodeID.(string); ok {
		step.NodeID, step.HasNodeID = nid, true
	}
	if c, has := p["caution"]; has {
		if f, ok := jsNum(c); ok {
			step.RFloor, step.HasRFloor = f, true
		}
	}
	if s, ok := effective.(string); ok {
		step.ReversibilityClass = s
	}
	dec := DecideRisk(step)
	for _, r := range dec.Reasons {
		*reasons = append(*reasons, "policy: "+r)
	}
	if in.AdaptivePolicy != nil {
		if ap := callAdaptive(in.AdaptivePolicy, now); ap != nil {
			if bad := ValidateRiskPolicy(*ap); bad != "" {
				fail("adaptive", "invalid policy ("+bad+")")
			} else if ta := RequiredThresholdOf(dec.R, ap.Theta1, ap.Theta2, false).T; ta > dec.RequiredThreshold.T {
				fail("adaptive", "tightened policy requires threshold t="+strconv.Itoa(ta)+" (grant policy: t="+strconv.Itoa(dec.RequiredThreshold.T)+")")
			}
		}
	}
	// the threshold: t > 1 needs a proof only an enforced threshold hook can give, and it must have enforced at least the
	// SERVER-derived t (below it, or silent, the check fails)
	t := dec.RequiredThreshold
	status, hookT, hasHookT := "", 0, false
	if in.Threshold != nil {
		res := callThreshold(in.Threshold, p, grant)
		if res.OK {
			status = "pass"
			if res.Enforced {
				hookT, hasHookT = res.T, true
			}
		} else {
			status = "fail"
		}
	}
	if dec.ReleaseGuardianShare && t.T > 1 {
		switch {
		case status == "pass" && hasHookT && hookT >= t.T:
			mark("threshold", "pass")
		case status == "pass":
			told := "unreported"
			if hasHookT {
				told = strconv.Itoa(hookT)
			}
			fail("threshold", "threshold hook enforced t="+told+" but the server requires t="+strconv.Itoa(t.T)+" (below the server-derived threshold; derive t from server-held data)")
		case status == "fail":
			fail("threshold", "t="+strconv.Itoa(t.T)+" required and the threshold proof was rejected")
		default:
			fail("threshold", "t="+strconv.Itoa(t.T)+" ("+t.Proof+") required but no threshold verifier is enforced")
		}
	} else if status != "" {
		if status == "pass" {
			mark("threshold", "pass")
		} else {
			fail("threshold", "the threshold proof was rejected")
		}
	}
	// only a spend that changes the budget is stored (a zero-cost release leaves it as it was)
	if persist && dec.Debit && RiskCost(dec.R, rp.Kappa) > 0 && !math.IsNaN(dec.Budget.B) {
		return &budgetWriteT{before: before, after: budgetMap(dec.Budget)}
	}
	return nil
}
