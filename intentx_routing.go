package pca

// Routing an admitted action by the map's posterior and the verb's reversibility (deny / allow / optimistic / jit-consent), the
// bond an optimistic claim stakes, and the principal's just-in-time decision fed back into the learner.

import (
	"math"
)

const (
	ixRtMicros       = 1000000.0
	ixRtMaxSafeMicro = 1e15
)

func ixRtQuantizeUp(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) || x <= 0 {
		return x
	}
	scaled := x * ixRtMicros
	if scaled > ixRtMaxSafeMicro {
		return x
	}
	r := math.Floor(scaled + 0.5)
	m := math.Ceil(scaled)
	if r/ixRtMicros == x || math.Abs(scaled-r) <= 1e-3 {
		m = r
	}
	return m / ixRtMicros
}

func ixRtCurve(curve any, k, e float64) float64 {
	c := ixM(curve)
	kind := c["kind"]
	if c == nil || kind == "linear" {
		return k * e
	}
	if kind == "power" {
		g, ok := c["gamma"].(float64)
		if !ok || math.IsNaN(g) || math.IsInf(g, 0) || g < 1 {
			ixFail("bondAmount: power curve requires finite gamma >= 1")
		}
		r, err := bsPowEighths(e, g)
		if err != nil {
			ixFail("%s", err.Error())
		}
		return float64(k * r)
	}
	tiers, ok := c["tiers"].([]any)
	if !ok || len(tiers) == 0 {
		ixFail("bondAmount: piecewise curve requires at least one tier")
	}
	acc, prevUp, prevMarginal := 0.0, 0.0, 0.0
	for _, tv := range tiers {
		t := ixM(tv)
		up, mk := ixF(t["upTo"]), ixF(t["marginalK"])
		if !(!math.IsInf(up, 0) && !math.IsNaN(up) && up > prevUp) && !math.IsInf(up, 1) {
			ixFail("bondAmount: piecewise tier `upTo` must be strictly increasing")
		}
		if !(!math.IsInf(mk, 0) && !math.IsNaN(mk) && mk >= 0) {
			ixFail("bondAmount: piecewise `marginalK` must be a finite number >= 0")
		}
		if mk < prevMarginal {
			ixFail("bondAmount: piecewise marginal rates must be non-decreasing (convex)")
		}
		if width := math.Min(e, up) - prevUp; width > 0 {
			acc += float64(width * mk)
		}
		prevUp, prevMarginal = up, mk
		if e <= up {
			break
		}
	}
	if e > prevUp {
		acc += float64((e - prevUp) * prevMarginal)
	}
	return k * acc
}

// IntentBondAmount is max(floor, curve(k, exposure)) snapped up onto the micro grid; a non-finite or non-positive exposure gives the floor.
func IntentBondAmount(policy map[string]any, exposure float64) (float64, error) {
	r, err := ixTry(func() any { return ixRtBond(policy, exposure) })
	if err != nil {
		return 0, err
	}
	return r.(float64), nil
}

func ixRtBond(policy map[string]any, exposure float64) float64 {
	e := 0.0
	if !math.IsNaN(exposure) && !math.IsInf(exposure, 0) && exposure > 0 {
		e = exposure
	}
	return ixRtQuantizeUp(math.Max(ixF(ixMkReq(policy, "floor")), ixRtCurve(policy["curve"], ixF(ixMkReq(policy, "k")), e)))
}

var ixRtDefaultBond = map[string]any{"floor": 1.0, "k": 1.0, "maxOpenClaims": 100.0, "maxOpenAmount": math.Inf(1)}

// IntentRouteAction routes an action by the learner's posterior: deny / allow / optimistic / jit-consent. opts: hMax, theta2, bondPolicy.
func IntentRouteAction(l *IntentLearner, o, opts map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixRtRoute(l, o, opts) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixRtRoute(l *IntentLearner, o, opts map[string]any) map[string]any {
	vs := ixMaFindVerb(l.omega, o["verb"])
	if vs == nil || ixCellOf(vs, o) == nil {
		rev := any("unknown")
		if vs != nil {
			rev = vs["reversibility"]
		}
		return map[string]any{"route": "deny", "p": 0.0, "inGrant": false, "vetoed": false, "reversibility": rev, "harm": 0.0, "risk": 1.0,
			"judges": false, "reason": "outside the Intent Map's outcome space"}
	}
	p := l.Acceptance(o)
	inGrant := l.AdmitsOutcome(o)
	vetoed := l.IsVetoed(o)
	harm := ixHarmOf(vs, o, l.harm)
	var hMax float64
	if v := opts["hMax"]; v != nil {
		hMax = ixF(v)
	} else {
		hMax = ixHarmMax(l.omega, l.harm)
	}
	den := 1.0
	if hMax > 0 {
		den = hMax
	}
	risk := math.Min(1, math.Max(0, ((1-p)*harm)/den))
	theta2 := ixLrOptF(opts, "theta2", 0.5)
	base := map[string]any{"p": p, "inGrant": inGrant, "vetoed": vetoed, "reversibility": vs["reversibility"], "harm": harm, "risk": risk}
	with := func(extra map[string]any) map[string]any {
		out := ixCopyMap(base)
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	if !inGrant {
		why := "outside the conservative grant (p_n < τ)"
		if vetoed {
			why = "the cell was vetoed by a runtime divergence"
		}
		return with(map[string]any{"route": "deny", "judges": false, "reason": why})
	}
	irreversible := vs["reversibility"] == "irreversible"
	judges := irreversible || p < 1-1e-12 || risk >= theta2
	if irreversible {
		return with(map[string]any{"route": "jit-consent", "judges": judges, "reason": "irreversible: just-in-time consent on the rendered action"})
	}
	if judges {
		policy := ixRtDefaultBond
		if bp := ixM(opts["bondPolicy"]); bp != nil {
			policy = bp
		}
		why := "risk ≥ θ₂: bonded claim + judges"
		if p < 1-1e-12 {
			why = "unconfirmed region (p_n < 1): bonded claim + judges"
		}
		return with(map[string]any{"route": "optimistic", "judges": judges, "bond": ixRtBond(policy, harm), "reason": why})
	}
	return with(map[string]any{"route": "allow", "judges": false, "reason": "confirmed region, reversible, low risk"})
}

// IntentRecordJitDecision records the principal's JIT decision as a runtime observation: approve -> y = 1 (widens the grant only
// through the posterior), deny -> y = 0 and the cell is vetoed.
func IntentRecordJitDecision(l *IntentLearner, req map[string]any, decision string) (map[string]any, error) {
	y := 0.0
	if decision == "approve" {
		y = 1
	}
	return IntentApplyDivergence(l, map[string]any{"verb": req["verb"], "values": req["values"]}, y)
}
