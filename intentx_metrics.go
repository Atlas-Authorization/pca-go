package pca

// Measuring a grant against an intent: Monte Carlo and exact risk / burden / fidelity, the Hoeffding half-width and the Wilson
// interval.

import "math"

func ixAdmitter(policy any) *IntentAdmitter { return &IntentAdmitter{anlToModel(policy)} }

// ixAcceptabilityOf is 1 where the policy admits the outcome, else 0.
func ixAcceptabilityOf(policy any) func(vs, o map[string]any) float64 {
	a := ixAdmitter(policy)
	return func(vs, o map[string]any) float64 {
		if a.admits(vs, o) {
			return 1
		}
		return 0
	}
}

func ixHoeffding(rng, samples, deltaPrime float64) float64 {
	return rng * math.Sqrt(math.Log(2/deltaPrime)/(2*samples))
}

func ixMeasureGrant(omega map[string]any, grant any, acceptability func(vs, o map[string]any) float64, opts map[string]any) map[string]any {
	M := ixFOr(opts["samples"], 20000)
	seed := ixFOr(opts["seed"], 1)
	rand := IntentRng(seed)
	g := ixAdmitter(grant)
	R, B, Rm, hMax := 0.0, 0.0, 0.0, 0.0
	for i := 0.0; i < M; i++ {
		vs, o := ixSampleOutcome(omega, rand)
		a := acceptability(vs, o)
		h := ixHarmOf(vs, o, ixDefaultHarm)
		hMax = math.Max(hMax, h)
		if g.admits(vs, o) {
			R += float64((1 - a) * h)
		} else {
			B += a
		}
		Rm += float64((1 - a) * h)
	}
	R, B, Rm = R/M, B/M, Rm/M
	hm := hMax
	if opts["hMax"] != nil {
		hm = ixF(opts["hMax"])
	}
	fid := 1.0
	if Rm > 0 {
		fid = 1 - R/Rm
	}
	return map[string]any{"risk": R, "burden": B, "riskMax": Rm, "fidelity": fid, "samples": M, "riskHalfWidth": ixHoeffding(hm, M, 0.05)}
}

// ixMeasureGrantExact is the exact R, B, R_max, F by summing over the cells (no sampling error).
func ixMeasureGrantExact(omega map[string]any, grant any, acceptability func(vs, o map[string]any) float64) map[string]any {
	g := ixAdmitter(grant)
	R, B, Rm, Eh := 0.0, 0.0, 0.0, 0.0
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		n := int(ixVerbCellCount(vs))
		for c := 0; c < n; c++ {
			idx := ixDecodeCell(vs, float64(c))
			o := ixCellRep(vs, idx)
			mass, h := ixCellStats(vs, idx, ixDefaultHarm)
			a := acceptability(vs, o)
			Eh += float64(mass * h)
			Rm += float64(mass * (1 - a) * h)
			if g.admits(vs, o) {
				R += float64(mass * (1 - a) * h)
			} else {
				B += float64(mass * a)
			}
		}
	}
	fid := 1.0
	if Rm > 0 {
		fid = 1 - R/Rm
	}
	return map[string]any{"risk": R, "burden": B, "riskMax": Rm, "fidelity": fid, "meanHarm": Eh}
}

// ixWilson is the Wilson score interval for a binomial proportion k/n (z default 1.959963984540054, 95%).
func ixWilson(k, n, z float64) map[string]any {
	if !(n > 0) {
		return map[string]any{"p": math.NaN(), "lo": 0.0, "hi": 1.0}
	}
	p := k / n
	z2 := z * z
	den := 1 + z2/n
	centre := (p + z2/(2*n)) / den
	half := (z * math.Sqrt((p*(1-p))/n+z2/(4*n*n))) / den
	return map[string]any{"p": p, "lo": math.Max(0, centre-half), "hi": math.Min(1, centre+half)}
}
