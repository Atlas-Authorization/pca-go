package pca

// Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor
// and the regret report.

import "math"

var ixFrictionOrder = []string{"tap", "hold", "typed", "device"}

func ixIndexOf(xs []string, v any) int {
	for i, x := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

// ixProvenanceBanner is the fixed banner for a tainted value (nil for trusted / first-party values).
func ixProvenanceBanner(level any, what string) any {
	switch level {
	case "web":
		return "This " + what + " was suggested by content on the page, not by you."
	case "agent":
		return "This " + what + " came from your agent, not from you or the site."
	case "tool":
		return "This " + what + " came from another service, not from you or this site."
	}
	return nil
}

func ixIsTainted(level any) bool { return level == "tool" || level == "web" || level == "agent" }

// ixProvenanceFriction: a tainted critical value is at least typed, a tainted material value at least hold.
func ixProvenanceFriction(base, sensitivity, level any) any {
	floor := "tap"
	if ixIsTainted(level) {
		floor = "hold"
		if sensitivity == "critical" {
			floor = "typed"
		}
	}
	i := ixIndexOf(ixFrictionOrder, base)
	if f := ixIndexOf(ixFrictionOrder, floor); f > i {
		i = f
	}
	if i >= 0 {
		return ixFrictionOrder[i]
	}
	return nil
}

// IntentRegretCase is one regret case: the feasible options, the chosen one, and the admission / utility oracles.
type IntentRegretCase struct {
	Feasible []any
	Chosen   any
	Admits   func(any) bool
	Utility  func(any) float64
}

func ixWithinGrantRegret(c IntentRegretCase) (regret float64, admitted bool) {
	admitted = c.Admits(c.Chosen)
	var best any
	bestU := math.Inf(-1)
	found := false
	for _, o := range c.Feasible {
		if !c.Admits(o) {
			continue
		}
		if u := c.Utility(o); u > bestU {
			bestU, best, found = u, o, true
		}
	}
	_ = best
	if !admitted || !found {
		return 0, admitted
	}
	d := bestU - c.Utility(c.Chosen)
	if d != d || d > 0 {
		return d, admitted
	}
	return 0, admitted
}

// IntentRegretReport summarizes within-grant regret over cases; scale <= 0 counts as 1.
func IntentRegretReport(cases []IntentRegretCase, scale float64) map[string]any {
	admitted, positive := 0, 0
	s, mx := 0.0, 0.0
	for _, c := range cases {
		r, adm := ixWithinGrantRegret(c)
		if !adm {
			continue
		}
		admitted++
		s += r
		if r > 0 {
			positive++
		}
		if r > mx {
			mx = r
		}
	}
	mean := 0.0
	if admitted > 0 {
		mean = s / float64(admitted)
	}
	if !(scale > 0) {
		scale = 1
	}
	return map[string]any{"cases": float64(len(cases)), "admitted": float64(admitted), "positive": float64(positive), "mean": mean,
		"max": mx, "regret_est_ppm": math.Floor(float64((mean/scale)*1000000) + 0.5)}
}
