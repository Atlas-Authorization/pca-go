package pca

// Classifier error folded into the residual-risk estimate: the confusion calibration (exact Clopper-Pearson upper bounds per
// entry), the risk on explicit arrays and the label-sound bound.

import (
	"math"
	"math/big"
	"sort"
)

func ixSortedLabels(labels []any) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range labels {
		s, ok := v.(string)
		if !ok {
			ixFail("label is not a string")
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return compareUtf8(out[i], out[j]) < 0 })
	return out
}

// ixCalibrateConfusion calibrates a classifier on labelled examples; labels outside the label set are refused.
func ixCalibrateConfusion(samples, labels []any, deltaGamma float64) map[string]any {
	L := ixSortedLabels(labels)
	if len(L) == 0 {
		ixFail("calibrateConfusion: empty label set")
	}
	if !(0 < deltaGamma && deltaGamma < 1) {
		ixFail("calibrateConfusion: delta must be in (0, 1)")
	}
	ix := map[string]int{}
	for i, l := range L {
		ix[l] = i
	}
	counts := make([][]float64, len(L))
	for i := range counts {
		counts[i] = make([]float64, len(L))
	}
	for _, sv := range samples {
		s := ixM(sv)
		ts, ok1 := s["truth"].(string)
		ps, ok2 := s["predicted"].(string)
		t, okt := ix[ts]
		p, okp := ix[ps]
		if !ok1 || !ok2 || !okt || !okp {
			ixFail("calibrateConfusion: label outside L (%s / %s)", jsValueString(s["truth"]), jsValueString(s["predicted"]))
		}
		counts[t][p]++
	}
	alpha := deltaGamma / float64(len(L)*len(L))
	gamma, gammaBar, cOut := []any{}, []any{}, []any{}
	for _, row := range counts {
		n := 0.0
		for _, c := range row {
			n += c
		}
		g, gb, co := []any{}, []any{}, []any{}
		for _, c := range row {
			if n != 0 {
				g = append(g, c/n)
			} else {
				g = append(g, 0.0)
			}
			u, err := ClopperPearsonUpper(c, n, alpha)
			if err != nil {
				ixFail("%v", err)
			}
			gb = append(gb, u)
			co = append(co, c)
		}
		gamma, gammaBar, cOut = append(gamma, g), append(gammaBar, gb), append(cOut, co)
	}
	return map[string]any{"labels": ixToAny(L), "counts": cOut, "gamma": gamma, "gammaBar": gammaBar, "delta_ppm": math.Floor(float64(deltaGamma*1000000) + 0.5)}
}

func ixConfusionDigest(c map[string]any) string {
	return ixHashCanon(map[string]any{"d": "atlas-pca/intent-classifier-calibration/v1", "labels": ixReq(c, "labels"),
		"counts": ixReq(c, "counts"), "delta_ppm": ixReq(c, "delta_ppm")})
}

// ixPublishedErrorRate is the max over true labels of the capped upper bound of any other label.
func ixPublishedErrorRate(c map[string]any) float64 {
	worst := 0.0
	for t, rv := range ixL(c["gammaBar"]) {
		s := 0.0
		for p, g := range ixL(rv) {
			if p != t {
				s += ixF(g)
			}
		}
		if e := math.Min(1, s); e > worst {
			worst = e
		}
	}
	return worst
}

// ixToFixed1 is JavaScript's x.toFixed(1) for a finite x >= 0 (exact binary value, ties up).
func ixToFixed1(x float64) string {
	b := new(big.Float).SetPrec(2000).SetFloat64(x)
	b.Mul(b, big.NewFloat(10))
	b.Add(b, big.NewFloat(0.5))
	n, _ := b.Int(nil)
	s := n.String()
	if len(s) == 1 {
		s = "0" + s
	}
	return s[:len(s)-1] + "." + s[len(s)-1:]
}

func ixClassifierCardNote(id string, c map[string]any) string {
	return "\"" + id + "\" is decided by an attested classifier, not by a person. Published error rate: up to " +
		ixToFixed1(ixPublishedErrorRate(c)*100) + "%."
}

func ixGammaOfSet(g []any, A []int, t int) float64 {
	s := 0.0
	for _, p := range A {
		s += ixF(ixL(ixL(g)[p])[t])
	}
	return math.Min(1, s)
}

func ixInGSet(row any) []int {
	var A []int
	for p, b := range ixL(row) {
		if ixTruthy(b) {
			A = append(A, p)
		}
	}
	return A
}

// ixClassifierRisk is R_kappa(G) = sum mu (1 - a) h Gamma(A_G(x) | l), with Gamma(A | l) capped at 1.
func ixClassifierRisk(m map[string]any) float64 {
	r := 0.0
	for x, rowv := range ixL(m["mu"]) {
		A := ixInGSet(ixL(m["inG"])[x])
		for t, mu := range ixL(rowv) {
			r += float64(ixF(mu) * (1 - ixF(ixL(ixL(m["a"])[x])[t])) * ixF(ixL(ixL(m["h"])[x])[t]) * ixGammaOfSet(ixL(m["g"]), A, t))
		}
	}
	return r
}

func ixLabelSound(m map[string]any) bool {
	for x, row := range ixL(m["inG"]) {
		for p, b := range ixL(row) {
			if ixTruthy(b) && ixL(ixL(m["a"])[x])[p] != 1.0 {
				return false
			}
		}
	}
	return true
}

func ixLabelSoundBound(m map[string]any, hMax float64) float64 {
	s := 0.0
	for x, rowv := range ixL(m["mu"]) {
		A := ixInGSet(ixL(m["inG"])[x])
		for t, mu := range ixL(rowv) {
			if ixL(ixL(m["a"])[x])[t] == 0.0 {
				s += float64(ixF(mu) * ixGammaOfSet(ixL(m["g"]), A, t))
			}
		}
	}
	return hMax * s
}
