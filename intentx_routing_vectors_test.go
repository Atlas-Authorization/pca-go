package pca

// Replays the routing corpus: bond sizing, judge verdicts, split-conformal calibration, the k-of-n threshold, routing by the learner's
// posterior, the IC-Att and just-in-time consent.

import (
	"math"
	"testing"
)

func ixRtInf(x float64) any {
	if math.IsInf(x, 0) {
		return "inf"
	}
	return x
}

func ixRtVerdicts(v any) []any { return ixL(v) }

func TestIntentRoutingReferenceVectors(t *testing.T) {
	replayVectorsApprox(t, "ref-intent-routing.json.gz", map[string]vecFn{
		"bondAmount":    ixWrap(func(a []any) any { return ixMkMust(IntentBondAmount(ixM(a[0]), ixF(a[1]))) }),
		"quantizeScore": ixWrap(func(a []any) any { return IntentQuantizeScore(ixF(a[0])) }),
		"verifyJudgeVerdict": ixWrap(func(a []any) any {
			return IntentVerifyJudgeVerdict(a[0], ixM(a[1]), ixM(ixArg(a, 2)))
		}),
		"conformalThreshold": ixWrap(func(a []any) any { return ixRtInf(IntentConformalThreshold(a[0])) }),
		"empiricalFalseAllowRate": ixWrap(func(a []any) any {
			return IntentEmpiricalFalseAllowRate(a[0], ixF(a[1]))
		}),
		"verifySemanticThreshold": ixWrap(func(a []any) any {
			r := IntentVerifySemanticThreshold(a[0], ixM(a[1]))
			if c, ok := r["cutoff"].(float64); ok {
				r["cutoff"] = ixRtInf(c)
			}
			return r
		}),
		"routeScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			out := []any{}
			for _, o := range ixL(a[3]) {
				out = append(out, ixMkMust(IntentRouteAction(l, ixM(o), ixM(a[4]))))
			}
			return out
		}),
		"routeVetoScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			for _, o := range ixL(a[3]) {
				l.observe(ixM(o), 0, "runtime", nil)
			}
			out := []any{}
			for _, o := range ixL(a[3]) {
				out = append(out, ixMkMust(IntentRouteAction(l, ixM(o), ixM(a[4]))))
			}
			return out
		}),
		"conformanceScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			oc := ixM(a[3])
			input := ixJudgeInputOf(l.omega, oc, l.Acceptance(oc), ixM(a[4]), nil)
			verdicts, copts := ixL(a[5]), ixM(a[6])
			att := ixMkMust(IntentConformanceAttestation(input, verdicts, copts))
			tampered := []any{}
			for i := 0; i < 6; i++ {
				c := ixM(ixClone(att))
				switch i {
				case 1:
					c["ok"] = !(c["ok"] == true)
				case 2:
					c["aggregate_score_ppm"] = ixF(c["aggregate_score_ppm"]) + 1
				case 3:
					if d := ixL(c["verdict_digests"]); len(d) > 0 {
						c["verdict_digests"] = d[:len(d)-1]
					}
				case 4:
					c["k"] = ixF(c["k"]) + 1
				case 5:
					c["reason"] = "x"
				}
				tampered = append(tampered, IntentVerifyICAtt(c, input, verdicts, copts))
			}
			rest := verdicts
			if len(rest) > 0 {
				rest = rest[1:]
			}
			tampered = append(tampered, IntentVerifyICAtt(att, input, rest, copts))
			check := ixMkMust(IntentCheckConformance(func(map[string]any) []any { return verdicts }, input, copts))
			return map[string]any{"input": input, "att": att, "digest": ixICAttDigest(att), "verify": IntentVerifyICAtt(att, input, verdicts, copts),
				"tampered": tampered, "check": check}
		}),
		"jitScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			oc, ctx := ixM(a[3]), ixM(a[5])
			req := ixJitConsentRequest(l.omega, oc, l.Acceptance(oc), map[string]any{"intentRef": ctx["intentRef"], "mapDigest": ctx["mapDigest"]}, nil)
			res := ixMkMust(IntentRecordJitDecision(l, req, ixS(a[4])))
			return map[string]any{"req": req, "digest": ixJitConsentDigest(req), "result": res, "metrics": l.Metrics(),
				"route": ixMkMust(IntentRouteAction(l, oc, nil))}
		}),
	})
}
