package pca

// Replays the Intent Map corpus: emit, replay-verify (clean and tampered), the committed form with its disclosures, the digests and
// the omega wire round trip, and the runtime divergence.

import (
	"strings"
	"testing"
)

func ixMkNormProblems(r map[string]any) map[string]any {
	ps := []any{}
	for _, p := range ixL(r["problems"]) {
		s := ixS(p)
		if strings.HasPrefix(s, "replay failed") {
			s = "replay failed"
		}
		ps = append(ps, s)
	}
	return map[string]any{"ok": r["ok"], "problems": ps}
}

func ixMkSecret(seed float64) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(int(seed) + 7*i)
	}
	return b
}

func ixMkMust[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func ixMkDisclosures(omega map[string]any, cm *IntentMapCommit) []any {
	out := []any{}
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		t := ixVerbCellCount(vs)
		for _, f := range []float64{0, float64(int(t) / 2), t - 1} {
			oc := ixCellRep(vs, ixDecodeCell(vs, f))
			params := map[string]any{}
			var resource any
			for k, v := range ixM(oc["values"]) {
				if k == "action.resource" {
					resource = v
				} else {
					params[strings.TrimPrefix(k, "action.params.")] = v
				}
			}
			out = append(out, ixMkMust(cm.Disclose(ixS(vs["verb"]), resource, params)))
		}
	}
	return out
}

func ixMkTamper(i int, m map[string]any) {
	metrics, cells := ixM(m["metrics"]), ixL(m["cells"])
	bump := func(x map[string]any, k string, by float64) { x[k] = ixF(x[k]) + by }
	switch i {
	case 1:
		bump(metrics, "residual_risk_ppm", 5)
	case 2:
		bump(ixM(cells[0]), "p_ppm", 3)
	case 3:
		c := ixM(cells[0])
		c["in_grant"] = !(c["in_grant"] == true)
	case 4:
		m["grant_digest"] = "AAAA"
	case 5:
		if o := ixL(m["observations"]); len(o) > 0 {
			m["observations"] = o[:len(o)-1]
		}
	case 6:
		m["kind"] = "x"
	case 7:
		m["principals"] = []any{"a", "b"}
	case 8:
		m["aggregation"] = map[string]any{"rule": "unanimity"}
	case 9:
		delete(metrics, "log2_vs_mbits")
	case 10:
		bump(ixM(m["learner"]), "eta_ppm", 100000)
	case 11:
		bump(metrics, "questions", 1)
	case 12:
		m["cells"] = cells[:len(cells)-1]
	case 13:
		ixM(ixL(ixM(m["omega"])["verbs"])[0])["w"] = 5.0
	case 14:
		metrics["log2_vs_mbits"] = nil
	case 15:
		bump(ixM(cells[0]), "p_ppm", 2)
	case 16:
		bump(ixM(cells[0]), "p_ppm", 1)
	}
}

func ixMkScenario(a []any) any {
	l := ixMkMust(IntentCreateLearner(ixM(a[0]), ixM(a[1])))
	for _, xv := range ixL(a[2]) {
		x := ixM(xv)
		l.observe(map[string]any{"verb": x["verb"], "values": x["values"]}, ixF(x["y"]), ixS(x["source"]), ixM(x["region"]))
	}
	var ref any = a[3]
	m := ixMkMust(IntentEmitMap(l, ref))
	tampered := []any{}
	for i := 0; i < 17; i++ {
		c := ixM(ixClone(m))
		ixMkTamper(i, c)
		tampered = append(tampered, ixMkNormProblems(IntentVerifyMap(c)))
	}
	tampered = append(tampered, ixMkNormProblems(IntentVerifyMap(nil)), ixMkNormProblems(IntentVerifyMap(map[string]any{"v": 2.0})))
	var commit any
	if _, err := ixTry(func() any {
		cm := ixMkMust(IntentCommitIntentMap(m, ixMkSecret(ixF(a[4]))))
		commit = map[string]any{"map_commit": cm.MapCommit, "size": float64(cm.Size), "leaves": cm.Leaves, "disclosures": ixMkDisclosures(l.omega, cm)}
		return nil
	}); err != nil {
		commit = map[string]any{"error": true}
	}
	return map[string]any{"map": m, "digest": ixMkMust(IntentMapDigest(m)), "grantDigest": ixMkMust(IntentGrantDigest(ixM(m["grant"]))),
		"verify": ixMkNormProblems(IntentVerifyMap(m)), "tampered": tampered, "options": ixMkMust(IntentMapLearnerOptions(m)),
		"omegaRoundtrip": ixMkMust(IntentOmegaToJSON(ixMkMust(IntentOmegaFromJSON(ixM(m["omega"]))))), "commit": commit}
}

func TestIntentMapKitReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-map.json.gz", map[string]vecFn{
		"mapScenario": ixWrap(ixMkScenario),
		"commitIntentMap": ixWrap(func(a []any) any {
			cm := ixMkMust(IntentCommitIntentMap(ixM(a[0]), ixMkSecret(3)))
			return map[string]any{"map_commit": cm.MapCommit, "size": float64(cm.Size), "leaves": cm.Leaves}
		}),
		"grantDigest":     ixWrap(func(a []any) any { return ixMkMust(IntentGrantDigest(ixM(a[0]))) }),
		"intentMapDigest": ixWrap(func(a []any) any { return ixMkMust(IntentMapDigest(a[0])) }),
		"omegaToJSON":     ixWrap(func(a []any) any { return ixMkMust(IntentOmegaToJSON(ixM(a[0]))) }),
		"omegaFromJSON":   ixWrap(func(a []any) any { return ixMkMust(IntentOmegaFromJSON(ixM(a[0]))) }),
		"divergence": ixWrap(func(a []any) any {
			l := ixMkMust(IntentCreateLearner(ixM(a[0]), ixM(a[1])))
			for _, xv := range ixL(a[2]) {
				x := ixM(xv)
				l.observe(map[string]any{"verb": x["verb"], "values": x["values"]}, ixF(x["y"]), ixS(x["source"]), nil)
			}
			out := []any{}
			for _, dv := range ixL(a[3]) {
				d := ixM(dv)
				out = append(out, ixMkMust(IntentApplyDivergence(l, ixM(d["outcome"]), ixF(d["y"]))))
			}
			return out
		}),
	})
}
