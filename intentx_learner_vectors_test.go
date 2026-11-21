package pca

// Replays the intent learner corpus: the posterior scenarios (observe, probe, next question, metrics, synthesis, replay and the
// elicitation loop), the hypothesis cell sets, the class names and the box cover.

import (
	"math"
	"testing"
)

func ixLrQuestionJSON(q any) any {
	m := ixM(q)
	if m == nil {
		return nil
	}
	return map[string]any{"verb": m["verb"], "cell": m["cell"], "outcome": m["outcome"], "p": m["p"], "score": m["score"]}
}

func ixLrHooks(opts map[string]any) (map[string]any, *IntentLearnerHooks) {
	x := ixCopyMap(opts)
	h := &IntentLearnerHooks{}
	if x["nullMassFn"] == "byRev" {
		h.NullMass = func(vs map[string]any) float64 {
			if vs["reversibility"] == "reversible" {
				return 0.1
			}
			return 0.3
		}
		delete(x, "nullMassFn")
	}
	if pm := ixM(x["priorMix"]); pm != nil {
		kind := pm["weight"]
		h.PriorMixWeight = func(_ map[string]any, has func(int) bool) float64 {
			switch kind {
			case "size":
				k := 1.0
				for c := 0; c < 64; c++ {
					if has(c) {
						k++
					}
				}
				return k
			case "neg":
				return -1
			}
			return 0
		}
		x["priorMix"] = map[string]any{"beta": pm["beta"]}
	}
	return x, h
}

func ixLrScenario(a []any) any {
	omega := ixM(a[0])
	lopts, hooks := ixLrHooks(ixM(a[1]))
	l := ixNewLearner(omega, lopts, hooks)
	out := []any{}
	for _, ov := range ixL(a[2]) {
		op := ixM(ov)
		switch op["op"] {
		case "observe":
			src := "elicitation"
			if s, ok := op["source"].(string); ok {
				src = s
			}
			if r := l.observe(map[string]any{"verb": op["verb"], "values": op["values"]}, ixF(op["y"]), src, ixM(op["region"])); r != nil {
				out = append(out, r)
			} else {
				out = append(out, nil)
			}
		case "probe":
			oc := map[string]any{"verb": op["verb"], "values": op["values"]}
			out = append(out, []any{l.Acceptance(oc), l.AdmitsOutcome(oc), l.IsVetoed(oc)})
		case "next":
			if q := l.NextQuestion(); q != nil {
				out = append(out, ixLrQuestionJSON(q))
			} else {
				out = append(out, nil)
			}
		case "metrics":
			out = append(out, l.Metrics())
		case "cells":
			out = append(out, l.Cells())
		case "unconfirmed":
			u := []any{}
			for _, x := range l.UnconfirmedGrantCells() {
				u = append(u, x)
			}
			out = append(out, u)
		case "synth":
			out = append(out, l.Synthesize())
		case "vetoed":
			out = append(out, l.vetoedCells())
		case "observations":
			out = append(out, l.ObservationsJSON())
		case "replay":
			r, err := ReplayIntentLearner(omega, lopts, hooks, l.observations)
			if err != nil {
				panic(err)
			}
			out = append(out, r.Metrics())
		case "elicit":
			adm, err := IntentNewAdmitter(op["policy"])
			if err != nil {
				panic(err)
			}
			k := 0
			flip := ixFOr(op["flipEvery"], 0)
			answer := func(q map[string]any) float64 {
				var vs map[string]any
				for _, v := range ixL(omega["verbs"]) {
					if ixM(v)["verb"] == q["verb"] {
						vs = ixM(v)
					}
				}
				y := 0.0
				if adm.admits(vs, ixM(q["outcome"])) {
					y = 1
				}
				k++
				if flip != 0 && math.Mod(float64(k), flip) == 0 {
					return 1 - y
				}
				return y
			}
			r := l.elicit(answer, map[string]any{"epsRisk": op["epsRisk"], "epsBurden": op["epsBurden"], "maxQuestions": op["maxQuestions"],
				"audit": op["audit"], "seed": op["seed"]})
			asked := []any{}
			for _, q := range ixL(r["asked"]) {
				asked = append(asked, ixLrQuestionJSON(q))
			}
			out = append(out, map[string]any{"stop": r["stop"], "questions": r["questions"], "auditQuestions": r["auditQuestions"],
				"seedQuestions": r["seedQuestions"], "asked": asked, "metrics": l.Metrics()})
		default:
			ixFail("bad op")
		}
	}
	return out
}

func ixLrMaskJSON(sets [][]byte) []any {
	out := make([]any, len(sets))
	for i, s := range sets {
		row := make([]any, len(s))
		for j, b := range s {
			row[j] = float64(b)
		}
		out[i] = row
	}
	return out
}

func TestIntentLearnerReferenceVectors(t *testing.T) {
	replayVectorsApprox(t, "ref-intent-learner.json.gz", map[string]vecFn{
		"scenario": ixWrap(ixLrScenario),
		"hypothesisCellSets": ixWrap(func(a []any) any {
			var caps map[string]any
			if len(a) > 2 {
				caps = ixM(a[2])
			}
			sets, cx, err := IntentHypothesisCellSets(ixM(a[0]), ixM(ixArg(a, 1)), caps)
			if err != nil {
				panic(err)
			}
			if len(a) > 2 || ixArg(a, 1) == nil {
				return float64(len(sets))
			}
			return map[string]any{"sets": ixLrMaskJSON(sets), "complexity": cx}
		}),
		"hypothesisClassName": ixWrap(func(a []any) any { return IntentHypothesisClassName(ixM(a[0])) }),
		"boxesToPredicates": ixWrap(func(a []any) any {
			al := make([]byte, len(ixL(a[1])))
			for i, x := range ixL(a[1]) {
				al[i] = byte(ixF(x))
			}
			return IntentBoxesToPredicates(ixM(a[0]), al)
		}),
	}, "scenario")
}
