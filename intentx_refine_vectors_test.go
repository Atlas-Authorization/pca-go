package pca

// Replays the refinement corpus: omega refinement, observation regions, refining a learner, partial answers and the adaptive
// elicitation loop.

import (
	"math"
	"testing"
)

func ixRfMk(omega, opts map[string]any, observations []any) *IntentLearner {
	l := ixMkMust(IntentCreateLearner(omega, opts))
	for _, xv := range observations {
		x := ixM(xv)
		l.observe(map[string]any{"verb": x["verb"], "values": x["values"]}, ixF(x["y"]), ixS(x["source"]), ixM(x["region"]))
	}
	return l
}

func ixRfCells(l *IntentLearner) []any {
	out := []any{}
	for _, cv := range l.Cells() {
		c := ixM(cv)
		out = append(out, map[string]any{"verb": c["verb"], "cell": c["cell"], "p": c["p"]})
	}
	return out
}

func ixRfObs(l *IntentLearner) []any { return l.ObservationsJSON() }

func TestIntentRefineReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-refine.json.gz", map[string]vecFn{
		"refineOmega": ixWrap(func(a []any) any { return ixMkMust(IntentRefineOmega(ixM(a[0]), ixM(a[1]))) }),
		"regionsOf": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			omega := l.omega
			if a[3] == true {
				omega = ixCopyMap(l.omega)
				omega["verbs"] = []any{}
			}
			out := []any{}
			for _, o := range l.observations {
				out = append(out, ixMkMust(IntentRegionOfObservation(omega, o)))
			}
			return out
		}),
		"refineScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			nl := ixMkMust(IntentRefineLearner(l, ixM(a[3]), nil))
			return map[string]any{"omega": nl.omega, "observations": ixRfObs(nl), "metrics": nl.Metrics(), "cells": ixRfCells(nl)}
		}),
		"partialScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			q := ixM(a[3])
			if q["verb"] == "nope" {
				_, added, err := IntentAnswerPartial(l, map[string]any{"verb": q["verb"], "cell": q["cell"],
					"outcome": map[string]any{"verb": q["verb"], "values": map[string]any{}}, "p": 0.5, "score": 0.0}, ixM(a[4]))
				if err != nil {
					panic(err)
				}
				return added
			}
			svs := ixMaFindVerb(ixM(a[0]), q["verb"])
			oc := ixCellRep(svs, ixL(q["cell"]))
			nl, added, err := IntentAnswerPartial(l, map[string]any{"verb": q["verb"], "cell": q["cell"], "outcome": oc, "p": l.Acceptance(oc), "score": 0.0}, ixM(a[4]))
			if err != nil {
				panic(err)
			}
			return map[string]any{"omega": nl.omega, "added": added, "observations": ixRfObs(nl), "metrics": nl.Metrics(), "synth": nl.Synthesize()}
		}),
		"adaptiveScenario": ixWrap(func(a []any) any {
			adm, err := IntentNewAdmitter(a[2])
			if err != nil {
				panic(err)
			}
			ps, every := ixL(a[3]), ixF(a[4])
			k, pi := 0.0, 0
			answer := func(q map[string]any, l *IntentLearner) any {
				k++
				if math.Mod(k, every) == 0 && pi < len(ps) && q["verb"] == "stripe.refund" {
					pi++
					return ps[pi-1]
				}
				vs := ixMaFindVerb(l.omega, q["verb"])
				if adm.admits(vs, ixM(q["outcome"])) {
					return 1.0
				}
				return 0.0
			}
			l0 := ixMkMust(IntentCreateLearner(ixM(a[0]), ixM(a[1])))
			opts := map[string]any{"epsRisk": 0.001, "epsBurden": 0.01, "maxQuestions": 25.0}
			for k, v := range ixM(a[5]) {
				opts[k] = v
			}
			r := ixMkMust(IntentElicitAdaptive(l0, answer, opts))
			l := r["learner"].(*IntentLearner)
			asked := []any{}
			for _, q := range ixL(r["asked"]) {
				asked = append(asked, ixLrQuestionJSON(q))
			}
			return map[string]any{"stop": r["stop"], "questions": r["questions"], "auditQuestions": r["auditQuestions"],
				"seedQuestions": r["seedQuestions"], "refinements": r["refinements"], "asked": asked, "omega": l.omega,
				"metrics": l.Metrics(), "observations": ixRfObs(l)}
		}),
	})
}
