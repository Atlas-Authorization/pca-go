package pca

// Replays the wallet-over-learner corpora: the grant view of a learner (with a ceiling predicate) and the mass a released population
// prior admits.

import (
	"math"
	"testing"
)

func ixWlIdx(v any) []int {
	out := []int{}
	for _, x := range ixL(v) {
		out = append(out, ixIdx(x))
	}
	return out
}

func ixWlCeiling(name any) func(string, []int) bool {
	switch name {
	case "all":
		return func(string, []int) bool { return true }
	case "idx0":
		return func(_ string, idx []int) bool { return idx[0] == 0 }
	case "never":
		return func(string, []int) bool { return false }
	}
	return nil
}

func ixWlObs(obs []any, src string) []map[string]any {
	out := []map[string]any{}
	for _, xv := range obs {
		x := ixM(xv)
		s := src
		if v, ok := x["source"].(string); ok {
			s = v
		}
		out = append(out, map[string]any{"verb": x["verb"], "values": x["values"], "y": x["y"], "source": s})
	}
	return out
}

func ixWlRel(omega map[string]any, schema string, q func(c int) float64) map[string]any {
	wom := ixMkMust(WalletOmegaFromJSON(omega))
	cells := map[string]any{}
	for i := range wom.Verbs {
		vs := &wom.Verbs[i]
		for c := 0; c < WalletVerbCellCount(vs); c++ {
			key, err := WalletPopulationCellKey(schema, vs, WalletDecodeCell(vs, c))
			if err != nil {
				panic(err)
			}
			cells[key] = map[string]any{"q": q(c), "n": 50.0}
		}
	}
	return map[string]any{"v": 1.0, "kind": "pca-intent-population-prior", "schema": schema, "period": 1.0, "epsilon": 0.9, "delta": 1e-5,
		"sigma": 1.0, "sensitivity": 8.0, "cells": cells}
}

func TestWalletLearnerPyReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-wallet-learner-py.json.gz", map[string]vecFn{
		"viewScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			v := NewIntentLearnerView(l, ixWlCeiling(a[3]))
			probes := []any{}
			for _, pv := range ixL(a[4]) {
				p := ixM(pv)
				idx := ixWlIdx(p["idx"])
				pp := ixMkMust(v.P(ixS(p["verb"]), idx))
				ve := ixMkMust(v.Vetoed(ixS(p["verb"]), idx))
				probes = append(probes, []any{pp, ve, v.OutsideCeiling(ixS(p["verb"]), idx)})
			}
			return map[string]any{"probes": probes, "confirmed": v.Confirmed()}
		}),
		"viewUnknownVerb": ixWrap(func(a []any) any {
			return ixMkMust(NewIntentLearnerView(ixRfMk(ixM(a[0]), nil, nil), nil).P(ixS(a[1]), ixWlIdx(a[2])))
		}),
		"priorScenario": ixWrap(func(a []any) any {
			omega, qOf, hi := ixM(a[0]), ixF(a[5]), len(a) > 6 && a[6] == true
			rel := ixWlRel(omega, ixS(a[4]), func(c int) float64 {
				x := 0.05 + 0.04*math.Mod(float64(c), qOf)
				if hi {
					x = 0.98 - 0.04*math.Mod(float64(c), qOf)
				}
				return math.Min(0.98, math.Max(0.02, x))
			})
			prior := ixMkMust(NewWalletPopulationPrior(rel, ixF(a[3])))
			return ixMkMust(WalletPriorAdmittedPpm(omega, ixM(a[1]), ixWlObs(ixL(a[2]), "elicitation"), prior))
		}),
	})
}

func TestWalletLearnerJavaReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-wallet-learner-java.json.gz", map[string]vecFn{
		"view": ixWrap(func(a []any) any {
			l := ixMkMust(NewIntentLearner(ixM(a[0]), nil, nil))
			for _, xv := range ixL(a[1]) {
				x := ixM(xv)
				l.observe(map[string]any{"verb": x["verb"], "values": x["values"]}, ixF(x["y"]), "elicitation", nil)
			}
			var inside func(string, []int) bool
			if a[2] != nil {
				k := ixF(a[2])
				inside = func(_ string, idx []int) bool { return float64(idx[0]) <= k }
			}
			v := NewIntentLearnerView(l, inside)
			cells := []any{}
			for _, vv := range ixL(ixM(a[0])["verbs"]) {
				vs := ixM(vv)
				verb := ixS(vs["verb"])
				for f := 0; f < int(ixVerbCellCount(vs)); f++ {
					idx := ixDecodeCell(vs, float64(f))
					ii := ixWlIdx(idx)
					cells = append(cells, []any{verb, idx, ixMkMust(v.P(verb, ii)), ixMkMust(v.Vetoed(verb, ii)), v.OutsideCeiling(verb, ii)})
				}
			}
			return map[string]any{"cells": cells, "confirmed": v.Confirmed()}
		}),
		"probe": ixWrap(func(a []any) any {
			l := ixMkMust(NewIntentLearner(ixM(a[0]), nil, nil))
			return ixMkMust(NewIntentLearnerView(l, nil).P(ixS(a[1]), []int{0, 0}))
		}),
		"ppm": ixWrap(func(a []any) any {
			prior := ixMkMust(NewWalletPopulationPrior(ixM(a[3]), ixF(a[4])))
			return ixMkMust(WalletPriorAdmittedPpm(ixM(a[0]), ixM(a[1]), ixWlObs(ixL(a[2]), "elicitation"), prior))
		}),
	})
}
