package pca

// Specification by example for a fixed grant: boundary, verb and unconstrained witness actions to ask the principal about.

import (
	"fmt"
)

func ixBoundaryWitnesses(grant any, omega map[string]any, catalog any) []any {
	g := ixAdmitter(grant)
	out := []any{}
	seen := map[string]bool{}
	push := func(vs map[string]any, kind string, idx []any, allows bool, facet string) {
		key := ixS(vs["verb"]) + "|" + ixCellKeyJoin(idx)
		if seen[key] {
			return
		}
		seen[key] = true
		side := "outside"
		if allows {
			side = "inside"
		}
		out = append(out, map[string]any{"kind": kind, "side": side, "verb": vs["verb"], "cell": idx, "outcome": ixCellRep(vs, idx),
			"grantAllows": allows, "facet": facet, "question": ixRenderQuestion(vs, idx, catalog)})
	}
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		verb := ixS(vs["verb"])
		dims := ixL(vs["dims"])
		n := int(ixVerbCellCount(vs))
		acc := make([]bool, n)
		mass := make([]float64, n)
		typical, typicalOut := -1, -1
		for c := 0; c < n; c++ {
			idx := ixDecodeCell(vs, float64(c))
			acc[c] = g.admits(vs, ixCellRep(vs, idx))
			mass[c], _ = ixCellStats(vs, idx, ixDefaultHarm)
			if acc[c] && (typical < 0 || mass[c] > mass[typical]) {
				typical = c
			}
			if typicalOut < 0 || mass[c] > mass[typicalOut] {
				typicalOut = c
			}
		}
		if typical < 0 {
			push(vs, "verb", ixDecodeCell(vs, float64(typicalOut)), false, verb+"|verb")
			continue
		}
		base := ixDecodeCell(vs, float64(typical))
		push(vs, "verb", base, true, verb+"|verb")
		type bst struct {
			ins, outs []any
			score     float64
		}
		best := map[string]bst{}
		for c := 0; c < n; c++ {
			if !acc[c] {
				continue
			}
			idx := ixDecodeCell(vs, float64(c))
			for k, dv := range dims {
				d := ixM(dv)
				nk := ixCellCount(d)
				ik := ixIdx(idx[k])
				var neigh []int
				if d["kind"] == "num" {
					for _, x := range []int{ik - 1, ik + 1} {
						if x >= 0 && x < nk {
							neigh = append(neigh, x)
						}
					}
				} else {
					for x := 0; x < nk; x++ {
						if x != ik {
							neigh = append(neigh, x)
						}
					}
				}
				for _, x := range neigh {
					j := append([]any{}, idx...)
					j[k] = float64(x)
					if acc[int(ixEncodeCell(vs, j))] {
						continue
					}
					var facet string
					if d["kind"] == "num" {
						lo, hi := x, ik
						if hi < lo {
							lo, hi = hi, lo
						}
						facet = fmt.Sprintf("%s|%s|%d~%d", verb, ixS(d["path"]), lo, hi)
					} else {
						facet = fmt.Sprintf("%s|%s|%d", verb, ixS(d["path"]), x)
					}
					shared := 0
					for t, v := range idx {
						if t != k && v == base[t] {
							shared++
						}
					}
					score := float64(float64(shared)*10) + mass[c]
					if prev, ok := best[facet]; !ok || score > prev.score {
						best[facet] = bst{idx, j, score}
					}
				}
			}
		}
		facets := make([]string, 0, len(best))
		for f := range best {
			facets = append(facets, f)
		}
		for _, facet := range ixSortU16(facets) {
			b := best[facet]
			push(vs, "boundary", b.ins, true, facet)
			push(vs, "boundary", b.outs, false, facet)
		}
		for k, dv := range dims {
			d := ixM(dv)
			nk := ixCellCount(d)
			if nk < 2 {
				continue
			}
			depends := false
			for c := 0; c < n && !depends; c++ {
				idx := ixDecodeCell(vs, float64(c))
				for x := 0; x < nk && !depends; x++ {
					j := append([]any{}, idx...)
					j[k] = float64(x)
					if acc[int(ixEncodeCell(vs, j))] != acc[c] {
						depends = true
					}
				}
			}
			if depends {
				continue
			}
			j := append([]any{}, base...)
			if d["kind"] == "num" {
				j[k] = float64(nk - 1)
			} else {
				o := -1
				for i, v := range ixL(d["values"]) {
					if ixM(v)["kind"] == "other" {
						o = i
						break
					}
				}
				j[k] = float64(o)
			}
			push(vs, "unconstrained", j, true, verb+"|"+ixS(d["path"])+"|unconstrained")
		}
	}
	return out
}

// ixCheckWitnesses asks an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree.
func ixCheckWitnesses(ws []any, oracle func(w map[string]any) bool) map[string]any {
	mismatches := []any{}
	for _, wv := range ws {
		w := ixM(wv)
		if oracle(w) != (w["grantAllows"] == true) {
			mismatches = append(mismatches, wv)
		}
	}
	return map[string]any{"questions": float64(len(ws)), "mismatches": mismatches}
}
