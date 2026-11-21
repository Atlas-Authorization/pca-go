package pca

// Replays the multi-principal aggregation corpus: aggregate and verify (clean, tampered, wrong inputs), cross-organisation
// aggregation, lifting onto a refinement, and the omega key.

import (
	"regexp"
	"testing"
)

var (
	ixMaReplayRe = regexp.MustCompile(`replay failed: [^;]*`)
	ixMaRecomp   = regexp.MustCompile(`(?s)^recompute failed: (.*)$`)
	ixMaRefMsg   = regexp.MustCompile(`^(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)`)
	ixMaKnown    = regexp.MustCompile(`^(input |aggregate does not|recompute failed)`)
)

func ixMaNorm(r map[string]any) map[string]any {
	ps := []any{}
	for _, pv := range ixL(r["problems"]) {
		q := ixMaReplayRe.ReplaceAllString(ixS(pv), "replay failed")
		if m := ixMaRecomp.FindStringSubmatch(q); m != nil {
			if !ixMaRefMsg.MatchString(m[1]) {
				q = "recompute failed: error"
			}
		} else if !ixMaKnown.MatchString(q) && !regexp.MustCompile(`^replay failed`).MatchString(q) {
			if !ixMaRefMsg.MatchString(q) {
				q = "error"
			}
		}
		ps = append(ps, q)
	}
	return map[string]any{"ok": r["ok"], "problems": ps}
}

func ixMaBuild(omega, opts map[string]any, observations []any, ref any) map[string]any {
	l := ixMkMust(IntentCreateLearner(omega, opts))
	for _, xv := range observations {
		x := ixM(xv)
		l.observe(map[string]any{"verb": x["verb"], "values": x["values"]}, ixF(x["y"]), ixS(x["source"]), ixM(x["region"]))
	}
	return ixMkMust(IntentEmitMap(l, ref))
}

func ixMaMutate(i int, m map[string]any) {
	switch i {
	case 1:
		mm := ixM(m["metrics"])
		mm["residual_risk_ppm"] = ixF(mm["residual_risk_ppm"]) + 7
	case 2:
		c := ixM(ixL(m["cells"])[0])
		c["in_grant"] = !(c["in_grant"] == true)
	case 3:
		m["aggregation"] = nil
	case 4:
		a := ixM(m["aggregation"])
		a["rule"], a["k"] = "quorum", 1.0
	case 5:
		ixM(m["aggregation"])["vetoers"] = []any{}
	}
}

func ixMaAnyList(maps []map[string]any) []any {
	out := make([]any, len(maps))
	for i, m := range maps {
		out[i] = m
	}
	return out
}

func TestIntentMultiAggReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-multi-agg.json.gz", map[string]vecFn{
		"aggregateScenario": ixWrap(func(a []any) any {
			orgs := ixM(ixM(a[3])["orgs"]) // the oracle hands its orgs map to the reference as the options object: `opts.orgs` is absent there
			var maps []map[string]any
			for _, pv := range ixL(a[1]) {
				p := ixM(pv)
				maps = append(maps, ixMaBuild(ixM(a[0]), ixM(a[4]), ixL(p["observations"]), p["ref"]))
			}
			all := ixMaAnyList(maps)
			rule := ixM(a[2])
			agg := ixMkMust(IntentAggregateMaps(all, rule, orgs))
			tampered := []any{}
			for i := 0; i < 6; i++ {
				c := ixM(ixClone(agg))
				ixMaMutate(i, c)
				tampered = append(tampered, ixMaNorm(IntentVerifyAggregate(c, all, orgs)))
			}
			var combined any
			if rule["kind"] == "unanimity" && rule["vetoers"] == nil {
				combined = ixMkMust(IntentCombineMaps(all, orgs))
			}
			wrong := all
			if len(wrong) > 0 {
				wrong = wrong[:len(wrong)-1]
			}
			return map[string]any{"aggregate": agg, "digest": ixMkMust(IntentMapDigest(agg)), "rule": ixMkMust(IntentRuleOf(agg)),
				"verify": ixMaNorm(IntentVerifyAggregate(agg, all, orgs)), "tampered": tampered,
				"wrongInputs": ixMaNorm(IntentVerifyAggregate(agg, wrong, orgs)), "combined": combined}
		}),
		"aggregateTwoOmegas": ixWrap(func(a []any) any {
			ps := ixL(a[2])
			m0 := ixMaBuild(ixM(a[0]), nil, ixL(ixM(ps[0])["observations"]), ixM(ps[0])["ref"])
			m1 := ixMaBuild(ixM(a[1]), nil, nil, ixM(ps[1])["ref"])
			return ixMkMust(IntentAggregateMaps([]any{m0, m1}, ixM(a[3]), nil))
		}),
		"aggregateOfAggregate": ixWrap(func(a []any) any {
			var maps []any
			for _, pv := range ixL(a[1]) {
				p := ixM(pv)
				maps = append(maps, ixMaBuild(ixM(a[0]), nil, ixL(p["observations"]), p["ref"]))
			}
			agg := ixMkMust(IntentAggregateMaps(maps, ixM(a[2]), nil))
			return ixMkMust(IntentAggregateMaps([]any{agg, maps[0]}, ixM(a[2]), nil))
		}),
		"liftOfAggregate": ixWrap(func(a []any) any {
			p := ixM(ixL(a[1])[0])
			agg := ixMkMust(IntentAggregateMaps([]any{ixMaBuild(ixM(a[0]), nil, ixL(p["observations"]), p["ref"])}, ixM(a[2]), nil))
			return ixMkMust(IntentLiftMap(agg, ixM(a[0])))
		}),
		"crossScenario": ixWrap(func(a []any) any {
			var maps []any
			for _, sv := range ixL(a[0]) {
				s := ixM(sv)
				maps = append(maps, ixMaBuild(ixM(s["omega"]), ixM(s["mapOpts"]), ixL(s["observations"]), s["ref"]))
			}
			if len(a) == 2 {
				ixM(ixM(maps[0])["metrics"])["residual_risk_ppm"] = ixF(ixM(ixM(maps[0])["metrics"])["residual_risk_ppm"]) + 9
				return ixMkMust(IntentCrossOrgAggregate(maps, a[1], nil))
			}
			orgs := ixM(ixM(a[2])["orgs"]) // as above
			r := ixMkMust(IntentCrossOrgAggregate(maps, a[1], orgs))
			agg := ixM(r["aggregate"])
			tampered := []any{}
			for i := 0; i < 6; i++ {
				c := ixM(ixClone(agg))
				ixMaMutate(i, c)
				tampered = append(tampered, ixMaNorm(IntentVerifyCrossOrgAggregate(c, maps, orgs)))
			}
			wrong := maps
			if len(wrong) > 0 {
				wrong = wrong[1:]
			}
			return map[string]any{"aggregate": agg, "lifted": r["lifted"], "omega": r["omega"], "digest": ixMkMust(IntentMapDigest(agg)),
				"verify": ixMaNorm(IntentVerifyCrossOrgAggregate(agg, maps, orgs)), "tampered": tampered,
				"wrong": ixMaNorm(IntentVerifyCrossOrgAggregate(agg, wrong, orgs))}
		}),
		"liftScenario": ixWrap(func(a []any) any {
			return ixMkMust(IntentLiftMap(ixMaBuild(ixM(a[0]), ixM(a[1]), ixL(a[2]), a[3]), ixM(a[4])))
		}),
		"omegaKey": ixWrap(func(a []any) any { return ixMkMust(IntentOmegaKey(ixM(a[0]))) }),
	})
}
