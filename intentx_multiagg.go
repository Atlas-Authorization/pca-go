package pca

// Multi-principal aggregation over Intent Maps: the joint grant under a unanimity / quorum / weighted rule (every number
// recomputable from the inputs), lifting a map onto a common refinement, and cross-organisation aggregation. The rule and
// refinement primitives are in intentx_multi.go.

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// ixMaStringify is a deterministic JSON text of a tree (sorted keys), used to compare two omegas.
func ixMaStringify(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ixOut(ixNums(v))); err != nil {
		ixFail("pca-intent: not JSON: %v", err)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func ixMaMaps(maps []any) []map[string]any {
	out := make([]map[string]any, len(maps))
	for i, m := range maps {
		out[i] = ixM(m)
	}
	return out
}

func ixMaMetric(m map[string]any, k string) float64 {
	if v := ixM(m["metrics"])[k]; v != nil {
		return ixF(v)
	}
	return 0
}

// IntentAggregateMaps aggregates single-principal maps over a SHARED omega under a rule; the result has `aggregation` set.
func IntentAggregateMaps(maps []any, rule any, orgs map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixMaAggregate(ixMaMaps(maps), rule, orgs) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMaAggregate(maps []map[string]any, rule any, orgs map[string]any) map[string]any {
	if len(maps) == 0 {
		ixFail("aggregateIntentMaps: no maps")
	}
	om := ixMaStringify(maps[0]["omega"])
	for _, m := range maps {
		if ixMaStringify(m["omega"]) != om {
			ixFail("aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)")
		}
	}
	for _, m := range maps {
		if m["aggregation"] != nil || len(ixL(ixMkReq(m, "principals"))) != 1 || !ixIsStr(m["intent_ref"]) {
			ixFail("aggregateIntentMaps: every input must be a single-principal map with an intent_ref")
		}
	}
	refs := make([]string, len(maps))
	seen := map[string]bool{}
	for i, m := range maps {
		refs[i] = ixS(m["intent_ref"])
		seen[refs[i]] = true
	}
	if len(seen) != len(refs) {
		ixFail("aggregateIntentMaps: duplicate principal")
	}
	n := ixNormalizeRule(rule, refs)
	omega := ixMkOmegaFromJSON(ixM(maps[0]["omega"]))
	var stats []struct{ mass, harm float64 }
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		for c := 0; c < int(ixVerbCellCount(vs)); c++ {
			mass, harm := ixCellStats(vs, ixDecodeCell(vs, float64(c)), ixDefaultHarm)
			stats = append(stats, struct{ mass, harm float64 }{mass, harm})
		}
	}
	cells := []any{}
	for i, cv := range ixL(maps[0]["cells"]) {
		c := ixM(cv)
		ps := make([]any, len(maps))
		ins := make([]any, len(maps))
		for k, m := range maps {
			mc := ixM(ixL(m["cells"])[i])
			ps[k] = ixF(mc["p_ppm"]) / ixPPM
			ins[k] = mc["in_grant"]
		}
		cells = append(cells, map[string]any{"verb": c["verb"], "cell": c["cell"], "p_ppm": ixMkPpm(ixJointAcceptance(n, ps)),
			"in_grant": ixRuleAdmits(n, ins)})
	}
	predicates := []any{}
	worst := -1
	off := 0
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		nc := int(ixVerbCellCount(vs))
		allowed := make([]byte, nc)
		anyIn := false
		for c := 0; c < nc; c++ {
			if ixM(cells[off+c])["in_grant"] == true {
				allowed[c] = 1
				anyIn = true
			}
		}
		off += nc
		if !anyIn {
			continue
		}
		for i, r := range ixLrOrder {
			if vs["reversibility"] == r && i > worst {
				worst = i
			}
		}
		predicates = append(predicates, IntentBoxesToPredicates(vs, allowed)...)
	}
	caveats := []any{}
	if worst >= 0 {
		caveats = append(caveats, map[string]any{"type": "reversibility_max", "class": ixLrOrder[worst]})
	}
	grant := map[string]any{"predicates": predicates, "caveats": caveats}
	type perT struct {
		ref     string
		org     any
		R, B, F float64
	}
	var per []perT
	for i, m := range maps {
		R, B, Rmax := 0.0, 0.0, 0.0
		for j, cv := range ixL(m["cells"]) {
			p := ixF(ixM(cv)["p_ppm"]) / ixPPM
			mass, harm := stats[j].mass, stats[j].harm
			Rmax += float64(mass * (1 - p) * harm)
			if ixM(cells[j])["in_grant"] == true {
				R += float64(mass * (1 - p) * harm)
			} else {
				B += float64(mass * p)
			}
		}
		e := perT{ref: refs[i], R: R, B: B, F: 1}
		if Rmax > 0 {
			e.F = 1 - R/Rmax
		}
		if o := orgs[refs[i]]; ixTruthy(o) {
			e.org = o
		}
		per = append(per, e)
	}
	kind := ixMember(rule, "kind")
	aggregation := map[string]any{"rule": kind}
	if kind == "quorum" {
		aggregation["k"] = ixMember(rule, "k")
	}
	if kind == "weighted" {
		weights := map[string]any{}
		for i, r := range refs {
			weights[r] = ixL(n["weights"])[i]
		}
		aggregation["weights"] = weights
		aggregation["threshold"] = ixMember(rule, "threshold")
	}
	vetoers := []any{}
	for i, r := range refs {
		if ixL(n["veto"])[i] == true {
			vetoers = append(vetoers, r)
		}
	}
	aggregation["vetoers"] = vetoers
	pp := []any{}
	maxRisk, maxBurden, minF := 0.0, 0.0, 0.0
	for i, x := range per {
		e := map[string]any{"intent_ref": x.ref}
		if x.org != nil {
			e["org"] = x.org
		}
		rr, bb := ixMkPpm(x.R), ixMkPpm(x.B)
		e["residual_risk_ppm"], e["burden_ppm"] = rr, bb
		pp = append(pp, e)
		if i == 0 || rr > maxRisk {
			maxRisk = rr
		}
		if i == 0 || bb > maxBurden {
			maxBurden = bb
		}
		if i == 0 || x.F < minF {
			minF = x.F
		}
	}
	aggregation["per_principal"] = pp
	worstMetric := func(k string, sum bool) float64 {
		acc := 0.0
		for i, m := range maps {
			v := ixMaMetric(m, k)
			switch {
			case sum:
				acc += v
			case i == 0 || v > acc:
				acc = v
			}
		}
		return acc
	}
	var log2vs any
	noneNil := true
	for _, m := range maps {
		if ixM(m["metrics"])["log2_vs_mbits"] == nil {
			noneNil = false
		}
	}
	if noneNil {
		log2vs = worstMetric("log2_vs_mbits", true)
	}
	observations := []any{}
	for _, m := range maps {
		observations = append(observations, ixL(m["observations"])...)
	}
	return map[string]any{
		"v": 1.0, "kind": "pca-intent-map", "intent_ref": nil, "principals": ixToAny(refs), "omega": maps[0]["omega"], "learner": maps[0]["learner"],
		"observations": observations, "cells": cells, "grant": grant, "grant_digest": ixMkGrantDigest(grant),
		"metrics": map[string]any{
			"residual_risk_ppm": maxRisk, "burden_ppm": maxBurden,
			"uncertainty_ppm": worstMetric("uncertainty_ppm", false), "disagreement_ppm": worstMetric("disagreement_ppm", false),
			"mean_harm_ppm": ixF(ixMkReq(ixM(maps[0]["metrics"]), "mean_harm_ppm")), "fidelity_est_ppm": ixMkPpm(minF),
			"entropy_mbits": worstMetric("entropy_mbits", true), "log2_vs_mbits": log2vs,
			"questions": worstMetric("questions", true), "conflicts": worstMetric("conflicts", true),
		},
		"aggregation": aggregation,
	}
}

// IntentCombineMaps is the unanimity rule: the joint grant is the intersection of the principals' conservative grants.
func IntentCombineMaps(maps []any, orgs map[string]any) (map[string]any, error) {
	return IntentAggregateMaps(maps, map[string]any{"kind": "unanimity"}, orgs)
}

// IntentRuleOf is the rule an aggregated map records.
func IntentRuleOf(agg map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixMaRuleOf(agg) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMaRuleOf(agg map[string]any) map[string]any {
	a := ixM(agg["aggregation"])
	if len(a) == 0 {
		ixFail("ruleOf: not an aggregated map")
	}
	vetoers := ixMkReq(a, "vetoers")
	switch ixMkReq(a, "rule") {
	case "unanimity":
		return map[string]any{"kind": "unanimity", "vetoers": vetoers}
	case "quorum":
		return map[string]any{"kind": "quorum", "k": a["k"], "vetoers": vetoers}
	}
	return map[string]any{"kind": "weighted", "weights": a["weights"], "threshold": a["threshold"], "vetoers": vetoers}
}

// IntentVerifyAggregate replay-verifies every input map, then recomputes the aggregate and compares digests.
func IntentVerifyAggregate(agg map[string]any, inputs []any, orgs map[string]any) map[string]any {
	problems := []any{}
	_, err := ixTry(func() any {
		for i, m := range inputs {
			r := IntentVerifyMap(m)
			if r["ok"] != true {
				var ps []string
				for _, p := range ixL(r["problems"]) {
					ps = append(ps, ixS(p))
				}
				problems = append(problems, "input "+jsNumberString(float64(i))+": "+strings.Join(ps, "; "))
			}
		}
		if len(problems) > 0 {
			return nil
		}
		again := ixMaAggregate(ixMaMaps(inputs), ixMaRuleOf(agg), orgs)
		if ixHashCanon(map[string]any{"d": ixMkMapDomain, "m": again}) != ixHashCanon(map[string]any{"d": ixMkMapDomain, "m": agg}) {
			problems = append(problems, "aggregate does not match its recomputation")
		}
		return nil
	})
	if err != nil {
		problems = append(problems, "recompute failed: "+err.Error())
	}
	return map[string]any{"ok": len(problems) == 0, "problems": problems}
}

// IntentLiftMap re-expresses a single-principal map on a refinement of its omega: observations re-applied as value-space regions
// and prior mass 1 on the empty hypothesis for every verb the map did not cover.
func IntentLiftMap(m, target map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixMaLift(m, target) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMaFindVerb(omega map[string]any, verb any) map[string]any {
	for _, v := range ixL(omega["verbs"]) {
		if ixM(v)["verb"] == verb {
			return ixM(v)
		}
	}
	return nil
}

func ixMaLift(m, target map[string]any) map[string]any {
	if m["aggregation"] != nil || len(ixL(ixMkReq(m, "principals"))) > 1 {
		ixFail("liftIntentMap: lift single-principal maps, then aggregate")
	}
	src := ixMkOmegaFromJSON(ixM(ixMkReq(m, "omega")))
	o := ixMkMapLearnerOptions(m)
	srcMass, _ := o["nullMass"].(map[string]any)
	nullMass := map[string]any{}
	for _, vv := range ixL(target["verbs"]) {
		vs := ixM(vv)
		verb := ixS(vs["verb"])
		if ixMaFindVerb(src, vs["verb"]) != nil {
			if own := srcMass[verb]; own != nil {
				nullMass[verb] = own
			} else {
				nullMass[verb] = 0.2
			}
		} else {
			nullMass[verb] = 1.0
		}
	}
	opts := ixCopyMap(o)
	opts["nullMass"] = nullMass
	l := ixMkCreateLearner(target, opts)
	for _, ov := range ixL(ixMkReq(m, "observations")) {
		ob := ixM(ov)
		svs, tvs := ixMaFindVerb(src, ob["verb"]), ixMaFindVerb(target, ob["verb"])
		if svs == nil || tvs == nil {
			ixFail("liftIntentMap: verb %s missing from Ω", jsValueString(ob["verb"]))
		}
		values := ixCopyMap(ixM(ob["values"]))
		for _, dv := range ixL(tvs["dims"]) {
			d := ixM(dv)
			if _, ok := values[ixS(d["path"])]; !ok {
				values[ixS(d["path"])] = ixRepValue(d, 0)
			}
		}
		ownCell := ixCellOf(svs, map[string]any{"verb": ob["verb"], "values": ob["values"]})
		if ownCell == nil {
			ixFail("liftIntentMap: an observation of %s lies outside the map's own Ω", jsValueString(ob["verb"]))
		}
		region := ixM(ob["region"])
		if region == nil {
			region = ixRegionOfCell(svs, ownCell)
		}
		l.observe(map[string]any{"verb": ob["verb"], "values": values}, ixF(ob["y"]), ixS(ob["source"]), region)
	}
	return ixMkEmit(l, m["intent_ref"])
}

// IntentCrossOrgAggregate replay-verifies every map, lifts all of them onto the common refinement of their omegas, then aggregates:
// {aggregate, lifted, omega}.
func IntentCrossOrgAggregate(maps []any, rule any, orgs map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixMaCross(maps, rule, orgs) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMaCross(maps []any, rule any, orgs map[string]any) map[string]any {
	for i, m := range maps {
		r := IntentVerifyMap(m)
		if r["ok"] != true {
			var ps []string
			for _, p := range ixL(r["problems"]) {
				ps = append(ps, ixS(p))
			}
			ixFail("crossOrgAggregate: map %d does not verify: %s", i, strings.Join(ps, "; "))
		}
	}
	omegas := make([]any, len(maps))
	for i, m := range maps {
		omegas[i] = ixMkOmegaFromJSON(ixM(ixMkReq(ixM(m), "omega")))
	}
	omega := ixCommonRefinement(omegas)
	lifted := make([]any, len(maps))
	liftedM := make([]map[string]any, len(maps))
	for i, m := range maps {
		liftedM[i] = ixMaLift(ixM(m), omega)
		lifted[i] = liftedM[i]
	}
	return map[string]any{"aggregate": ixMaAggregate(liftedM, rule, orgs), "lifted": lifted, "omega": omega}
}

// IntentVerifyCrossOrgAggregate verifies a cross-org aggregate by recomputing it from the ORIGINAL maps.
func IntentVerifyCrossOrgAggregate(agg map[string]any, maps []any, orgs map[string]any) map[string]any {
	r, err := ixTry(func() any {
		rule := ixMaRuleOf(agg)
		again := ixM(ixMaCross(maps, rule, orgs)["aggregate"])
		if ixHashCanon(map[string]any{"d": ixMkMapDomain, "m": again}) == ixHashCanon(map[string]any{"d": ixMkMapDomain, "m": agg}) {
			return map[string]any{"ok": true, "problems": []any{}}
		}
		return map[string]any{"ok": false, "problems": []any{"aggregate does not match its recomputation"}}
	})
	if err != nil {
		return map[string]any{"ok": false, "problems": []any{err.Error()}}
	}
	return r.(map[string]any)
}

// IntentOmegaKey is the omega of an aggregated or single map as JSON (a comparison key; sorted members).
func IntentOmegaKey(o map[string]any) (string, error) {
	r, err := ixTry(func() any { return ixMaOrdered(ixMkOmegaToJSON(o)) })
	if err != nil {
		return "", err
	}
	return r.(string), nil
}

var ixMaKeyOrder = map[string]int{"verbs": 0, "approximate": 1, "verb": 2, "reversibility": 3, "w": 4, "dims": 5, "kind": 6, "path": 7, "lo": 8,
	"hi": 9, "cuts": 10, "dist": 11, "values": 12, "value": 13}

// ixMaOrdered is JSON.stringify of an omega wire form: members in the order the reference builds them.
func ixMaOrdered(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, aok := ixMaKeyOrder[keys[i]]
			b, bok := ixMaKeyOrder[keys[j]]
			switch {
			case aok && bok:
				return a < b
			case aok != bok:
				return aok
			}
			return keys[i] < keys[j]
		})
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = ixMaStringify(k) + ":" + ixMaOrdered(t[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = ixMaOrdered(x)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	return ixMaStringify(v)
}
