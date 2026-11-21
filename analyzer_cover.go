package pca

// Policy coverage: which clauses decided, which never matched, how close traffic came to each threshold, and which single-edit mutants
// the traffic cannot tell from the policy.

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
)

var anlFlipOp = map[string]string{"lt": "lte", "lte": "lt", "gt": "gte", "gte": "gt", "eq": "ne", "ne": "eq", "in": "nin", "nin": "in"}

type anlVariant struct {
	cond any
	what string
}

func anlVariantsOfCond(c any, eps float64) []anlVariant {
	m, ok := c.(map[string]any)
	if !ok {
		if _, isList := c.([]any); !isList {
			return nil
		}
		return nil // a list is neither a group nor a leaf
	}
	var out []anlVariant
	if anlIsGroup(m) {
		if n, has := m["not"]; has {
			for _, v := range anlVariantsOfCond(n, eps) {
				out = append(out, anlVariant{map[string]any{"not": v.cond}, fmt.Sprintf("not(%s)", v.what)})
			}
			return out
		}
		key := "any_of"
		var kidsV any = anlUndef
		if anlHas(m, "all_of") {
			key = "all_of"
			kidsV = m["all_of"]
		} else if anlHas(m, "any_of") {
			kidsV = m["any_of"]
		}
		kids := anlReqList(kidsV)
		for i, k := range kids {
			for _, v := range anlVariantsOfCond(k, eps) {
				nxt := make([]any, len(kids))
				copy(nxt, kids)
				nxt[i] = v.cond
				out = append(out, anlVariant{map[string]any{key: nxt}, fmt.Sprintf("%s[%d] %s", key, i, v.what)})
			}
		}
		return out
	}
	leaf, ok := anlLeaf(m)
	if !ok || anlHas(leaf, "ref") {
		return nil
	}
	name := strings.TrimPrefix(leaf["field"].(string), "action.params.")
	val, op := anlOwn(leaf, "value"), anlOwn(leaf, "op")
	if anlIsFin(val) && (op == "lt" || op == "lte" || op == "gt" || op == "gte" || op == "eq") {
		vf := anlToNumber(val)
		up, dn := vf+eps, vf-eps
		for _, nv := range []float64{up, dn} {
			c2 := anlCopy(leaf)
			c2["value"] = nv
			out = append(out, anlVariant{c2, fmt.Sprintf("%s %s %s -> %s", name, op, anlNumStr(vf), anlNumStr(nv))})
		}
	}
	if s, ok := op.(string); ok {
		if f, has := anlFlipOp[s]; has {
			c2 := anlCopy(leaf)
			c2["op"] = f
			out = append(out, anlVariant{c2, fmt.Sprintf("%s %s -> %s", name, s, f)})
		}
	}
	return out
}

type anlMutant struct {
	id, description string
	policy          map[string]any
}

func anlMutantsOf(policy map[string]any, eps float64) []anlMutant {
	var out []anlMutant
	mk := func(over map[string]any) map[string]any {
		p := map[string]any{"predicates": policy["predicates"], "caveats": policy["caveats"], "vetoes": policy["vetoes"], "tighten": policy["tighten"]}
		for k, v := range over {
			p[k] = v
		}
		return p
	}
	without := func(xs []any, i int) []any {
		r := make([]any, 0, len(xs))
		for j, x := range xs {
			if j != i {
				r = append(r, x)
			}
		}
		return r
	}
	replace := func(xs []any, i int, v any) []any {
		r := append([]any{}, xs...)
		r[i] = v
		return r
	}
	preds := policy["predicates"].([]any)
	for i, p := range preds {
		out = append(out, anlMutant{"drop-" + anlPermitID(i), "drop " + anlPermitID(i), mk(map[string]any{"predicates": without(preds, i)})})
		where := anlReqList(anlNN(anlGet(p, "where"), []any{}))
		for j, c := range where {
			for _, v := range anlVariantsOfCond(c, eps) {
				np := anlSpread(p)
				np["where"] = replace(where, j, v.cond)
				out = append(out, anlMutant{fmt.Sprintf("%s.where[%d]:%s", anlPermitID(i), j, v.what), anlPermitID(i) + ": " + v.what, mk(map[string]any{"predicates": replace(preds, i, np)})})
			}
			np := anlSpread(p)
			np["where"] = without(where, j)
			out = append(out, anlMutant{fmt.Sprintf("%s.where[%d]:drop", anlPermitID(i), j), fmt.Sprintf("%s: drop condition %d", anlPermitID(i), j), mk(map[string]any{"predicates": replace(preds, i, np)})})
		}
	}
	vetoes := policy["vetoes"].([]any)
	for i, v := range vetoes {
		vid := anlJS(anlGet(v, "id"))
		out = append(out, anlMutant{"drop-veto:" + vid, "drop prohibition " + vid, mk(map[string]any{"vetoes": without(vetoes, i)})})
		if over := anlGet(v, "over"); anlTruthy(over) {
			no := anlSpread(over)
			no["threshold"] = anlToNumber(anlGet(over, "threshold")) + eps
			nv := anlSpread(v)
			nv["over"] = no
			out = append(out, anlMutant{"veto:" + vid + ":threshold+", fmt.Sprintf("raise the %s threshold by %s", vid, anlNumStr(eps)), mk(map[string]any{"vetoes": replace(vetoes, i, nv)})})
		}
	}
	tighten := policy["tighten"].([]any)
	for i, t := range tighten {
		tid := anlJS(anlGet(t, "id"))
		out = append(out, anlMutant{"drop-tighten:" + tid, "drop tighten rule " + tid, mk(map[string]any{"tighten": without(tighten, i)})})
	}
	return out
}

// anlReach is true / false / "unknown": can any action reach the clause?
func anlReach(model map[string]any, kind string, idx int) any {
	var r map[string]any
	switch kind {
	case "permit":
		r = anlAlwaysDenies(map[string]any{"predicates": []any{model["predicates"].([]any)[idx]}, "caveats": model["caveats"]}, nil, nil)
	case "veto":
		r = anlAlwaysDenies(map[string]any{"predicates": []any{anlGet(model["vetoes"].([]any)[idx], "when")}}, nil, nil)
	default:
		return "unknown"
	}
	if anlTruthy(r["approximate"]) {
		return "unknown"
	}
	return r["alwaysDenies"] != true
}

func anlCountKey(id any) string { return anlJSON(id) }

// anlCoverage is the coverage of `policy` by `traffic` (actions): clauses, boundaries, mutants and the 0..1 scores.
func anlCoverage(policy, trafficIn, optsIn any) map[string]any {
	o := optsIn
	if o == nil || anlIsUndef(o) {
		o = map[string]any{}
	}
	traffic := anlReqList(trafficIn)
	model := anlToModel(policy)
	eps := anlToNumber(anlNN(anlGet(o, "epsilon"), 1))
	type clauseID struct {
		id   any
		kind string
	}
	var ids []clauseID
	preds, vetoes, tighten := model["predicates"].([]any), model["vetoes"].([]any), model["tighten"].([]any)
	for i := range preds {
		ids = append(ids, clauseID{anlPermitID(i), "permit"})
	}
	for _, v := range vetoes {
		ids = append(ids, clauseID{anlID(anlGet(v, "id")), "veto"})
	}
	for _, t := range tighten {
		ids = append(ids, clauseID{anlID(anlGet(t, "id")), "tighten"})
	}
	matched, decisive := map[string]int{}, map[string]int{}
	bump := func(m map[string]int, k any) {
		if k != nil {
			m[anlCountKey(k)]++
		}
	}
	for _, a := range traffic {
		w := anlWitnessOf(model, a)
		win := w["winner"].(map[string]any)["id"]
		bump(decisive, win)
		bump(matched, win)
		for _, i := range w["also"].([]any) {
			bump(matched, i)
		}
	}
	np, nv := len(preds), len(vetoes)
	clauses := []any{}
	type cl struct {
		id             any
		matched, decis int
		reachable      any
	}
	var cls []cl
	for n, c := range ids {
		idx := n
		if c.kind == "veto" {
			idx = n - np
		} else if c.kind == "tighten" {
			idx = n - np - nv
		}
		x := cl{c.id, 0, 0, anlReach(model, c.kind, idx)}
		if c.id != nil {
			x.matched, x.decis = matched[anlCountKey(c.id)], decisive[anlCountKey(c.id)]
		}
		cls = append(cls, x)
		clauses = append(clauses, map[string]any{"id": c.id, "kind": c.kind, "matched": x.matched, "decisive": x.decis, "reachable": x.reachable})
	}
	pathSet := &anlSet{}
	var walk func(c any)
	walk = func(c any) {
		m, ok := c.(map[string]any)
		if !ok {
			return
		}
		if anlIsGroup(m) {
			if anlHas(m, "all_of") {
				for _, x := range anlReqList(m["all_of"]) {
					walk(x)
				}
			} else if anlHas(m, "any_of") {
				for _, x := range anlReqList(m["any_of"]) {
					walk(x)
				}
			} else {
				walk(m["not"])
			}
			return
		}
		if leaf, ok := anlLeaf(m); ok && strings.HasPrefix(leaf["field"].(string), "action.params.") {
			switch anlOwn(leaf, "op") {
			case "lt", "lte", "gt", "gte", "eq", "in", "nin":
				pathSet.add(leaf["field"].(string))
			}
		}
	}
	for _, p := range anlProbeSet(model) {
		for _, c := range anlReqList(anlNN(anlGet(p, "where"), []any{})) {
			walk(c)
		}
	}
	for _, v := range vetoes {
		if over := anlGet(v, "over"); anlTruthy(over) {
			pathSet.add(anlStr(anlGet(over, "path"), "path"))
		}
	}
	paths := append([]string{}, pathSet.keys...)
	sort.SliceStable(paths, func(i, j int) bool { return anlUnitLess(paths[i], paths[j]) })
	boundaries := []any{}
	for _, path := range paths {
		r := []rune(path)
		name := ""
		if len(r) > 14 {
			name = string(r[14:])
		}
		var vals []float64
		for _, a := range traffic {
			if x := anlOwn(anlNN(anlGet(a, "params"), map[string]any{}), name); anlIsNum(x) {
				vals = append(vals, anlToNumber(x))
			}
		}
		for _, t := range anlThresholdsOf(model, path) {
			tf := anlToNumber(t)
			at, below, above := false, false, false
			for _, v := range vals {
				at = at || v == tf
				below = below || (v < tf && v >= tf-eps)
				above = above || (v > tf && v <= tf+eps)
			}
			boundaries = append(boundaries, map[string]any{"path": path, "threshold": t, "at": at, "below": below, "above": above})
		}
	}
	survivors := []any{}
	killed, equiv := 0, 0
	mm := anlToNumber(anlNN(anlGet(o, "maxMutants"), 200))
	var allm []anlMutant
	if !math.IsNaN(mm) {
		all := anlMutantsOf(model, eps)
		end := int(math.Max(math.Min(mm, 1<<30), -(1 << 30)))
		if end < 0 {
			end = len(all) + end
			if end < 0 {
				end = 0
			}
		}
		if end > len(all) {
			end = len(all)
		}
		allm = all[:end]
	}
	base := make([]string, len(traffic))
	for i, a := range traffic {
		base[i] = anlDecideAction(model, a)
	}
	for _, m := range allm {
		mmod := anlToModel(m.policy)
		diff := false
		for i, a := range traffic {
			if anlDecideAction(mmod, a) != base[i] {
				diff = true
				break
			}
		}
		if diff {
			killed++
			continue
		}
		eq := anlEquivalent(policy, m.policy, nil)
		if eq["equivalent"] == true {
			equiv++
			continue
		}
		s := map[string]any{"id": m.id, "description": m.description}
		if ce, has := eq["counterexample"]; has && anlTruthy(ce) {
			s["killer"] = ce
		}
		survivors = append(survivors, s)
	}
	ratio := func(n, d int) float64 {
		if d == 0 {
			return 1
		}
		return float64(n) / float64(d)
	}
	var live, liveDecisive int
	var neverMatched, neverDecisive, untested, unreachable []any
	for _, c := range cls {
		if c.reachable != false {
			live++
			if c.decis > 0 {
				liveDecisive++
			}
		}
		if c.matched == 0 {
			neverMatched = append(neverMatched, c.id)
			if c.reachable != false {
				untested = append(untested, c.id)
			}
		}
		if c.decis == 0 {
			neverDecisive = append(neverDecisive, c.id)
		}
		if c.reachable == false {
			unreachable = append(unreachable, c.id)
		}
	}
	full := 0
	for _, b := range boundaries {
		bm := b.(map[string]any)
		if bm["at"] == true && bm["below"] == true && bm["above"] == true {
			full++
		}
	}
	nz := func(x []any) []any {
		if x == nil {
			return []any{}
		}
		return x
	}
	return map[string]any{
		"traffic": len(traffic), "policyDigest": anlPolicyDigestOf(model), "clauses": clauses,
		"neverMatched": nz(neverMatched), "neverDecisive": nz(neverDecisive), "untested": nz(untested), "unreachable": nz(unreachable),
		"boundaries": boundaries,
		"mutants":    map[string]any{"total": len(allm), "killed": killed, "equivalent": equiv, "survivors": survivors},
		"score": map[string]any{
			"clauses": ratio(liveDecisive, live), "boundaries": ratio(full, len(boundaries)), "mutation": ratio(killed, len(allm)-equiv),
		},
	}
}

// anlToFixed is `x.toFixed(digits)`: the exact decimal expansion of the double, ties away from zero.
func anlToFixed(x float64, digits int) string {
	if math.IsNaN(x) {
		return "NaN"
	}
	if math.IsInf(x, 0) {
		if x > 0 {
			return "Infinity"
		}
		return "-Infinity"
	}
	r := new(big.Rat).SetFloat64(math.Abs(x))
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	r.Mul(r, new(big.Rat).SetInt(scale))
	r.Add(r, big.NewRat(1, 2))
	n := new(big.Int).Quo(r.Num(), r.Denom())
	s := n.String()
	for len(s) <= digits {
		s = "0" + s
	}
	out := s[:len(s)-digits] + "." + s[len(s)-digits:]
	if digits == 0 {
		out = s
	}
	if x < 0 {
		out = "-" + out
	}
	return out
}

// anlCoverageGate is a CI gate over a coverage report: {ok, reasons}.
func anlCoverageGate(r, minimum any) map[string]any {
	mn := minimum
	if mn == nil || anlIsUndef(mn) {
		mn = map[string]any{}
	}
	reasons := []any{}
	score := anlGet(r, "score")
	for _, k := range [][2]string{{"clauses", "clause coverage"}, {"boundaries", "boundary coverage"}, {"mutation", "mutation score"}} {
		lim := anlGet(mn, k[0])
		sc := anlToNumber(anlGet(score, k[0]))
		if sc < anlToNumber(anlNN(lim, 0)) {
			ls := anlJS(lim)
			if anlIsNum(lim) {
				ls = anlNumStr(anlToNumber(lim))
			}
			reasons = append(reasons, fmt.Sprintf("%s %s < %s", k[1], anlToFixed(sc, 2), ls))
		}
	}
	surv := anlReqList(anlGet(anlGet(r, "mutants"), "survivors"))
	if ms := anlGet(mn, "maxSurvivors"); !anlIsUndef(ms) && float64(len(surv)) > anlToNumber(ms) {
		s := anlJS(ms)
		if anlIsNum(ms) {
			s = anlNumStr(anlToNumber(ms))
		}
		reasons = append(reasons, fmt.Sprintf("%d surviving mutants > %s", len(surv), s))
	}
	if un := anlReqList(anlGet(r, "unreachable")); len(un) > 0 {
		parts := make([]string, len(un))
		for i, x := range un {
			parts[i] = anlJS(x)
		}
		reasons = append(reasons, "unreachable clauses: "+strings.Join(parts, ", "))
	}
	return map[string]any{"ok": len(reasons) == 0, "reasons": reasons}
}
