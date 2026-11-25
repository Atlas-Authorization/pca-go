package pca

// Cut refinement and partial answers: a "partly" answer inserts the stated cuts / values (or adds a whole dimension) to the outcome
// space, re-enumerates the hypotheses and replays every earlier observation as a value-space region. Refinements, partial answers
// and questions are plain JSON trees.

import "sort"

func ixRfHasLen(v any) bool { return len(ixL(v)) > 0 }

func ixRfUniqNums(xs []any) []any {
	out := []any{}
	for _, x := range xs {
		dup := false
		for _, y := range out {
			if ixF(x) == ixF(y) {
				dup = true
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}

func ixRfFilterSort(cuts []any, lo, hi float64) []any {
	out := []any{}
	for _, c := range cuts {
		if f := ixF(c); f >= lo && f <= hi {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return ixF(out[i]) < ixF(out[j]) })
	return out
}

func ixRfSortedCat(values []any) []any {
	var ex, pre []string
	seenEx, seenPre := map[string]bool{}, map[string]bool{}
	for _, vv := range values {
		v := ixM(vv)
		s := ixS(v["value"])
		switch v["kind"] {
		case "exact":
			if !seenEx[s] {
				seenEx[s] = true
				ex = append(ex, s)
			}
		case "prefix":
			if !seenPre[s] {
				seenPre[s] = true
				pre = append(pre, s)
			}
		}
	}
	ixSortU16(ex)
	ixSortU16(pre)
	out := []any{}
	for _, s := range ex {
		out = append(out, map[string]any{"kind": "exact", "value": s})
	}
	for _, s := range pre {
		out = append(out, map[string]any{"kind": "prefix", "value": s})
	}
	return append(out, map[string]any{"kind": "other", "value": mapOther})
}

// IntentRefineOmega is omega with one verb's dimension refined (a deep copy; other verbs and the weights are unchanged).
func IntentRefineOmega(omega, r map[string]any) (map[string]any, error) {
	v, err := ixTry(func() any { return ixRefineOmega(omega, r) })
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func ixRefineOmega(omega, r map[string]any) map[string]any {
	out := ixM(ixClone(omega))
	var vs map[string]any
	for _, v := range ixL(out["verbs"]) {
		if ixM(v)["verb"] == r["verb"] {
			vs = ixM(v)
			break
		}
	}
	if vs == nil {
		ixFail("refineOmega: no verb %s in Ω", jsValueString(r["verb"]))
	}
	dims := ixL(vs["dims"])
	i := -1
	for k, d := range dims {
		if ixM(d)["path"] == r["path"] {
			i = k
			break
		}
	}
	if nd := ixM(r["newDim"]); nd != nil {
		if i >= 0 {
			ixFail("refineOmega: %s is already a dimension of %s", jsValueString(r["path"]), jsValueString(r["verb"]))
		}
		if nd["path"] != r["path"] {
			ixFail("refineOmega: newDim.path must equal path")
		}
		d := ixM(ixClone(nd))
		if d["kind"] == "cat" {
			d["values"] = ixRfSortedCat(ixL(d["values"]))
		} else {
			d["cuts"] = ixRfFilterSort(ixRfUniqNums(ixL(d["cuts"])), ixF(d["lo"]), ixF(d["hi"]))
		}
		dims = append(dims, d)
		sort.SliceStable(dims, func(a, b int) bool {
			return compareUnits(utf16Units(ixS(ixM(dims[a])["path"])), utf16Units(ixS(ixM(dims[b])["path"]))) < 0
		})
		vs["dims"] = dims
		return out
	}
	if i < 0 {
		ixFail("refineOmega: %s has no dimension %s (pass newDim to add it)", jsValueString(r["verb"]), jsValueString(r["path"]))
	}
	d := ixM(dims[i])
	if d["kind"] == "num" {
		if ixRfHasLen(r["values"]) || ixRfHasLen(r["prefixes"]) {
			ixFail("refineOmega: %s is numeric", jsValueString(r["path"]))
		}
		cuts := []any{}
		for _, c := range ixL(r["cuts"]) {
			if ixLrIsInteger(c) {
				cuts = append(cuts, c)
			}
		}
		d["cuts"] = ixRfFilterSort(ixRfUniqNums(append(append([]any{}, ixL(d["cuts"])...), cuts...)), ixF(d["lo"]), ixF(d["hi"]))
	} else {
		if ixRfHasLen(r["cuts"]) {
			ixFail("refineOmega: %s is categorical", jsValueString(r["path"]))
		}
		all := append([]any{}, ixL(d["values"])...)
		for _, v := range ixL(r["values"]) {
			all = append(all, map[string]any{"kind": "exact", "value": v})
		}
		for _, v := range ixL(r["prefixes"]) {
			all = append(all, map[string]any{"kind": "prefix", "value": v})
		}
		d["values"] = ixRfSortedCat(all)
		if len(ixL(d["values"])) > 20 {
			ixFail("refineOmega: %s would have more than 20 values", jsValueString(r["path"]))
		}
	}
	return out
}

// IntentRegionOfObservation is the value-space region an observation was about, in the omega it was recorded in.
func IntentRegionOfObservation(omega, o map[string]any) (map[string]any, error) {
	v, err := ixTry(func() any { return ixRegionOfObservation(omega, o) })
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func ixRegionOfObservation(omega, o map[string]any) map[string]any {
	if r := ixM(o["region"]); len(r) > 0 {
		return r
	}
	vs := ixMaFindVerb(omega, o["verb"])
	if vs == nil {
		ixFail("regionOfObservation: no verb %s", jsValueString(o["verb"]))
	}
	return ixRegionOfCell(vs, ixL(o["cell"]))
}

// IntentRefineLearner rebuilds a learner over a refined omega and replays every observation as a region (rescope may rewrite one).
func IntentRefineLearner(l *IntentLearner, r map[string]any, rescope func(o, region map[string]any) map[string]any) (*IntentLearner, error) {
	v, err := ixTry(func() any { return l.refine(r, rescope) })
	if err != nil {
		return nil, err
	}
	return v.(*IntentLearner), nil
}

func (l *IntentLearner) refine(r map[string]any, rescope func(o, region map[string]any) map[string]any) *IntentLearner {
	omega := ixRefineOmega(l.omega, r)
	nxt := ixMkCreateLearner(omega, ixMkLearnerOptionsOf(l))
	for _, o := range l.observations {
		region := ixRegionOfObservation(l.omega, o)
		if rescope != nil {
			region = rescope(o, region)
		}
		vs := ixMaFindVerb(omega, o["verb"])
		if vs == nil {
			ixFail("no verb space")
		}
		values := ixCopyMap(ixM(o["values"]))
		for _, dv := range ixL(vs["dims"]) {
			d := ixM(dv)
			if _, ok := values[ixS(d["path"])]; !ok {
				values[ixS(d["path"])] = ixRepValue(d, 0)
			}
		}
		nxt.observe(map[string]any{"verb": o["verb"], "values": values}, ixF(o["y"]), ixS(o["source"]), region)
	}
	return nxt
}

// ixRfPartLabel is the label (0 / 1) a partial answer gives cell j of d; ok false when no part covers it.
func ixRfPartLabel(d map[string]any, j int, parts []any) (float64, bool) {
	x := ixRepValue(d, j)
	for _, pv := range parts {
		p := ixM(pv)
		if ixHas(p, "lo") {
			if d["kind"] != "num" {
				continue
			}
			c := ixNumCells(d)[j]
			if c.lo >= ixF(p["lo"]) && c.hi <= ixF(p["hi"]) {
				return ixF(p["y"]), true
			}
		} else if ixHas(p, "values") {
			if d["kind"] == "cat" && ixM(ixL(d["values"])[j])["kind"] == "exact" {
				for _, s := range ixL(p["values"]) {
					if str, ok := x.(string); ok && s == str {
						return ixF(p["y"]), true
					}
				}
			}
		} else if d["kind"] == "cat" && ixM(ixL(d["values"])[j])["kind"] != "exact" {
			return ixF(p["y"]), true
		}
	}
	return 0, false
}

// ixRfSubCells are the sub-cells of dimension d (in the refined omega) that lie inside the questioned region's dimension.
func ixRfSubCells(d, region map[string]any) []int {
	n := ixCellCount(d)
	rd := ixM(ixM(region["dims"])[ixS(d["path"])])
	out := []int{}
	for j := 0; j < n; j++ {
		switch {
		case len(rd) == 0:
			out = append(out, j)
		case d["kind"] == "num" && rd["kind"] == "num":
			c := ixNumCells(d)[j]
			if c.lo >= ixF(rd["lo"]) && c.hi <= ixF(rd["hi"]) {
				out = append(out, j)
			}
		case d["kind"] == "cat" && rd["kind"] == "cat":
			cell := ixCatCellOf(map[string]any{"kind": "cat", "path": d["path"], "values": rd["values"]}, ixS(ixRepValue(d, j)))
			for _, c := range ixL(rd["cells"]) {
				if ixF(c) == float64(cell) {
					out = append(out, j)
					break
				}
			}
		}
	}
	return out
}

// IntentAnswerPartial applies a partial answer to question q: a NEW learner over the refined omega and the observations it added.
func IntentAnswerPartial(l *IntentLearner, q, a map[string]any) (*IntentLearner, []any, error) {
	var nxt *IntentLearner
	var added []any
	_, err := ixTry(func() any { nxt, added = l.answerPartial(q, a); return nil })
	return nxt, added, err
}

func (l *IntentLearner) answerPartial(q, a map[string]any) (*IntentLearner, []any) {
	oldVs := ixMaFindVerb(l.omega, q["verb"])
	if oldVs == nil {
		ixFail("answerPartial: no verb %s", jsValueString(q["verb"]))
	}
	qRegion := ixRegionOfCell(oldVs, ixL(q["cell"]))
	r := map[string]any{"verb": q["verb"], "path": a["path"]}
	for _, k := range []string{"cuts", "values", "newDim"} {
		if ixTruthy(a[k]) {
			r[k] = a[k]
		}
	}
	refined := ixRefineOmega(l.omega, r)
	nvs := ixMaFindVerb(refined, q["verb"])
	var d map[string]any
	for _, x := range ixL(nvs["dims"]) {
		if ixM(x)["path"] == a["path"] {
			d = ixM(x)
			break
		}
	}
	if d == nil {
		ixFail("answerPartial: no dimension %s", jsValueString(a["path"]))
	}
	parts := ixL(a["parts"])
	var rescope func(o, region map[string]any) map[string]any
	if ixTruthy(a["newDim"]) {
		var yes []any
		for j := 0; j < ixCellCount(d); j++ {
			if y, ok := ixRfPartLabel(d, j, parts); ok && y == 1 {
				yes = append(yes, float64(j))
			}
		}
		rescope = func(o, region map[string]any) map[string]any {
			if o["verb"] != q["verb"] || ixF(o["y"]) != 1 {
				return region
			}
			if d["kind"] == "cat" {
				return ixRestrictRegion(region, d, map[string]any{"cells": append([]any{}, yes...)})
			}
			if len(yes) == 0 {
				return ixRestrictRegion(region, d, map[string]any{"lo": ixF(d["hi"]) + 1, "hi": ixF(d["hi"]) + 1})
			}
			cells := ixNumCells(d)
			return ixRestrictRegion(region, d, map[string]any{"lo": cells[ixIdx(yes[0])].lo, "hi": cells[ixIdx(yes[len(yes)-1])].hi})
		}
	}
	nxt := l.refine(r, rescope)
	added := []any{}
	for _, j := range ixRfSubCells(d, qRegion) {
		y, ok := ixRfPartLabel(d, j, parts)
		if !ok {
			continue
		}
		var region map[string]any
		if d["kind"] == "num" {
			c := ixNumCells(d)[j]
			region = ixRestrictRegion(qRegion, d, map[string]any{"lo": c.lo, "hi": c.hi})
		} else {
			region = ixRestrictRegion(qRegion, d, map[string]any{"cells": []any{float64(j)}})
		}
		values := ixCopyMap(ixM(ixM(q["outcome"])["values"]))
		values[ixS(d["path"])] = ixRepValue(d, j)
		for _, xv := range ixL(nvs["dims"]) {
			x := ixM(xv)
			if _, ok := values[ixS(x["path"])]; !ok {
				values[ixS(x["path"])] = ixRepValue(x, 0)
			}
		}
		if ob := nxt.observe(map[string]any{"verb": q["verb"], "values": values}, y, "elicitation", region); ob != nil {
			added = append(added, ob)
		}
	}
	return nxt, added
}

// IntentElicitAdaptive is elicitation that accepts "yes", "no" and "partly": the stop rule and audit of IntentElicit, a partial
// answer counting as one question and swapping in the refined learner; after maxRefinements partial answers a further one is
// treated as "no". answer returns 0 / 1 as float64, or a partial answer map. The result carries the final learner under "learner".
func IntentElicitAdaptive(l *IntentLearner, answer func(q map[string]any, l *IntentLearner) any, o map[string]any) (map[string]any, error) {
	v, err := ixTry(func() any { return ixElicitAdaptive(l, answer, o) })
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func ixElicitAdaptive(l *IntentLearner, answer func(q map[string]any, l *IntentLearner) any, o map[string]any) map[string]any {
	asked := []any{}
	refinements := 0.0
	maxRef := ixLrOptF(o, "maxRefinements", 8)
	epsRisk, epsBurden, maxQ := ixF(o["epsRisk"]), ixF(o["epsBurden"]), ixF(o["maxQuestions"])
	apply := func(q map[string]any) {
		a := answer(q, l)
		asked = append(asked, q)
		pm, isMap := a.(map[string]any)
		if isMap || a == nil {
			if refinements < maxRef {
				l, _ = l.answerPartial(q, pm)
				refinements++
			} else {
				l.observe(ixM(q["outcome"]), 0, "elicitation", nil)
			}
		} else {
			l.observe(ixM(q["outcome"]), ixF(a), "elicitation", nil)
		}
	}
	seedQuestions := 0.0
	for _, sv := range ixL(o["seed"]) {
		if !(float64(len(asked)) < maxQ) {
			break
		}
		s := ixM(sv)
		vs := ixMaFindVerb(l.omega, s["verb"])
		cell := ixL(s["cell"])
		if vs == nil || len(cell) != len(ixL(vs["dims"])) {
			continue
		}
		values := map[string]any{}
		for k, dv := range ixL(vs["dims"]) {
			d := ixM(dv)
			values[ixS(d["path"])] = ixRepValue(d, ixIdx(cell[k]))
		}
		outcome := map[string]any{"verb": s["verb"], "values": values}
		p := l.Acceptance(outcome)
		if p <= 1e-9 || p >= 1-1e-9 || l.IsVetoed(outcome) {
			continue
		}
		apply(map[string]any{"verb": s["verb"], "cell": ixToAnyL(cell), "outcome": outcome, "p": p, "score": 0.0})
		seedQuestions++
	}
	stop := ""
	for stop == "" {
		m := l.Metrics()
		if m["residualRisk"].(float64) <= epsRisk && m["burden"].(float64) <= epsBurden {
			stop = "converged"
		} else if !(float64(len(asked)) < maxQ) {
			stop = "budget"
		} else if q := l.NextQuestion(); q == nil {
			stop = "no-disagreement"
		} else {
			apply(q)
		}
	}
	auditQuestions := 0.0
	if ixTruthy(o["audit"]) {
		for {
			pending := l.UnconfirmedGrantCells()
			total := 0.0
			for _, x := range pending {
				total += x["weight"].(float64)
			}
			if len(pending) == 0 || total <= epsRisk {
				break
			}
			if !(float64(len(asked)) < maxQ) {
				stop = "budget"
				break
			}
			top := pending[0]
			vs := ixMaFindVerb(l.omega, top["verb"])
			if vs == nil {
				ixFail("no verb space")
			}
			outcome := ixCellRep(vs, top["cell"].([]any))
			apply(map[string]any{"verb": top["verb"], "cell": top["cell"], "outcome": outcome, "p": l.Acceptance(outcome), "score": top["weight"]})
			auditQuestions++
		}
	}
	return map[string]any{"stop": stop, "questions": float64(len(asked)), "auditQuestions": auditQuestions, "seedQuestions": seedQuestions,
		"asked": asked, "learner": l, "refinements": refinements}
}
