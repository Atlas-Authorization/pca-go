package pca

// N-version interpretation: the enforced policy is the semantic meet of the readings (the TypeScript reference is
// @atlasauth/pca-goal `nversion`). Allow(meet gs) a implies Allow(g) a for every g in gs. Grants are the cross product of the
// readings' grants on equal verbs (a merged grant is named `x&y&z`), resources intersect through `all_of`, conditions conjoin; a
// bound of one reading counts the actions admitted by the merged grants derived from the grants that bound selected.

import (
	"sort"
)

// goalOrd is an insertion-ordered map keyed by a canonical string: setting an existing key keeps its position.
type goalOrd struct {
	keys []string
	m    map[string]any
}

func (o *goalOrd) set(k string, v any) {
	if o.m == nil {
		o.m = map[string]any{}
	}
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

func (o *goalOrd) values() []any {
	out := make([]any, len(o.keys))
	for i, k := range o.keys {
		out[i] = o.m[k]
	}
	return out
}

func goalNvPartsOf(s any) []any {
	switch anlGet(s, "k") {
	case "all_of":
		return anlReqList(anlGet(s, "parts"))
	case "any":
		return []any{}
	}
	return []any{s}
}

func goalNvIntersect(a, b any) any {
	if anlGet(a, "k") == "any" {
		return b
	}
	if anlGet(b, "k") == "any" {
		return a
	}
	var u goalOrd
	for _, p := range append(append([]any{}, goalNvPartsOf(a)...), goalNvPartsOf(b)...) {
		u.set(goalStable(p), p)
	}
	uniq := u.values()
	if len(uniq) == 1 {
		return uniq[0]
	}
	return map[string]any{"k": "all_of", "parts": uniq}
}

func goalNvConj(a, b any) any {
	if anlGet(a, "k") == "true" {
		return b
	}
	if anlGet(b, "k") == "true" {
		return a
	}
	return map[string]any{"k": "and", "a": a, "b": b}
}

// goalTracked is a merged grant and the gids of the per-reading grants it derives from (one per reading, in order).
type goalTracked struct {
	g    any
	from []any
}

func goalNvCross(a, b []goalTracked) []goalTracked {
	out := []goalTracked{}
	for _, x := range a {
		for _, y := range b {
			if anlStrictEq(anlGet(x.g, "verb"), anlGet(y.g, "verb")) {
				out = append(out, goalTracked{
					g: map[string]any{"gid": anlJS(anlGet(x.g, "gid")) + "&" + anlJS(anlGet(y.g, "gid")), "verb": anlGet(x.g, "verb"),
						"res": goalNvIntersect(anlGet(x.g, "res"), anlGet(y.g, "res")), "cond": goalNvConj(anlGet(x.g, "cond"), anlGet(y.g, "cond"))},
					from: append(append([]any{}, x.from...), y.from...)})
			}
		}
	}
	return out
}

func goalNvTrack(grants any) []goalTracked {
	out := []goalTracked{}
	for _, g := range anlReqList(grants) {
		out = append(out, goalTracked{g: g, from: []any{anlGet(g, "gid")}})
	}
	return out
}

// goalMeetGrants is the cross product on equal verbs, resource intersection, conjoined conditions.
func goalMeetGrants(a, b any) []any {
	out := []any{}
	for _, t := range goalNvCross(goalNvTrack(a), goalNvTrack(b)) {
		out = append(out, t.g)
	}
	return out
}

func goalNvSorted(xs []any) []any {
	out := append([]any{}, xs...)
	sort.SliceStable(out, func(i, j int) bool { return utf16Less(anlJS(out[i]), anlJS(out[j])) })
	return out
}

// goalNvDedupe removes repeated values (===), keeping the first occurrence.
func goalNvDedupe(xs []any) []any {
	out := []any{}
	for _, x := range xs {
		if !goalDriftHas(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// goalMeet is the semantic meet of readings that share principal, ontology and text.
func goalMeet(goalsIn any) map[string]any {
	goals := anlReqList(goalsIn)
	if len(goals) == 0 {
		anlFail("meet: no goals")
	}
	first := goals[0]
	for _, g := range goals {
		if !anlStrictEq(anlGet(g, "principal"), anlGet(first, "principal")) || !anlStrictEq(anlGet(g, "ontDigest"), anlGet(first, "ontDigest")) ||
			!anlStrictEq(anlGet(g, "nlDigest"), anlGet(first, "nlDigest")) {
			anlFail("meet: readings must share principal, ontology and text")
		}
	}
	if len(goals) == 1 {
		m, ok := first.(map[string]any)
		if !ok {
			anlFail("meet: a goal is not an object")
		}
		return m
	}
	tracked := goalNvTrack(anlGet(first, "grants"))
	for _, g := range goals[1:] {
		tracked = goalNvCross(tracked, goalNvTrack(anlGet(g, "grants")))
	}
	grants := make([]any, len(tracked))
	for i, t := range tracked {
		grants[i] = t.g
	}
	derived := func(i int, gids any) []any {
		out := []any{}
		for _, t := range tracked {
			if anlIncludes(gids, t.from[i]) {
				out = append(out, anlGet(t.g, "gid"))
			}
		}
		return out
	}

	prohibits := []any{}
	pseen := map[string]any{}
	for i, g := range goals {
		for _, p := range anlReqList(anlGet(g, "prohibits")) {
			body := goalStable(anlSet2(p, "pid", ""))
			if _, ok := pseen[body]; ok {
				continue
			}
			taken := false
			for _, v := range pseen {
				if anlStrictEq(v, anlGet(p, "pid")) {
					taken = true
				}
			}
			pseen[body] = anlGet(p, "pid")
			if taken {
				prohibits = append(prohibits, anlSet2(p, "pid", anlJS(anlGet(p, "pid"))+"#"+itoa(i)))
			} else {
				prohibits = append(prohibits, p)
			}
		}
	}

	bounds := []any{}
	bseen := map[string]map[string]any{}
	for i, g := range goals {
		for _, b := range anlReqList(anlGet(g, "bounds")) {
			bsel := anlGet(b, "sel")
			var sel any = bsel
			if anlGet(bsel, "k") == "gids" {
				sel = map[string]any{"k": "gids", "gids": goalNvSorted(derived(i, anlGet(bsel, "gids")))}
			}
			if anlGet(sel, "k") == "gids" && len(sel.(map[string]any)["gids"].([]any)) == 0 {
				continue // no merged grant derives from the selected grants: nothing to count
			}
			capv := anlGet(b, "cap")
			key := goalStable(map[string]any{"sel": sel, "agg": anlGet(b, "agg"), "value": anlGet(b, "value"), "key": anlGet(b, "key"), "window": anlGet(b, "window"),
				"scope": anlGet(b, "scope"), "unit": anlGet(capv, "u")})
			if prev := bseen[key]; prev != nil {
				// the same aggregate over the same counted grants in several readings: the minimum cap, the stricter exceed action
				if goalExNum(anlGet(capv, "n")) < goalExNum(anlGet(prev["cap"], "n")) {
					prev["cap"] = capv
				}
				if anlGet(b, "onExceed") == "deny" {
					prev["onExceed"] = "deny"
				}
				continue
			}
			bid := anlGet(b, "bid")
			for _, x := range bounds {
				if anlStrictEq(anlGet(x, "bid"), anlGet(b, "bid")) {
					bid = anlJS(anlGet(b, "bid")) + "#" + itoa(i)
					break
				}
			}
			nb := anlSpread(b)
			nb["sel"] = sel
			nb["bid"] = bid
			bounds = append(bounds, nb)
			bseen[key] = nb
		}
	}

	var esc goalOrd
	for _, g := range goals {
		for _, c := range anlReqList(anlGet(g, "escalateOn")) {
			esc.set(goalStable(c), c)
		}
	}
	idle := []any{}
	for _, g := range goals {
		x := anlGet(anlGet(g, "validity"), "maxIdle")
		if anlToNumber(x) > 0 {
			idle = append(idle, x)
		}
	}
	touch := []any{}
	for _, t := range tracked {
		ok := true
		for i, g := range goals {
			if !anlIncludes(anlGet(anlGet(g, "deleg"), "mayTouch"), t.from[i]) {
				ok = false
				break
			}
		}
		if ok {
			touch = append(touch, anlGet(t.g, "gid"))
		}
	}
	ackOK := func(g any, i int, t goalTracked) bool {
		var x any
		for _, y := range anlReqList(anlGet(g, "grants")) {
			if anlStrictEq(anlGet(y, "gid"), t.from[i]) {
				x = y
				break
			}
		}
		return x == nil || anlGet(anlGet(x, "res"), "k") != "any" || anlIncludes(anlGet(g, "wildcardAck"), t.from[i])
	}
	ack := []any{}
	for _, t := range tracked {
		if anlGet(anlGet(t.g, "res"), "k") != "any" {
			continue
		}
		ok := true
		for i, g := range goals {
			if !ackOK(g, i, t) {
				ok = false
				break
			}
		}
		if ok {
			ack = append(ack, anlGet(t.g, "gid"))
		}
	}

	var holes goalOrd
	for i, g := range goals {
		for _, h := range anlReqList(anlGet(g, "holes")) {
			hk := goalStable(anlGet(h, "hid"))
			prev, hasPrev := holes.m[hk]
			prevAff := []any{}
			var prevGlobal any = false
			if hasPrev {
				prevAff = anlReqList(anlGet(prev, "affects"))
				prevGlobal = anlGet(prev, "global")
			}
			affects := goalNvSorted(goalNvDedupe(append(append([]any{}, prevAff...), derived(i, anlGet(h, "affects"))...)))
			gl := anlGet(h, "global")
			if !anlTruthy(gl) {
				gl = prevGlobal
			}
			nh := anlSpread(h)
			nh["affects"] = affects
			nh["global"] = gl
			holes.set(hk, nh)
		}
	}
	sources := []any{}
	for _, g := range goals {
		sources = append(sources, anlReqList(anlGet(g, "sources"))...)
	}
	notBefore, notAfter := anlGet(anlGet(goals[0], "validity"), "notBefore"), anlGet(anlGet(goals[0], "validity"), "notAfter")
	maxDepth := anlGet(anlGet(goals[0], "deleg"), "maxDepth")
	for _, g := range goals[1:] {
		v := anlGet(g, "validity")
		if goalExNum(anlGet(v, "notBefore")) > goalExNum(notBefore) {
			notBefore = anlGet(v, "notBefore")
		}
		if goalExNum(anlGet(v, "notAfter")) < goalExNum(notAfter) {
			notAfter = anlGet(v, "notAfter")
		}
		if d := anlGet(anlGet(g, "deleg"), "maxDepth"); goalExNum(d) < goalExNum(maxDepth) {
			maxDepth = d
		}
	}
	var maxIdle any = goalNum(0)
	if len(idle) > 0 {
		maxIdle = idle[0]
		for _, x := range idle[1:] {
			if goalExNum(x) < goalExNum(maxIdle) {
				maxIdle = x
			}
		}
	}
	out := anlSpread(first)
	out["grants"] = grants
	out["prohibits"] = prohibits
	out["bounds"] = bounds
	out["escalateOn"] = esc.values()
	out["sources"] = goalNvDedupe(sources)
	out["validity"] = map[string]any{"notBefore": notBefore, "notAfter": notAfter, "maxIdle": maxIdle}
	out["deleg"] = map[string]any{"maxDepth": maxDepth, "narrowOnly": true, "mayTouch": touch}
	out["holes"] = holes.values()
	out["wildcardAck"] = ack
	return goalCanonicalizeGoal(out)
}

// goalCheckPanel: k >= 3, at least one deterministic non-LLM interpreter, at least two distinct model families.
func goalCheckPanel(readings any) []any {
	rs := anlReqList(readings)
	out := []any{}
	if len(rs) < 3 {
		out = append(out, map[string]any{"code": "too_few", "msg": "need at least 3 interpreters"})
	}
	anyDet := false
	fams := []any{}
	for _, r := range rs {
		if anlTruthy(anlGet(r, "deterministic")) {
			anyDet = true
		} else if f := anlGet(r, "family"); !goalDriftHas(fams, f) {
			fams = append(fams, f)
		}
	}
	if !anyDet {
		out = append(out, map[string]any{"code": "no_deterministic", "msg": "need at least one deterministic template interpreter"})
	}
	if len(fams) < 2 {
		out = append(out, map[string]any{"code": "no_family_diversity", "msg": "need at least two distinct model families"})
	}
	return out
}

// goalNVersion: opts carries the question options plus MassThreshold. Auto-signable only when the panel is valid and no hole remains.
func goalNVersion(readings any, opts GoalDisambOpts) map[string]any {
	rs := anlReqList(readings)
	goals := make([]any, len(rs))
	for i, r := range rs {
		goals[i] = anlGet(r, "goal")
	}
	merged := goalMeet(goals)
	panelIssues := goalCheckPanel(readings)
	verbSets := make([]map[string]bool, len(rs))
	allVerbs := map[string]bool{}
	for i, g := range goals {
		verbSets[i] = map[string]bool{}
		for _, gr := range anlReqList(anlGet(g, "grants")) {
			v := anlStr(anlGet(gr, "verb"), "verb")
			verbSets[i][v] = true
			allVerbs[v] = true
		}
	}
	holes := []any{}
	for _, v := range goalExSortedKeys(allVerbs) {
		missing := false
		for _, s := range verbSets {
			if !s[v] {
				missing = true
			}
		}
		if missing {
			holes = append(holes, map[string]any{"hid": "nv:verb:" + v, "q": "Only some readings allow \"" + v + "\". Should it be allowed at all?", "domain": []any{}, "affects": []any{}, "global": false})
		}
	}
	mass := goalDisagreementMass(readings, opts.Ont)
	thr := 0.0
	if opts.MassThreshold != nil {
		thr = goalExNum(opts.MassThreshold)
	}
	if mass > thr {
		q := any("The readings disagree.")
		if qs := goalQuestions(readings, opts); len(qs) > 0 {
			q = anlGet(qs[0], "text")
		}
		holes = append(holes, map[string]any{"hid": "nv:split", "q": q, "domain": []any{}, "affects": []any{}, "global": true})
	}
	allH := append(append([]any{}, anlReqList(anlGet(merged, "holes"))...), holes...)
	var byHid goalOrd
	for _, h := range allH {
		byHid.set(goalStable(anlGet(h, "hid")), h)
	}
	m2 := anlSpread(merged)
	m2["holes"] = byHid.values()
	return map[string]any{"merged": goalCanonicalizeGoal(m2), "panelIssues": panelIssues, "disagreementHoles": holes, "mass": mass,
		"signable": len(panelIssues) == 0 && len(allH) == 0}
}

// GoalMeet is the semantic meet of readings that share principal, ontology and text.
func GoalMeet(goals any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalMeet(goals); return nil })
	return
}

// GoalMeetGrants is the cross product of two grant lists on equal verbs.
func GoalMeetGrants(a, b any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalMeetGrants(a, b); return nil })
	return
}

// GoalCheckPanel reports the panel requirements a reading set misses.
func GoalCheckPanel(readings any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalCheckPanel(readings); return nil })
	return
}

// GoalNVersion is the N-version interpretation of a reading set.
func GoalNVersion(readings any, opts GoalDisambOpts) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalNVersion(readings, opts); return nil })
	return
}
