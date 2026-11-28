package pca

// Boundary examples and signed goal tests over the Goal IR and its reference semantics (the TypeScript reference is
// @atlasauth/pca-goal `examples`). An action is classified per coordinate (verb, resource, relation bits, each parameter) against
// the literals of the policy; goalCells enumerates one representative per decision cell. A case is {act, rels}: an action plus the
// relation facts it is decided under. A GoalSpace is {verbs, resources, rels, q, d}: q maps parameter -> unit key -> sorted numbers
// (unit keys keep their first-seen order, as the reference's insertion order drives the cell order), d maps parameter -> sorted
// discrete literals.

import (
	"math"
	"sort"
	"strings"
)

const goalMaxCells = 40000
const goalExOther = "\x00other"

type goalRelAnchor struct{ rel, anchor string }

type goalQGroup struct {
	key  string
	vals []float64
}

// GoalSpace is the decision-cell space of a set of goals.
type GoalSpace struct {
	verbs     []string
	resources []string
	rels      []goalRelAnchor
	q         map[string][]goalQGroup
	d         map[string][]string
}

// JSON is the space as the reference's plain object.
func (s *GoalSpace) JSON() map[string]any {
	strs := func(xs []string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	rels := make([]any, len(s.rels))
	for i, r := range s.rels {
		rels[i] = map[string]any{"rel": r.rel, "anchor": r.anchor}
	}
	q := map[string]any{}
	for p, gs := range s.q {
		m := map[string]any{}
		for _, g := range gs {
			vs := make([]any, len(g.vals))
			for i, v := range g.vals {
				vs[i] = jsNumber(v)
			}
			m[g.key] = vs
		}
		q[p] = m
	}
	d := map[string]any{}
	for p, xs := range s.d {
		d[p] = strs(xs)
	}
	return map[string]any{"verbs": strs(s.verbs), "resources": strs(s.resources), "rels": rels, "q": q, "d": d}
}

func goalExNum(v any) float64 {
	f, ok := jsNum(v)
	if !ok {
		anlFail("not a number")
	}
	return f
}

func goalExHash(v any) string {
	h, err := HashCanonical(v)
	if err != nil {
		anlFail("%v", err)
	}
	return h
}

func goalExHasStr(xs []string, v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func goalExSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return goalSortU16(out)
}

func goalFreshHist() map[string]any {
	return map[string]any{"adms": []any{}, "last": goalNum(-1), "aggs": map[string]any{}}
}

func goalDecisionOf(d int64) string {
	if d == 2 {
		return "allow"
	}
	if d == 1 {
		return "escalate"
	}
	return "deny"
}

func goalRankOf(d any) int {
	if d == "allow" {
		return 0
	}
	if d == "escalate" {
		return 1
	}
	return 2
}

// goalMkAct is an action with the fixed envelope the examples use (one session, one principal, no delegation, time 0).
func goalMkAct(verb, res string, params map[string]any, over map[string]any) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	a := map[string]any{"verb": verb, "res": res, "params": params, "t": goalNum(0), "sess": "s", "prin": "p", "org": "o", "agent": "a", "depth": goalNum(0)}
	order := []string{"verb", "res", "params", "t", "sess", "prin", "org", "agent", "depth"} // the reference's member order (JSON text of an action)
	for k, v := range over {
		if _, had := a[k]; !had {
			order = append(order, k)
		}
		a[k] = v
	}
	recordKeyOrder(a, order)
	return a
}

// goalDecideCase is the reference decision of a goal for {act, hist?, rels?}: {decision, witness, prohibited}.
func goalDecideCase(g, ont, c any) map[string]any {
	rels := anlGet(c, "rels")
	hist := anlGet(c, "hist")
	ont2 := ont
	if anlTruthy(rels) {
		m := anlSpread(ont)
		m["rels"] = rels
		ont2 = m
	}
	var h any = hist
	if hist == nil || anlIsUndef(hist) {
		h = goalFreshHist()
	}
	x := goalRefExplain(g, ont2, anlGet(c, "act"), h)
	w := anlGet(x, "witness")
	if anlIsUndef(w) {
		w = nil
	}
	return map[string]any{"decision": goalDecisionOf(int64(goalExNum(anlGet(x, "d")))), "witness": w, "prohibited": goalExNum(anlGet(x, "prohibit")) < 2}
}

// goalReplay is the history of the admitted prefix of acts (an action the goal refuses is not recorded).
func goalReplay(g, ont, acts, rels any) map[string]any {
	h := goalFreshHist()
	for _, act := range anlReqList(acts) {
		v := goalDecideCase(g, ont, map[string]any{"act": act, "hist": h, "rels": rels})
		if v["decision"] == "allow" && v["witness"] != nil {
			h["adms"] = append(h["adms"].([]any), map[string]any{"gid": v["witness"], "act": act})
			h["last"] = anlGet(act, "t")
		}
	}
	return h
}

func goalExQKey(q any) string {
	u := anlGet(q, "u")
	if anlGet(u, "k") == "money" {
		return "money:" + anlJS(anlGet(u, "ccy"))
	}
	return anlJS(anlGet(u, "k"))
}

func goalExUnitOfKey(key string) map[string]any {
	if strings.HasPrefix(key, "money:") {
		return goalExOrd(map[string]any{"k": "money", "ccy": key[6:]}, "k", "ccy")
	}
	return map[string]any{"k": key}
}

func goalExDKey(v any) (string, bool) {
	if anlGet(v, "k") == "s" {
		return "s:" + anlJS(anlGet(v, "s")), true
	}
	return "", false
}

func goalExWalkCond(c any, f func(p string, v any)) {
	switch anlGet(c, "k") {
	case "cmp":
		l, r := anlGet(c, "l"), anlGet(c, "r")
		var path, other any
		found := false
		if anlGet(l, "k") == "param" {
			path, other, found = anlGet(l, "path"), r, true
		} else {
			other = l
			if anlGet(r, "k") == "param" {
				path, found = anlGet(r, "path"), true
			}
		}
		ps, isStr := path.(string)
		if !found || !isStr || anlGet(other, "k") != "lit" {
			return
		}
		v := anlGet(other, "v")
		if anlGet(v, "k") == "set" {
			for _, i := range anlReqList(anlGet(v, "items")) {
				f(ps, i)
			}
		} else {
			f(ps, v)
		}
	case "and", "or":
		goalExWalkCond(anlGet(c, "a"), f)
		goalExWalkCond(anlGet(c, "b"), f)
	case "not":
		goalExWalkCond(anlGet(c, "c"), f)
	}
}

func goalExParts(s any) []any {
	switch anlGet(s, "k") {
	case "all_of":
		return anlReqList(anlGet(s, "parts"))
	case "any":
		return []any{}
	}
	return []any{s}
}

// goalBuildSpace is the space of the goals' literals; extraVerbs are verbs to include even when no goal mentions them.
func goalBuildSpace(goals any, extraVerbs []string) *GoalSpace {
	type qacc struct {
		keys []string
		sets map[string]map[float64]bool
	}
	verbs := map[string]bool{}
	for _, v := range extraVerbs {
		verbs[v] = true
	}
	resources := map[string]bool{}
	rels := map[string]goalRelAnchor{}
	q := map[string]*qacc{}
	d := map[string]map[string]bool{}

	lit := func(p string, v any) {
		if anlGet(v, "k") == "q" {
			acc := q[p]
			if acc == nil {
				acc = &qacc{sets: map[string]map[float64]bool{}}
				q[p] = acc
			}
			qq := anlGet(v, "q")
			key := goalExQKey(qq)
			s := acc.sets[key]
			if s == nil {
				s = map[float64]bool{}
				acc.sets[key] = s
				acc.keys = append(acc.keys, key)
			}
			s[goalExNum(anlGet(qq, "n"))] = true
		} else if k, ok := goalExDKey(v); ok {
			if d[p] == nil {
				d[p] = map[string]bool{}
			}
			d[p][k] = true
		}
	}
	res := func(s any) {
		for _, x := range goalExParts(s) {
			switch anlGet(x, "k") {
			case "exact":
				resources[anlStr(anlGet(x, "id"), "id")] = true
			case "oneof":
				for _, i := range anlReqList(anlGet(x, "ids")) {
					resources[anlStr(i, "id")] = true
				}
			default:
				rel, anchor := anlStr(anlGet(x, "rel"), "rel"), anlStr(anlGet(x, "anchor"), "anchor")
				rels[rel+"\x00"+anchor] = goalRelAnchor{rel, anchor}
			}
		}
	}

	for _, g := range anlReqList(goals) {
		for _, gr := range anlReqList(anlGet(g, "grants")) {
			verbs[anlStr(anlGet(gr, "verb"), "verb")] = true
			res(anlGet(gr, "res"))
			goalExWalkCond(anlGet(gr, "cond"), lit)
		}
		for _, p := range anlReqList(anlGet(g, "prohibits")) {
			t := anlGet(p, "target")
			if anlGet(t, "k") == "verb" {
				verbs[anlStr(anlGet(t, "verb"), "verb")] = true
			}
			res(anlGet(p, "res"))
			goalExWalkCond(anlGet(p, "cond"), lit)
		}
		for _, c := range anlReqList(anlGet(g, "escalateOn")) {
			goalExWalkCond(c, lit)
		}
		for _, b := range anlReqList(anlGet(g, "bounds")) {
			v := anlGet(b, "value")
			if anlGet(b, "agg") == "sum" && anlGet(v, "k") == "param" {
				// reps around the cap so witnesses carry the summed param
				lit(anlStr(anlGet(v, "path"), "path"), map[string]any{"k": "q", "q": anlGet(b, "cap")})
			}
		}
	}

	sp := &GoalSpace{verbs: goalExSortedKeys(verbs), resources: goalExSortedKeys(resources), q: map[string][]goalQGroup{}, d: map[string][]string{}}
	for _, r := range rels {
		sp.rels = append(sp.rels, r)
	}
	sort.Slice(sp.rels, func(i, j int) bool {
		return utf16Less(sp.rels[i].rel+sp.rels[i].anchor, sp.rels[j].rel+sp.rels[j].anchor)
	})
	for p, acc := range q {
		for _, key := range acc.keys {
			vals := make([]float64, 0, len(acc.sets[key]))
			for v := range acc.sets[key] {
				vals = append(vals, v)
			}
			sort.Float64s(vals)
			sp.q[p] = append(sp.q[p], goalQGroup{key, vals})
		}
	}
	for p, s := range d {
		sp.d[p] = goalExSortedKeys(s)
	}
	return sp
}

func (s *GoalSpace) group(p, key string) ([]float64, bool) {
	for _, g := range s.q[p] {
		if g.key == key {
			return g.vals, true
		}
	}
	return nil, false
}

func goalExClassifyLit(sp *GoalSpace, p string, l any) string {
	if anlIsUndef(l) {
		return "missing"
	}
	if anlGet(l, "k") == "set" {
		return "missing"
	}
	_, hasGroups := sp.q[p]
	ds, hasDs := sp.d[p]
	if anlGet(l, "k") == "q" {
		key := goalExQKey(anlGet(l, "q"))
		g, ok := sp.group(p, key)
		if !ok {
			if hasGroups || hasDs {
				return "unit"
			}
			return "any"
		}
		v := goalExNum(anlGet(anlGet(l, "q"), "n"))
		for j, x := range g {
			if x == v {
				return key + "=" + itoa(j)
			}
		}
		pos := 0
		for pos < len(g) && g[pos] < v {
			pos++
		}
		return key + "@" + itoa(pos) // strictly between literal pos-1 and pos
	}
	k, isD := goalExDKey(l)
	if !hasDs {
		if hasGroups {
			return "unit"
		}
		return "any"
	}
	if isD && goalExHasStr(ds, k) {
		return k
	}
	return "other"
}

func goalExRelBit(c any, rel, anchor string) int64 {
	for _, x := range anlReqList(anlGet(c, "rels")) {
		if anlStrictEq(anlGet(x, "rel"), rel) && anlStrictEq(anlGet(x, "anchor"), anchor) {
			if anlIncludes(anlGet(x, "members"), anlGet(anlGet(c, "act"), "res")) {
				return 1
			}
			return 0
		}
	}
	return 0
}

func goalExParamsOf(sp *GoalSpace) []string {
	set := map[string]bool{}
	for p := range sp.q {
		set[p] = true
	}
	for p := range sp.d {
		set[p] = true
	}
	return goalExSortedKeys(set)
}

// goalCellKey is the decision cell of a case under a space (canonical string; the unit of precedents).
func goalCellKey(sp *GoalSpace, c any) string {
	act := anlGet(c, "act")
	params := anlGet(act, "params")
	pm, _ := params.(map[string]any)
	verb, res := anlGet(act, "verb"), anlGet(act, "res")
	var v, r any = "*", "*"
	if goalExHasStr(sp.verbs, verb) {
		v = verb
	}
	if goalExHasStr(sp.resources, res) {
		r = res
	}
	l := make([]any, len(sp.rels))
	for i, x := range sp.rels {
		l[i] = goalNum(goalExRelBit(c, x.rel, x.anchor))
	}
	p := map[string]any{}
	for _, name := range goalExParamsOf(sp) {
		var lv any = anlUndef
		if pm != nil {
			if x, ok := pm[name]; ok {
				lv = x
			}
		}
		p[name] = goalExClassifyLit(sp, name, lv)
	}
	return goalStable(map[string]any{"v": v, "r": r, "l": l, "p": p})
}

func goalExParamOptions(sp *GoalSpace, p string) []any {
	out := []any{nil} // nil = the parameter is absent
	seen := map[string]bool{}
	add := func(v any) {
		k := goalStable(v)
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	for _, g := range sp.q[p] {
		isInstant := g.key == "instant"
		for _, v := range g.vals {
			for _, x := range []float64{v - 1, v, v + 1} {
				if x >= 0 || isInstant {
					add(map[string]any{"k": "q", "q": goalExOrd(map[string]any{"u": goalExUnitOfKey(g.key), "n": jsNumber(x)}, "u", "n")})
				}
			}
		}
		if strings.HasPrefix(g.key, "money:") {
			add(map[string]any{"k": "q", "q": goalExOrd(map[string]any{"u": goalExUnitOfKey("money:ZZZ"), "n": goalNum(0)}, "u", "n")}) // unit mismatch -> Unknown
		}
	}
	for _, k := range sp.d[p] {
		add(map[string]any{"k": "s", "s": k[2:]})
	}
	if _, ok := sp.d[p]; ok {
		add(map[string]any{"k": "s", "s": goalExOther})
	}
	return out
}

// goalCells is one representative per decision cell. verbs overrides the verb list when non-nil. "complete" is false when the grid
// exceeded the cell cap (then the cases are a subset).
func goalCells(sp *GoalSpace, verbsOpt []string) map[string]any {
	verbs := verbsOpt
	if verbs == nil {
		verbs = append(append([]string(nil), sp.verbs...), "\x00other-verb")
	}
	resources := append(append([]string(nil), sp.resources...), "\x00other-resource")
	params := goalExParamsOf(sp)
	pOpts := make([][]any, len(params))
	for i, p := range params {
		pOpts[i] = goalExParamOptions(sp, p)
	}
	relBits := len(sp.rels)
	total := float64(len(verbs)*len(resources)) * math.Ldexp(1, relBits)
	for _, o := range pOpts {
		total *= float64(len(o))
	}
	complete := total <= goalMaxCells
	out := []any{}
	seen := map[string]bool{}
	push := func(c map[string]any) {
		k := goalCellKey(sp, c)
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	build := func(verb, resource string, bits int, choice []any) map[string]any {
		pr := map[string]any{}
		prKeys := []string{}
		for i, p := range params {
			if choice[i] != nil {
				pr[p] = choice[i]
				prKeys = append(prKeys, p)
			}
		}
		recordKeyOrder(pr, prKeys)
		rels := make([]any, len(sp.rels))
		for i, x := range sp.rels {
			members := []any{}
			if bits&(1<<uint(i)) != 0 {
				members = []any{resource}
			}
			rels[i] = map[string]any{"rel": x.rel, "anchor": x.anchor, "members": members}
		}
		return map[string]any{"act": goalMkAct(verb, resource, pr, nil), "rels": rels}
	}
	nbits := 1 << uint(relBits)
	if complete {
		for _, verb := range verbs {
			for _, res := range resources {
				for bits := 0; bits < nbits; bits++ {
					idx := make([]int, len(params))
					for {
						choice := make([]any, len(params))
						for i, j := range idx {
							choice[i] = pOpts[i][j]
						}
						push(build(verb, res, bits, choice))
						k := 0
						for k < len(idx) {
							idx[k]++
							if idx[k] != len(pOpts[k]) {
								break
							}
							idx[k] = 0
							k++
						}
						if k == len(idx) {
							break
						}
					}
				}
			}
		}
	} else {
		baseChoice := func() []any {
			ch := make([]any, len(pOpts))
			for i, o := range pOpts {
				j := 2
				if len(o)-1 < j {
					j = len(o) - 1
				}
				ch[i] = o[j]
			}
			return ch
		}
		for _, verb := range verbs {
			push(build(verb, resources[0], 0, baseChoice()))
			for _, res := range resources {
				for bits := 0; bits < nbits; bits++ {
					push(build(verb, res, bits, baseChoice()))
				}
			}
			for i, o := range pOpts {
				for _, l := range o {
					ch := baseChoice()
					ch[i] = l
					push(build(verb, resources[0], 0, ch))
				}
			}
		}
	}
	return map[string]any{"cases": out, "complete": complete}
}

func goalExMagnitude(a any) float64 {
	var s float64
	pm, _ := anlGet(a, "params").(map[string]any)
	for _, v := range pm {
		if anlGet(v, "k") == "q" {
			s += math.Abs(goalExNum(anlGet(anlGet(v, "q"), "n")))
		}
	}
	return s
}

// goalAllowWitness is the smallest-magnitude case the grant admits (a minimal Allow witness), or nil if its Allow set is empty.
func goalAllowWitness(g, gr, ont any) map[string]any {
	sp := goalBuildSpace([]any{g}, nil)
	var best map[string]any
	for _, c := range goalCells(sp, []string{anlStr(anlGet(gr, "verb"), "verb")})["cases"].([]any) {
		cm := c.(map[string]any)
		v := goalDecideCase(g, ont, cm)
		if v["decision"] == "allow" && anlStrictEq(v["witness"], anlGet(gr, "gid")) && (best == nil || goalExMagnitude(cm["act"]) < goalExMagnitude(best["act"])) {
			best = cm
		}
	}
	return best
}

// GoalExampleOpts are the options of GoalBoundaryExamples: the ontology, further goals sharing the space, extra verbs.
type GoalExampleOpts struct {
	Ont   any
	Extra []any
	Verbs []string
}

// goalBoundaryExamples is the full example set: decision-cell representatives, cap sequences and unmentioned-dimension probes.
func goalBoundaryExamples(g any, opts GoalExampleOpts) map[string]any {
	ont := opts.Ont
	goals := append([]any{g}, opts.Extra...)
	sp := goalBuildSpace(goals, opts.Verbs)
	c := goalCells(sp, nil)
	out := []any{}

	add := func(kind, why string, cs map[string]any, hist map[string]any) {
		h := hist
		if h == nil {
			h = goalFreshHist()
		}
		id := kind + ":" + goalExHash(map[string]any{"act": cs["act"], "hist": h, "rels": cs["rels"]})[:12]
		out = append(out, map[string]any{"id": id, "kind": kind, "why": why, "act": cs["act"], "hist": h, "rels": cs["rels"],
			"decision": goalDecideCase(g, ont, map[string]any{"act": cs["act"], "hist": h, "rels": cs["rels"]})["decision"]})
	}

	for _, x := range c["cases"].([]any) {
		cs := x.(map[string]any)
		v := goalDecideCase(g, ont, cs)
		dec := v["decision"].(string)
		kind := "boundary"
		if v["prohibited"] == true && dec == "deny" {
			kind = "prohibit_trigger"
		} else if dec == "allow" {
			kind = "member"
		}
		add(kind, "cell "+dec, cs, nil)
	}
	for _, gr := range anlReqList(anlGet(g, "grants")) {
		if w := goalAllowWitness(g, gr, ont); w != nil {
			add("allow_witness", "minimal Allow witness of grant "+anlJS(anlGet(gr, "gid")), w, nil)
		}
	}
	for _, b := range anlReqList(anlGet(g, "bounds")) {
		sel := anlGet(b, "sel")
		var gids any = []any{}
		if anlGet(sel, "k") == "gids" {
			gids = anlGet(sel, "gids")
		}
		var gr any
		for _, x := range anlReqList(anlGet(g, "grants")) {
			if anlIncludes(gids, anlGet(x, "gid")) {
				gr = x
				break
			}
		}
		var w map[string]any
		if gr != nil {
			w = goalAllowWitness(g, gr, ont)
		}
		if w == nil {
			continue
		}
		capN := goalExNum(anlGet(anlGet(b, "cap"), "n"))
		var per float64 = 1
		if anlGet(b, "agg") != "count" {
			val := anlGet(b, "value")
			var v any = anlUndef
			if anlGet(val, "k") == "param" {
				if pm, ok := anlGet(w["act"], "params").(map[string]any); ok {
					if x, ok := pm[anlStr(anlGet(val, "path"), "path")]; ok {
						v = x
					}
				}
			}
			per = 0
			if !anlIsUndef(v) && anlTruthy(v) && anlGet(v, "k") == "q" {
				per = goalExNum(anlGet(anlGet(v, "q"), "n"))
			}
		}
		if anlGet(b, "agg") == "sum" && per <= 0 {
			continue
		}
		n := math.Floor(capN / per) // JavaScript division: x / 0 is +-Infinity, 0 / 0 is NaN
		if n > 60 {
			continue // sequence too long to review; the aggregate theorem (not examples) covers it
		}
		count := 0
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n > 0 {
			count = int(n)
		}
		acts := make([]any, count)
		for i := range acts {
			acts[i] = w["act"]
		}
		add("cap_sequence", "reach the "+anlJS(anlGet(b, "bid"))+" cap with "+anlJS(n)+" action(s), then one more", w, goalReplay(g, ont, acts, w["rels"]))
	}
	for _, gr := range anlReqList(anlGet(g, "grants")) { // unmentioned-dimension probes: extreme amount, other resource, other relation anchor
		w := goalAllowWitness(g, gr, ont)
		if w == nil {
			continue
		}
		wact := w["act"].(map[string]any)
		wparams := wact["params"].(map[string]any)
		pnames := make([]string, 0, len(wparams))
		for p := range wparams {
			pnames = append(pnames, p)
		}
		for _, p := range goalSortU16(pnames) {
			l := wparams[p]
			if anlGet(l, "k") == "q" && anlGet(anlGet(anlGet(l, "q"), "u"), "k") == "money" {
				np := anlCopy(wparams)
				np[p] = map[string]any{"k": "q", "q": anlSet2(anlGet(l, "q"), "n", goalNum(1000000000))}
				act := anlCopy(wact)
				act["params"] = np
				add("probe", "extreme "+p, map[string]any{"act": act, "rels": w["rels"]}, nil)
			}
		}
		nothing := []any{}
		for _, r := range anlReqList(w["rels"]) {
			m := anlCopy(r.(map[string]any))
			m["members"] = []any{}
			nothing = append(nothing, m)
		}
		other := anlCopy(wact)
		other["res"] = "\x00other-resource"
		add("probe", "other resource", map[string]any{"act": other, "rels": nothing}, nil)
		add("probe", "other customer/anchor", map[string]any{"act": wact, "rels": nothing}, nil)
	}
	seen := map[string]bool{}
	res := []any{}
	for _, x := range out {
		e := x.(map[string]any)
		id := e["id"].(string)
		if !seen[id] {
			seen[id] = true
			res = append(res, e)
		}
	}
	return map[string]any{"examples": res, "complete": c["complete"]}
}

// anlSet2 is {...o, k: v} (member order kept; a new member goes last).
func anlSet2(o any, k string, v any) map[string]any {
	m := anlSpread(o)
	keys := []string{}
	if om, ok := o.(map[string]any); ok {
		keys = append(keys, jsKeys(om)...)
	}
	if _, had := m[k]; !had {
		keys = append(keys, k)
	}
	m[k] = v
	recordKeyOrder(m, keys)
	return m
}

// goalExOrd records the member order of a map literal (the reference's JSON text order) and returns it.
func goalExOrd(m map[string]any, keys ...string) map[string]any {
	recordKeyOrder(m, keys)
	return m
}

var goalExKindW = map[string]int{"probe": 0, "cap_sequence": 1, "allow_witness": 2, "prohibit_trigger": 3, "member": 4, "boundary": 5}

// goalReviewSet caps the examples, riskiest-looking first (Allow of the unmentioned, then Allow, then boundary), stable.
func goalReviewSet(examples any, cap int) []any {
	xs := append([]any(nil), anlReqList(examples)...)
	less := func(a, b any) bool {
		r := goalRankOf(anlGet(a, "decision")) - goalRankOf(anlGet(b, "decision"))
		if r == 0 {
			ka, oka := goalExKindW[anlStr(anlGet(a, "kind"), "kind")]
			kb, okb := goalExKindW[anlStr(anlGet(b, "kind"), "kind")]
			if !oka || !okb {
				anlFail("unknown example kind")
			}
			r = ka - kb
		}
		if r != 0 {
			return r < 0
		}
		return utf16Less(anlStr(anlGet(a, "id"), "id"), anlStr(anlGet(b, "id"), "id"))
	}
	sort.SliceStable(xs, func(i, j int) bool { return less(xs[i], xs[j]) })
	if cap < 0 {
		cap += len(xs)
		if cap < 0 {
			cap = 0
		}
	}
	if cap > len(xs) {
		cap = len(xs)
	}
	return xs[:cap]
}

func goalExpectedDecision(a any) string {
	if a == "allow" {
		return "allow"
	}
	if a == "deny" {
		return "deny"
	}
	return "escalate"
}

// goalTestsDigest is the order-independent digest of a test list.
func goalTestsDigest(tests any) string {
	xs := append([]any(nil), anlReqList(tests)...)
	sort.SliceStable(xs, func(i, j int) bool {
		return utf16Less(anlStr(anlGet(xs[i], "id"), "id"), anlStr(anlGet(xs[j], "id"), "id"))
	})
	return goalExHash(map[string]any{"d": "atlas-pca/goal-tests/v1", "tests": xs})
}

func goalMakeGoalTests(g any, confirmed any) map[string]any {
	tests := []any{}
	for _, c := range anlReqList(confirmed) {
		ex := anlGet(c, "example")
		tests = append(tests, map[string]any{"id": anlGet(ex, "id"), "act": anlGet(ex, "act"), "hist": anlGet(ex, "hist"), "rels": anlGet(ex, "rels"), "answer": anlGet(c, "answer")})
	}
	return map[string]any{"goal_digest": goalGoalDigest(g), "ontology_digest": anlGet(g, "ontDigest"), "tests": tests, "tests_digest": goalTestsDigest(tests)}
}

func goalSignGoalTests(s any, secret any, rest ...any) map[string]any {
	return goalSignPayload("goal-tests", s, secret, rest...)
}

// goalCheckGoalTests is the recompile check: any recompile must reproduce every confirmed test or the policy is refused.
func goalCheckGoalTests(s any, pins any, decide func(t any) string) map[string]any {
	if !goalVerifyPayload(s, "goal-tests", anlReqList(pins)) {
		return map[string]any{"ok": false, "reason": "signature", "failures": []any{}}
	}
	pl := anlGet(s, "payload")
	if !anlStrictEq(goalTestsDigest(anlGet(pl, "tests")), anlGet(pl, "tests_digest")) {
		return map[string]any{"ok": false, "reason": "tests_digest", "failures": []any{}}
	}
	failures := []any{}
	for _, t := range anlReqList(anlGet(pl, "tests")) {
		got := decide(t)
		exp := goalExpectedDecision(anlGet(t, "answer"))
		if got != exp {
			failures = append(failures, map[string]any{"id": anlGet(t, "id"), "expected": exp, "got": got})
		}
	}
	if len(failures) > 0 {
		return map[string]any{"ok": false, "reason": "test_regression", "failures": failures}
	}
	return map[string]any{"ok": true, "failures": failures}
}

// goalSignPin signs the pin: the policy version cannot silently change under a signed test set.
func goalSignPin(p any, secret any, rest ...any) map[string]any {
	return goalSignPayload("policy-pin", p, secret, rest...)
}

func goalCheckPin(pin any, pins any, cur any) map[string]any {
	if !goalVerifyPayload(pin, "policy-pin", anlReqList(pins)) {
		return map[string]any{"ok": false, "reason": "signature"}
	}
	p := anlGet(pin, "payload")
	goal, tests := anlGet(cur, "goal"), anlGet(cur, "tests")
	if !anlStrictEq(anlGet(p, "goal_digest"), goalGoalDigest(goal)) {
		return map[string]any{"ok": false, "reason": "goal changed under the pin"}
	}
	if !anlStrictEq(anlGet(p, "policy_digest"), anlGet(cur, "policy_digest")) {
		return map[string]any{"ok": false, "reason": "policy changed under the pin"}
	}
	if !anlStrictEq(anlGet(p, "tests_digest"), anlGet(tests, "tests_digest")) || !anlStrictEq(anlGet(p, "tests_digest"), goalTestsDigest(anlGet(tests, "tests"))) {
		return map[string]any{"ok": false, "reason": "tests changed under the pin"}
	}
	if !anlStrictEq(anlGet(p, "ontology_digest"), anlGet(goal, "ontDigest")) {
		return map[string]any{"ok": false, "reason": "ontology changed under the pin"}
	}
	return map[string]any{"ok": true}
}

// GoalDecideCase is the reference decision of a goal for {act, hist?, rels?}: {decision, witness, prohibited}.
func GoalDecideCase(g, ont, c any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalDecideCase(g, ont, c); return nil })
	return
}

// GoalReplay is the history of the admitted prefix of acts.
func GoalReplay(g, ont, acts, rels any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalReplay(g, ont, acts, rels); return nil })
	return
}

// GoalBoundaryExamples is the full example set of a goal.
func GoalBoundaryExamples(g any, opts GoalExampleOpts) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalBoundaryExamples(g, opts); return nil })
	return
}

// GoalTestsDigest is the order-independent digest of a test list.
func GoalTestsDigest(tests any) (d string, err error) {
	_, err = anlTry(func() any { d = goalTestsDigest(tests); return nil })
	return
}

// GoalCheckPin checks a signed policy pin against the current goal, policy digest and tests.
func GoalCheckPin(pin, pins, cur any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalCheckPin(pin, pins, cur); return nil })
	return
}
