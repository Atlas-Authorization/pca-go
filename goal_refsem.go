package pca

// An independent reading of the goal semantics D_G (the TypeScript reference is @atlasauth/pca-goal `refsem`): a second,
// hand-written implementation used to cross-check a compiled policy. NOT the trusted decision function. Decisions are 0 deny,
// 1 escalate, 2 allow; condition truth is 0 false, 1 unknown, 2 true.

import "math"

func goalRefB2t(b bool) int {
	if b {
		return 2
	}
	return 0
}

func goalRefSameUnit(a, b any) bool {
	if anlIsUndef(a) || anlIsUndef(b) {
		return anlIsUndef(a) && anlIsUndef(b)
	}
	// The reference compares JSON.stringify of the two units; every unit it builds is {k} or {k, ccy} in that order. Go maps carry no
	// insertion order of their own, so a unit built here and a unit read from a document would differ only in member order: compare
	// the members themselves.
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok && len(am) <= 2 && len(bm) <= 2 {
		known := func(m map[string]any) bool {
			for k := range m {
				if k != "k" && k != "ccy" {
					return false
				}
			}
			return true
		}
		if known(am) && known(bm) {
			if len(am) != len(bm) {
				return false
			}
			for _, k := range []string{"k", "ccy"} {
				x, hx := am[k]
				y, hy := bm[k]
				if hx != hy || (hx && anlJSON(x) != anlJSON(y)) {
					return false
				}
			}
			return true
		}
	}
	return anlJSON(a) == anlJSON(b)
}

// goalRefHas is `k in o` for an object o and a string k; null / undefined o throws.
func goalRefHas(o, k any) bool {
	if o == nil || anlIsUndef(o) {
		anlFail("cannot convert undefined or null to object")
	}
	m, ok := o.(map[string]any)
	ks, kok := k.(string)
	if !ok || !kok {
		return false
	}
	_, has := m[ks]
	return has
}

func goalRefVal(t, a, h any) any {
	switch anlGet(t, "k") {
	case "param":
		params, path := anlGet(a, "params"), anlGet(t, "path")
		if goalRefHas(params, path) {
			return params.(map[string]any)[path.(string)]
		}
		return anlUndef
	case "lit":
		return anlGet(t, "v")
	}
	aggs, bid := anlGet(h, "aggs"), anlGet(t, "bid")
	if goalRefHas(aggs, bid) {
		return map[string]any{"k": "q", "q": aggs.(map[string]any)[bid.(string)]}
	}
	return anlUndef
}

func goalRefEq(x, y any) int {
	if anlGet(x, "k") == "q" && anlGet(y, "k") == "q" {
		xq, yq := anlGet(x, "q"), anlGet(y, "q")
		if goalRefSameUnit(anlGet(xq, "u"), anlGet(yq, "u")) {
			return goalRefB2t(anlStrictEq(anlGet(xq, "n"), anlGet(yq, "n")))
		}
		return 1
	}
	if anlGet(x, "k") == "s" && anlGet(y, "k") == "s" {
		return goalRefB2t(anlStrictEq(anlGet(x, "s"), anlGet(y, "s")))
	}
	return 1
}

func goalRefLt(x, y any) int {
	if anlGet(x, "k") == "q" && anlGet(y, "k") == "q" && goalRefSameUnit(anlGet(anlGet(x, "q"), "u"), anlGet(anlGet(y, "q"), "u")) {
		return goalRefB2t(anlLt(anlGet(anlGet(x, "q"), "n"), anlGet(anlGet(y, "q"), "n")))
	}
	return 1
}

func goalRefInSet(x, y any) int {
	if anlGet(y, "k") != "set" {
		return 1
	}
	acc := 0
	for _, it := range anlReqList(anlGet(y, "items")) {
		acc = max(acc, goalRefEq(x, it))
	}
	return acc
}

func goalRefCmp(op, x, y any) int {
	if !anlTruthy(x) || !anlTruthy(y) {
		return 1
	}
	switch op {
	case "eq":
		return goalRefEq(x, y)
	case "ne":
		return 2 - goalRefEq(x, y)
	case "lt":
		return goalRefLt(x, y)
	case "gte":
		return 2 - goalRefLt(x, y)
	case "gt":
		return goalRefLt(y, x)
	case "lte":
		return 2 - goalRefLt(y, x)
	case "in":
		return goalRefInSet(x, y)
	}
	return 2 - goalRefInSet(x, y)
}

func goalRefEvalC(c, a, h any) int {
	switch anlGet(c, "k") {
	case "true":
		return 2
	case "cmp":
		return goalRefCmp(anlGet(c, "op"), goalRefVal(anlGet(c, "l"), a, h), goalRefVal(anlGet(c, "r"), a, h))
	case "and":
		x := goalRefEvalC(anlGet(c, "a"), a, h)
		return min(x, goalRefEvalC(anlGet(c, "b"), a, h))
	case "or":
		x := goalRefEvalC(anlGet(c, "a"), a, h)
		return max(x, goalRefEvalC(anlGet(c, "b"), a, h))
	case "not":
		return 2 - goalRefEvalC(anlGet(c, "c"), a, h)
	}
	anlFail("unknown condition") // the reference yields NaN here; refuse instead
	return 0
}

func goalRefResOk(s, ont, r any) bool {
	switch anlGet(s, "k") {
	case "any":
		return true
	case "exact":
		return anlStrictEq(r, anlGet(s, "id"))
	case "oneof":
		return anlIncludes(anlGet(s, "ids"), r)
	case "related":
		var members any = []any{}
		for _, x := range anlReqList(anlGet(ont, "rels")) {
			if anlStrictEq(anlGet(x, "rel"), anlGet(s, "rel")) && anlStrictEq(anlGet(x, "anchor"), anlGet(s, "anchor")) {
				if m := anlGet(x, "members"); m != nil && !anlIsUndef(m) {
					members = m
				}
				break
			}
		}
		return anlIncludes(members, r)
	case "all_of":
		for _, p := range anlReqList(anlGet(s, "parts")) {
			if !goalRefResOk(p, ont, r) {
				return false
			}
		}
		return true
	}
	return false
}

func goalRefVerbsOf(ont, cls any) []any {
	out := []any{}
	for _, v := range anlReqList(anlGet(ont, "verbs")) {
		if anlStrictEq(anlGet(v, "cls"), cls) {
			out = append(out, anlGet(v, "verb"))
		}
	}
	return out
}

func goalRefInScope(sc, a, x any) bool {
	switch anlGet(sc, "k") {
	case "session":
		return anlStrictEq(anlGet(a, "sess"), anlGet(x, "sess"))
	case "principal":
		return anlStrictEq(anlGet(a, "prin"), anlGet(x, "prin"))
	case "org":
		return anlStrictEq(anlGet(a, "org"), anlGet(x, "org"))
	case "fleet":
		return anlIncludes(anlGet(sc, "agents"), anlGet(a, "agent")) && anlIncludes(anlGet(sc, "agents"), anlGet(x, "agent"))
	}
	return false
}

func goalRefInWin(w, a, x any) bool {
	switch anlGet(w, "k") {
	case "task", "lifetime":
		return true
	case "sliding":
		at, xt, ms := anlToNumber(anlGet(a, "t")), anlToNumber(anlGet(x, "t")), anlToNumber(anlGet(w, "ms"))
		return anlGt(anlGet(x, "t"), at-ms) && xt <= at
	case "period":
		ms := anlGet(w, "ms")
		if !anlGt(ms, 0) {
			return false
		}
		m, t0 := anlToNumber(ms), anlToNumber(anlGet(w, "t0"))
		return math.Floor((anlToNumber(anlGet(a, "t"))-t0)/m) == math.Floor((anlToNumber(anlGet(x, "t"))-t0)/m)
	}
	return false
}

// goalRefFsum is `xs.reduce((s, x) => s + x, 0)` as the reference port reads it: numbers add, anything else concatenates.
func goalRefFsum(xs []any) any {
	var s any = 0.0
	for _, x := range xs {
		sf, sNum := s.(float64)
		xf, xNum := jsNum(x)
		if sNum && xNum {
			s = sf + xf
		} else {
			s = anlJS(s) + anlJS(x)
		}
	}
	return s
}

func goalRefDecide(g, ont, a, h any) int { return goalRefExplain(g, ont, a, h)["d"].(int) }

// goalRefExplain is `{d, witness, prohibit}`: the decision, the first grant (goal order) whose own decision is Allow (null unless
// d = 2), and the meet over the prohibitions alone (0 one fires, 1 one is unknown, 2 none applies).
func goalRefExplain(g, ont, a, h any) map[string]any {
	d, prohibit := 2, 2
	var witness any
	v := anlGet(g, "validity")
	t := anlGet(a, "t")
	deleg := anlGet(g, "deleg")
	last := anlGet(h, "last")
	depth := anlGet(a, "depth")
	switch {
	case anlLt(t, anlGet(v, "notBefore")) || anlGt(t, anlGet(v, "notAfter")):
		d = 0
	case anlGt(anlGet(v, "maxIdle"), 0) && !anlLt(last, 0) && anlToNumber(last) == anlToNumber(last) &&
		anlGt(anlToNumber(t)-anlToNumber(last), anlGet(v, "maxIdle")):
		d = 0
	case anlLt(depth, 0) || anlGt(depth, anlGet(deleg, "maxDepth")):
		d = 0
	}
	for _, p := range anlReqList(anlGet(g, "prohibits")) {
		tg := anlGet(p, "target")
		var verbs []any
		if anlGet(tg, "k") == "verb" {
			verbs = []any{anlGet(tg, "verb")}
		} else {
			verbs = goalRefVerbsOf(ont, anlGet(tg, "cls"))
		}
		m1 := goalRefB2t(anlIncludes(verbs, anlGet(a, "verb")))
		m2 := goalRefB2t(goalRefResOk(anlGet(p, "res"), ont, anlGet(a, "res")))
		m := min(m1, min(m2, goalRefEvalC(anlGet(p, "cond"), a, h)))
		pd := 2
		if m == 2 {
			pd = 0
		} else if m == 1 {
			pd = 1
		}
		d = min(d, pd)
		prohibit = min(prohibit, pd)
	}
	for _, c := range anlReqList(anlGet(g, "escalateOn")) {
		if goalRefEvalC(c, a, h) == 0 {
			d = min(d, 2)
		} else {
			d = min(d, 1)
		}
	}
	best := 0
	for _, gr := range anlReqList(anlGet(g, "grants")) {
		verbOk := anlStrictEq(anlGet(a, "verb"), anlGet(gr, "verb")) &&
			(anlStrictEq(depth, 0) || anlIncludes(anlGet(deleg, "mayTouch"), anlGet(gr, "gid")))
		m1 := goalRefB2t(verbOk)
		m2 := goalRefB2t(goalRefResOk(anlGet(gr, "res"), ont, anlGet(a, "res")))
		gd := min(m1, min(m2, goalRefEvalC(anlGet(gr, "cond"), a, h)))
		for _, b := range anlReqList(anlGet(g, "bounds")) {
			if e := goalRefBound(b, gr, a, h, ont); e >= 0 {
				gd = min(gd, e)
			}
		}
		if gd == 2 && witness == nil {
			witness = anlGet(gr, "gid")
		}
		best = max(best, gd)
	}
	d = min(d, best)
	if d != 2 {
		witness = nil
	}
	return anlU(map[string]any{"d": d, "witness": witness, "prohibit": prohibit})
}

// goalRefBound is the decision a bound allows its grant `gr` (0 deny, 1 escalate, 2 allow), or -1 when the bound does not select
// the grant or the action's verb.
func goalRefBound(b, gr, a, h, ont any) int {
	sel := anlGet(b, "sel")
	var gids, verbs any = []any{}, []any{}
	if anlGet(sel, "k") == "gids" {
		gids = anlGet(sel, "gids")
	}
	if anlGet(sel, "k") == "effect" {
		verbs = goalRefVerbsOf(ont, anlGet(sel, "cls"))
	}
	if !(anlIncludes(gids, anlGet(gr, "gid")) || anlIncludes(verbs, anlGet(a, "verb"))) {
		return -1
	}
	items := []any{}
	for _, x := range anlReqList(anlGet(h, "adms")) {
		xa := anlGet(x, "act")
		if (anlIncludes(gids, anlGet(x, "gid")) || anlIncludes(verbs, anlGet(xa, "verb"))) &&
			goalRefInScope(anlGet(b, "scope"), a, xa) && goalRefInWin(anlGet(b, "window"), a, xa) {
			items = append(items, xa)
		}
	}
	items = append(items, a)
	capv := anlGet(b, "cap")
	agg := anlGet(b, "agg")
	var ex int
	switch agg {
	case "count":
		ex = goalRefB2t(anlGt(len(items), anlGet(capv, "n")))
	case "sum", "max":
		xs := []any{}
		ok := true
		for _, it := range items {
			val := goalRefVal(anlGet(b, "value"), it, h)
			if !anlTruthy(val) || anlGet(val, "k") != "q" || !goalRefSameUnit(anlGet(anlGet(val, "q"), "u"), anlGet(capv, "u")) {
				ok = false
				break
			}
			xs = append(xs, anlGet(anlGet(val, "q"), "n"))
		}
		switch {
		case !ok:
			ex = 1
		case agg == "sum":
			ex = goalRefB2t(anlGt(goalRefFsum(xs), anlGet(capv, "n")))
		case len(xs) == 0:
			ex = 1
		default:
			mx := math.Inf(-1)
			for _, x := range xs {
				n := anlToNumber(x)
				if n != n {
					mx = math.NaN()
					break
				}
				mx = math.Max(mx, n)
			}
			ex = goalRefB2t(anlGt(mx, anlGet(capv, "n")))
		}
	default:
		seen := map[string]bool{}
		ok := true
		key := anlGet(b, "key")
		for _, it := range items {
			ip := anlGet(it, "params")
			if !goalRefHas(ip, key) {
				ok = false
				break
			}
			seen[anlJSON(ip.(map[string]any)[key.(string)])] = true
		}
		if ok {
			ex = goalRefB2t(anlGt(len(seen), anlGet(capv, "n")))
		} else {
			ex = 1
		}
	}
	switch ex {
	case 2:
		if anlGet(b, "onExceed") == "deny" {
			return 0
		}
		return 1
	case 1:
		return 1
	}
	return 2
}

// GoalRefDecide is the reference decision of a goal for an action: 0 deny, 1 escalate, 2 allow.
func GoalRefDecide(g, ont, a, h any) (d int, err error) {
	_, err = anlTry(func() any { d = goalRefDecide(g, ont, a, h); return nil })
	return
}

// GoalRefExplain is {d, witness, prohibit}: the decision, the first allowing grant, and the meet over the prohibitions alone.
func GoalRefExplain(g, ont, a, h any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalRefExplain(g, ont, a, h); return nil })
	return
}
