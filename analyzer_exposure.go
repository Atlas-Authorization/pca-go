package pca

// Quantitative and ternary static queries over a policy: the most that can ever be spent, the actions that need a human, the reach of
// a delegation chain, a first-class diff of two policies, and the check of an external solver's answer.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const anlHuge = 9007199254740991.0

var anlInf = math.Inf(1)

func anlCondThresholds(c any, path string, into *[]any) {
	m, ok := c.(map[string]any)
	if !ok {
		return
	}
	if anlIsGroup(m) {
		if xs, ok := m["all_of"].([]any); ok {
			for _, x := range xs {
				anlCondThresholds(x, path, into)
			}
		} else if xs, ok := m["any_of"].([]any); ok {
			for _, x := range xs {
				anlCondThresholds(x, path, into)
			}
		} else if n, has := m["not"]; has {
			anlCondThresholds(n, path, into)
		}
		return
	}
	leaf, ok := anlLeaf(m)
	if !ok || leaf["field"] != path {
		return
	}
	v := anlOwn(m, "value")
	if anlIsFin(v) {
		*into = append(*into, v)
	} else if xs, ok := v.([]any); ok {
		for _, x := range xs {
			if anlIsFin(x) {
				*into = append(*into, x)
			}
		}
	}
}

// anlThresholdsOf is every numeric literal the policy compares `path` against, ascending and de-duplicated.
func anlThresholdsOf(model map[string]any, path string) []any {
	out := []any{}
	for _, p := range anlProbeSet(model) {
		for _, c := range anlReqList(anlNN(anlGet(p, "where"), []any{})) {
			anlCondThresholds(c, path, &out)
		}
	}
	for _, v := range model["vetoes"].([]any) {
		over := anlGet(v, "over")
		if anlTruthy(over) && anlGet(over, "path") == path && anlIsNum(anlGet(over, "threshold")) {
			out = append(out, anlGet(over, "threshold"))
		}
	}
	seen := map[float64]any{}
	keys := []float64{}
	for _, x := range out {
		f := anlToNumber(x)
		if _, has := seen[f]; !has {
			seen[f] = x
			keys = append(keys, f)
		}
	}
	sort.Float64s(keys)
	res := make([]any, len(keys))
	for i, k := range keys {
		res[i] = seen[k]
	}
	return res
}

func anlPinned(pr *anlProbes, path string, value any, resource any) *anlProbes {
	c := *pr
	if !anlIsUndef(resource) {
		c.resources = []any{resource}
	}
	c.fields = nil
	for _, f := range pr.fields {
		if f.path != path {
			c.fields = append(c.fields, f)
		}
	}
	c.fields = append(c.fields, anlField{path: path, values: []any{value}})
	return &c
}

func anlUnboundedPeak() map[string]any {
	return map[string]any{"admitted": true, "max": anlInf, "attained": false}
}

// anlPeakAt is the largest amount the policy admits (level "admit": anything but a deny; "allow": without a human).
func anlPeakAt(model map[string]any, o map[string]any, level string) (map[string]any, bool) {
	fname := anlJS(anlNN(anlOwn(o, "amountField"), "amount"))
	path := "action.params." + fname
	mx := anlBound(o)
	base := anlProbesFor([]map[string]any{model}, nil)
	base.verbs = []any{anlOwn(o, "verb")}
	var T []float64
	for _, x := range anlThresholdsOf(model, path) {
		T = append(T, anlToNumber(x))
	}
	lo := math.Max(0, anlToNumber(anlNN(anlOwn(o, "min"), 0)))
	hi := anlToNumber(anlNN(anlOwn(o, "max"), anlInf))
	var raw []float64
	for i, t := range T {
		raw = append(raw, t-1, t)
		if i+1 < len(T) {
			raw = append(raw, (t+T[i+1])/2)
		}
	}
	if len(T) > 0 {
		raw = append(raw, T[len(T)-1]+1)
	} else {
		raw = append(raw, 0)
	}
	raw = append(raw, anlHuge, lo)
	if !math.IsInf(hi, 0) && !math.IsNaN(hi) {
		raw = append(raw, hi)
	}
	uniq := map[float64]bool{}
	var cands []float64
	for _, c := range raw {
		if !uniq[c] {
			uniq[c] = true
			if lo <= c && c <= hi && !math.IsInf(c, 0) && !math.IsNaN(c) {
				cands = append(cands, c)
			}
		}
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(cands)))
	resource := anlOwn(o, "resource")
	pred := func(rep *anlRep) bool {
		d := anlDecide(model, rep)
		if level == "allow" {
			return d == "allow"
		}
		return d != "deny"
	}
	for _, c := range cands {
		hit, overflow := anlSearch(anlPinned(base, path, c, resource), pred, mx)
		if overflow {
			return map[string]any{"admitted": false, "max": 0, "attained": false}, true
		}
		if hit == nil {
			continue
		}
		h := hit
		act := func(v float64) map[string]any {
			a := anlRepToAction(h)
			p := anlCopy(a["params"].(map[string]any))
			p[fname] = v
			a["params"] = p
			return a
		}
		holds := func(a map[string]any) bool {
			d := anlDecideAction(model, a)
			if level == "allow" {
				return d == "allow"
			}
			return d != "deny"
		}
		top := math.Inf(-1)
		if len(T) > 0 {
			top = T[len(T)-1]
		}
		if c > top {
			if !math.IsInf(hi, 0) && !math.IsNaN(hi) {
				w := act(hi)
				return map[string]any{"admitted": true, "max": hi, "attained": holds(w), "witness": w}, false
			}
			return map[string]any{"admitted": true, "max": anlInf, "attained": false, "witness": act(anlHuge)}, false
		}
		for _, t := range T {
			if t == c {
				return map[string]any{"admitted": true, "max": c, "attained": true, "witness": act(c)}, false
			}
		}
		nxt := 0.0
		for _, t := range T {
			if t > c {
				nxt = t
				break
			}
		}
		if anlOwn(o, "integer") == true {
			m := math.Ceil(nxt) - 1
			if m >= c {
				if w := act(m); holds(w) {
					return map[string]any{"admitted": true, "max": m, "attained": true, "witness": w}, false
				}
			}
		}
		return map[string]any{"admitted": true, "max": nxt, "attained": false, "witness": act(c)}, false
	}
	return map[string]any{"admitted": false, "max": 0, "attained": false}, false
}

func anlLen(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case string:
		return len(utf16Units(t))
	}
	anlFail("cannot read properties of %s (reading 'length')", map[bool]string{true: "null", false: "undefined"}[v == nil])
	return 0
}

func anlUniversal(p, verb any) bool {
	pv := anlGet(p, "verb")
	verbOK := anlStrictEq(pv, "*") || anlStrictEq(pv, verb)
	if l, ok := pv.([]any); ok && !verbOK {
		verbOK = anlIncludes(l, "*") || anlIncludes(l, verb)
	}
	res := anlGet(p, "resource")
	where := anlGet(p, "where")
	if where == nil {
		anlFail("cannot read properties of null (reading 'length')")
	}
	whereEmpty := anlIsUndef(where)
	if !whereEmpty {
		if l, ok := where.([]any); ok {
			whereEmpty = len(l) == 0
		} else if s, ok := where.(string); ok {
			whereEmpty = len(s) == 0
		}
	}
	return verbOK && (anlIsUndef(res) || anlStrictEq(res, "*")) && whereEmpty
}

func anlCeilDiv(a, b any) float64 {
	q := anlToNumber(a) / anlToNumber(b)
	if math.IsInf(q, 0) || math.IsNaN(q) {
		return q
	}
	return math.Ceil(q)
}

func anlBuiltinBlast(verb any) float64 {
	if s, ok := verb.(string); ok {
		for _, a := range BuiltinActions {
			if a.Verb == s {
				return a.BlastRadius
			}
		}
	}
	return 1
}

func anlWindowBound(model map[string]any, c any, o map[string]any, peak map[string]any) map[string]any {
	W := anlOwn(o, "windowSecs")
	path := "action.params." + anlJS(anlNN(anlOwn(o, "amountField"), "amount"))
	per := 0.0
	if peak["admitted"] == true {
		per = anlToNumber(peak["max"])
	}
	basis := []any{}
	notApplied := []any{}
	maxActions := anlInf
	limitActions := func(n, perSecs any, why string) {
		k := anlInf
		if !anlIsUndef(W) {
			k = anlToNumber(n) * anlCeilDiv(W, perSecs)
		}
		if k < maxActions {
			maxActions = k
			basis = append(basis, why)
		}
	}
	caveats := append([]any{}, model["caveats"].([]any)...)
	for _, m := range model["meets"].([]any) {
		caveats = append(caveats, m.(map[string]any)["caveats"].([]any)...)
	}
	invs := []any{}
	if cm, ok := c.(map[string]any); ok {
		if l, ok := cm["invariants"].([]any); ok {
			invs = l
		}
	}
	for _, cv := range caveats {
		mx, ps := anlGet(cv, "max"), anlGet(cv, "per_secs")
		if anlGet(cv, "type") == "rate" && anlIsNum(mx) && anlIsNum(ps) && anlToNumber(ps) > 0 {
			limitActions(mx, ps, fmt.Sprintf("rate caveat %s/%ss", anlNumStr(anlToNumber(mx)), anlNumStr(anlToNumber(ps))))
		}
	}
	for _, inv := range invs {
		if anlGet(inv, "kind") != "rate" {
			continue
		}
		if anlUniversal(anlGet(inv, "when"), anlOwn(o, "verb")) {
			limitActions(anlGet(inv, "max"), anlGet(inv, "window_secs"), "rate invariant "+anlJS(anlGet(inv, "id")))
		} else {
			notApplied = append(notApplied, anlGet(inv, "id"))
		}
	}
	var bound float64
	switch {
	case per == 0:
		bound = 0
	case math.IsInf(maxActions, 1):
		bound = anlInf
	default:
		bound = per * maxActions
	}
	if !math.IsInf(per, 0) && !math.IsNaN(per) && per > 0 {
		basis = append([]any{"per-action ceiling"}, basis...)
	}
	for _, cv := range caveats {
		lim := anlGet(cv, "limit")
		if anlGet(cv, "type") != "budget_alloc" || !anlIsNum(lim) {
			continue
		}
		limF := anlToNumber(lim)
		bm := anlOwn(o, "budgetModel")
		kappa := anlOwn(o, "kappa")
		if bm == "dollars" {
			if limF < bound {
				bound = limF
				basis = append(basis, "budget_alloc limit "+anlNumStr(limF))
			}
		} else if bm == "risk" && anlIsNum(kappa) && anlToNumber(kappa) > 0 {
			r := anlOwn(o, "blastRadius")
			var rf float64
			if anlIsUndef(r) || r == nil {
				rf = anlBuiltinBlast(anlOwn(o, "verb"))
			} else {
				rf = anlToNumber(r)
			}
			cost := anlToNumber(kappa) * math.Min(1, math.Max(0, rf))
			n := anlInf
			if cost > 0 {
				n = math.Floor(limF / cost)
			}
			if n < maxActions {
				maxActions = n
				if n == 0 {
					bound = 0
				} else if !math.IsInf(per, 0) && !math.IsNaN(per) && per > 0 {
					bound = per * n
				}
				basis = append(basis, fmt.Sprintf("budget_alloc %s / cost %s = %s actions", anlNumStr(limF), anlNumStr(cost), anlNumStr(n)))
			}
		} else {
			notApplied = append(notApplied, "budget_alloc "+anlNumStr(limF)+" (trust-budget units; pass budgetModel and kappa)")
		}
	}
	for _, inv := range invs {
		if anlGet(inv, "kind") != "cap" {
			continue
		}
		if !anlUniversal(anlGet(inv, "when"), anlOwn(o, "verb")) || anlGet(inv, "amount") != path {
			notApplied = append(notApplied, anlGet(inv, "id"))
			continue
		}
		ws := anlGet(inv, "window_secs")
		if !anlIsUndef(ws) && anlIsUndef(W) {
			continue // a windowed cap says nothing about a lifetime total
		}
		cap := anlToNumber(anlGet(inv, "max"))
		if !anlIsUndef(ws) && !anlIsUndef(W) {
			cap = cap * anlCeilDiv(W, ws)
		}
		if cap < bound {
			bound = cap
			basis = append(basis, "cap invariant "+anlJS(anlGet(inv, "id")))
		}
	}
	na := []any{}
	for _, x := range notApplied {
		if !anlIsUndef(x) {
			na = append(na, x)
		}
	}
	out := map[string]any{"maxActions": maxActions, "bound": bound, "basis": basis, "notApplied": na}
	if !anlIsUndef(W) {
		out["secs"] = W
	}
	pm := anlToNumber(peak["max"])
	if w, ok := peak["witness"]; ok && peak["admitted"] == true && w != nil && !math.IsInf(maxActions, 0) && !math.IsNaN(maxActions) &&
		!math.IsInf(pm, 0) && !math.IsNaN(pm) && pm > 0 {
		out["sequence"] = map[string]any{"action": w, "repeat": maxActions}
	}
	return out
}

func anlApproxReason(overflow bool, undecidable []any) string {
	if overflow {
		return "representative grid exceeded the bound"
	}
	return "over-approximated (" + anlJoin(undecidable, "; ") + ")"
}

// anlMaxExposure is the most that can ever leave under a policy: the largest single action, the largest autonomous action and the
// windowed total.
func anlMaxExposure(policy, given any) map[string]any {
	o := map[string]any{}
	if g, ok := given.(map[string]any); ok {
		o = anlCopy(g)
	}
	if anlIsUndef(anlGet(given, "budgetModel")) {
		bm := anlGet(policy, "budgetModel")
		if bm == "dollars" || bm == "risk" {
			o["budgetModel"] = bm
		}
	}
	if anlIsUndef(anlGet(given, "kappa")) {
		rp := anlGet(policy, "riskPolicy")
		pk := anlUndef
		if !anlIsUndef(rp) && rp != nil {
			pk = anlGet(rp, "kappa")
		}
		if anlIsNum(pk) {
			o["kappa"] = pk
		}
	}
	c := anlOwn(o, "constitution")
	var cv map[string]any
	if !anlIsUndef(c) {
		cv = anlVetoesFromConstitution(c)
	}
	base := anlToModel(policy)
	model := base
	if cv != nil {
		model = anlCopy(base)
		model["vetoes"] = append(append([]any{}, base["vetoes"].([]any)...), cv["vetoes"].([]any)...)
	}
	admit, aOver := anlPeakAt(model, o, "admit")
	auto, uOver := anlPeakAt(model, o, "allow")
	und := model["undecidable"].([]any)
	approximate := aOver || uOver || len(und) > 0
	ap, up := admit, auto
	if aOver {
		ap = anlUnboundedPeak()
	}
	if uOver {
		up = anlUnboundedPeak()
	}
	unmodeled := []any{}
	if cv != nil {
		for _, u := range cv["unmodeled"].([]any) {
			um := u.(map[string]any)
			if k := um["kind"]; k != "cap" && k != "rate" {
				unmodeled = append(unmodeled, anlJS(anlOwn(um, "id"))+": "+anlJS(um["reason"]))
			}
		}
	}
	e := anlU(map[string]any{
		"verb": anlOwn(o, "verb"), "amountField": anlNN(anlOwn(o, "amountField"), "amount"),
		"perAction": ap, "autonomousPerAction": up,
		"window": anlWindowBound(model, c, o, ap), "autonomousWindow": anlWindowBound(model, c, o, up),
		"unmodeled": unmodeled,
	})
	if approximate {
		e["approximate"] = true
		e["reason"] = "representative grid exceeded the bound; exposure reported as unbounded"
		if !aOver && !uOver {
			e["reason"] = anlApproxReason(false, und)
		}
	}
	return e
}

func anlWithVerbs(pr *anlProbes, verbs []any) *anlProbes {
	c := *pr
	c.verbs = verbs
	return &c
}

// anlEscalationSurface is the set of actions admitted only with a human: {escalates, witnesses, approximate?, reason?}.
func anlEscalationSurface(policy, opts any) map[string]any {
	if opts == nil || anlIsUndef(opts) {
		opts = map[string]any{}
	}
	model := anlToModel(policy)
	base := anlProbesFor([]map[string]any{model}, nil)
	if verb := anlGet(opts, "verb"); !anlIsUndef(verb) {
		base.verbs = []any{verb}
	}
	limit := int(math.Max(0, math.Min(anlToNumber(anlNN(anlGet(opts, "limit"), 8)), 1<<30)))
	hits, overflow := anlCollect(base, func(r *anlRep) bool { return anlDecide(model, r) == "escalate" }, anlBound(opts), limit)
	witnesses := []any{}
	for _, h := range hits {
		if a := anlRepToAction(h); anlDecideAction(model, a) == "escalate" {
			witnesses = append(witnesses, a)
		}
	}
	und := model["undecidable"].([]any)
	out := map[string]any{"escalates": len(witnesses) > 0, "witnesses": witnesses}
	if overflow || len(und) > 0 {
		out["approximate"] = true
		out["reason"] = anlApproxReason(overflow, und)
	}
	return out
}

// anlDelegationEnvelope is the join of everything any holder of the leaf could do, with the remaining delegation depth.
func anlDelegationEnvelope(chainIn, opts any) map[string]any {
	chain := anlReqList(chainIn)
	var leaf any = anlUndef
	if len(chain) > 0 {
		leaf = chain[len(chain)-1]
	}
	var policy any
	switch lm := leaf.(type) {
	case map[string]any:
		extra := anlOwn(lm, "meet")
		var ex []any
		if anlTruthy(extra) {
			l, ok := extra.([]any)
			if !ok {
				anlFail("meet is not iterable")
			}
			ex = l
		}
		p := anlCopy(lm)
		p["meet"] = append(append([]any{}, chain[:len(chain)-1]...), ex...)
		policy = p
	case []any:
		policy = map[string]any{"meet": append([]any{}, chain[:len(chain)-1]...)}
	default:
		policy = map[string]any{"predicates": []any{}}
	}
	model := anlToModel(policy)
	base := anlProbesFor([]map[string]any{model}, nil)
	mx := anlBound(opts)
	verbs := []any{}
	anyVerb := false
	overflow := false
	for _, verb := range base.verbs {
		hits, ov := anlCollect(anlWithVerbs(base, []any{verb}), func(r *anlRep) bool { return anlDecide(model, r) != "deny" }, mx, 1)
		if ov {
			overflow = true
			break
		}
		if len(hits) == 0 {
			continue
		}
		hit := hits[0]
		if s, ok := verb.(string); ok && strings.HasPrefix(s, "\x00") {
			anyVerb = true
		} else {
			verbs = append(verbs, map[string]any{"verb": verb, "witness": anlRepToAction(hit), "autonomous": anlDecide(model, hit) == "allow"})
		}
	}
	violations := []any{}
	for i := 0; i < len(chain)-1; i++ {
		a, b := anlToModel(chain[i]), anlToModel(chain[i+1])
		pr := anlProbesFor([]map[string]any{a, b}, nil)
		hit, ov := anlSearch(pr, func(r *anlRep) bool { return anlDecide(b, r) != "deny" && anlDecide(a, r) == "deny" }, mx)
		if hit != nil || ov {
			violations = append(violations, i+1)
		}
	}
	var depths []float64
	for _, p := range chain {
		if pm, ok := p.(map[string]any); ok {
			if cvs, ok := pm["caveats"].([]any); ok {
				for _, c := range cvs {
					if anlGet(c, "type") == "delegation_depth" && anlIsNum(anlGet(c, "max")) {
						depths = append(depths, anlToNumber(anlGet(c, "max")))
					}
				}
			}
		}
	}
	used := math.Max(0, float64(len(chain)-1))
	depth := map[string]any{"used": used}
	if len(depths) > 0 {
		allowed := depths[0]
		for _, d := range depths[1:] {
			if d < allowed {
				allowed = d
			}
		}
		depth["allowed"] = allowed
		depth["remaining"] = math.Max(0, allowed-used)
	}
	out := map[string]any{"violations": violations, "verbs": verbs, "anyVerb": anyVerb, "depth": depth}
	und := model["undecidable"].([]any)
	if overflow || len(und) > 0 {
		out["approximate"] = true
		out["reason"] = anlApproxReason(overflow, und)
	}
	return out
}

var anlWiden = []string{"deny->allow", "deny->escalate", "escalate->allow"}

func anlIsWiden(k string) bool {
	for _, w := range anlWiden {
		if k == w {
			return true
		}
	}
	return false
}

func anlSub(x, y float64) float64 {
	if x == y {
		return 0
	}
	return x - y
}

func anlNumField(m any, k string) float64 { return anlToNumber(anlGet(m, k)) }

// anlDiffPolicies is `diff(A, B)`: which actions move between allow / escalate / deny, with witnesses, and optionally how the max
// exposure moved.
func anlDiffPolicies(a, b, optsIn any) map[string]any {
	o := optsIn
	if o == nil || anlIsUndef(o) {
		o = map[string]any{}
	}
	ma, mb := anlToModel(a), anlToModel(b)
	pr := anlProbesFor([]map[string]any{ma, mb}, nil)
	limit := anlToNumber(anlNN(anlGet(o, "limit"), 4))
	shifts := map[string][]any{}
	var kinds []string
	counts := map[string]float64{}
	walkOver := false
	{
		_, ov := anlCollect(pr, func(rep *anlRep) bool {
			x, y := anlDecide(ma, rep), anlDecide(mb, rep)
			if x == y {
				return false
			}
			k := x + "->" + y
			n := counts[k]
			counts[k] = n + 1
			if n < limit {
				if _, has := shifts[k]; !has {
					kinds = append(kinds, k)
				}
				shifts[k] = append(shifts[k], anlRepToAction(rep))
			}
			return false
		}, anlBound(o), 1)
		walkOver = ov
	}
	widens, narrows := false, false
	for _, k := range kinds {
		if anlIsWiden(k) {
			widens = true
		} else {
			narrows = true
		}
	}
	summary := []any{}
	shiftsOut := map[string]any{}
	for _, k := range kinds {
		first := shifts[k][0].(map[string]any)
		params := anlNN(first["params"], map[string]any{})
		summary = append(summary, fmt.Sprintf("%s: %d+ action(s), e.g. %s %s %s", k, len(shifts[k]), anlJS(first["verb"]), anlJS(first["resource"]), anlJSON(params)))
		shiftsOut[k] = shifts[k]
	}
	ua, ub := ma["undecidable"].([]any), mb["undecidable"].([]any)
	d := map[string]any{
		"equivalent": len(kinds) == 0 && !walkOver && len(ua) == 0 && len(ub) == 0,
		"shifts":     shiftsOut, "widens": widens, "narrows": narrows,
	}
	if ex := anlGet(o, "exposure"); !anlIsUndef(ex) {
		before, after := anlMaxExposure(a, ex), anlMaxExposure(b, ex)
		e := map[string]any{
			"before": before, "after": after,
			"perActionDelta":  anlSub(anlNumField(after["perAction"], "max"), anlNumField(before["perAction"], "max")),
			"autonomousDelta": anlSub(anlNumField(after["autonomousWindow"], "bound"), anlNumField(before["autonomousWindow"], "bound")),
			"delta":           anlSub(anlNumField(after["window"], "bound"), anlNumField(before["window"], "bound")),
		}
		d["exposure"] = e
		dl, pa, au := e["delta"].(float64), e["perActionDelta"].(float64), e["autonomousDelta"].(float64)
		worst := math.Max(dl, math.Max(pa, au))
		best := math.Min(dl, pa)
		verb := anlJS(anlGet(ex, "verb"))
		if worst > 0 {
			summary = append(summary, "max exposure of "+verb+" rises by "+anlNumStr(worst))
		} else if best < 0 {
			summary = append(summary, "max exposure of "+verb+" falls by "+anlNumStr(-best))
		}
	}
	d["summary"] = summary
	if walkOver || len(ua) > 0 || len(ub) > 0 {
		d["approximate"] = true
		seen := &anlSet{}
		for _, r := range append(append([]any{}, ua...), ub...) {
			seen.add(r.(string))
		}
		if walkOver {
			d["reason"] = "representative grid exceeded the bound"
		} else {
			d["reason"] = "over-approximated (" + strings.Join(seen.keys, "; ") + ")"
		}
	}
	return d
}

// anlDiffGate is a CI gate over a diff: it fails when the change widens authority beyond what the reviewer allowed.
func anlDiffGate(d, allowIn any) map[string]any {
	allow := allowIn
	if allow == nil || anlIsUndef(allow) {
		allow = map[string]any{}
	}
	reasons := []any{}
	if anlGet(d, "widens") == true && anlGet(allow, "widen") != true {
		var ws []string
		if l, ok := anlGet(d, "summary").([]any); ok {
			for _, s := range l {
				str := anlJS(s)
				for _, w := range anlWiden {
					if strings.HasPrefix(str, w) {
						ws = append(ws, str)
						break
					}
				}
			}
		} else {
			anlFail("d.summary is not iterable")
		}
		reasons = append(reasons, "widens authority: "+strings.Join(ws, "; "))
	}
	rise := 0.0
	if ex := anlGet(d, "exposure"); anlTruthy(ex) {
		rise = math.Max(anlToNumber(anlGet(ex, "delta")), math.Max(anlToNumber(anlGet(ex, "perActionDelta")), anlToNumber(anlGet(ex, "autonomousDelta"))))
	}
	if rise > anlToNumber(anlNN(anlGet(allow, "maxExposureIncrease"), 0)) {
		reasons = append(reasons, "max exposure rises by "+anlNumStr(rise))
	}
	if anlTruthy(anlGet(d, "approximate")) {
		reasons = append(reasons, "inconclusive: "+anlJS(anlNN(anlGet(d, "reason"), "approximate")))
	}
	return map[string]any{"ok": len(reasons) == 0, "reasons": reasons}
}

// anlFindWithBackend checks what an optional external solver returned: a witness is re-checked by the real evaluator (never trusted);
// an unsat claim is returned labelled as solver-claimed.
func anlFindWithBackend(q any, name any, result any) map[string]any {
	w := anlGet(result, "witness")
	if !anlIsUndef(w) {
		ma := anlToModel(anlGet(q, "a"))
		qb := anlGet(q, "b")
		qv := anlGet(q, "verb")
		var ok bool
		if anlGet(q, "kind") == "reachable" {
			ok = anlDecideAction(ma, w) != "deny" && (anlIsUndef(qv) || anlStrictEq(anlGet(w, "verb"), qv))
		} else {
			ok = !anlIsUndef(qb) && ((anlDecideAction(ma, w) != "deny") != (anlDecideAction(anlToModel(qb), w) != "deny"))
		}
		if ok {
			return map[string]any{"witness": w}
		}
		return map[string]any{"rejected": true}
	}
	if anlGet(result, "unsat") == true {
		return map[string]any{"claimedUnsat": map[string]any{"by": name, "proof": "solver-claimed, not machine-checked"}}
	}
	return map[string]any{}
}
