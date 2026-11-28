package pca

// The learner-bound parts of the classifier, frame and just-in-time modules: classifier-aware residual risk and the cells it sends
// to consent, folding a frame violation back into the learner, the ordered lazy-elicitation decision and the delta between two
// learners' grants.

import (
	"math"
	"sort"
	"strings"
)

// ixLpGroups are the cells of a classifier spec's verb grouped by every dimension but the categorical classifier one, in cell order.
type ixLpGroup struct {
	byIdx map[int]map[string]any
	order []int
}

func ixLpGroupsOf(l *IntentLearner, spec map[string]any) (dim map[string]any, vs map[string]any, groups []*ixLpGroup) {
	vs = ixMaFindVerb(l.omega, spec["verb"])
	if vs == nil {
		ixFail("classifier: no verb %s in Ω", jsValueString(spec["verb"]))
	}
	k := -1
	for i, d := range ixL(vs["dims"]) {
		if ixM(d)["path"] == spec["path"] {
			k = i
			break
		}
	}
	if k < 0 || ixM(ixL(vs["dims"])[k])["kind"] != "cat" {
		ixFail("classifier: %s has no categorical dimension %s", jsValueString(spec["verb"]), jsValueString(spec["path"]))
	}
	dim = ixM(ixL(vs["dims"])[k])
	byKey := map[string]*ixLpGroup{}
	for _, cv := range l.Cells() {
		c := ixM(cv)
		if c["verb"] != spec["verb"] {
			continue
		}
		cell := ixL(c["cell"])
		var parts []string
		for i, x := range cell {
			if i != k {
				parts = append(parts, jsNumberString(ixF(x)))
			}
		}
		key := strings.Join(parts, ",")
		g := byKey[key]
		if g == nil {
			g = &ixLpGroup{byIdx: map[int]map[string]any{}}
			byKey[key] = g
			groups = append(groups, g)
		}
		ci := ixIdx(cell[k])
		if _, ok := g.byIdx[ci]; !ok {
			g.order = append(g.order, ci)
		}
		g.byIdx[ci] = map[string]any{"cell": c["cell"], "p": c["p"], "mass": c["mass"], "harm": c["harm"], "inGrant": c["inGrant"]}
	}
	return dim, vs, groups
}

func ixLpGbar(spec, dim map[string]any, pred, truth int) float64 {
	pv, tv := ixM(ixL(dim["values"])[pred]), ixM(ixL(dim["values"])[truth])
	if pv["kind"] != "exact" {
		return 0
	}
	cal := ixM(spec["cal"])
	labels := ixL(cal["labels"])
	idx := func(v any) int {
		for i, x := range labels {
			if x == v {
				return i
			}
		}
		return -1
	}
	pi := idx(pv["value"])
	if pi < 0 {
		return 0
	}
	ti := -1
	if tv["kind"] == "exact" {
		ti = idx(tv["value"])
	}
	if ti < 0 {
		return 1
	}
	return ixF(ixL(ixL(cal["gammaBar"])[ti])[pi])
}

func ixLpSumGbar(spec, dim map[string]any, A []int, t int) float64 {
	s := 0.0
	for _, p := range A {
		s += ixLpGbar(spec, dim, p, t)
	}
	return s
}

func (g *ixLpGroup) admitted() []int {
	var A []int
	for _, i := range g.order {
		if g.byIdx[i]["inGrant"] == true {
			A = append(A, i)
		}
	}
	return A
}

// IntentClassifierAwareResidualRisk is R-hat of the learner's grant with classifier error folded in; other verbs contribute the
// ordinary sum. specs: {verb, path, cal}.
func IntentClassifierAwareResidualRisk(l *IntentLearner, specs []any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixLpAware(l, specs) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixLpAware(l *IntentLearner, specs []any) map[string]any {
	perVerb := map[string]float64{}
	var order []string
	set := func(v string, x float64) {
		if _, ok := perVerb[v]; !ok {
			order = append(order, v)
		}
		perVerb[v] = x
	}
	specVerbs := map[any]bool{}
	for _, sv := range specs {
		specVerbs[ixM(sv)["verb"]] = true
	}
	for _, cv := range l.Cells() {
		c := ixM(cv)
		if specVerbs[c["verb"]] {
			continue
		}
		v := ixS(c["verb"])
		prev := perVerb[v]
		if c["inGrant"] == true {
			set(v, prev+float64(ixF(c["mass"])*(1-ixF(c["p"]))*ixF(c["harm"])))
		} else {
			set(v, prev)
		}
	}
	for _, sv := range specs {
		spec := ixM(sv)
		dim, _, groups := ixLpGroupsOf(l, spec)
		r := 0.0
		for _, g := range groups {
			A := g.admitted()
			for _, t := range g.order {
				m := g.byIdx[t]
				r += float64(ixF(m["mass"]) * (1 - ixF(m["p"])) * ixF(m["harm"]) * math.Min(1, ixLpSumGbar(spec, dim, A, t)))
			}
		}
		set(ixS(spec["verb"]), r)
	}
	total := 0.0
	pv := map[string]any{}
	for _, v := range order {
		total += perVerb[v]
		pv[v] = perVerb[v]
	}
	return map[string]any{"total": total, "perVerb": pv}
}

// IntentClassifierJitCells are the cells admitted on a classifier label that go to JIT consent: some true label the grant does not
// admit at the same x has an upper-bounded mislabel rate above gammaMax.
func IntentClassifierJitCells(l *IntentLearner, spec map[string]any, gammaMax float64) ([]any, error) {
	r, err := ixTry(func() any { return ixLpJitCells(l, spec, gammaMax) })
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func ixLpJitCells(l *IntentLearner, spec map[string]any, gammaMax float64) []any {
	dim, vs, groups := ixLpGroupsOf(l, spec)
	var out []map[string]any
	for _, g := range groups {
		A := g.admitted()
		if len(A) == 0 {
			continue
		}
		worst := 0.0
		for _, t := range g.order {
			if g.byIdx[t]["inGrant"] != true && ixM(ixL(dim["values"])[t])["kind"] == "exact" {
				worst = math.Max(worst, math.Min(1, ixLpSumGbar(spec, dim, A, t)))
			}
		}
		if worst > gammaMax {
			for _, p := range A {
				cell := g.byIdx[p]["cell"]
				out = append(out, map[string]any{"verb": spec["verb"], "cell": cell, "flat": ixEncodeCell(vs, ixL(cell))})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return ixF(out[i]["flat"]) < ixF(out[j]["flat"]) })
	res := []any{}
	for _, o := range out {
		res = append(res, o)
	}
	return res
}

// IntentApplyFrameReport feeds a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell
// for good; ok and pending change nothing (a met frame is not the principal's endorsement).
func IntentApplyFrameReport(l *IntentLearner, o map[string]any, report any) (map[string]any, error) {
	rep, ok := report.(map[string]any)
	if !ok || rep["status"] != "violated" {
		return map[string]any{}, nil
	}
	div, err := IntentApplyDivergence(l, o, 0)
	if err != nil {
		return nil, err
	}
	return map[string]any{"signal": "postcondition-violation", "divergence": div}, nil
}

// IntentDecideVisit is the ordered lazy-elicitation decision: schema violation, ceiling, denied, admit, or intent_required.
// conform is {ok, code?, reason?}; ceilings are admission predicates over the verb space and the lifted outcome.
func IntentDecideVisit(l *IntentLearner, lifted, conform map[string]any, ceilings []func(vs, o map[string]any) bool, inEffective bool) (map[string]any, error) {
	r, err := ixTry(func() any {
		if conform["ok"] != true {
			return map[string]any{"kind": "schema_violation", "reason": jsMemberString(conform, "code") + ": " + jsMemberString(conform, "reason")}
		}
		vs := ixMaFindVerb(l.omega, lifted["verb"])
		var cell []any
		if vs != nil {
			cell = ixCellOf(vs, lifted)
		}
		if vs == nil || cell == nil {
			return map[string]any{"kind": "schema_violation", "reason": "the lifted action lies outside Ω̃"}
		}
		for _, c := range ceilings {
			if !c(vs, lifted) {
				return map[string]any{"kind": "ceiling"}
			}
		}
		vetoed := l.IsVetoed(lifted)
		p := l.Acceptance(lifted)
		if vetoed || p <= 0 {
			return map[string]any{"kind": "intent_denied", "vetoed": vetoed}
		}
		if inEffective {
			return map[string]any{"kind": "admit", "cell": cell}
		}
		return map[string]any{"kind": "intent_required", "cell": cell, "p": p}
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixLpCellKey(c map[string]any) string {
	var parts []string
	for _, i := range ixL(c["cell"]) {
		parts = append(parts, jsNumberString(ixF(i)))
	}
	return ixS(c["verb"]) + "|" + strings.Join(parts, ",")
}

// IntentDeltaCells are, per verb, the cells the next learner's grant adds over the previous one's (0/1 arrays over the flat cell
// index); verbs with no added cell are absent.
func IntentDeltaCells(prev, next *IntentLearner) (map[string][]byte, error) {
	r, err := ixTry(func() any {
		out := map[string][]byte{}
		prevIn := map[string]bool{}
		for _, cv := range prev.Cells() {
			if c := ixM(cv); c["inGrant"] == true {
				prevIn[ixLpCellKey(c)] = true
			}
		}
		for _, vv := range ixL(next.omega["verbs"]) {
			vs := ixM(vv)
			a := make([]byte, int(ixVerbCellCount(vs)))
			anyIn := false
			for _, cv := range next.Cells() {
				c := ixM(cv)
				if c["verb"] != vs["verb"] || c["inGrant"] != true || prevIn[ixLpCellKey(c)] {
					continue
				}
				a[int(ixEncodeCell(vs, ixL(c["cell"])))] = 1
				anyIn = true
			}
			if anyIn {
				out[ixS(vs["verb"])] = a
			}
		}
		return out
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string][]byte), nil
}

// IntentDeltaPredicates are the predicates of a delta (one maximal box per covered region, per verb).
func IntentDeltaPredicates(omegaTilde map[string]any, delta map[string][]byte) []any {
	out := []any{}
	for _, vv := range ixL(omegaTilde["verbs"]) {
		vs := ixM(vv)
		if d, ok := delta[ixS(vs["verb"])]; ok {
			out = append(out, IntentBoxesToPredicates(vs, d)...)
		}
	}
	return out
}
