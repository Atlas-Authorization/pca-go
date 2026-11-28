package pca

// The intent outcome space (omega): typed dimensions derived from the grant vocabulary, cells, representatives, the workload
// and harm measures, a seeded generator, the derivation from policies + slots, regions, and the policy plumbing (an outcome as
// a concrete action, the evaluator as an admission oracle). Dimensions, verb spaces and omegas are JSON trees, as in the
// reference; numbers are float64.

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	ixOther               = "⊥"
	ixExactSpan           = 4096
	ixHarmQuadraturePiece = 1024
	ixEulerGamma          = 0.5772156649015329
	ixAnyResource         = "resource:any"
)

var ixDefaultDomains = map[string]map[string]any{
	"action.params.amount": {"lo": 0.0, "hi": 100000.0, "dist": "loguniform"},
	"env.hour":             {"lo": 0.0, "hi": 23.0, "dist": "uniform"},
	"action.params.count":  {"lo": 0.0, "hi": 1000.0, "dist": "loguniform"},
}

func ixJsRound(x float64) float64 { x = float64(x); return math.Floor(x + 0.5) }

type ixCell struct{ lo, hi float64 }

func ixNumCells(d map[string]any) []ixCell {
	lo, hi := ixF(d["lo"]), ixF(d["hi"])
	var out []ixCell
	cur := lo
	for _, cv := range ixL(d["cuts"]) {
		c := ixF(cv)
		if c < lo || c > hi {
			continue
		}
		if cur <= c-1 {
			out = append(out, ixCell{cur, c - 1})
		}
		out = append(out, ixCell{c, c})
		cur = c + 1
	}
	if cur <= hi {
		out = append(out, ixCell{cur, hi})
	}
	return out
}

func ixNumCellsJSON(d map[string]any) any {
	cs := ixNumCells(d)
	out := make([]any, len(cs))
	for i, c := range cs {
		out[i] = map[string]any{"lo": c.lo, "hi": c.hi}
	}
	return out
}

func ixCellAt(cs []ixCell, i int) ixCell {
	if i < 0 || i >= len(cs) {
		ixFail("cell index %d out of range", i)
	}
	return cs[i]
}

func ixIdx(v any) int {
	f := ixF(v)
	if f != math.Trunc(f) || math.IsInf(f, 0) {
		ixFail("bad index")
	}
	return int(f)
}

func ixCellCount(d map[string]any) int {
	if ixS(d["kind"]) == "num" {
		return len(ixNumCells(d))
	}
	return len(ixL(d["values"]))
}

func ixVerbCellCount(vs map[string]any) float64 {
	n := 1.0
	for _, d := range ixL(vs["dims"]) {
		n *= float64(ixCellCount(ixM(d)))
	}
	return n
}

func ixDecodeCell(vs map[string]any, flat float64) []any {
	dims := ixL(vs["dims"])
	idx := make([]any, len(dims))
	for i := len(dims) - 1; i >= 0; i-- {
		n := float64(ixCellCount(ixM(dims[i])))
		if n == 0 {
			ixFail("division by zero")
		}
		idx[i] = math.Mod(flat, n)
		flat = math.Floor(flat / n)
	}
	return idx
}

func ixEncodeCell(vs map[string]any, idx []any) float64 {
	flat := 0.0
	for i, dv := range ixL(vs["dims"]) {
		if i >= len(idx) {
			ixFail("cell index missing")
		}
		flat = float64(flat*float64(ixCellCount(ixM(dv)))) + ixF(idx[i])
	}
	return flat
}

func ixCatCellOf(d map[string]any, s string) int {
	best, bestLen := -1, -1
	vals := ixL(d["values"])
	for i, v := range vals {
		vm := ixM(v)
		k, val := ixS(vm["kind"]), ixS(vm["value"])
		if k == "exact" && val == s {
			return i
		}
		if k == "prefix" && strings.HasPrefix(s, val) && jsLen(val) > bestLen {
			best, bestLen = i, jsLen(val)
		}
	}
	if best >= 0 {
		return best
	}
	for i, v := range vals {
		if ixS(ixM(v)["kind"]) == "other" {
			return i
		}
	}
	return -1
}

func ixCellOfValue(d map[string]any, x any) int {
	if ixS(d["kind"]) == "num" {
		if !ixIsFin(x) {
			return -1
		}
		f := x.(float64)
		for i, c := range ixNumCells(d) {
			if f >= c.lo && f <= c.hi {
				return i
			}
		}
		return -1
	}
	s, ok := x.(string)
	if !ok {
		return -1
	}
	return ixCatCellOf(d, s)
}

// ixCellOf is the cell of an outcome, or nil when a value lies outside the space.
func ixCellOf(vs, o map[string]any) []any {
	idx := []any{}
	values := ixM(o["values"])
	for _, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		i := ixCellOfValue(d, values[ixS(d["path"])])
		if i < 0 {
			return nil
		}
		idx = append(idx, float64(i))
	}
	return idx
}

func ixCatRep(d map[string]any, i int) string {
	vals := ixL(d["values"])
	if i < 0 || i >= len(vals) {
		ixFail("cell index %d out of range", i)
	}
	v := ixM(vals[i])
	if ixS(v["kind"]) == "exact" {
		return ixS(v["value"])
	}
	base := "other"
	if ixS(v["kind"]) == "prefix" {
		base = ixS(v["value"]) + "x"
	}
	for k := 0; k < 64; k++ {
		s := base
		if k != 0 {
			s += strconv.Itoa(k)
		}
		if ixCatCellOf(d, s) == i {
			return s
		}
	}
	return base
}

func ixNumRep(d map[string]any, i int) float64 {
	c := ixCellAt(ixNumCells(d), i)
	if i > 0 {
		return c.lo
	}
	return c.hi
}

func ixRepValue(d map[string]any, i int) any {
	if ixS(d["kind"]) == "num" {
		return ixNumRep(d, i)
	}
	return ixCatRep(d, i)
}

func ixCellRep(vs map[string]any, idx []any) map[string]any {
	values := map[string]any{}
	for i, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		if i >= len(idx) {
			ixFail("cell index missing")
		}
		values[ixS(d["path"])] = ixRepValue(d, ixIdx(idx[i]))
	}
	return map[string]any{"verb": vs["verb"], "values": values}
}

// ---- workload and harm ----

func ixLogUniform(d map[string]any) bool {
	return ixS(d["dist"]) == "loguniform" && ixF(d["lo"]) >= 0
}

func ixPointWeight(d map[string]any, x float64) float64 {
	if ixLogUniform(d) {
		return 1 / (x + 1)
	}
	return 1
}

var ixAmountRe = regexp.MustCompile(`(^|\.)amount$`)

func ixLinearAmount(d map[string]any) bool {
	return ixS(d["kind"]) == "num" && ixAmountRe.MatchString(ixS(d["path"]))
}

// ixHarm is the harm model: verb weight, per-dimension value harm, and an optional closed form of the mean over an interval.
type ixHarm struct {
	verb    func(vs map[string]any) float64
	dim     func(d map[string]any, x any) float64
	dimMean func(d map[string]any, lo, hi float64) float64
}

var ixDefaultHarm = &ixHarm{
	verb: func(vs map[string]any) float64 {
		switch ixS(vs["reversibility"]) {
		case "irreversible":
			return 10
		case "rate_limited":
			return 3
		}
		return 1
	},
	dim: func(d map[string]any, x any) float64 {
		if f, ok := x.(float64); ok && ixLinearAmount(d) {
			return 1 + math.Max(0, f)/100
		}
		return 1
	},
	dimMean: func(d map[string]any, lo, hi float64) float64 {
		if !ixLinearAmount(d) {
			return 1
		}
		return 1 + math.Max(0, ixIntervalMeanX(d, math.Max(lo, 0), hi, lo))/100
	},
}

func ixHarmMax(omega map[string]any, h *ixHarm) float64 {
	m := 0.0
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		f := h.verb(vs)
		for _, dv := range ixL(vs["dims"]) {
			d := ixM(dv)
			if ixS(d["kind"]) == "num" {
				f *= math.Max(h.dim(d, d["lo"]), h.dim(d, d["hi"]))
			} else {
				n := len(ixL(d["values"]))
				if n == 0 {
					ixFail("max of an empty sequence")
				}
				mx := math.Inf(-1)
				for i := 0; i < n; i++ {
					mx = math.Max(mx, h.dim(d, ixCatRep(d, i)))
				}
				f *= mx
			}
		}
		m = math.Max(m, f)
	}
	return m
}

func ixHarmonic(n float64) float64 {
	if n <= 0 {
		return 0
	}
	if n <= ixExactSpan {
		s := 0.0
		for k := int(n); k > 0; k-- {
			s += 1 / float64(k)
		}
		return s
	}
	n2 := n * n
	return DetLn(n) + ixEulerGamma + 1/(2*n) - 1/(12*n2) + 1/(120*n2*n2) - 1/(252*n2*n2*n2)
}

func ixIntervalWeight(d map[string]any, a, b float64) float64 {
	if b < a {
		return 0
	}
	if !ixLogUniform(d) {
		return b - a + 1
	}
	if b-a+1 <= ixExactSpan {
		s := 0.0
		for x := math.Trunc(b); x >= a; x-- {
			s += 1 / (x + 1)
		}
		return s
	}
	return ixHarmonic(b+1) - ixHarmonic(a)
}

func ixIntervalFirstMoment(d map[string]any, a, b float64) float64 {
	if b < a {
		return 0
	}
	if !ixLogUniform(d) {
		return ((a + b) * (b - a + 1)) / 2
	}
	return b - a + 1 - ixIntervalWeight(d, a, b)
}

func ixIntervalMeanX(d map[string]any, a, b, cellLo float64) float64 {
	whole := ixIntervalWeight(d, cellLo, b)
	if whole > 0 {
		return ixIntervalFirstMoment(d, a, b) / whole
	}
	return 0
}

func ixIntervalHarm(d map[string]any, a, b float64, h *ixHarm) float64 {
	if h.dimMean != nil {
		return h.dimMean(d, a, b)
	}
	n := b - a + 1
	wTot := ixIntervalWeight(d, a, b)
	if !(wTot > 0) {
		return h.dim(d, a)
	}
	if n <= ixExactSpan {
		s := 0.0
		for x := a; x <= b; x++ {
			s += float64(ixPointWeight(d, x) * h.dim(d, x))
		}
		return s / wTot
	}
	s := 0.0
	for i := 0; i < ixHarmQuadraturePiece; i++ {
		pa := a + math.Floor(float64(i)*n/ixHarmQuadraturePiece)
		pb := a + math.Floor(float64(i+1)*n/ixHarmQuadraturePiece) - 1
		if pb < pa {
			continue
		}
		w := ixIntervalWeight(d, pa, pb)
		s += float64(w * h.dim(d, ixJsRound((pa+pb)/2)))
	}
	return s / wTot
}

func ixDimTotal(d map[string]any) float64 {
	lo := ixF(d["lo"])
	return ixIntervalWeight(map[string]any{"lo": d["lo"], "dist": d["dist"]}, lo, ixF(d["hi"]))
}

// ixDimCellStats is mu_d(cell) and E[g_d | cell] for one dimension cell (categorical values are uniform).
func ixDimCellStats(d map[string]any, i int, h *ixHarm) (mass, harm float64) {
	if ixS(d["kind"]) == "cat" {
		n := len(ixL(d["values"]))
		if n == 0 {
			ixFail("division by zero")
		}
		return 1 / float64(n), h.dim(d, ixCatRep(d, i))
	}
	c := ixCellAt(ixNumCells(d), i)
	wm := ixIntervalWeight(d, c.lo, c.hi)
	mass = wm / ixDimTotal(d)
	if wm > 0 {
		return mass, ixIntervalHarm(d, c.lo, c.hi, h)
	}
	return mass, h.dim(d, c.lo)
}

func ixQuantileValue(d map[string]any, target float64) float64 {
	acc := 0.0
	cells := ixNumCells(d)
	for ci, c := range cells {
		w := ixIntervalWeight(d, c.lo, c.hi)
		if target < acc+w || ci == len(cells)-1 {
			r := target - acc
			if c.hi-c.lo+1 <= ixExactSpan {
				for x := c.lo; x < c.hi; x++ {
					r -= ixPointWeight(d, x)
					if r < 0 {
						return x
					}
				}
				return c.hi
			}
			if !ixLogUniform(d) {
				return math.Min(c.hi, c.lo+math.Floor(r))
			}
			x := math.Floor(float64((c.lo+1)*DetExp(r)) - 1)
			return math.Max(c.lo, math.Min(c.hi, x))
		}
		acc += w
	}
	return ixF(d["hi"])
}

func ixCellStats(vs map[string]any, idx []any, h *ixHarm) (mass, harm float64) {
	mass = ixF(vs["weight"])
	harm = h.verb(vs)
	for k, dv := range ixL(vs["dims"]) {
		if k >= len(idx) {
			ixFail("cell index missing")
		}
		m, hh := ixDimCellStats(ixM(dv), ixIdx(idx[k]), h)
		mass *= m
		harm *= hh
	}
	return
}

func ixHarmOf(vs, o map[string]any, h *ixHarm) float64 {
	r := h.verb(vs)
	values := ixM(o["values"])
	for _, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		r *= h.dim(d, values[ixS(d["path"])])
	}
	return r
}

// IntentRng is a small seeded PRNG (mulberry32), bit-identical to the reference.
func IntentRng(seed float64) func() float64 {
	state := uint32(int64(seed))
	return func() float64 {
		state += 0x6D2B79F5
		t := state
		t = (t ^ (t >> 15)) * (t | 1)
		t ^= t + (t^(t>>7))*(t|61)
		return float64(t^(t>>14)) / 4294967296
	}
}

func ixSampleOutcome(omega map[string]any, rand func() float64) (map[string]any, map[string]any) {
	u := rand()
	verbs := ixL(omega["verbs"])
	if len(verbs) == 0 {
		ixFail("no verbs")
	}
	vs := ixM(verbs[len(verbs)-1])
	for _, vv := range verbs {
		v := ixM(vv)
		if u < ixF(v["weight"]) {
			vs = v
			break
		}
		u -= ixF(v["weight"])
	}
	values := map[string]any{}
	for _, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		if ixS(d["kind"]) == "cat" {
			n := len(ixL(d["values"]))
			values[ixS(d["path"])] = ixCatRep(d, int(math.Min(float64(n-1), math.Floor(rand()*float64(n)))))
			continue
		}
		values[ixS(d["path"])] = ixQuantileValue(d, rand()*ixDimTotal(d))
	}
	return vs, map[string]any{"verb": vs["verb"], "values": values}
}

// ---- derivation from policies + slots ----

type ixFieldLits struct {
	nums     map[float64]bool
	exacts   map[string]bool
	prefixes map[string]bool
}

func ixLits(m map[string]*ixFieldLits, path string) *ixFieldLits {
	f := m[path]
	if f == nil {
		f = &ixFieldLits{map[float64]bool{}, map[string]bool{}, map[string]bool{}}
		m[path] = f
	}
	return f
}

func ixAddNum(f *ixFieldLits, x any) {
	if !ixIsFin(x) {
		return
	}
	v := x.(float64)
	f.nums[math.Floor(v)+0] = true
	f.nums[math.Ceil(v)+0] = true
}

func ixIsGroupCond(c map[string]any) bool {
	return ixHas(c, "all_of") || ixHas(c, "any_of") || ixHas(c, "not")
}

func ixCollectCond(cv any, m map[string]*ixFieldLits, approx map[string]bool) {
	c, ok := cv.(map[string]any)
	if !ok {
		return
	}
	if ixIsGroupCond(c) {
		if l, ok := c["all_of"].([]any); ok {
			for _, x := range l {
				ixCollectCond(x, m, approx)
			}
		} else if l, ok := c["any_of"].([]any); ok {
			for _, x := range l {
				ixCollectCond(x, m, approx)
			}
		} else if ixHas(c, "not") {
			ixCollectCond(c["not"], m, approx)
		}
		return
	}
	field, ok := c["field"].(string)
	if !ok {
		return
	}
	op := ixS(c["op"])
	if c["ref"] != nil {
		approx["cross-field ref on "+field] = true
	}
	switch op {
	case "like", "matches", "is_a", "member_of":
		approx[op+" on "+field] = true
	}
	if op == "exists" {
		ixLits(m, field)
		return
	}
	f := ixLits(m, field)
	vals, isList := c["value"].([]any)
	if !isList {
		vals = []any{c["value"]}
	}
	for _, v := range vals {
		if ixIsNum(v) {
			ixAddNum(f, v)
		} else if s, ok := v.(string); ok {
			if op == "prefix" {
				f.prefixes[s] = true
			} else {
				f.exacts[s] = true
			}
		}
	}
}

func ixAddResource(r any, m map[string]*ixFieldLits, approx map[string]bool) {
	s, ok := r.(string)
	if !ok || s == "*" {
		return
	}
	if strings.HasPrefix(s, "re:") {
		approx["re: resource matcher"] = true
		return
	}
	f := ixLits(m, "action.resource")
	if strings.HasSuffix(s, "*") {
		f.prefixes[s[:len(s)-1]] = true
	} else {
		f.exacts[s] = true
	}
}

// ixVerbsOf is the verbs of a predicate: wild (any verb) or the listed ones.
func ixVerbsOf(p any) (wild bool, verbs []string) {
	v := ixM(p)["verb"]
	if s, ok := v.(string); ok {
		if s == "*" {
			return true, nil
		}
		return false, []string{s}
	}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				if s == "*" {
					return true, nil
				}
			}
		}
		for _, x := range l {
			if s, ok := x.(string); ok {
				verbs = append(verbs, s)
			}
		}
	}
	return false, verbs
}

func ixCatalogAll(catalog any) []map[string]any {
	var out []map[string]any
	if catalog == nil {
		for _, a := range BuiltinActions {
			m := map[string]any{"verb": a.Verb, "connector": a.Connector, "reversibility": a.Reversibility, "description": a.Description}
			if a.AmountField != "" {
				m["amountField"] = a.AmountField
			}
			out = append(out, m)
		}
		return out
	}
	if m, ok := catalog.(map[string]any); ok {
		for _, k := range ixKeysSorted(m) {
			if s := ixM(m[k]); s != nil {
				out = append(out, s)
			}
		}
		return out
	}
	by := map[string]map[string]any{}
	var order []string
	for _, x := range ixL(catalog) {
		s := ixM(x)
		v := ixS(s["verb"])
		if _, ok := by[v]; !ok {
			order = append(order, v)
		}
		by[v] = s
	}
	for _, v := range order {
		out = append(out, by[v])
	}
	return out
}

func ixSortedFloats(m map[float64]bool) []float64 {
	out := make([]float64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Float64s(out)
	return out
}

func ixSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return ixSortU16(out)
}

// ixDeriveOmega derives the outcome space from the vocabulary of the policies and the intent slots.
func ixDeriveOmega(opts map[string]any) map[string]any {
	poolAll := ixCatalogAll(opts["catalog"])
	catByVerb := map[string]map[string]any{}
	for _, s := range poolAll {
		catByVerb[ixS(s["verb"])] = s
	}
	approx := map[string]bool{}
	var preds []any
	pol, ok := opts["policies"].([]any)
	if !ok {
		ixFail("policies is not iterable")
	}
	for _, p := range pol {
		preds = append(preds, ixNormalizePolicy(p)["predicates"].([]any)...)
	}
	slots := ixM(opts["slots"])
	explicit := map[string]bool{}
	for _, v := range ixL(opts["extraVerbs"]) {
		explicit[ixS(v)] = true
	}
	wildcard := false
	for _, p := range preds {
		w, vs := ixVerbsOf(p)
		if w {
			wildcard = true
		} else {
			for _, v := range vs {
				explicit[v] = true
			}
		}
	}
	for _, v := range ixL(slots["verbs"]) {
		explicit[ixS(v)] = true
	}
	if wildcard {
		connectors := map[string]bool{}
		for v := range explicit {
			connectors[strings.SplitN(v, ".", 2)[0]] = true
		}
		for _, s := range poolAll {
			if len(connectors) == 0 || connectors[ixS(s["connector"])] {
				explicit[ixS(s["verb"])] = true
			}
		}
	}
	domains := ixM(opts["domains"])
	var out []any
	for _, verb := range ixSortedKeys(explicit) {
		m := map[string]*ixFieldLits{}
		for _, p := range preds {
			w, pv := ixVerbsOf(p)
			if !w {
				found := false
				for _, x := range pv {
					if x == verb {
						found = true
					}
				}
				if !found {
					continue
				}
			}
			pm := ixM(p)
			ixAddResource(pm["resource"], m, approx)
			if wh, ok := pm["where"].([]any); ok {
				for _, c := range wh {
					ixCollectCond(c, m, approx)
				}
			}
		}
		for _, sv := range ixL(slots["constraints"]) {
			sc := ixM(sv)
			if sc["verb"] != nil && sc["verb"] != verb {
				continue
			}
			f := ixLits(m, ixS(sc["path"]))
			if sc["max"] != nil {
				ixAddNum(f, sc["max"])
			}
			if sc["min"] != nil {
				ixAddNum(f, sc["min"])
			}
			for _, x := range ixL(sc["oneOf"]) {
				f.exacts[ixS(x)] = true
			}
			for _, x := range ixL(sc["noneOf"]) {
				f.exacts[ixS(x)] = true
			}
			for _, x := range ixL(sc["prefixOneOf"]) {
				f.prefixes[ixS(x)] = true
			}
		}
		dims := []any{}
		paths := make([]string, 0, len(m))
		for p := range m {
			paths = append(paths, p)
		}
		for _, path := range ixSortU16(paths) {
			f := m[path]
			_, hasDef := ixDefaultDomains[path]
			if len(f.nums) > 0 || (len(f.exacts) == 0 && len(f.prefixes) == 0 && hasDef) {
				cuts := ixSortedFloats(f.nums)
				dom := ixM(domains[path])
				if len(dom) == 0 {
					if dd, ok := ixDefaultDomains[path]; ok {
						dom = dd
					}
				}
				maxCut, minCut := 0.0, 0.0
				if len(cuts) > 0 {
					maxCut, minCut = cuts[len(cuts)-1], cuts[0]
				}
				var lo, hi float64
				if dom != nil && dom["lo"] != nil {
					lo = ixF(dom["lo"])
				} else {
					lo = math.Min(0, minCut-1)
				}
				if dom != nil && dom["hi"] != nil {
					hi = ixF(dom["hi"])
				} else {
					hi = math.Max(10, math.Max(2*maxCut, maxCut+10))
				}
				var dist any
				if dom != nil && dom["dist"] != nil {
					dist = dom["dist"]
				} else if lo >= 0 {
					dist = "loguniform"
				} else {
					dist = "uniform"
				}
				kept := []any{}
				for _, c := range cuts {
					if lo <= c && c <= hi {
						kept = append(kept, c)
					}
				}
				dims = append(dims, map[string]any{"kind": "num", "path": path, "lo": lo, "hi": hi, "cuts": kept, "dist": dist})
			} else {
				values := []any{}
				for _, v := range ixSortedKeys(f.exacts) {
					values = append(values, map[string]any{"kind": "exact", "value": v})
				}
				for _, v := range ixSortedKeys(f.prefixes) {
					values = append(values, map[string]any{"kind": "prefix", "value": v})
				}
				values = append(values, map[string]any{"kind": "other", "value": ixOther})
				dims = append(dims, map[string]any{"kind": "cat", "path": path, "values": values})
			}
		}
		rev := any("irreversible")
		if spec, ok := catByVerb[verb]; ok && spec["reversibility"] != nil {
			rev = spec["reversibility"]
		}
		out = append(out, map[string]any{"verb": verb, "reversibility": rev, "weight": 0.0, "dims": dims})
	}
	for _, v := range out {
		v.(map[string]any)["weight"] = 1 / float64(len(out))
	}
	if out == nil {
		out = []any{}
	}
	return map[string]any{"v": 1.0, "verbs": out, "approximate": ixToAny(ixSortedKeys(approx))}
}

func ixVerbSpace(omega map[string]any, verb string) any {
	for _, v := range ixL(omega["verbs"]) {
		if ixS(ixM(v)["verb"]) == verb {
			return v
		}
	}
	return nil
}

// ---- policy plumbing ----

// ixNormalizePolicy is {predicates, caveats}: a non-array member counts as empty.
func ixNormalizePolicy(p any) map[string]any {
	switch p.(type) { // `'caveats' in p` throws for any truthy primitive; a falsy one (null, 0, "", false) is just no policy
	case nil, map[string]any, []any:
	default:
		if ixTruthy(p) {
			ixFail("Cannot use 'in' operator to search for 'caveats' in %s", jsValueString(p))
		}
	}
	m := ixM(p)
	preds, ok := m["predicates"].([]any)
	if !ok {
		preds = []any{}
	}
	cavs, ok := m["caveats"].([]any)
	if !ok {
		cavs = []any{}
	}
	return map[string]any{"predicates": preds, "caveats": cavs}
}

func ixSetPath(root map[string]any, segs []string, value any) {
	cur := root
	for _, k := range segs[:len(segs)-1] {
		nxt, ok := cur[k].(map[string]any)
		if !ok {
			nxt = map[string]any{}
			cur[k] = nxt
		}
		cur = nxt
	}
	cur[segs[len(segs)-1]] = value
}

// ixOutcomeToAction is the outcome as the analyzer's concrete action (params / env / subject trees).
func ixOutcomeToAction(vs, o map[string]any) map[string]any {
	params, env, subject := map[string]any{}, map[string]any{}, map[string]any{}
	resource := any(ixAnyResource)
	values := ixM(o["values"])
	for _, path := range ixKeysSorted(values) {
		value := values[path]
		segs := strings.Split(path, ".")
		switch {
		case path == "action.resource":
			resource = jsValueString(value)
		case segs[0] == "action" && len(segs) > 2 && segs[1] == "params":
			ixSetPath(params, segs[2:], value)
		case segs[0] == "env" && len(segs) > 1:
			ixSetPath(env, segs[1:], value)
		case segs[0] == "subject" && len(segs) > 1:
			ixSetPath(subject, segs[1:], value)
		}
	}
	a := map[string]any{"verb": o["verb"], "resource": resource, "params": params, "reversibilityClass": vs["reversibility"]}
	if len(env) > 0 {
		a["env"] = env
	}
	if len(subject) > 0 {
		a["subject"] = subject
	}
	return a
}

// IntentAdmitter is a compiled admission oracle for one policy (compile once, query many times).
type IntentAdmitter struct{ model map[string]any }

// IntentNewAdmitter compiles a policy ({predicates, caveats}) into an admission oracle.
func IntentNewAdmitter(policy any) (a *IntentAdmitter, err error) {
	r, err := ixTry(func() any { return &IntentAdmitter{anlToModel(policy)} })
	if err != nil {
		return nil, err
	}
	return r.(*IntentAdmitter), nil
}

func (a *IntentAdmitter) admits(vs, o map[string]any) bool {
	return anlAdmitsAction(a.model, ixOutcomeToAction(vs, o))
}

// ---- slots ----

func ixSlotConds(sc map[string]any) []any {
	out := []any{}
	p := sc["path"]
	if sc["min"] != nil {
		out = append(out, map[string]any{"field": p, "op": "gte", "value": sc["min"]})
	}
	if sc["max"] != nil {
		out = append(out, map[string]any{"field": p, "op": "lte", "value": sc["max"]})
	}
	var anyOf []any
	if l := ixL(sc["oneOf"]); len(l) > 0 {
		anyOf = append(anyOf, map[string]any{"field": p, "op": "in", "value": ixClone(l)})
	}
	for _, x := range ixL(sc["prefixOneOf"]) {
		anyOf = append(anyOf, map[string]any{"field": p, "op": "prefix", "value": x})
	}
	if len(anyOf) == 1 {
		out = append(out, anyOf[0])
	} else if len(anyOf) > 1 {
		out = append(out, map[string]any{"any_of": anyOf})
	}
	if l := ixL(sc["noneOf"]); len(l) > 0 {
		out = append(out, map[string]any{"field": p, "op": "nin", "value": ixClone(l)})
	}
	return out
}

// ixSlotsToPolicy is one predicate per slot verb.
func ixSlotsToPolicy(slots map[string]any) map[string]any {
	preds := []any{}
	for _, verb := range ixL(slots["verbs"]) {
		where := []any{}
		for _, cv := range ixL(slots["constraints"]) {
			c := ixM(cv)
			if c["verb"] == nil || c["verb"] == verb {
				where = append(where, ixSlotConds(c)...)
			}
		}
		pr := map[string]any{"verb": verb, "resource": "*"}
		if len(where) > 0 {
			pr["where"] = where
		}
		preds = append(preds, pr)
	}
	return map[string]any{"predicates": preds, "caveats": []any{}}
}

// ---- regions ----

func ixRegionOfCell(vs map[string]any, idx []any) map[string]any {
	dims := map[string]any{}
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		if k >= len(idx) {
			ixFail("cell index missing")
		}
		i := ixIdx(idx[k])
		if ixS(d["kind"]) == "num" {
			c := ixCellAt(ixNumCells(d), i)
			dims[ixS(d["path"])] = map[string]any{"kind": "num", "lo": c.lo, "hi": c.hi}
		} else {
			dims[ixS(d["path"])] = map[string]any{"kind": "cat", "values": ixClone(d["values"]), "cells": []any{float64(i)}}
		}
	}
	return map[string]any{"verb": vs["verb"], "dims": dims}
}

func ixRestrictRegion(r, d, part map[string]any) map[string]any {
	dims := map[string]any{}
	for k, v := range ixM(r["dims"]) {
		dims[k] = v
	}
	switch {
	case ixS(d["kind"]) == "num" && ixHas(part, "lo"):
		dims[ixS(d["path"])] = map[string]any{"kind": "num", "lo": part["lo"], "hi": part["hi"]}
	case ixS(d["kind"]) == "cat" && ixHas(part, "cells"):
		dims[ixS(d["path"])] = map[string]any{"kind": "cat", "values": ixClone(d["values"]), "cells": ixClone(part["cells"])}
	default:
		ixFail("restrictRegion: part does not match the kind of %s", ixS(d["path"]))
	}
	return map[string]any{"verb": r["verb"], "dims": dims}
}

func ixRefDim(path string, rd map[string]any) map[string]any {
	return map[string]any{"kind": "cat", "path": path, "values": rd["values"]}
}

// ixDimCellsIn is the cells of dimension d covered by the region dimension: inner (wholly inside) or outer (meeting it).
func ixDimCellsIn(d, rd map[string]any, mode string) []int {
	n := ixCellCount(d)
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	if len(rd) == 0 {
		return all
	}
	if ixS(d["kind"]) == "num" {
		if ixS(rd["kind"]) != "num" {
			ixFail("region: %s is numeric in the space but categorical in the region", ixS(d["path"]))
		}
		cells := ixNumCells(d)
		rlo, rhi := ixF(rd["lo"]), ixF(rd["hi"])
		out := []int{}
		for _, i := range all {
			c := cells[i]
			var ok bool
			if mode == "inner" {
				ok = c.lo >= rlo && c.hi <= rhi
			} else {
				ok = c.hi >= rlo && c.lo <= rhi
			}
			if ok {
				out = append(out, i)
			}
		}
		return out
	}
	if ixS(rd["kind"]) != "cat" {
		ixFail("region: %s is categorical in the space but numeric in the region", ixS(d["path"]))
	}
	ref := ixRefDim(ixS(d["path"]), rd)
	in := map[int]bool{}
	for _, c := range ixL(rd["cells"]) {
		in[ixIdx(c)] = true
	}
	out := []int{}
	for _, i := range all {
		if in[ixCatCellOf(ref, ixCatRep(d, i))] {
			out = append(out, i)
		}
	}
	return out
}

func ixIntsOut(xs []int) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = float64(x)
	}
	return out
}

// ixRegionCells is the flat cell indices of vs covered by the region (row-major, last dimension fastest).
func ixRegionCells(vs, r map[string]any, mode string) []int {
	if r["verb"] != vs["verb"] {
		ixFail("region: verb %s does not match %s", jsValueString(r["verb"]), jsValueString(vs["verb"]))
	}
	rdims := ixM(r["dims"])
	dims := ixL(vs["dims"])
	for p := range rdims {
		found := false
		for _, d := range dims {
			if ixS(ixM(d)["path"]) == p {
				found = true
			}
		}
		if !found {
			ixFail("region: restricts %s, which the space has no dimension for", p)
		}
	}
	per := make([][]int, len(dims))
	for k, dv := range dims {
		d := ixM(dv)
		var rd map[string]any
		if x, ok := rdims[ixS(d["path"])]; ok {
			rd = ixM(x)
		}
		per[k] = ixDimCellsIn(d, rd, mode)
	}
	for _, c := range per {
		if len(c) == 0 {
			return []int{}
		}
	}
	acc := []int{0}
	for k, cells := range per {
		size := ixCellCount(ixM(dims[k]))
		var next []int
		for _, f := range acc {
			for _, c := range cells {
				next = append(next, f*size+c)
			}
		}
		acc = next
	}
	return acc
}

func ixValueInRegionDim(path string, rd map[string]any, x any) bool {
	if ixS(rd["kind"]) == "num" {
		f, ok := x.(float64)
		return ok && f >= ixF(rd["lo"]) && f <= ixF(rd["hi"])
	}
	s, ok := x.(string)
	if !ok {
		return false
	}
	c := ixCatCellOf(ixRefDim(path, rd), s)
	for _, v := range ixL(rd["cells"]) {
		if f, ok := v.(float64); ok && int(f) == c && f == float64(c) {
			return true
		}
	}
	return false
}

// IntentDeriveOmega derives the outcome space from {policies, slots?, domains?, extraVerbs?, catalog?} (numbers are float64).
func IntentDeriveOmega(opts map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixDeriveOmega(opts) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// IntentSlotsToPolicy compiles structured intent slots into the policy they literally describe.
func IntentSlotsToPolicy(slots map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixSlotsToPolicy(slots) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// Admits reports whether the policy admits the outcome (vs is its verb space).
func (a *IntentAdmitter) Admits(vs, o map[string]any) (bool, error) {
	r, err := ixTry(func() any { return a.admits(vs, o) })
	if err != nil {
		return false, err
	}
	return r.(bool), nil
}
