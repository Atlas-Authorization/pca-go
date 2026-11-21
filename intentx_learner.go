package pca

// Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes, decision
// lists), the conservative grant it implies, the next question, the audit round and the synthesis of the grant as predicates.
// Omegas, verb spaces, options, observations and questions are plain JSON trees with the reference's field names; the posterior
// arithmetic keeps the reference's operation order. A reference throw is a panic(ixThrow) turned into an error at the public
// boundary.

import (
	"math"
	"sort"
	"strings"
)

// ixLog2 is Math.log2 (the fdlibm log2 the reference engine uses); the exact powers of two are exact.
func ixLog2(x float64) float64 {
	const (
		two54   = 1.80143985094819840000e+16
		ivln2hi = 1.44269504072144627571e+00
		ivln2lo = 1.67517131648865118353e-10
	)
	if math.IsNaN(x) || x < 0 {
		return math.NaN()
	}
	if x == 0 {
		return math.Inf(-1)
	}
	if math.IsInf(x, 1) {
		return x
	}
	k := 0
	bits := math.Float64bits(x)
	hx := int32(bits >> 32)
	if hx < 0x00100000 {
		k -= 54
		x *= two54
		bits = math.Float64bits(x)
		hx = int32(bits >> 32)
	}
	if hx == 0x3ff00000 && uint32(bits) == 0 {
		return 0
	}
	k += int(hx>>20) - 1023
	hx &= 0x000fffff
	i := (hx + 0x95f64) & 0x100000
	bits = uint64(uint32(hx|(i^0x3ff00000)))<<32 | uint64(uint32(bits))
	x = math.Float64frombits(bits)
	k += int(i >> 20)
	y := float64(k)
	f := x - 1.0
	hfsq := float64(0.5*f) * f
	r := ixKLog1p(f)
	hi := f - hfsq
	hi = math.Float64frombits(math.Float64bits(hi) &^ 0xffffffff)
	lo := float64(float64(f-hi)-hfsq) + r
	valHi := hi * ivln2hi
	valLo := float64(float64(lo+hi)*ivln2lo) + float64(lo*ivln2hi)
	w := y + valHi
	valLo += float64(y-w) + valHi
	valHi = w
	return valLo + valHi
}

func ixKLog1p(f float64) float64 {
	const (
		lg1 = 6.666666666666735130e-01
		lg2 = 3.999999999940941908e-01
		lg3 = 2.857142874366239149e-01
		lg4 = 2.222219843214978396e-01
		lg5 = 1.818357216161805012e-01
		lg6 = 1.531383769920937332e-01
		lg7 = 1.479819860511658591e-01
	)
	s := f / (2.0 + f)
	z := s * s
	w := z * z
	t1 := w * float64(lg2+float64(w*float64(lg4+float64(w*lg6))))
	t2 := z * float64(lg1+float64(w*float64(lg3+float64(w*float64(lg5+float64(w*lg7))))))
	r := t2 + t1
	hfsq := float64(0.5*f) * f
	return s * float64(hfsq+r)
}

// IntentLearnerHooks carries the options a JSON tree cannot: a custom harm model, a per-verb null mass and a prior-mix weight.
type IntentLearnerHooks struct {
	NullMass       func(vs map[string]any) float64
	PriorMixWeight func(vs map[string]any, has func(cell int) bool) float64
	harm           *ixHarm
}

var ixLrOrder = []string{"reversible", "rate_limited", "irreversible"}

func ixLrIsInteger(v any) bool {
	f, ok := v.(float64)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Floor(f)
}

// ixLrOr1 is JS `x || 1`: 0 and NaN are falsy there.
func ixLrOr1(x float64) float64 {
	if x != x || x == 0 {
		return 1
	}
	return x
}

// ixLrOpt is JS `o.k ?? def`.
func ixLrOpt(o map[string]any, k string, def any) any {
	if v, ok := o[k]; ok && v != nil {
		return v
	}
	return def
}

func ixLrOptF(o map[string]any, k string, def float64) float64 {
	return ixF(ixLrOpt(o, k, def))
}

// IntentHypothesisClassName is the canonical name of a hypothesis class (stored in the Intent Map).
func IntentHypothesisClassName(h map[string]any) string {
	switch h["kind"] {
	case "box":
		return "per-verb-box/v1"
	case "union":
		return "per-verb-union/v1"
	}
	if ixLrOpt(h, "conditions", "box") == "atomic" {
		return "per-verb-decision-list/v1"
	}
	return "per-verb-decision-list/v2"
}

func ixLrBinEnt(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -(float64(p*ixLog2(p)) + float64((1-p)*ixLog2(1-p))) // float64() stops a fused multiply-add (arm64)
}

type ixLrVerbModel struct {
	vs       map[string]any
	nChoice  []int
	contains [][]byte
	nCellsD  []int
	nh       int
	choice   []int
	member   [][]byte
	cmplx    []int
	prior    []float64
	w        []float64
	err      []int
	nCells   int
	cellIdx  []int
	mass     []float64
	harm     []float64
	p        []float64
	veto     []byte
	seen     []byte
	dirty    bool
}

func ixLrBuildBoxTables(vs map[string]any, nCellsD []int) ([][]byte, []int) {
	var contains [][]byte
	var nChoice []int
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		n := nCellsD[k]
		if d["kind"] == "num" {
			cnt := n * (n + 1) / 2
			t := make([]byte, cnt*n)
			c := 0
			for i := 0; i < n; i++ {
				for j := i; j < n; j++ {
					for x := i; x <= j; x++ {
						t[c*n+x] = 1
					}
					c++
				}
			}
			contains = append(contains, t)
			nChoice = append(nChoice, cnt)
		} else {
			if n > 20 {
				ixFail("pca-intent: categorical dimension %s has %d values (max 20 for exact enumeration)", ixS(d["path"]), n)
			}
			m := (1 << uint(n)) - 1
			t := make([]byte, m*n)
			for mask := 1; mask <= m; mask++ {
				for x := 0; x < n; x++ {
					if mask&(1<<uint(x)) != 0 {
						t[(mask-1)*n+x] = 1
					}
				}
			}
			contains = append(contains, t)
			nChoice = append(nChoice, m)
		}
	}
	return contains, nChoice
}

func ixLrBoxMasks(vs map[string]any, nCells int, cellIdx, nCellsD []int, contains [][]byte, nChoice []int, capN float64) [][]byte {
	D := len(ixL(vs["dims"]))
	boxesF := 1.0
	for _, c := range nChoice {
		boxesF *= float64(c)
	}
	if !(boxesF <= capN) {
		ixFail("pca-intent: %d boxes for %s exceed the enumeration cap; coarsen the cuts", int64(boxesF), ixS(vs["verb"]))
	}
	boxes := int(boxesF)
	out := make([][]byte, 0, boxes)
	cur := make([]int, D)
	for b := 0; b < boxes; b++ {
		mask := make([]byte, nCells)
		for c := 0; c < nCells; c++ {
			inside := true
			for d := 0; d < D && inside; d++ {
				if contains[d][cur[d]*nCellsD[d]+cellIdx[c*D+d]] == 0 {
					inside = false
				}
			}
			if inside {
				mask[c] = 1
			}
		}
		out = append(out, mask)
		for d := D - 1; d >= 0; d-- {
			cur[d]++
			if cur[d] < nChoice[d] {
				break
			}
			cur[d] = 0
		}
	}
	return out
}

func ixLrEnumerateUnions(boxes [][]byte, k int, capN float64, verb string) ([][]byte, []int) {
	seen := map[string]bool{}
	var sets [][]byte
	var cx []int
	var frontier [][]byte
	for _, b := range boxes {
		key := string(b)
		if seen[key] {
			continue
		}
		seen[key] = true
		sets = append(sets, b)
		cx = append(cx, 1)
		frontier = append(frontier, b)
	}
	work := 0.0
	for level := 2; level <= k; level++ {
		var next [][]byte
		for _, s := range frontier {
			for _, b := range boxes {
				work++
				if !(work <= capN) {
					ixFail("pca-intent: the union-of-%d-boxes class for %s exceeds the enumeration cap; coarsen the cuts or lower k", k, verb)
				}
				u := make([]byte, len(s))
				for i := range s {
					u[i] = s[i] | b[i]
				}
				key := string(u)
				if seen[key] {
					continue
				}
				seen[key] = true
				sets = append(sets, u)
				cx = append(cx, level)
				next = append(next, u)
			}
		}
		frontier = next
	}
	return sets, cx
}

func ixLrAtomicTests(vs map[string]any, nCells int, cellIdx, nCellsD []int) [][]byte {
	D := len(ixL(vs["dims"]))
	var tests [][]byte
	add := func(k int, pred func(x int) bool) {
		m := make([]byte, nCells)
		anyIn, all := false, true
		for c := 0; c < nCells; c++ {
			if pred(cellIdx[c*D+k]) {
				m[c] = 1
				anyIn = true
			} else {
				all = false
			}
		}
		if anyIn && !all {
			tests = append(tests, m)
		}
	}
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		n := nCellsD[k]
		if d["kind"] == "num" {
			for i := 0; i < n-1; i++ {
				i := i
				add(k, func(x int) bool { return x <= i })
			}
			for i := 1; i < n; i++ {
				i := i
				add(k, func(x int) bool { return x >= i })
			}
			if n > 2 {
				for i := 1; i < n-1; i++ {
					i := i
					add(k, func(x int) bool { return x == i })
				}
			}
		} else {
			for i := 0; i < n; i++ {
				i := i
				add(k, func(x int) bool { return x == i })
			}
		}
	}
	return ixLrDedup(tests)
}

func ixLrDedup(masks [][]byte) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	for _, t := range masks {
		key := string(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func ixLrEnumerateDecisionLists(tests [][]byte, nCells, L int, capN float64, verb string) ([][]byte, []int) {
	seen := map[string]bool{}
	var sets [][]byte
	var cx []int
	emit := func(acc, decided []byte, rules int) {
		for dflt := byte(0); dflt <= 1; dflt++ {
			s := make([]byte, nCells)
			anyIn := false
			for c := 0; c < nCells; c++ {
				if decided[c] != 0 {
					s[c] = acc[c]
				} else {
					s[c] = dflt
				}
				if s[c] != 0 {
					anyIn = true
				}
			}
			if !anyIn {
				continue
			}
			key := string(s)
			if seen[key] {
				continue
			}
			seen[key] = true
			sets = append(sets, s)
			r := rules
			if r < 1 {
				r = 1
			}
			cx = append(cx, r)
		}
	}
	type st struct{ decided, acc []byte }
	frontier := []st{{make([]byte, nCells), make([]byte, nCells)}}
	emit(frontier[0].acc, frontier[0].decided, 0)
	work := 0.0
	for depth := 1; depth <= L; depth++ {
		states := map[string]bool{}
		var order []st
		for _, s0 := range frontier {
			for _, t := range tests {
				for label := byte(0); label <= 1; label++ {
					work++
					if !(work <= capN) {
						ixFail("pca-intent: the decision-list class (≤ %d rules) for %s exceeds the enumeration cap", L, verb)
					}
					decided := make([]byte, nCells)
					acc := make([]byte, nCells)
					fresh := false
					for c := 0; c < nCells; c++ {
						if s0.decided[c] != 0 {
							decided[c] = 1
							acc[c] = s0.acc[c]
						} else if t[c] != 0 {
							decided[c] = 1
							acc[c] = label
							fresh = true
						}
					}
					if !fresh {
						continue
					}
					key := string(decided) + "\x02" + string(acc)
					if states[key] {
						continue
					}
					states[key] = true
					order = append(order, st{decided, acc})
				}
			}
		}
		frontier = order
		for _, s := range frontier {
			emit(s.acc, s.decided, depth)
		}
	}
	return sets, cx
}

func ixLrBuildVerbModel(vs map[string]any, opts map[string]any, harm *ixHarm) *ixLrVerbModel {
	dims := ixL(vs["dims"])
	D := len(dims)
	nCellsD := make([]int, D)
	for k, dv := range dims {
		nCellsD[k] = ixCellCount(ixM(dv))
	}
	contains, nChoice := ixLrBuildBoxTables(vs, nCellsD)
	nCells := int(ixVerbCellCount(vs))
	cellIdx := make([]int, nCells*D)
	mass := make([]float64, nCells)
	hm := make([]float64, nCells)
	for c := 0; c < nCells; c++ {
		idx := ixDecodeCell(vs, float64(c))
		for d := 0; d < D; d++ {
			cellIdx[c*D+d] = ixIdx(idx[d])
		}
		mass[c], hm[c] = ixCellStats(vs, idx, harm)
	}
	hc, _ := ixLrOpt(opts, "hypothesisClass", map[string]any{"kind": "box"}).(map[string]any)
	maxHyp := ixLrOptF(opts, "maxHypotheses", 400000)
	maxEnum := ixLrOptF(opts, "maxEnumeration", 4000000)
	choice := []int{0}
	var member [][]byte
	var cmplx []int
	var nh int
	if hc["kind"] == "box" {
		boxesF := 1.0
		for _, c := range nChoice {
			boxesF *= float64(c)
		}
		if !(boxesF+1 <= maxHyp) {
			ixFail("pca-intent: |Θ_%s| = %d exceeds maxHypotheses %s; coarsen the cuts", ixS(vs["verb"]), int64(boxesF)+1, jsNumberString(maxHyp))
		}
		boxes := int(boxesF)
		nh = boxes + 1
		n := boxes * D
		if n < 1 {
			n = 1
		}
		choice = make([]int, n)
		cur := make([]int, D)
		for h := 0; h < boxes; h++ {
			for d := 0; d < D; d++ {
				choice[h*D+d] = cur[d]
			}
			for d := D - 1; d >= 0; d-- {
				cur[d]++
				if cur[d] < nChoice[d] {
					break
				}
				cur[d] = 0
			}
		}
	} else {
		var sets [][]byte
		var cx []int
		if hc["kind"] == "union" {
			k := hc["k"]
			if !(ixLrIsInteger(k) && k.(float64) >= 1) {
				ixFail("pca-intent: union class needs an integer k ≥ 1")
			}
			bm := ixLrBoxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, maxEnum)
			sets, cx = ixLrEnumerateUnions(bm, int(k.(float64)), maxEnum, ixS(vs["verb"]))
		} else {
			mr := hc["maxRules"]
			if !(ixLrIsInteger(mr) && mr.(float64) >= 1) {
				ixFail("pca-intent: decision-list class needs an integer maxRules ≥ 1")
			}
			cond := ixLrOpt(hc, "conditions", "box")
			if cond != "box" && cond != "atomic" {
				ixFail("pca-intent: decision-list conditions must be 'box' or 'atomic'")
			}
			var tests [][]byte
			if cond == "atomic" {
				tests = ixLrAtomicTests(vs, nCells, cellIdx, nCellsD)
			} else {
				tests = ixLrDedup(ixLrBoxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, maxEnum))
			}
			sets, cx = ixLrEnumerateDecisionLists(tests, nCells, int(mr.(float64)), maxEnum, ixS(vs["verb"]))
		}
		if !(float64(len(sets)+1) <= maxHyp) {
			ixFail("pca-intent: |Θ_%s| = %d exceeds maxHypotheses %s; coarsen the cuts", ixS(vs["verb"]), len(sets)+1, jsNumberString(maxHyp))
		}
		nh = len(sets) + 1
		member = append([][]byte{make([]byte, nCells)}, sets...)
		cmplx = append([]int{0}, cx...)
	}
	return &ixLrVerbModel{vs: vs, nChoice: nChoice, contains: contains, nCellsD: nCellsD, nh: nh, choice: choice, member: member,
		cmplx: cmplx, prior: make([]float64, nh), w: make([]float64, nh), err: make([]int, nh), nCells: nCells, cellIdx: cellIdx,
		mass: mass, harm: hm, p: make([]float64, nCells), veto: make([]byte, nCells), seen: make([]byte, nCells), dirty: true}
}

// holds: does hypothesis h (>= 1) contain flat cell c?
func (m *ixLrVerbModel) holds(h, c int) bool {
	if m.member != nil {
		return m.member[h][c] == 1
	}
	D := len(ixL(m.vs["dims"]))
	base := (h - 1) * D
	for d := 0; d < D; d++ {
		n := m.nCellsD[d]
		if m.contains[d][m.choice[base+d]*n+m.cellIdx[c*D+d]] == 0 {
			return false
		}
	}
	return true
}

func (m *ixLrVerbModel) holdsAll(h int, cells []int) bool {
	if h == 0 {
		return false
	}
	for _, c := range cells {
		if !m.holds(h, c) {
			return false
		}
	}
	return true
}

func (m *ixLrVerbModel) flat(idx []any) int {
	f := 0
	for d := range idx {
		f = f*m.nCellsD[d] + ixIdx(idx[d])
	}
	return f
}

func ixLrNormalize(w []float64) {
	s := 0.0
	for _, x := range w {
		s += x
	}
	if s > 0 {
		for i := range w {
			w[i] = w[i] / s
		}
	}
}

func ixLrApplyMonotone(m *ixLrVerbModel, mono map[string]any) {
	off := ixLrOptF(mono, "offMass", 0)
	if !(off >= 0 && off <= 1) {
		ixFail("pca-intent: monotone.offMass must be in [0, 1]")
	}
	dims := ixL(m.vs["dims"])
	D := len(dims)
	paths := map[string]bool{}
	for _, p := range ixL(mono["paths"]) {
		paths[ixS(p)] = true
	}
	var ks []int
	for k, dv := range dims {
		d := ixM(dv)
		if d["kind"] == "num" && paths[ixS(d["path"])] {
			ks = append(ks, k)
		}
	}
	if len(ks) == 0 {
		return
	}
	stride := make([]int, len(ks))
	for i, k := range ks {
		s := 1
		for _, x := range m.nCellsD[k+1:] {
			s *= x
		}
		stride[i] = s
	}
	for h := 1; h < m.nh; h++ {
		isMono := true
		for c := 0; c < m.nCells && isMono; c++ {
			if m.holds(h, c) {
				for i := range ks {
					if m.cellIdx[c*D+ks[i]] > 0 && !m.holds(h, c-stride[i]) {
						isMono = false
						break
					}
				}
			}
		}
		if !isMono {
			m.w[h] = m.w[h] * off
		}
	}
}

func ixLrMixPrior(m *ixLrVerbModel, beta float64, weight func(vs map[string]any, has func(cell int) bool) float64) {
	if !(beta >= 0 && beta < 1) {
		ixFail("pca-intent: priorMix.beta must be in [0, 1)")
	}
	pop := make([]float64, m.nh)
	z := 0.0
	for h := 0; h < m.nh; h++ {
		h := h
		has := func(c int) bool { return h != 0 && c >= 0 && c < m.nCells && m.holds(h, c) }
		if weight == nil {
			ixFail("pca-intent: priorMix.weight must be finite and >= 0")
		}
		x := weight(m.vs, has)
		if !(!math.IsNaN(x) && !math.IsInf(x, 0) && x >= 0) {
			ixFail("pca-intent: priorMix.weight must be finite and >= 0")
		}
		pop[h] = x
		z += x
	}
	if !(z > 0) {
		return
	}
	for h := 0; h < m.nh; h++ {
		m.w[h] = float64((1-beta)*m.w[h]) + (beta*pop[h])/z
	}
}

// IntentLearner is the exact posterior over Theta = prod_v Theta_v; options are the reference's plain-data LearnerOptions.
type IntentLearner struct {
	omega        map[string]any
	opts         map[string]any
	hooks        IntentLearnerHooks
	eta          float64
	etaPos       float64
	etaNeg       float64
	noisy        bool
	tau          float64
	strategy     string
	harm         *ixHarm
	hc           map[string]any
	agnostic     float64
	hasAgnostic  bool
	observations []map[string]any
	models       []*ixLrVerbModel
	mapParams    map[string]any // the options an Intent Map can record (set by IntentCreateLearner only)
}

// NewIntentLearner builds the learner for an outcome space; hooks may be nil.
func NewIntentLearner(omega, opts map[string]any, hooks *IntentLearnerHooks) (l *IntentLearner, err error) {
	r, err := ixTry(func() any { return ixNewLearner(omega, opts, hooks) })
	if err != nil {
		return nil, err
	}
	return r.(*IntentLearner), nil
}

func ixNewLearner(omega, opts map[string]any, hooks *IntentLearnerHooks) *IntentLearner {
	if opts == nil {
		opts = map[string]any{}
	}
	l := &IntentLearner{omega: omega, opts: opts}
	if hooks != nil {
		l.hooks = *hooks
	}
	l.eta = ixLrOptF(opts, "eta", 0)
	if !(l.eta >= 0 && l.eta < 0.5) {
		ixFail("pca-intent: eta must be in [0, 0.5)")
	}
	l.etaPos = ixLrOptF(opts, "etaPos", l.eta)
	l.etaNeg = ixLrOptF(opts, "etaNeg", l.eta)
	if !(l.etaPos >= 0 && l.etaPos < 0.5 && l.etaNeg >= 0 && l.etaNeg < 0.5) {
		ixFail("pca-intent: etaPos and etaNeg must be in [0, 0.5)")
	}
	l.noisy = l.etaPos != 0 || l.etaNeg != 0
	defTau := 1.0
	if l.noisy {
		defTau = 0.95
	}
	l.tau = ixLrOptF(opts, "tau", defTau)
	l.strategy = ixS(ixLrOpt(opts, "strategy", "disagreement"))
	l.harm = ixDefaultHarm
	if l.hooks.harm != nil {
		l.harm = l.hooks.harm
	}
	l.hc, _ = ixLrOpt(opts, "hypothesisClass", map[string]any{"kind": "box"}).(map[string]any)
	if v := opts["agnosticSlack"]; v != nil {
		if !(ixLrIsInteger(v) && v.(float64) >= 0) {
			ixFail("pca-intent: agnosticSlack must be a non-negative integer")
		}
		if l.noisy {
			ixFail("pca-intent: agnostic selection replaces the noise model; use eta = 0")
		}
		l.agnostic, l.hasAgnostic = v.(float64), true
	}
	for _, vv := range ixL(omega["verbs"]) {
		l.models = append(l.models, ixLrBuildVerbModel(ixM(vv), opts, l.harm))
	}
	l.initPrior()
	return l
}

func (l *IntentLearner) initPrior() {
	opts := l.opts
	var anchors []map[string]any
	if a := ixM(opts["anchor"]); a != nil {
		anchors = append(anchors, a)
	}
	for _, a := range ixL(opts["anchors"]) {
		anchors = append(anchors, ixM(a))
	}
	type anc struct {
		adm *IntentAdmitter
		lam float64
	}
	var admitters []anc
	for _, a := range anchors {
		if ixF(a["lambda"]) > 0 {
			adm, err := IntentNewAdmitter(a["policy"])
			if err != nil {
				panic(err)
			}
			admitters = append(admitters, anc{adm, ixF(a["lambda"])})
		}
	}
	decay := 1.0
	if l.hc["kind"] != "box" {
		decay = ixLrOptF(l.hc, "decay", 0.25)
	}
	if !(decay > 0 && decay <= 1) {
		ixFail("pca-intent: decay must be in (0, 1]")
	}
	for _, m := range l.models {
		var nm float64
		if l.hooks.NullMass != nil {
			nm = l.hooks.NullMass(m.vs)
		} else {
			nm = ixLrOptF(opts, "nullMass", 0.2)
		}
		if !(nm >= 0 && nm <= 1) {
			ixFail("pca-intent: nullMass must be in [0, 1]")
		}
		m.w[0] = nm
		z := 0.0
		for h := 1; h < m.nh; h++ {
			raw := 1.0
			if m.cmplx != nil {
				raw = math.Pow(decay, float64(m.cmplx[h]-1))
			}
			m.w[h] = raw
			z += raw
		}
		for h := 1; h < m.nh; h++ {
			m.w[h] = ((1 - nm) * m.w[h]) / ixLrOr1(z)
		}
		if mono := ixM(opts["monotone"]); mono != nil {
			ixLrApplyMonotone(m, mono)
		}
		if len(admitters) > 0 {
			tot := 0.0
			for c := 0; c < m.nCells; c++ {
				tot += m.mass[c]
			}
			accs := make([][]byte, len(admitters))
			for i, a := range admitters {
				acc := make([]byte, m.nCells)
				for c := 0; c < m.nCells; c++ {
					if a.adm.admits(m.vs, ixCellRep(m.vs, ixDecodeCell(m.vs, float64(c)))) {
						acc[c] = 1
					}
				}
				accs[i] = acc
			}
			for h := 0; h < m.nh; h++ {
				mix := 0.0
				for i, acc := range accs {
					dist := 0.0
					for c := 0; c < m.nCells; c++ {
						in := byte(0)
						if h != 0 && m.holds(h, c) {
							in = 1
						}
						if in != acc[c] {
							dist += m.mass[c]
						}
					}
					mix += math.Exp((-admitters[i].lam * dist) / ixLrOr1(tot))
				}
				m.w[h] = m.w[h] * (mix / float64(len(accs)))
			}
		}
		ixLrNormalize(m.w)
		if pm := ixM(opts["priorMix"]); pm != nil {
			ixLrMixPrior(m, ixF(pm["beta"]), l.hooks.PriorMixWeight)
		}
		m.prior = append([]float64(nil), m.w...)
		m.dirty = true
	}
}

func (l *IntentLearner) inGrant(m *ixLrVerbModel, c int) bool {
	return m.veto[c] == 0 && m.p[c] >= l.tau-1e-12
}

func (l *IntentLearner) model(verb any) *ixLrVerbModel {
	for _, m := range l.models {
		if m.vs["verb"] == verb {
			return m
		}
	}
	return nil
}

func (l *IntentLearner) refresh(m *ixLrVerbModel) {
	if !m.dirty {
		return
	}
	m.p = make([]float64, m.nCells)
	anyIn := make([]bool, m.nCells)
	anyOut := make([]bool, m.nCells)
	live := false
	for h := 0; h < m.nh; h++ {
		w := m.w[h]
		if w == 0 {
			continue
		}
		live = true
		for c := 0; c < m.nCells; c++ {
			if h > 0 && m.holds(h, c) {
				m.p[c] = m.p[c] + w
				anyIn[c] = true
			} else {
				anyOut[c] = true
			}
		}
	}
	for c := 0; c < m.nCells; c++ {
		switch {
		case !live || !anyIn[c]:
			m.p[c] = 0
		case !anyOut[c]:
			m.p[c] = 1
		default:
			m.p[c] = math.Min(1, math.Max(0, m.p[c]))
		}
	}
	m.dirty = false
}

// Acceptance is p_n(omega) for a concrete outcome (0 if outside Omega: the conservative reading).
func (l *IntentLearner) Acceptance(o map[string]any) float64 {
	m := l.model(o["verb"])
	if m == nil {
		return 0
	}
	idx := ixCellOf(m.vs, o)
	if idx == nil {
		return 0
	}
	l.refresh(m)
	return m.p[m.flat(idx)]
}

// AdmitsOutcome reports whether the outcome is inside the conservative grant.
func (l *IntentLearner) AdmitsOutcome(o map[string]any) bool {
	m := l.model(o["verb"])
	if m == nil {
		return false
	}
	idx := ixCellOf(m.vs, o)
	if idx == nil {
		return false
	}
	l.refresh(m)
	return l.inGrant(m, m.flat(idx))
}

// IsVetoed reports whether the outcome's cell was refused at run time.
func (l *IntentLearner) IsVetoed(o map[string]any) bool {
	m := l.model(o["verb"])
	if m == nil {
		return false
	}
	idx := ixCellOf(m.vs, o)
	return idx != nil && m.veto[m.flat(idx)] == 1
}

func (l *IntentLearner) vetoedCells() []any {
	out := []any{}
	for _, m := range l.models {
		for c := 0; c < m.nCells; c++ {
			if m.veto[c] != 0 {
				out = append(out, ixS(m.vs["verb"])+"|"+jsNumberString(float64(c)))
			}
		}
	}
	return out
}

// Observe records the principal's answer y to "should omega be allowed?" (or, with a region, "should EVERY outcome in it be
// allowed?") and updates the posterior. nil when the outcome is outside Omega or the region covers no cell.
func (l *IntentLearner) Observe(o map[string]any, y float64, source string, region map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any {
		if v := l.observe(o, y, source, region); v != nil {
			return v
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	m, _ := r.(map[string]any)
	return m, nil
}

func (l *IntentLearner) observe(o map[string]any, y float64, source string, region map[string]any) map[string]any {
	m := l.model(o["verb"])
	if m == nil {
		return nil
	}
	idx := ixCellOf(m.vs, o)
	if idx == nil {
		return nil
	}
	var cells []int
	if region != nil {
		mode := "outer"
		if y == 1 {
			mode = "inner"
		}
		cells = ixRegionCells(m.vs, region, mode)
	} else {
		cells = []int{m.flat(idx)}
	}
	if len(cells) == 0 {
		return nil
	}
	l.refresh(m)
	vals := map[string]any{}
	for k, v := range ixM(o["values"]) {
		vals[k] = v
	}
	obs := map[string]any{"verb": o["verb"], "values": vals, "cell": ixToAnyL(idx), "y": y, "source": source}
	if region != nil {
		obs["region"] = region
	}
	regionP := 0.0
	for h := 1; h < m.nh; h++ {
		if m.w[h] > 0 && m.holdsAll(h, cells) {
			regionP += m.w[h]
		}
	}
	var contradictsAll bool
	if y == 0 {
		contradictsAll = regionP >= 1-1e-12
	} else {
		contradictsAll = regionP <= 1e-12
	}
	if source == "runtime" && y == 0 {
		for _, c := range cells {
			m.veto[c] = 1
		}
	}
	for _, c := range cells {
		m.seen[c] = 1
	}
	if l.hasAgnostic {
		for h := 0; h < m.nh; h++ {
			in := 0.0
			if m.holdsAll(h, cells) {
				in = 1
			}
			if in != y {
				m.err[h]++
			}
		}
		minErr := math.Inf(1)
		for h := 0; h < m.nh; h++ {
			if m.prior[h] > 0 {
				minErr = math.Min(minErr, float64(m.err[h]))
			}
		}
		for h := 0; h < m.nh; h++ {
			if float64(m.err[h]) <= minErr+l.agnostic {
				m.w[h] = m.prior[h]
			} else {
				m.w[h] = 0
			}
		}
		ixLrNormalize(m.w)
		if contradictsAll {
			obs["conflict"] = true
			if y == 0 {
				for _, c := range cells {
					m.veto[c] = 1
				}
			}
		}
	} else {
		var prev []float64
		if l.etaPos == 0 || l.etaNeg == 0 {
			prev = append([]float64(nil), m.w...)
		}
		lik := func(in bool) float64 {
			if in {
				if y == 1 {
					return 1 - l.etaNeg
				}
				return l.etaNeg
			}
			if y == 1 {
				return l.etaPos
			}
			return 1 - l.etaPos
		}
		total := 0.0
		for h := 0; h < m.nh; h++ {
			m.w[h] = m.w[h] * lik(m.holdsAll(h, cells))
			total += m.w[h]
		}
		if total == 0 && prev != nil {
			m.w = prev
			obs["conflict"] = true
			if y == 0 {
				for _, c := range cells {
					m.veto[c] = 1
				}
			}
		} else {
			ixLrNormalize(m.w)
		}
	}
	m.dirty = true
	l.observations = append(l.observations, obs)
	return obs
}

func ixToAnyL(xs []any) []any { return append([]any{}, xs...) }

// ObservationsJSON is the recorded observations as a JSON list.
func (l *IntentLearner) ObservationsJSON() []any {
	out := make([]any, len(l.observations))
	for i, o := range l.observations {
		out[i] = o
	}
	return out
}

// Cells is the per-cell posterior view.
func (l *IntentLearner) Cells() []any {
	out := []any{}
	for _, m := range l.models {
		l.refresh(m)
		for c := 0; c < m.nCells; c++ {
			out = append(out, map[string]any{"verb": m.vs["verb"], "cell": ixDecodeCell(m.vs, float64(c)), "p": m.p[c], "mass": m.mass[c],
				"harm": m.harm[c], "inGrant": l.inGrant(m, c), "vetoed": m.veto[c] == 1})
		}
	}
	return out
}

// Metrics is the learner's risk / burden / uncertainty summary.
func (l *IntentLearner) Metrics() map[string]any {
	var R, B, U, H, vsBits, dis, meanHarm float64
	for _, m := range l.models {
		l.refresh(m)
		for c := 0; c < m.nCells; c++ {
			p := m.p[c]
			mu := m.mass[c]
			meanHarm += float64(mu * m.harm[c])
			if l.inGrant(m, c) {
				R += float64(mu * (1 - p) * m.harm[c])
			} else {
				B += float64(mu * p)
			}
			U += float64(mu * math.Min(p, 1-p))
			if p > 1e-12 && p < 1-1e-12 {
				dis += mu
			}
		}
		alive := 0
		for h := 0; h < m.nh; h++ {
			w := m.w[h]
			if w > 0 {
				alive++
				H -= float64(w * ixLog2(w))
			}
		}
		vsBits += ixLog2(math.Max(1, float64(alive)))
	}
	var vsOut any = vsBits
	if l.noisy {
		vsOut = nil
	}
	questions, conflicts := 0.0, 0.0
	for _, o := range l.observations {
		if o["source"] == "elicitation" {
			questions++
		}
		if o["conflict"] == true {
			conflicts++
		}
	}
	return map[string]any{"residualRisk": R, "burden": B, "uncertainty": U, "entropyBits": H, "log2VersionSpace": vsOut,
		"disagreementMass": dis, "meanHarm": meanHarm, "questions": questions, "conflicts": conflicts}
}

// NextQuestion is the argmax-expected-information question (x mu*h for the risk strategy); nil when nothing is uncertain.
func (l *IntentLearner) NextQuestion() map[string]any {
	var best map[string]any
	bestScore := 0.0
	hPos, hNeg := ixLrBinEnt(l.etaPos), ixLrBinEnt(l.etaNeg)
	for _, m := range l.models {
		l.refresh(m)
		for c := 0; c < m.nCells; c++ {
			if m.veto[c] != 0 {
				continue
			}
			p := m.p[c]
			if p <= 1e-9 || p >= 1-1e-9 {
				continue
			}
			pe := float64(p*(1-l.etaNeg)) + float64((1-p)*l.etaPos)
			var sub float64
			if l.etaPos == l.etaNeg {
				sub = hPos
			} else {
				sub = float64(p*hNeg) + float64((1-p)*hPos)
			}
			score := ixLrBinEnt(pe) - sub
			if l.strategy == "risk" {
				score *= m.mass[c] * m.harm[c]
			}
			if score <= 1e-15 {
				continue
			}
			if best == nil || score > bestScore+1e-12 {
				cell := ixDecodeCell(m.vs, float64(c))
				best = map[string]any{"verb": m.vs["verb"], "cell": cell, "outcome": ixCellRep(m.vs, cell), "p": p, "score": score}
				bestScore = score
			}
		}
	}
	return best
}

// UnconfirmedGrantCells are the grant cells inferred but never directly observed, most consequential first.
func (l *IntentLearner) UnconfirmedGrantCells() []map[string]any {
	var out []map[string]any
	for _, m := range l.models {
		l.refresh(m)
		for c := 0; c < m.nCells; c++ {
			if m.seen[c] != 0 || !l.inGrant(m, c) {
				continue
			}
			out = append(out, map[string]any{"verb": m.vs["verb"], "cell": ixDecodeCell(m.vs, float64(c)), "weight": m.mass[c] * m.harm[c]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["weight"].(float64) > out[j]["weight"].(float64) })
	return out
}

// Synthesize is the conservative grant G_tau as a real PCA policy: allow only cells with p_n >= tau.
func (l *IntentLearner) Synthesize() map[string]any {
	predicates := []any{}
	worst := -1
	for _, m := range l.models {
		l.refresh(m)
		allowed := make([]byte, m.nCells)
		anyIn := false
		for c := 0; c < m.nCells; c++ {
			if l.inGrant(m, c) {
				allowed[c] = 1
				anyIn = true
			}
		}
		if !anyIn {
			continue
		}
		for i, r := range ixLrOrder {
			if m.vs["reversibility"] == r && i > worst {
				worst = i
			}
		}
		predicates = append(predicates, IntentBoxesToPredicates(m.vs, allowed)...)
	}
	caveats := []any{}
	if worst >= 0 {
		caveats = append(caveats, map[string]any{"type": "reversibility_max", "class": ixLrOrder[worst]})
	}
	return map[string]any{"predicates": predicates, "caveats": caveats}
}

// ReplayIntentLearner replays observations onto a fresh learner (used to verify an Intent Map).
func ReplayIntentLearner(omega, opts map[string]any, hooks *IntentLearnerHooks, observations []map[string]any) (*IntentLearner, error) {
	l, err := NewIntentLearner(omega, opts, hooks)
	if err != nil {
		return nil, err
	}
	for _, o := range observations {
		region, _ := o["region"].(map[string]any)
		if _, err := l.Observe(map[string]any{"verb": o["verb"], "values": o["values"]}, ixF(o["y"]), ixS(o["source"]), region); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// IntentHypothesisCellSets are the non-empty hypotheses of Theta_v for a class as 0/1 cell masks, each with its Occam complexity.
func IntentHypothesisCellSets(vs, class, caps map[string]any) (sets [][]byte, complexity []int, err error) {
	_, err = ixTry(func() any {
		o := map[string]any{"maxHypotheses": 400000.0, "maxEnumeration": 4000000.0}
		for k, v := range caps {
			if v != nil {
				o[k] = v
			}
		}
		if class == nil {
			class = map[string]any{"kind": "box"}
		}
		o["hypothesisClass"] = class
		m := ixLrBuildVerbModel(vs, o, ixDefaultHarm)
		for h := 1; h < m.nh; h++ {
			s := make([]byte, m.nCells)
			for c := 0; c < m.nCells; c++ {
				if m.holds(h, c) {
					s[c] = 1
				}
			}
			sets = append(sets, s)
			if m.cmplx != nil {
				complexity = append(complexity, m.cmplx[h])
			} else {
				complexity = append(complexity, 1)
			}
		}
		return nil
	})
	return
}

// ---- synthesis: allowed cells -> union of boxes -> predicates ----

func ixLrEncode(vs map[string]any, idx []int) int {
	f := 0
	for i, dv := range ixL(vs["dims"]) {
		f = f*ixCellCount(ixM(dv)) + idx[i]
	}
	return f
}

// ixLrRange is one dimension of a box: a numeric [lo, hi] or a categorical set with insertion order.
type ixLrRange struct {
	lo, hi int
	set    []int
	in     map[int]bool
}

func ixLrBoxCells(ranges []*ixLrRange, cat []bool, emit func(idx []int) bool) bool {
	vals := make([][]int, len(ranges))
	for i, r := range ranges {
		if cat[i] {
			s := append([]int(nil), r.set...)
			sort.Ints(s)
			vals[i] = s
		} else {
			for x := r.lo; x <= r.hi; x++ {
				vals[i] = append(vals[i], x)
			}
		}
	}
	idx := make([]int, len(ranges))
	var rec func(k int) bool
	rec = func(k int) bool {
		if k == len(ranges) {
			return emit(idx)
		}
		for _, v := range vals[k] {
			idx[k] = v
			if !rec(k + 1) {
				return false
			}
		}
		return true
	}
	return rec(0)
}

func ixLrCatCondition(d map[string]any, s []int) any {
	values := ixL(d["values"])
	if len(s) == len(values) {
		return nil
	}
	path := d["path"]
	var exacts, prefixes []string
	for _, v := range values {
		vm := ixM(v)
		switch vm["kind"] {
		case "exact":
			exacts = append(exacts, ixS(vm["value"]))
		case "prefix":
			prefixes = append(prefixes, ixS(vm["value"]))
		}
	}
	alts := []any{}
	var allowedExacts []any
	for _, i := range s {
		vm := ixM(values[i])
		if vm["kind"] == "exact" {
			allowedExacts = append(allowedExacts, vm["value"])
		}
	}
	if len(allowedExacts) == 1 {
		alts = append(alts, map[string]any{"field": path, "op": "eq", "value": allowedExacts[0]})
	} else if len(allowedExacts) > 1 {
		alts = append(alts, map[string]any{"field": path, "op": "in", "value": allowedExacts})
	}
	sorted := append([]int(nil), s...)
	sort.Ints(sorted)
	for _, i := range sorted {
		v := ixM(values[i])
		if v["kind"] == "exact" {
			continue
		}
		parts := []any{}
		if v["kind"] == "prefix" {
			vp := ixS(v["value"])
			parts = append(parts, map[string]any{"field": path, "op": "prefix", "value": vp})
			var under []string
			for _, e := range exacts {
				if strings.HasPrefix(e, vp) {
					under = append(under, e)
				}
			}
			if len(under) > 0 {
				parts = append(parts, map[string]any{"field": path, "op": "nin", "value": ixToAny(under)})
			}
			for _, q := range prefixes {
				if q != vp && strings.HasPrefix(q, vp) {
					parts = append(parts, map[string]any{"not": map[string]any{"field": path, "op": "prefix", "value": q}})
				}
			}
		} else {
			if len(exacts) > 0 {
				parts = append(parts, map[string]any{"field": path, "op": "nin", "value": ixToAny(exacts)})
			}
			for _, q := range prefixes {
				parts = append(parts, map[string]any{"not": map[string]any{"field": path, "op": "prefix", "value": q}})
			}
		}
		if len(parts) == 1 {
			alts = append(alts, parts[0])
		} else if len(parts) > 1 {
			alts = append(alts, map[string]any{"all_of": parts})
		}
	}
	if len(alts) == 0 {
		return nil
	}
	if len(alts) == 1 {
		return alts[0]
	}
	return map[string]any{"any_of": alts}
}

func ixLrBoxToPredicate(vs map[string]any, ranges []*ixLrRange) map[string]any {
	where := []any{}
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		r := ranges[k]
		if d["kind"] == "num" {
			cells := ixNumCells(d)
			where = append(where, map[string]any{"field": d["path"], "op": "gte", "value": cells[r.lo].lo},
				map[string]any{"field": d["path"], "op": "lte", "value": cells[r.hi].hi})
		} else if c := ixLrCatCondition(d, r.set); c != nil {
			where = append(where, c)
		}
	}
	out := map[string]any{"verb": vs["verb"], "resource": "*"}
	if len(where) > 0 {
		out["where"] = where
	}
	return out
}

// IntentBoxesToPredicates covers the allowed cell set exactly with greedily grown maximal boxes; one predicate per box.
func IntentBoxesToPredicates(vs map[string]any, allowed []byte) []any {
	dims := ixL(vs["dims"])
	cat := make([]bool, len(dims))
	for k, dv := range dims {
		cat[k] = ixM(dv)["kind"] != "num"
	}
	covered := make([]bool, len(allowed))
	out := []any{}
	all := func(ranges []*ixLrRange) bool {
		return ixLrBoxCells(ranges, cat, func(idx []int) bool { return allowed[ixLrEncode(vs, idx)] == 1 })
	}
	for c := range allowed {
		if allowed[c] == 0 || covered[c] {
			continue
		}
		idx := ixDecodeCell(vs, float64(c))
		ranges := make([]*ixLrRange, len(dims))
		for k := range dims {
			i := ixIdx(idx[k])
			if cat[k] {
				ranges[k] = &ixLrRange{set: []int{i}, in: map[int]bool{i: true}}
			} else {
				ranges[k] = &ixLrRange{lo: i, hi: i}
			}
		}
		for k, dv := range dims {
			d := ixM(dv)
			if !cat[k] {
				n := len(ixNumCells(d))
				r := ranges[k]
				for r.hi+1 < n {
					r.hi++
					if !all(ranges) {
						r.hi--
						break
					}
				}
				for r.lo > 0 {
					r.lo--
					if !all(ranges) {
						r.lo++
						break
					}
				}
			} else {
				s := ranges[k]
				for v := 0; v < len(ixL(d["values"])); v++ {
					if s.in[v] {
						continue
					}
					s.in[v] = true
					s.set = append(s.set, v)
					if !all(ranges) {
						delete(s.in, v)
						s.set = s.set[:len(s.set)-1]
					}
				}
			}
		}
		ixLrBoxCells(ranges, cat, func(bi []int) bool { covered[ixLrEncode(vs, bi)] = true; return true })
		out = append(out, ixLrBoxToPredicate(vs, ranges))
	}
	return out
}

// ---- the stop rule ----

func (l *IntentLearner) seedQuestion(s map[string]any) map[string]any {
	var vs map[string]any
	for _, v := range ixL(l.omega["verbs"]) {
		if ixM(v)["verb"] == s["verb"] {
			vs = ixM(v)
			break
		}
	}
	cell := ixL(s["cell"])
	if vs == nil || len(cell) != len(ixL(vs["dims"])) {
		return nil
	}
	outcome := ixCellRep(vs, cell)
	p := l.Acceptance(outcome)
	if p <= 1e-9 || p >= 1-1e-9 || l.IsVetoed(outcome) {
		return nil
	}
	return map[string]any{"verb": s["verb"], "cell": ixToAnyL(cell), "outcome": outcome, "p": p, "score": 0.0}
}

// IntentElicit asks questions until the stop rule of spec 2.5 holds. o: epsRisk, epsBurden, maxQuestions, audit, seed.
func IntentElicit(l *IntentLearner, answer func(q map[string]any) float64, o map[string]any) (res map[string]any, err error) {
	r, err := ixTry(func() any { return l.elicit(answer, o) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (l *IntentLearner) elicit(answer func(q map[string]any) float64, o map[string]any) map[string]any {
	epsRisk, epsBurden, maxQ := ixF(o["epsRisk"]), ixF(o["epsBurden"]), ixF(o["maxQuestions"])
	var asked []any
	seedQuestions := 0.0
	for _, sv := range ixL(o["seed"]) {
		if !(float64(len(asked)) < maxQ) {
			break
		}
		m := l.Metrics()
		if m["residualRisk"].(float64) <= epsRisk && m["burden"].(float64) <= epsBurden {
			break
		}
		q := l.seedQuestion(ixM(sv))
		if q == nil {
			continue
		}
		l.observe(ixM(q["outcome"]), answer(q), "elicitation", nil)
		asked = append(asked, q)
		seedQuestions++
	}
	stop := ""
	for stop == "" {
		m := l.Metrics()
		if m["residualRisk"].(float64) <= epsRisk && m["burden"].(float64) <= epsBurden {
			stop = "converged"
		} else if !(float64(len(asked)) < maxQ) {
			stop = "budget"
		} else {
			q := l.NextQuestion()
			if q == nil {
				stop = "no-disagreement"
			} else {
				l.observe(ixM(q["outcome"]), answer(q), "elicitation", nil)
				asked = append(asked, q)
			}
		}
	}
	n, exhausted := l.auditRound(answer, o, &asked)
	if exhausted {
		stop = "budget"
	}
	if asked == nil {
		asked = []any{}
	}
	return map[string]any{"stop": stop, "questions": float64(len(asked)), "auditQuestions": float64(n), "seedQuestions": seedQuestions, "asked": asked}
}

// auditRound is the audit round on its own (spec 4.2c): the questions asked, and whether the budget ran out.
func (l *IntentLearner) auditRound(answer func(q map[string]any) float64, o map[string]any, asked *[]any) (n int, exhausted bool) {
	if !ixTruthy(o["audit"]) {
		return 0, false
	}
	epsRisk, maxQ := ixF(o["epsRisk"]), ixF(o["maxQuestions"])
	for {
		pending := l.UnconfirmedGrantCells()
		mass := 0.0
		for _, x := range pending {
			mass += x["weight"].(float64)
		}
		if len(pending) == 0 || mass <= epsRisk {
			return n, false
		}
		if !(float64(len(*asked)) < maxQ) {
			return n, true
		}
		top := pending[0]
		var vs map[string]any
		for _, v := range ixL(l.omega["verbs"]) {
			if ixM(v)["verb"] == top["verb"] {
				vs = ixM(v)
				break
			}
		}
		if vs == nil {
			ixFail("no verb space")
		}
		outcome := ixCellRep(vs, top["cell"].([]any))
		q := map[string]any{"verb": top["verb"], "cell": top["cell"], "outcome": outcome, "p": l.Acceptance(ixCellRep(vs, top["cell"].([]any))), "score": top["weight"]}
		l.observe(ixM(q["outcome"]), answer(q), "elicitation", nil)
		*asked = append(*asked, q)
		n++
	}
}
