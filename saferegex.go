package pca

// The linear-time regular-expression subset of the predicate DSL (`re:` resource patterns and the `matches`
// operator), a port of packages/pca/src/safe-regex.ts (parser, Thompson NFA, Pike simulation) together with the
// isSafeRegexSource guard and the per-document work budget of predicates.ts / regex-budget.ts. Patterns and subjects
// are sequences of UTF-16 code units, exactly like a flagless JavaScript RegExp.

import (
	"math"
	"sort"
)

const (
	maxNFAInstructions         = 4096
	maxRegexRepeat             = 64
	maxMatchSteps              = 2_000_000
	maxRegexEvaluationsPerDoc  = 64
	maxRegexSourceCharsPerDoc  = 8192
	maxRegexStepsPerDoc        = 5_000_000
	maxRegexCostBits           = 22
	unboundedQuantifierBits    = 8
	maxBoundedRepeatSafeSource = 64
	regexOpSet, regexOpSplit   = 0, 1
	regexOpJmp, regexOpBol     = 2, 3
	regexOpEol, regexOpMatch   = 4, 5
)

type charRange [2]int

type charSet struct {
	ranges  []charRange
	negated bool
}

func (c *charSet) has(u int) bool {
	lo, hi := 0, len(c.ranges)-1
	inside := false
	for lo <= hi {
		mid := (lo + hi) >> 1
		r := c.ranges[mid]
		if u < r[0] {
			hi = mid - 1
		} else if u > r[1] {
			lo = mid + 1
		} else {
			inside = true
			break
		}
	}
	return inside != c.negated
}

var (
	reDigit = []charRange{{0x30, 0x39}}
	reWord  = []charRange{{0x30, 0x39}, {0x41, 0x5a}, {0x5f, 0x5f}, {0x61, 0x7a}}
	reSpace = []charRange{{0x09, 0x0d}, {0x20, 0x20}, {0xa0, 0xa0}, {0x1680, 0x1680}, {0x2000, 0x200a}, {0x2028, 0x2029},
		{0x202f, 0x202f}, {0x205f, 0x205f}, {0x3000, 0x3000}, {0xfeff, 0xfeff}}
	reLineTerminators = []charRange{{0x0a, 0x0a}, {0x0d, 0x0d}, {0x2028, 0x2029}}
)

func normalizeRanges(rs []charRange) []charRange {
	s := append([]charRange(nil), rs...)
	sort.SliceStable(s, func(i, j int) bool { return s[i][0] < s[j][0] })
	out := []charRange{}
	for _, r := range s {
		if n := len(out); n > 0 && r[0] <= out[n-1][1]+1 {
			if r[1] > out[n-1][1] {
				out[n-1][1] = r[1]
			}
		} else {
			out = append(out, r)
		}
	}
	return out
}

func complementRanges(r []charRange) []charRange {
	out := []charRange{}
	next := 0
	for _, x := range normalizeRanges(r) {
		if x[0] > next {
			out = append(out, charRange{next, x[0] - 1})
		}
		next = x[1] + 1
	}
	if next <= 0xffff {
		out = append(out, charRange{next, 0xffff})
	}
	return out
}

const (
	nodeSet = iota
	nodeBol
	nodeEol
	nodeCat
	nodeAlt
	nodeRep
)

type reNode struct {
	k        int
	set      *charSet
	items    []*reNode
	node     *reNode
	min, max int // max < 0: unbounded
}

type regexRefuse struct{}

type reParser struct {
	s []uint16
	i int
}

func (p *reParser) at(i int) (uint16, bool) {
	if i < len(p.s) {
		return p.s[i], true
	}
	return 0, false
}

func (p *reParser) parse() *reNode {
	n := p.alt()
	if p.i < len(p.s) {
		panic(regexRefuse{})
	}
	return n
}

func (p *reParser) alt() *reNode {
	items := []*reNode{p.cat()}
	for {
		c, ok := p.at(p.i)
		if !ok || c != '|' {
			break
		}
		p.i++
		items = append(items, p.cat())
	}
	if len(items) == 1 {
		return items[0]
	}
	return &reNode{k: nodeAlt, items: items}
}

func (p *reParser) cat() *reNode {
	items := []*reNode{}
	for p.i < len(p.s) && p.s[p.i] != '|' && p.s[p.i] != ')' {
		items = append(items, p.quantified())
	}
	return &reNode{k: nodeCat, items: items}
}

// braceQuant matches ^\{(\d{lo})(?:(,)(\d{0,hi}))?\} at s[i:] (maxDigits < 0: unlimited digits). Returns the bounds
// as float64 (Number() of the digit strings), whether a comma was present, whether the upper bound is empty, and
// the length matched.
func braceQuant(s []uint16, i int, window, maxDigits int) (lo, hi float64, comma, emptyHi bool, n int, ok bool) {
	end := len(s)
	if window >= 0 && i+window < end {
		end = i + window
	}
	j := i
	if j >= end || s[j] != '{' {
		return
	}
	j++
	d0 := j
	for j < end && s[j] >= '0' && s[j] <= '9' && (maxDigits < 0 || j-d0 < maxDigits) {
		j++
	}
	if j == d0 {
		return
	}
	lo = digitsValue(s[d0:j])
	if j < end && s[j] == ',' {
		k := j + 1
		e0 := k
		for k < end && s[k] >= '0' && s[k] <= '9' && (maxDigits < 0 || k-e0 < maxDigits) {
			k++
		}
		if k < end && s[k] == '}' {
			comma = true
			emptyHi = k == e0
			if !emptyHi {
				hi = digitsValue(s[e0:k])
			}
			return lo, hi, comma, emptyHi, k + 1 - i, true
		}
		// the optional group fails; fall through to require `}` right after the first number
	}
	if j < end && s[j] == '}' {
		return lo, lo, false, false, j + 1 - i, true
	}
	return
}

func digitsValue(d []uint16) float64 {
	b := make([]byte, len(d))
	for i, c := range d {
		b[i] = byte(c)
	}
	f := 0.0
	for _, c := range b {
		f = f*10 + float64(c-'0') // Number() of an ASCII digit string
	}
	return f
}

func (p *reParser) quantified() *reNode {
	atom := p.atom()
	c, ok := p.at(p.i)
	if !ok {
		return atom
	}
	var min, max int
	switch c {
	case '*':
		min, max = 0, -1
		p.i++
	case '+':
		min, max = 1, -1
		p.i++
	case '?':
		min, max = 0, 1
		p.i++
	case '{':
		lo, hi, comma, emptyHi, n, ok := braceQuant(p.s, p.i, 16, 4)
		if !ok {
			panic(regexRefuse{})
		}
		min = int(lo)
		switch {
		case !comma:
			max = min
		case emptyHi:
			max = -1
		default:
			max = int(hi)
		}
		if max >= 0 && max < min {
			panic(regexRefuse{})
		}
		p.i += n
	default:
		return atom
	}
	if atom.k == nodeBol || atom.k == nodeEol {
		panic(regexRefuse{})
	}
	if (max >= 0 && max > maxRegexRepeat) || min > maxRegexRepeat {
		panic(regexRefuse{})
	}
	if c2, ok := p.at(p.i); ok && c2 == '?' {
		p.i++
	}
	return &reNode{k: nodeRep, node: atom, min: min, max: max}
}

func singleSet(code int) *charSet { return &charSet{ranges: []charRange{{code, code}}} }

func (p *reParser) atom() *reNode {
	c := p.s[p.i]
	switch c {
	case '(':
		p.i++
		if c2, ok := p.at(p.i); ok && c2 == '?' {
			if c3, ok := p.at(p.i + 1); !ok || c3 != ':' {
				panic(regexRefuse{})
			}
			p.i += 2
		}
		n := p.alt()
		if c2, ok := p.at(p.i); !ok || c2 != ')' {
			panic(regexRefuse{})
		}
		p.i++
		return n
	case '[':
		return p.cls()
	case '.':
		p.i++
		return &reNode{k: nodeSet, set: &charSet{ranges: reLineTerminators, negated: true}}
	case '^':
		p.i++
		return &reNode{k: nodeBol}
	case '$':
		p.i++
		return &reNode{k: nodeEol}
	case '\\':
		set, _, _ := p.escapeInner(false)
		return &reNode{k: nodeSet, set: set}
	case '*', '+', '?', '{':
		panic(regexRefuse{})
	}
	p.i++
	return &reNode{k: nodeSet, set: singleSet(int(c))}
}

func isHex(c uint16) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(u []uint16) int {
	n := 0
	for _, c := range u {
		d := 0
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		default:
			d = int(c-'A') + 10
		}
		n = n*16 + d
	}
	return n
}

// escapeInner: after `\`. Returns the set, whether it is a class escape (\d etc.) and the single code unit (ch >= 0).
func (p *reParser) escapeInner(inClass bool) (*charSet, bool, int) {
	p.i++
	c, ok := p.at(p.i)
	if !ok {
		panic(regexRefuse{})
	}
	p.i++
	single := func(code int) (*charSet, bool, int) { return singleSet(code), false, code }
	switch c {
	case 'd':
		return &charSet{ranges: reDigit}, true, -1
	case 'D':
		return &charSet{ranges: reDigit, negated: true}, true, -1
	case 'w':
		return &charSet{ranges: reWord}, true, -1
	case 'W':
		return &charSet{ranges: reWord, negated: true}, true, -1
	case 's':
		return &charSet{ranges: reSpace}, true, -1
	case 'S':
		return &charSet{ranges: reSpace, negated: true}, true, -1
	case 't':
		return single(9)
	case 'n':
		return single(10)
	case 'v':
		return single(11)
	case 'f':
		return single(12)
	case 'r':
		return single(13)
	case '0':
		if n, ok := p.at(p.i); ok && n >= '0' && n <= '9' {
			panic(regexRefuse{})
		}
		return single(0)
	case 'x':
		if p.i+2 > len(p.s) || !isHex(p.s[p.i]) || !isHex(p.s[p.i+1]) {
			panic(regexRefuse{})
		}
		v := hexVal(p.s[p.i : p.i+2])
		p.i += 2
		return single(v)
	case 'u':
		if p.i+4 > len(p.s) {
			panic(regexRefuse{})
		}
		for _, h := range p.s[p.i : p.i+4] {
			if !isHex(h) {
				panic(regexRefuse{})
			}
		}
		v := hexVal(p.s[p.i : p.i+4])
		p.i += 4
		return single(v)
	case 'c':
		l, ok := p.at(p.i)
		if !ok || !(l >= 'A' && l <= 'Z' || l >= 'a' && l <= 'z') {
			panic(regexRefuse{})
		}
		p.i++
		return single(int(l) % 32)
	case 'b':
		if inClass {
			return single(8)
		}
		panic(regexRefuse{})
	}
	if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
		panic(regexRefuse{})
	}
	return single(int(c))
}

func (p *reParser) cls() *reNode {
	p.i++
	negated := false
	if c, ok := p.at(p.i); ok && c == '^' {
		negated = true
		p.i++
	}
	ranges := []charRange{}
	readAtom := func() ([]charRange, int, bool) {
		c := p.s[p.i]
		if c == '\\' {
			set, cls, ch := p.escapeInner(true)
			rs := set.ranges
			if set.negated {
				rs = complementRanges(set.ranges)
			}
			return rs, ch, cls
		}
		p.i++
		return []charRange{{int(c), int(c)}}, int(c), false
	}
	for {
		c, ok := p.at(p.i)
		if !ok {
			panic(regexRefuse{})
		}
		if c == ']' {
			p.i++
			break
		}
		ar, ach, acls := readAtom()
		dash, ok1 := p.at(p.i)
		nx, ok2 := p.at(p.i + 1)
		if ok1 && dash == '-' && ok2 && nx != ']' {
			p.i++
			br, bch, bcls := readAtom()
			if acls || bcls {
				ranges = append(ranges, ar...)
				ranges = append(ranges, charRange{0x2d, 0x2d})
				ranges = append(ranges, br...)
			} else {
				if ach > bch {
					panic(regexRefuse{})
				}
				ranges = append(ranges, charRange{ach, bch})
			}
		} else {
			ranges = append(ranges, ar...)
		}
	}
	return &reNode{k: nodeSet, set: &charSet{ranges: normalizeRanges(ranges), negated: negated}}
}

type reInst struct {
	op, x, y int
	set      *charSet
}

func reEmit(n *reNode, prog *[]reInst) {
	if len(*prog) > maxNFAInstructions {
		panic(regexRefuse{})
	}
	switch n.k {
	case nodeSet:
		*prog = append(*prog, reInst{op: regexOpSet, set: n.set})
	case nodeBol:
		*prog = append(*prog, reInst{op: regexOpBol})
	case nodeEol:
		*prog = append(*prog, reInst{op: regexOpEol})
	case nodeCat:
		for _, it := range n.items {
			reEmit(it, prog)
		}
	case nodeAlt:
		jmps := []int{}
		for i, it := range n.items {
			if i < len(n.items)-1 {
				split := len(*prog)
				*prog = append(*prog, reInst{op: regexOpSplit, x: split + 1, y: -1})
				reEmit(it, prog)
				jmps = append(jmps, len(*prog))
				*prog = append(*prog, reInst{op: regexOpJmp, x: -1})
				(*prog)[split].y = len(*prog)
			} else {
				reEmit(it, prog)
			}
		}
		for _, j := range jmps {
			(*prog)[j].x = len(*prog)
		}
	case nodeRep:
		for i := 0; i < n.min; i++ {
			reEmit(n.node, prog)
		}
		if n.max < 0 {
			split := len(*prog)
			*prog = append(*prog, reInst{op: regexOpSplit, x: split + 1, y: -1})
			reEmit(n.node, prog)
			*prog = append(*prog, reInst{op: regexOpJmp, x: split})
			(*prog)[split].y = len(*prog)
		} else {
			splits := []int{}
			for i := n.min; i < n.max; i++ {
				splits = append(splits, len(*prog))
				*prog = append(*prog, reInst{op: regexOpSplit, x: len(*prog) + 1, y: -1})
				reEmit(n.node, prog)
			}
			for _, sp := range splits {
				(*prog)[sp].y = len(*prog)
			}
		}
		if len(*prog) > maxNFAInstructions {
			panic(regexRefuse{})
		}
	}
}

// compileSafeRegex compiles src (UTF-16 units) into an NFA, or nil outside the subset / too large. Never panics.
func compileSafeRegex(src []uint16) (prog []reInst) {
	defer func() {
		if recover() != nil {
			prog = nil
		}
	}()
	ast := (&reParser{s: src}).parse()
	p := []reInst{}
	reEmit(ast, &p)
	p = append(p, reInst{op: regexOpMatch})
	if len(p) > maxNFAInstructions {
		return nil
	}
	return p
}

// runSafeRegex full-matches subject; ok false when the work budget would be exceeded.
func runSafeRegex(prog []reInst, subject []uint16) (matched bool, ok bool) {
	n := len(subject)
	if len(prog)*(n+1) > maxMatchSteps {
		return false, false
	}
	clist := make([]int, len(prog))
	nlist := make([]int, len(prog))
	mark := make([]int, len(prog))
	for i := range mark {
		mark[i] = -1
	}
	gen := 0
	stack := make([]int, 0, len(prog)*2+2)
	add := func(list []int, count, pc0, pos int) int {
		stack = append(stack[:0], pc0)
		for len(stack) > 0 {
			pc := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if mark[pc] == gen {
				continue
			}
			mark[pc] = gen
			ins := prog[pc]
			switch ins.op {
			case regexOpJmp:
				stack = append(stack, ins.x)
			case regexOpSplit:
				stack = append(stack, ins.y, ins.x)
			case regexOpBol:
				if pos == 0 {
					stack = append(stack, pc+1)
				}
			case regexOpEol:
				if pos == n {
					stack = append(stack, pc+1)
				}
			case regexOpMatch:
				if pos == n {
					matched = true
				}
			case regexOpSet:
				list[count] = pc
				count++
			}
		}
		return count
	}
	gen++
	cn := add(clist, 0, 0, 0)
	for pos := 0; pos < n; pos++ {
		c := int(subject[pos])
		gen++
		nn := 0
		for k := 0; k < cn; k++ {
			pc := clist[k]
			if prog[pc].set.has(c) {
				nn = add(nlist, nn, pc+1, pos+1)
			}
		}
		clist, nlist = nlist, clist
		cn = nn
		if cn == 0 && !matched {
			return false, true
		}
	}
	return matched, true
}

// isSafeRegexSource is the predicates.ts guard (nesting, alternation and the backtracking-cost budget), then the
// source must compile in the engine that runs it.
func isSafeRegexSource(src []uint16) bool {
	type frame struct{ hasQuant, hasAlt bool }
	stack := []*frame{{}}
	const prevNone, prevAtom, prevFrame = 0, 1, 2
	prev := prevNone
	var prevF *frame
	bits := 0
	i := 0
	for i < len(src) {
		ch := src[i]
		if ch == '\\' {
			if i+1 >= len(src) {
				return false
			}
			n := src[i+1]
			if n >= '1' && n <= '9' || n == 'k' {
				return false
			}
			i += 2
			prev = prevAtom
			continue
		}
		if ch == '[' {
			j := i + 1
			if j < len(src) && src[j] == '^' {
				j++
			}
			for ; j < len(src) && src[j] != ']'; j++ {
				if src[j] == '\\' {
					j++
				}
			}
			if j >= len(src) {
				return false
			}
			i = j + 1
			prev = prevAtom
			continue
		}
		if ch == '(' {
			if i+1 < len(src) && src[i+1] == '?' {
				if !(i+2 < len(src) && src[i+2] == ':') {
					return false
				}
				i += 3
			} else {
				i++
			}
			stack = append(stack, &frame{})
			prev = prevNone
			continue
		}
		if ch == ')' {
			if len(stack) < 2 {
				return false
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			parent := stack[len(stack)-1]
			parent.hasQuant = parent.hasQuant || f.hasQuant
			parent.hasAlt = parent.hasAlt || f.hasAlt
			prev, prevF = prevFrame, f
			i++
			continue
		}
		if ch == '|' {
			bits++
			if bits > maxRegexCostBits {
				return false
			}
			stack[len(stack)-1].hasAlt = true
			prev = prevNone
			i++
			continue
		}
		isQ := false
		qlen := 0
		unbounded := false
		qmax := 0.0
		options := 0.0
		switch ch {
		case '*', '+':
			isQ, qlen, unbounded, qmax, options = true, 1, true, math.Inf(1), math.Inf(1)
		case '?':
			isQ, qlen, qmax, options = true, 1, 1, 2
		case '{':
			lo, hi, comma, emptyHi, n, ok := braceQuant(src, i, -1, -1)
			if !ok {
				return false
			}
			h := lo
			if comma {
				if emptyHi {
					h = math.Inf(1)
				} else {
					h = hi
				}
			}
			if h < lo {
				return false
			}
			isQ, qlen, unbounded, qmax = true, n, math.IsInf(h, 1), h
			if math.IsInf(h, 1) {
				options = math.Inf(1)
			} else {
				options = h - lo + 1
			}
		}
		if isQ {
			if prev == prevNone {
				return false
			}
			if prev == prevFrame && (prevF.hasQuant || prevF.hasAlt) {
				return false
			}
			if !unbounded && !math.IsInf(qmax, 1) && qmax > maxBoundedRepeatSafeSource {
				return false
			}
			if unbounded {
				bits += unboundedQuantifierBits
			} else if options > 1 {
				bits += int(math.Ceil(math.Log2(options)))
			}
			if bits > maxRegexCostBits {
				return false
			}
			stack[len(stack)-1].hasQuant = true
			i += qlen
			if i < len(src) && src[i] == '?' {
				i++
			}
			prev = prevNone
			continue
		}
		i++
		prev = prevAtom
	}
	return len(stack) == 1 && compileSafeRegex(src) != nil
}

// regexBudget is one DOCUMENT budget of regex-budget.ts (opened per evaluatePredicates / predicateMatches /
// evaluateConditionTri call when no document scope is open).
type regexBudget struct {
	evaluations, chars, steps int
}

func (b *regexBudget) charge(src []uint16, subjectLen int) bool {
	prog := compileSafeRegex(src)
	if prog == nil {
		return false
	}
	ev := b.evaluations + 1
	chars := b.chars + len(src)
	steps := b.steps + len(prog)*(subjectLen+1)
	if ev > maxRegexEvaluationsPerDoc || chars > maxRegexSourceCharsPerDoc || steps > maxRegexStepsPerDoc {
		b.evaluations = maxRegexEvaluationsPerDoc + 1
		return false
	}
	b.evaluations, b.chars, b.steps = ev, chars, steps
	return true
}

// safeRegexFullMatch: (match, ok); ok false when src is outside the subset or the per-match budget is exceeded.
func safeRegexFullMatch(src, subject []uint16) (bool, bool) {
	prog := compileSafeRegex(src)
	if prog == nil {
		return false, false
	}
	return runSafeRegex(prog, subject)
}
