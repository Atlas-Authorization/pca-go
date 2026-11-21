package pca

// A translator from the JavaScript regular expression dialect (ECMAScript, no flags, Annex B leniency) used by `path_re` of the
// suggestion rules to an RE2 pattern with the same meaning on UTF-16 code units. A rule set is accepted or refused as the reference's
// `new RegExp(...)` does and matches the same locations. Syntax the reference rejects is an error. Supported: literals, `.`, anchors,
// `\b \B`, classes with ranges and class escapes, groups `(...)` and `(?:...)`, alternation, greedy and lazy quantifiers. Lookaround,
// named groups and back-references are refused (the rule validator refuses them before a pattern is compiled).
//
// The input is matched as UTF-16 units: each unit is one rune of the matched string, and a surrogate unit is shifted by 0x10000 so
// that a Go string can carry it (no real astral rune is ever present in a mapped string).

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type jsrIv struct{ lo, hi int }

var (
	jsrWS    = []jsrIv{{9, 13}, {32, 32}, {0xA0, 0xA0}, {0x1680, 0x1680}, {0x2000, 0x200A}, {0x2028, 0x2029}, {0x202F, 0x202F}, {0x205F, 0x205F}, {0x3000, 0x3000}, {0xFEFF, 0xFEFF}}
	jsrDigit = []jsrIv{{48, 57}}
	jsrWord  = []jsrIv{{48, 57}, {65, 90}, {95, 95}, {97, 122}}
)

func jsrNorm(iv []jsrIv) []jsrIv {
	s := append([]jsrIv{}, iv...)
	sort.Slice(s, func(i, j int) bool {
		if s[i].lo != s[j].lo {
			return s[i].lo < s[j].lo
		}
		return s[i].hi < s[j].hi
	})
	out := []jsrIv{}
	for _, x := range s {
		if n := len(out); n > 0 && x.lo <= out[n-1].hi+1 {
			if x.hi > out[n-1].hi {
				out[n-1].hi = x.hi
			}
		} else {
			out = append(out, x)
		}
	}
	return out
}

func jsrNeg(iv []jsrIv) []jsrIv {
	out := []jsrIv{}
	cur := 0
	for _, x := range jsrNorm(iv) {
		if x.lo > cur {
			out = append(out, jsrIv{cur, x.lo - 1})
		}
		cur = x.hi + 1
	}
	if cur <= 0xFFFF {
		out = append(out, jsrIv{cur, 0xFFFF})
	}
	return out
}

// jsrRune maps a UTF-16 unit to the rune that stands for it.
func jsrRune(u int) int {
	if u >= 0xD800 && u <= 0xDFFF {
		return u + 0x10000
	}
	return u
}

func jsrLit(u int) string { return fmt.Sprintf(`\x{%x}`, jsrRune(u)) }

func jsrCls(iv []jsrIv) string {
	n := jsrNorm(iv)
	if len(n) == 0 {
		return `[^\x00-\x{10FFFF}]`
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for _, x := range n {
		// split around the surrogate block, whose runes are shifted
		for _, p := range []jsrIv{{x.lo, min(x.hi, 0xD7FF)}, {max(x.lo, 0xD800), min(x.hi, 0xDFFF)}, {max(x.lo, 0xE000), x.hi}} {
			if p.lo > p.hi {
				continue
			}
			fmt.Fprintf(&sb, `\x{%x}-\x{%x}`, jsrRune(p.lo), jsrRune(p.hi))
		}
	}
	sb.WriteByte(']')
	return sb.String()
}

func jsrClassEsc(c int) ([]jsrIv, bool) {
	switch c {
	case 'd':
		return jsrDigit, true
	case 'D':
		return jsrNeg(jsrDigit), true
	case 'w':
		return jsrWord, true
	case 'W':
		return jsrNeg(jsrWord), true
	case 's':
		return jsrWS, true
	case 'S':
		return jsrNeg(jsrWS), true
	}
	return nil, false
}

func jsrCtrl(c int) (int, bool) {
	switch c {
	case 'f':
		return 12, true
	case 'n':
		return 10, true
	case 'r':
		return 13, true
	case 't':
		return 9, true
	case 'v':
		return 11, true
	}
	return 0, false
}

type jsrParser struct {
	s []uint16
	i int
}

func (p *jsrParser) peek(k int) int {
	if j := p.i + k; j < len(p.s) {
		return int(p.s[j])
	}
	return -1
}

func (p *jsrParser) err(msg string) { panic(errors.New("Invalid regular expression: " + msg)) }

func (p *jsrParser) disjunction(depth int) string {
	alts := []string{p.alternative(depth)}
	for p.peek(0) == '|' {
		p.i++
		alts = append(alts, p.alternative(depth))
	}
	return strings.Join(alts, "|")
}

func (p *jsrParser) alternative(depth int) string {
	var sb strings.Builder
	for p.i < len(p.s) && p.peek(0) != '|' && p.peek(0) != ')' {
		sb.WriteString(p.term(depth))
	}
	return sb.String()
}

// braced reads {n}, {n,} or {n,m} at the cursor: (min, max or -1 for open, length), ok=false when the brace is not a quantifier.
func (p *jsrParser) braced() (lo, hi, n int, ok bool) {
	j := p.i + 1
	digits := func() (int, int, bool) {
		st, v := j, 0
		for j < len(p.s) && p.s[j] >= '0' && p.s[j] <= '9' {
			if v < 1<<30 {
				v = v*10 + int(p.s[j]-'0')
			}
			j++
		}
		return v, j - st, j > st
	}
	l, _, got := digits()
	if !got {
		return 0, 0, 0, false
	}
	h := l
	if j < len(p.s) && p.s[j] == ',' {
		j++
		v, _, g := digits()
		if g {
			h = v
		} else {
			h = -1
		}
	}
	if j >= len(p.s) || p.s[j] != '}' {
		return 0, 0, 0, false
	}
	j++
	if h != -1 && h < l {
		p.err("numbers out of order in {} quantifier")
	}
	return l, h, j - p.i, true
}

func (p *jsrParser) quantifier(atom string) string {
	c := p.peek(0)
	var q string
	switch {
	case c == '*' || c == '+' || c == '?':
		p.i++
		q = string(rune(c))
	default:
		if c != '{' {
			return atom
		}
		lo, hi, n, ok := p.braced()
		if !ok {
			return atom
		}
		p.i += n
		if hi == -1 {
			q = fmt.Sprintf("{%d,}", lo)
		} else {
			q = fmt.Sprintf("{%d,%d}", lo, hi)
		}
	}
	if p.peek(0) == '?' {
		p.i++
		q += "?"
	}
	return atom + q
}

func (p *jsrParser) term(depth int) string {
	c := p.peek(0)
	switch {
	case c == '^':
		p.i++
		return `\A`
	case c == '$':
		p.i++
		return `\z`
	case c == '\\' && (p.peek(1) == 'b' || p.peek(1) == 'B'):
		p.i += 2
		return `\` + string(rune(p.s[p.i-1]))
	case c == '*' || c == '+' || c == '?':
		p.err("nothing to repeat")
	case c == '{':
		if _, _, _, ok := p.braced(); ok {
			p.err("nothing to repeat")
		}
	}
	return p.quantifier(p.atom(depth))
}

func (p *jsrParser) atom(depth int) string {
	c := p.peek(0)
	if depth > 200 {
		p.err("too deeply nested")
	}
	switch c {
	case '(':
		p.i++
		head := "("
		if p.peek(0) == '?' {
			if p.peek(1) != ':' {
				p.err("invalid group")
			}
			p.i += 2
			head = "(?:"
		}
		body := p.disjunction(depth + 1)
		if p.peek(0) != ')' {
			p.err("unterminated group")
		}
		p.i++
		return head + body + ")"
	case '.':
		p.i++
		return `[^\n\r\x{2028}\x{2029}]`
	case '[':
		return p.charClass()
	case '\\':
		return p.atomEscape()
	}
	p.i++
	return jsrLit(c)
}

func (p *jsrParser) hex(n int) (int, bool) {
	if p.i+n > len(p.s) {
		return 0, false
	}
	v := 0
	for _, u := range p.s[p.i : p.i+n] {
		var d int
		switch {
		case u >= '0' && u <= '9':
			d = int(u - '0')
		case u >= 'a' && u <= 'f':
			d = int(u-'a') + 10
		case u >= 'A' && u <= 'F':
			d = int(u-'A') + 10
		default:
			return 0, false
		}
		v = v*16 + d
	}
	p.i += n
	return v, true
}

func jsrIsOctal(c int) bool { return c >= '0' && c <= '7' }

// escapeChar is the code unit a character escape at `\` denotes (cursor past the escape).
func (p *jsrParser) escapeChar(inClass bool) int {
	p.i++ // the backslash
	if p.i >= len(p.s) {
		p.err(`\ at end of pattern`)
	}
	c := int(p.s[p.i])
	if v, ok := jsrCtrl(c); ok {
		p.i++
		return v
	}
	switch {
	case c == 'c':
		nxt := p.peek(1)
		if (nxt >= 'A' && nxt <= 'Z') || (nxt >= 'a' && nxt <= 'z') {
			p.i += 2
			return nxt % 32
		}
		if inClass && ((nxt >= '0' && nxt <= '9') || nxt == '_') {
			p.i += 2
			return nxt % 32
		}
		return '\\' // a lone backslash; the `c` is read next
	case c == '0':
		p.i++
		if jsrIsOctal(p.peek(0)) {
			v, n := 0, 0
			for n < 3 && jsrIsOctal(p.peek(0)) && v*8+(p.peek(0)-'0') <= 0377 {
				v = v*8 + (p.peek(0) - '0')
				p.i++
				n++
			}
			return v
		}
		return 0
	case c == 'x':
		p.i++
		if v, ok := p.hex(2); ok {
			return v
		}
		return 'x'
	case c == 'u':
		p.i++
		if v, ok := p.hex(4); ok {
			return v
		}
		return 'u'
	case c == 'b' && inClass:
		p.i++
		return 8
	case c >= '1' && c <= '9':
		p.err("back-references are not supported")
	case c == 'k':
		p.i++
		return 'k'
	}
	p.i++
	return c
}

func (p *jsrParser) atomEscape() string {
	if iv, ok := jsrClassEsc(p.peek(1)); ok {
		p.i += 2
		return jsrCls(iv)
	}
	return jsrLit(p.escapeChar(false))
}

// classAtom is (code unit, nil) or (-1, interval set).
func (p *jsrParser) classAtom() (int, []jsrIv) {
	c := p.peek(0)
	if c == '\\' {
		if iv, ok := jsrClassEsc(p.peek(1)); ok {
			p.i += 2
			return -1, iv
		}
		return p.escapeChar(true), nil
	}
	p.i++
	return c, nil
}

func (p *jsrParser) charClass() string {
	p.i++
	negate := false
	if p.peek(0) == '^' {
		negate = true
		p.i++
	}
	iv := []jsrIv{}
	for {
		if p.i >= len(p.s) {
			p.err("unterminated character class")
		}
		if p.peek(0) == ']' {
			p.i++
			break
		}
		a, aset := p.classAtom()
		if p.peek(0) == '-' && p.peek(1) != ']' && p.peek(1) != -1 {
			p.i++
			b, bset := p.classAtom()
			if aset != nil || bset != nil { // Annex B: a class escape on either side makes the dash a literal
				if aset != nil {
					iv = append(iv, aset...)
				} else {
					iv = append(iv, jsrIv{a, a})
				}
				iv = append(iv, jsrIv{45, 45})
				if bset != nil {
					iv = append(iv, bset...)
				} else {
					iv = append(iv, jsrIv{b, b})
				}
				continue
			}
			if a > b {
				p.err("range out of order in character class")
			}
			iv = append(iv, jsrIv{a, b})
			continue
		}
		if aset != nil {
			iv = append(iv, aset...)
		} else {
			iv = append(iv, jsrIv{a, a})
		}
	}
	if negate {
		return jsrCls(jsrNeg(iv))
	}
	return jsrCls(iv)
}

// jsrTranslate is the RE2 pattern text for a JavaScript pattern, or an error.
func jsrTranslate(pattern string) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				return
			}
			panic(r)
		}
	}()
	p := &jsrParser{s: utf16Units(pattern)}
	out = p.disjunction(0)
	if p.i < len(p.s) {
		p.err("unmatched ')'")
	}
	return out, nil
}

type jsrEntry struct {
	re  *regexp.Regexp
	err error
}

var jsrCache sync.Map

// jsrCompile compiles a JavaScript pattern (cached): the error is the reference's refusal of the pattern.
func jsrCompile(pattern string) (*regexp.Regexp, error) {
	if e, ok := jsrCache.Load(pattern); ok {
		return e.(jsrEntry).re, e.(jsrEntry).err
	}
	var ent jsrEntry
	if t, err := jsrTranslate(pattern); err != nil {
		ent.err = err
	} else if re, err := regexp.Compile(t); err != nil {
		ent.err = errors.New("Invalid regular expression: " + err.Error())
	} else {
		ent.re = re
	}
	jsrCache.Store(pattern, ent)
	return ent.re, ent.err
}

// jsrTest is RegExp.prototype.test: a match anywhere in the string, read as UTF-16 code units.
func jsrTest(re *regexp.Regexp, s string) bool {
	u := utf16Units(s)
	rs := make([]rune, len(u))
	for i, x := range u {
		rs[i] = rune(jsrRune(int(x)))
	}
	return re.MatchString(string(rs))
}
