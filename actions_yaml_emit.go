package pca

// The YAML text the reference writes for an action pack (defsToYaml): a line-for-line port of the default stringifier of the
// `yaml` package (v2, core schema, 80 columns): plain, quoted and block scalars, folding, escapes, anchors and aliases for
// repeated containers. Comments, tags, flow collections and custom schemas are not produced for plain data and are not ported.
//
// The reference measures and folds in UTF-16 code units. Inside this file a string is therefore a "unit string": every rune
// is one code unit (an astral character is two runes, its surrogate halves; a surrogate unit is stored as a rune in
// U+10000..U+107FF so it survives as a valid rune). yToUnits / yFromUnits convert at the boundary. Plain data is: map[string]any
// (key order = jsKeys), []any, *[]any (a sequence that can be shared: its identity is the pointer), string, bool, nil, and the
// numbers jsNum reads. Containers met more than once become an anchor on the first sighting and an alias on every later one.

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	yLineWidth      = 80
	yMinContent     = 20
	yDQMinMultiline = 40
	ySurBase        = 0x10000
	yIndentStep     = "  "
)

// ---- UTF-16 code unit domain ----------------------------------------------------------------------------------------

func yUnitRune(u uint16) rune {
	if u >= 0xD800 && u <= 0xDFFF {
		return ySurBase + rune(u-0xD800)
	}
	return rune(u)
}

func yRuneUnit(r rune) uint16 {
	if r >= ySurBase {
		return uint16(0xD800 + (r - ySurBase))
	}
	return uint16(r)
}

func yIsHi(r rune) bool { return r >= ySurBase && r < ySurBase+0x400 }
func yIsLo(r rune) bool { return r >= ySurBase+0x400 && r < ySurBase+0x800 }

func yToUnits(s string) string {
	var b strings.Builder
	for _, u := range utf16Units(s) {
		b.WriteRune(yUnitRune(u))
	}
	return b.String()
}

// yFromUnits recombines surrogate pairs; a lone half stays as its 3-byte WTF-8 form.
func yFromUnits(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if r < ySurBase {
			b.WriteRune(r)
			continue
		}
		if yIsHi(r) && i+1 < len(rs) && yIsLo(rs[i+1]) {
			hi, lo := rune(yRuneUnit(r)), rune(yRuneUnit(rs[i+1]))
			b.WriteRune(0x10000 + (hi-0xD800)<<10 + (lo - 0xDC00))
			i++
			continue
		}
		u := rune(yRuneUnit(r))
		b.WriteByte(byte(0xE0 | u>>12))
		b.WriteByte(byte(0x80 | (u>>6)&0x3F))
		b.WriteByte(byte(0x80 | u&0x3F))
	}
	return b.String()
}

func yLen(s string) int { return utf8.RuneCountInString(s) }

func yAt(rs []rune, i int) rune {
	if i >= 0 && i < len(rs) {
		return rs[i]
	}
	return -1
}

// ySlice is Python / JavaScript slicing: a negative bound counts from the end, bounds are clamped.
func ySlice(rs []rune, a, b int) []rune {
	n := len(rs)
	if a < 0 {
		a += n
		if a < 0 {
			a = 0
		}
	}
	if b < 0 {
		b += n
		if b < 0 {
			b = 0
		}
	}
	if a > n {
		a = n
	}
	if b > n {
		b = n
	}
	if a >= b {
		return nil
	}
	return rs[a:b]
}

func yIsLT(r rune) bool { return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029 }

// yJSONString is JSON.stringify of a unit string (well-formed: a lone surrogate is escaped).
func yJSONString(s string) string {
	rs := []rune(s)
	var b strings.Builder
	b.WriteByte('"')
	for i, c := range rs {
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		case yIsHi(c) && i+1 < len(rs) && yIsLo(rs[i+1]):
			b.WriteRune(c)
		case yIsLo(c) && i > 0 && yIsHi(rs[i-1]):
			b.WriteRune(c)
		case c >= ySurBase:
			fmt.Fprintf(&b, `\u%04x`, yRuneUnit(c))
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---- folding --------------------------------------------------------------------------------------------------------

type yOpt struct {
	v  int
	ok bool
}

func yConsumeMoreIndented(text []rune, i, indent int) int {
	end := i
	start := i + 1
	ch := yAt(text, start)
	for ch == ' ' || ch == '\t' {
		if i < start+indent {
			i++
			ch = yAt(text, i)
		} else {
			for {
				i++
				ch = yAt(text, i)
				if ch < 0 || ch == '\n' {
					break
				}
			}
			end = i
			start = i + 1
			ch = yAt(text, start)
		}
	}
	return end
}

func yMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func yFold(text, indent, mode string, indentAtStart yOpt, onOverflow func()) string {
	lineWidth, minContent := yLineWidth, yMinContent
	if minContent > lineWidth {
		minContent = 0
	}
	endStep := yMax(1+minContent, 1+lineWidth-len(indent))
	tr := []rune(text)
	if len(tr) <= endStep {
		return text
	}
	var folds []int
	escaped := map[int]bool{}
	end := lineWidth - len(indent)
	if indentAtStart.ok {
		if indentAtStart.v > lineWidth-yMax(2, minContent) {
			folds = append(folds, 0)
		} else {
			end = lineWidth - indentAtStart.v
		}
	}
	split, hasSplit := 0, false
	prev := rune(-1)
	overflow := false
	i := -1
	escStart, escEnd := -1, -1
	if mode == "block" {
		i = yConsumeMoreIndented(tr, i, len(indent))
		if i != -1 {
			end = i + endStep
		}
	}
	for {
		i++
		ch := yAt(tr, i)
		if ch < 0 {
			break
		}
		if mode == "quoted" && ch == '\\' {
			escStart = i
			switch yAt(tr, i+1) {
			case 'x':
				i += 3
			case 'u':
				i += 5
			case 'U':
				i += 9
			default:
				i++
			}
			escEnd = i
		}
		if ch == '\n' {
			if mode == "block" {
				i = yConsumeMoreIndented(tr, i, len(indent))
			}
			end = i + len(indent) + endStep
			hasSplit = false
		} else {
			if ch == ' ' && prev >= 0 && prev != ' ' && prev != '\n' && prev != '\t' {
				nxt := yAt(tr, i+1)
				if nxt >= 0 && nxt != ' ' && nxt != '\n' && nxt != '\t' {
					split, hasSplit = i, true
				}
			}
			if i >= end {
				if hasSplit {
					folds = append(folds, split)
					end = split + endStep
					hasSplit = false
				} else if mode == "quoted" {
					for prev == ' ' || prev == '\t' {
						prev = ch
						i++
						ch = yAt(tr, i)
						overflow = true
					}
					j := escStart - 1
					if i > escEnd+1 {
						j = i - 2
					}
					if escaped[j] {
						return text
					}
					folds = append(folds, j)
					escaped[j] = true
					end = j + endStep
					hasSplit = false
				} else {
					overflow = true
				}
			}
		}
		prev = ch
	}
	if overflow && onOverflow != nil {
		onOverflow()
	}
	if len(folds) == 0 {
		return text
	}
	res := string(ySlice(tr, 0, folds[0]))
	for k, fold := range folds {
		stop := len(tr)
		if k+1 < len(folds) && folds[k+1] != 0 {
			stop = folds[k+1]
		}
		if fold == 0 {
			res = "\n" + indent + string(ySlice(tr, 0, stop))
		} else {
			if mode == "quoted" && escaped[fold] {
				res += string(ySlice(tr, fold, fold+1))
				res += "\\"
			}
			res += "\n" + indent + string(ySlice(tr, fold+1, stop))
		}
	}
	return res
}

// ---- context --------------------------------------------------------------------------------------------------------

type yctx struct {
	indent           string
	indentAtStart    yOpt
	implicitKey      bool
	actualString     bool
	forceBlockIndent bool
	anchors          map[string]bool
}

func (c *yctx) copy() *yctx { n := *c; return &n }

var (
	yReNL       = regexp.MustCompile(`\n+`)
	yReSpNL     = regexp.MustCompile(`[ \t]\n|\n[ \t]`)
	yReEndWS    = regexp.MustCompile(`\n[\t ]+$`)
	yReControl  = regexp.MustCompile(`[\x00-\x08\x0b-\x1f\x7f-\x9f]`)
	yRePlainBad = regexp.MustCompile(`^[\n\t ,\[\]{}#&*!|>'"%@\x60]|^[?-]$|^[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]$`)
	yReTagTests = yTagTests()
)

func yTagTests() []*regexp.Regexp {
	src := []string{
		`(?:~|[Nn]ull|NULL)?`, `(?:[Tt]rue|TRUE|[Ff]alse|FALSE)`, `0o[0-7]+`, `[-+]?[0-9]+`, `0x[0-9a-fA-F]+`,
		`(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)`, `[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+`, `[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)`,
	}
	out := make([]*regexp.Regexp, len(src))
	for i, s := range src {
		out[i] = regexp.MustCompile(`^(?:` + s + `)$`)
	}
	return out
}

// yContainsDocMarker: a line (or the text) starting with %, --- or ...
func yContainsDocMarker(s string) bool {
	rs := []rune(s)
	for i, c := range rs {
		if i > 0 && !yIsLT(rs[i-1]) {
			continue
		}
		if w := string(rs[i:yMin(i+3, len(rs))]); c == '%' || w == "---" || w == "..." {
			return true
		}
	}
	return false
}

func yMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// yLineLenOver reports a line longer than lineWidth - indentLen (a text no longer than that has none).
func yLineLenOver(s string, lineWidth, indentLen int) bool {
	if lineWidth <= 0 {
		return false
	}
	limit := lineWidth - indentLen
	rs := []rune(s)
	n := len(rs)
	if n <= limit {
		return false
	}
	start := 0
	for i := 0; i < n; i++ {
		if rs[i] == '\n' {
			if i-start > limit {
				return true
			}
			start = i + 1
			if n-start <= limit {
				return false
			}
		}
	}
	return true
}

// ---- strings --------------------------------------------------------------------------------------------------------

func yDoubleQuoted(value string, ctx *yctx) string {
	js := []rune(yJSONString(value))
	implicit := ctx.implicitKey
	indent := ctx.indent
	if indent == "" && yContainsDocMarker(value) {
		indent = yIndentStep
	}
	var out []rune
	start, i, n := 0, 0, len(js)
	for i < n {
		ch := js[i]
		if ch == ' ' && yAt(js, i+1) == '\\' && yAt(js, i+2) == 'n' {
			out = append(out, ySlice(js, start, i)...)
			out = append(out, '\\', ' ')
			i++
			start = i
			ch = '\\'
		}
		if ch == '\\' {
			switch nx := yAt(js, i+1); {
			case nx == 'u':
				out = append(out, ySlice(js, start, i)...)
				code := string(ySlice(js, i+2, i+6))
				switch {
				case code == "0000":
					out = append(out, []rune(`\0`)...)
				case code == "0007":
					out = append(out, []rune(`\a`)...)
				case code == "000b":
					out = append(out, []rune(`\v`)...)
				case code == "001b":
					out = append(out, []rune(`\e`)...)
				case code == "0085":
					out = append(out, []rune(`\N`)...)
				case code == "00a0":
					out = append(out, []rune(`\_`)...)
				case code == "2028":
					out = append(out, []rune(`\L`)...)
				case code == "2029":
					out = append(out, []rune(`\P`)...)
				case strings.HasPrefix(code, "00"):
					out = append(out, []rune(`\x`+code[2:])...)
				default:
					out = append(out, ySlice(js, i, i+6)...)
				}
				i += 5
				start = i + 1
			case nx == 'n':
				if implicit || yAt(js, i+2) == '"' || len(js) < yDQMinMultiline {
					i++
				} else {
					out = append(out, ySlice(js, start, i)...)
					out = append(out, '\n', '\n')
					for yAt(js, i+2) == '\\' && yAt(js, i+3) == 'n' && yAt(js, i+4) != '"' {
						out = append(out, '\n')
						i += 2
					}
					out = append(out, []rune(indent)...)
					if yAt(js, i+2) == ' ' {
						out = append(out, '\\')
					}
					i++
					start = i + 1
				}
			default:
				i++
			}
		}
		i++
	}
	var res []rune
	if start != 0 {
		res = append(out, ySlice(js, start, len(js))...)
	} else {
		res = js
	}
	if implicit {
		return string(res)
	}
	return yFold(string(res), indent, "quoted", ctx.indentAtStart, nil)
}

func ySingleQuoted(value string, ctx *yctx) string {
	if (ctx.implicitKey && strings.Contains(value, "\n")) || yReSpNL.MatchString(value) {
		return yDoubleQuoted(value, ctx)
	}
	indent := ctx.indent
	if indent == "" && yContainsDocMarker(value) {
		indent = yIndentStep
	}
	res := "'" + yReNL.ReplaceAllStringFunc(strings.ReplaceAll(value, "'", "''"), func(m string) string { return m + "\n" + indent }) + "'"
	if ctx.implicitKey {
		return res
	}
	return yFold(res, indent, "flow", ctx.indentAtStart, nil)
}

func yQuoted(value string, ctx *yctx) string {
	if strings.Contains(value, `"`) && !strings.Contains(value, "'") {
		return ySingleQuoted(value, ctx)
	}
	return yDoubleQuoted(value, ctx) // a lone single quote, both or neither: double (the default)
}

// yEndNL appends indent after every run of newlines that is not the very end of s (the reference's end-newline rule).
func yEndNL(s, indent string) string {
	rs := []rune(s)
	var b strings.Builder
	for i := 0; i < len(rs); {
		if rs[i] != '\n' {
			b.WriteRune(rs[i])
			i++
			continue
		}
		j := i
		for j < len(rs) && rs[j] == '\n' {
			j++
		}
		b.WriteString(string(rs[i:j]))
		if j < len(rs) {
			b.WriteString(indent)
		}
		i = j
	}
	return b.String()
}

// yFoldMoreIndented drops the line break before a more-indented line (and the one after it, when it ends a blank-line run).
func yFoldMoreIndented(s string) string {
	rs := []rune(s)
	var out []rune
	i := 0
	for i < len(rs) {
		g := -1
		switch {
		case i == 0 && (rs[0] == ' ' || rs[0] == '\t'):
			g = 0
		case rs[i] == '\n' && i+1 < len(rs) && (rs[i+1] == ' ' || rs[i+1] == '\t'):
			g = i + 1
		}
		if g < 0 {
			out = append(out, rs[i])
			i++
			continue
		}
		q := g + 1
		for q < len(rs) && !yIsLT(rs[q]) {
			q++
		}
		out = append(out, rs[g:q]...)
		m := q
		for m < len(rs) && (rs[m] == '\n' || rs[m] == '\t' || rs[m] == ' ') {
			m++
		}
		if m > q && rs[m-1] == '\n' {
			out = append(out, rs[q:m-1]...)
			i = m
		} else {
			i = q
		}
	}
	return string(out)
}

func yBlockString(value string, ctx *yctx) string {
	if yReEndWS.MatchString(value) {
		return yQuoted(value, ctx)
	}
	indent := ctx.indent
	if indent == "" && (ctx.forceBlockIndent || yContainsDocMarker(value)) {
		indent = yIndentStep
	}
	literal := !yLineLenOver(value, yLineWidth, len(indent))
	if value == "" {
		if literal {
			return "|\n"
		}
		return ">\n"
	}
	endStart := len(strings.TrimRight(value, "\n\t "))
	end := value[endStart:]
	nl := strings.Index(end, "\n")
	chomp := ""
	switch {
	case nl == -1:
		chomp = "-"
	case value == end || nl != len(end)-1:
		chomp = "+"
	}
	if end != "" {
		value = value[:endStart]
		if end[len(end)-1] == '\n' {
			end = end[:len(end)-1]
		}
		end = yEndNL(end, indent)
	}
	startWithSpace := false
	startEnd := 0
	startNL := -1
	for startEnd < len(value) {
		ch := value[startEnd]
		if ch == ' ' {
			startWithSpace = true
		} else if ch == '\n' {
			startNL = startEnd
		} else {
			break
		}
		startEnd++
	}
	cut := startEnd
	if startNL < startEnd {
		cut = startNL + 1
	}
	start := value[:cut]
	if start != "" {
		value = value[len(start):]
		start = yReNL.ReplaceAllStringFunc(start, func(m string) string { return m + indent })
	}
	header := ""
	if startWithSpace {
		if indent != "" {
			header = "2"
		} else {
			header = "1"
		}
	}
	header += chomp
	if !literal {
		folded := yReNL.ReplaceAllStringFunc(value, func(m string) string { return "\n" + m })
		folded = yFoldMoreIndented(folded)
		folded = yReNL.ReplaceAllStringFunc(folded, func(m string) string { return m + indent })
		fell := false
		body := yFold(start+folded+end, indent, "block", yOpt{len(ctx.indent), true}, func() { fell = true })
		if !fell {
			return ">" + header + "\n" + indent + body
		}
	}
	value = yReNL.ReplaceAllStringFunc(value, func(m string) string { return m + indent })
	return "|" + header + "\n" + indent + start + value + end
}

func yPlain(value string, ctx *yctx) string {
	if ctx.implicitKey && strings.Contains(value, "\n") {
		return yQuoted(value, ctx)
	}
	if yRePlainBad.MatchString(value) {
		if ctx.implicitKey || !strings.Contains(value, "\n") {
			return yQuoted(value, ctx)
		}
		return yBlockString(value, ctx)
	}
	if !ctx.implicitKey && strings.Contains(value, "\n") {
		return yBlockString(value, ctx)
	}
	if yContainsDocMarker(value) {
		if ctx.indent == "" {
			ctx.forceBlockIndent = true
			return yBlockString(value, ctx)
		}
		if ctx.implicitKey && ctx.indent == yIndentStep {
			return yQuoted(value, ctx)
		}
	}
	s := yReNL.ReplaceAllStringFunc(value, func(m string) string { return m + "\n" + ctx.indent })
	if ctx.actualString {
		for _, t := range yReTagTests {
			if t.MatchString(s) {
				return yQuoted(value, ctx)
			}
		}
	}
	if ctx.implicitKey {
		return s
	}
	return yFold(s, ctx.indent, "flow", ctx.indentAtStart, nil)
}

func yString(raw string, ctx *yctx) string {
	lone := hasLoneSurrogate(raw)
	value := yToUnits(raw)
	if lone || yReControl.MatchString(value) {
		return yDoubleQuoted(value, ctx)
	}
	return yPlain(value, ctx)
}

func yNumber(v any) string {
	f, _ := jsNum(v)
	return jsNumberStringYAML(f)
}

func jsNumberStringYAML(f float64) string {
	switch {
	case math.IsNaN(f):
		return ".nan"
	case math.IsInf(f, 1):
		return ".inf"
	case math.IsInf(f, -1):
		return "-.inf"
	}
	return jsNumberLexeme(f)
}

// ---- nodes ----------------------------------------------------------------------------------------------------------

type yScalar struct{ value any }

type ySeq struct {
	anchor string
	items  []any
}

type yPair struct {
	key   *yScalar
	value any
}

type yMap struct {
	anchor string
	pairs  []yPair
}

type yAlias struct{ source string }

type yID struct {
	kind byte
	ptr  uintptr
	n    int
}

type yRef struct {
	anchor string
	node   any
}

type yBuilder struct {
	seen map[yID]*yRef
	keep []any
	n    int
	refs []*yRef
}

type yEmitErr struct{ msg string }

func yFail(format string, a ...any) { panic(yEmitErr{fmt.Sprintf(format, a...)}) }

func newYBuilder() *yBuilder { return &yBuilder{seen: map[yID]*yRef{}} }

// share registers a container; it returns the alias to emit when it was met before.
func (b *yBuilder) share(id yID, v any) (*yRef, *yAlias) {
	if ref, ok := b.seen[id]; ok {
		if ref.anchor == "" {
			b.n++
			ref.anchor = "a" + strconv.Itoa(b.n)
		}
		return nil, &yAlias{ref.anchor}
	}
	ref := &yRef{}
	b.seen[id] = ref
	b.keep = append(b.keep, v)
	b.refs = append(b.refs, ref)
	return ref, nil
}

func (b *yBuilder) seq(id yID, shared bool, v any, items []any) any {
	var ref *yRef
	if shared {
		var al *yAlias
		if ref, al = b.share(id, v); al != nil {
			return al
		}
	}
	s := &ySeq{}
	if ref != nil {
		ref.node = s
	}
	for _, x := range items {
		s.items = append(s.items, b.node(x))
	}
	return s
}

func (b *yBuilder) node(v any) any {
	switch t := v.(type) {
	case nil, string, bool:
		return &yScalar{v}
	case map[string]any:
		ref, al := b.share(yID{'m', reflect.ValueOf(t).Pointer(), 0}, v)
		if al != nil {
			return al
		}
		m := &yMap{}
		ref.node = m
		for _, k := range jsKeys(t) {
			m.pairs = append(m.pairs, yPair{&yScalar{k}, b.node(t[k])})
		}
		return m
	case []any:
		return b.seq(yID{'s', reflect.ValueOf(t).Pointer(), len(t)}, len(t) > 0, v, t)
	case *[]any:
		if t == nil {
			yFail("cannot write a nil sequence as YAML")
		}
		return b.seq(yID{'p', reflect.ValueOf(t).Pointer(), 0}, true, v, *t)
	}
	if _, ok := jsNum(v); ok {
		return &yScalar{v}
	}
	yFail("cannot write a %T as YAML", v)
	return nil
}

func (b *yBuilder) finish() {
	for _, ref := range b.refs {
		if ref.anchor == "" {
			continue
		}
		switch n := ref.node.(type) {
		case *ySeq:
			n.anchor = ref.anchor
		case *yMap:
			n.anchor = ref.anchor
		}
	}
}

func yIsColl(n any) bool {
	switch n.(type) {
	case *ySeq, *yMap:
		return true
	}
	return false
}

func yStringify(item any, ctx *yctx) string {
	if a, ok := item.(*yAlias); ok {
		if !ctx.anchors[a.source] {
			yFail("Unresolved alias (the anchor must be set before the alias): %s", a.source)
		}
		if ctx.implicitKey {
			return "*" + a.source + " "
		}
		return "*" + a.source
	}
	anchor := ""
	switch n := item.(type) {
	case *ySeq:
		anchor = n.anchor
	case *yMap:
		anchor = n.anchor
	}
	props := ""
	if anchor != "" {
		ctx.anchors[anchor] = true
		props = "&" + anchor
		ctx.indentAtStart = yOpt{ctx.indentAtStart.v + len(props) + 1, true}
	}
	var s string
	isScalar := false
	switch n := item.(type) {
	case *yScalar:
		isScalar = true
		switch v := n.value.(type) {
		case string:
			c := ctx.copy()
			c.actualString = true
			s = yString(v, c)
		case nil:
			s = "null"
		case bool:
			if v {
				s = "true"
			} else {
				s = "false"
			}
		default:
			s = yNumber(v)
		}
	case *ySeq:
		ictx := ctx.copy() // one context for every item, as the reference shares it
		ictx.indent = ctx.indent + yIndentStep
		lines := make([]string, 0, len(n.items))
		for _, x := range n.items {
			lines = append(lines, "- "+yStringify(x, ictx))
		}
		s = yBlock(ctx, lines, "[", "]")
	case *yMap:
		ictx := ctx.copy()
		lines := make([]string, 0, len(n.pairs))
		for _, p := range n.pairs {
			lines = append(lines, yPairText(p.key, p.value, ictx))
		}
		s = yBlock(ctx, lines, "{", "}")
	default:
		yFail("cannot write a %T as YAML", item)
	}
	if props == "" {
		return s
	}
	if isScalar || (len(s) > 0 && (s[0] == '{' || s[0] == '[')) {
		return props + " " + s
	}
	return props + "\n" + ctx.indent + s
}

func yBlock(ctx *yctx, lines []string, start, end string) string {
	if len(lines) == 0 {
		return start + end
	}
	out := lines[0]
	for _, line := range lines[1:] {
		if line != "" {
			out += "\n" + ctx.indent + line
		} else {
			out += "\n"
		}
	}
	return out
}

func yPairText(key *yScalar, value any, ctx *yctx) string {
	indent := ctx.indent
	ctx = ctx.copy()
	ctx.implicitKey = true
	ctx.indent = indent + yIndentStep
	s := yStringify(key, ctx)
	explicit := yLen(s) > 1024
	if explicit {
		s = "? " + s + "\n" + indent + ":"
	} else {
		s += ":"
	}
	ctx.implicitKey = false
	if _, isScalar := value.(*yScalar); !explicit && isScalar {
		ctx.indentAtStart = yOpt{yLen(s) + 1, true}
	}
	vs := yStringify(value, ctx)
	ws := " "
	if !explicit && yIsColl(value) {
		nl0 := strings.Index(vs, "\n")
		hasNL := nl0 != -1
		flow := false
		switch c := value.(type) {
		case *ySeq:
			flow = len(c.items) == 0
		case *yMap:
			flow = len(c.pairs) == 0
		}
		if hasNL || !flow {
			propsLine := false
			if hasNL && (vs[0] == '&' || vs[0] == '!') {
				sp0 := strings.Index(vs, " ")
				if vs[0] == '&' && sp0 != -1 && sp0 < nl0 && sp0+1 < len(vs) && vs[sp0+1] == '!' {
					if k := strings.Index(vs[sp0+1:], " "); k >= 0 {
						sp0 += 1 + k
					} else {
						sp0 = -1
					}
				}
				if sp0 == -1 || nl0 < sp0 {
					propsLine = true
				}
			}
			if !propsLine {
				ws = "\n" + ctx.indent
			}
		}
	} else if vs == "" || vs[0] == '\n' {
		ws = ""
	}
	return s + ws + vs
}

func yRun(build func(b *yBuilder) any) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(yEmitErr)
			if !ok {
				panic(r)
			}
			text, err = "", fmt.Errorf("yaml: %s", e.msg)
		}
	}()
	b := newYBuilder()
	root := build(b)
	b.finish()
	ctx := &yctx{anchors: map[string]bool{}}
	return yFromUnits(yStringify(root, ctx)) + "\n", nil
}

// YamlStringify is the YAML text of plain data (see the file comment for the accepted Go types); repeated containers become
// anchors and aliases. It refuses a value that is not plain data.
func YamlStringify(v any) (string, error) {
	return yRun(func(b *yBuilder) any { return b.node(v) })
}

// ActionsDefsToYaml writes `ns: <ns>` and `actions: [...]` as YAML; a def whose verb has an own entry in rules gets it
// re-attached as its `rules` member (a copy, so the def itself is never the shared node of that entry).
func ActionsDefsToYaml(ns string, defs []any, rules map[string]any) (string, error) {
	return yRun(func(b *yBuilder) any {
		actions := &ySeq{}
		for _, d := range defs {
			dm, isMap := d.(map[string]any)
			if !isMap {
				actions.items = append(actions.items, b.node(d))
				continue
			}
			verb, hasVerb := dm["verb"].(string)
			rv, has := rules[verb]
			if !hasVerb || !has {
				actions.items = append(actions.items, b.node(d))
				continue
			}
			m := &yMap{}
			done := false
			for _, k := range jsKeys(dm) {
				if k == "rules" {
					m.pairs = append(m.pairs, yPair{&yScalar{k}, b.node(rv)})
					done = true
				} else {
					m.pairs = append(m.pairs, yPair{&yScalar{k}, b.node(dm[k])})
				}
			}
			if !done {
				m.pairs = append(m.pairs, yPair{&yScalar{"rules"}, b.node(rv)})
			}
			actions.items = append(actions.items, m)
		}
		return &yMap{pairs: []yPair{{&yScalar{"ns"}, &yScalar{ns}}, {&yScalar{"actions"}, actions}}}
	})
}
