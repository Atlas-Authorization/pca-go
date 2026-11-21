package pca

// Strict CEL: ONE boolean expression of a small subset as a PCA condition, or a rejection naming the construct (there is
// no best-effort mode). Offsets are UTF-16 code units of the expression.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	pbCelMaxExpr  = 4096
	pbCelMaxDepth = 32
	pbCelMaxNodes = 256
	pbCelMaxList  = 64
	pbCelMaxStr   = 256
)

var (
	pbCelIdent  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	pbCelPath   = regexp.MustCompile(`^(action|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	pbCelTS     = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$`)
	pbCelPunct  = []string{"&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-"}
	pbCelRelops = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true}
	pbForbidden = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}
	pbCelUnsup  = map[uint16]string{
		'+': "arithmetic (+)", '*': "arithmetic (*)", '/': "arithmetic (/)", '%': "arithmetic (%)", '?': "the conditional operator",
		':': "the conditional operator / map literal", '{': "map or message literal", '}': "map or message literal", '@': "@", '&': "bitwise &",
		'|': "bitwise |", '^': "^", '~': "~", '=': "assignment", '`': "quoted identifier",
	}
	pbCelRejectedFuncs = pbSet(strings.Fields("size matches exists all exists_one map filter int uint double string bytes bool duration type dyn min max getHours getDayOfWeek " +
		"getMinutes getSeconds getFullYear getMonth getDate getDayOfMonth getDayOfYear getMilliseconds extract format lowerAscii upperAscii " +
		"trim split join replace substring indexOf lastIndexOf charAt isIpv4 inIpRange cidr ip isCIDR containsIp url quantity semver optional"))
	pbCelEscapes = map[int]uint16{'\\': '\\', '"': '"', '\'': '\'', 'n': '\n', 't': '\t', 'r': '\r'}
)

func pbSet(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

type pbReject struct {
	code, message string
	at            int
}

func pbRej(code, message string, at int) { panic(&pbReject{code, message, at}) }

type pbTok struct {
	k, v string
	at   int
}

func pbIsLetter(c int) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' }
func pbIsDigit(c int) bool  { return c >= '0' && c <= '9' }

func pbLex(src []uint16) []pbTok {
	out := []pbTok{}
	n := len(src)
	at := func(j int) int {
		if j >= 0 && j < n {
			return int(src[j])
		}
		return -1
	}
	has := func(i int, tok string) bool {
		for k := 0; k < len(tok); k++ {
			if at(i+k) != int(tok[k]) {
				return false
			}
		}
		return true
	}
	i := 0
	for i < n {
		c := int(src[i])
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		if c == '/' && at(i+1) == '/' {
			pbRej("unsupported", "comments", i)
		}
		if pbIsLetter(c) {
			j := i + 1
			for j < n && (pbIsLetter(int(src[j])) || pbIsDigit(int(src[j]))) {
				j++
			}
			w := unitsString(src[i:j])
			if (w == "r" || w == "b" || w == "R" || w == "B") && (at(j) == '"' || at(j) == '\'') {
				kind := "bytes"
				if strings.ToLower(w) == "r" {
					kind = "raw string"
				}
				pbRej("unsupported", kind+" literal", i)
			}
			out = append(out, pbTok{"id", w, i})
			i = j
			continue
		}
		if pbIsDigit(c) {
			j := i
			for j < n && pbIsDigit(int(src[j])) {
				j++
			}
			nxt := at(j)
			if nxt == '.' && pbIsDigit(at(j+1)) {
				pbRej("unsupported", "double literal", i)
			}
			if nxt == 'e' || nxt == 'E' {
				pbRej("unsupported", "double literal", i)
			}
			if nxt == 'u' || nxt == 'U' {
				pbRej("unsupported", "unsigned integer literal", i)
			}
			if nxt == 'x' || nxt == 'X' {
				pbRej("unsupported", "hexadecimal literal", i)
			}
			w := unitsString(src[i:j])
			if len(w) > 1 && w[0] == '0' {
				pbRej("unsupported", "integer literal with a leading zero", i)
			}
			out = append(out, pbTok{"int", w, i})
			i = j
			continue
		}
		if c == '"' || c == '\'' {
			if at(i+1) == c && at(i+2) == c {
				pbRej("unsupported", "triple-quoted string", i)
			}
			j := i + 1
			parts := []uint16{}
			for {
				d := at(j)
				if d == -1 || d == '\n' || d == '\r' {
					pbRej("syntax", "unterminated string", i)
				}
				if d == c {
					break
				}
				if d == '\\' {
					e := at(j + 1)
					esc, ok := pbCelEscapes[e]
					if e == -1 || !ok {
						shown := ""
						if e != -1 {
							shown = unitsString(src[j+1 : j+2])
						}
						pbRej("unsupported", "string escape \\"+shown, j)
					}
					parts = append(parts, esc)
					j += 2
					continue
				}
				parts = append(parts, uint16(d))
				j++
			}
			if len(parts) > pbCelMaxStr {
				pbRej("too_complex", fmt.Sprintf("string literal longer than %d", pbCelMaxStr), i)
			}
			out = append(out, pbTok{"str", unitsString(parts), i})
			i = j + 1
			continue
		}
		p := ""
		for _, x := range pbCelPunct {
			if has(i, x) {
				p = x
				break
			}
		}
		if p == "" {
			if m, ok := pbCelUnsup[uint16(c)]; ok {
				pbRej("unsupported", m, i)
			}
			pbRej("syntax", "unexpected character '"+unitsString(src[i:i+1])+"'", i)
		}
		out = append(out, pbTok{"p", p, i})
		i += len(p)
	}
	return out
}

func pbDaysFromCivil(y, m, d int) int {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 {
		era = (y - 399) / 400
	}
	yoe := y - era*400
	mm := m - 3
	if m <= 2 {
		mm = m + 9
	}
	doy := (153*mm+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

func pbParseTimestamp(s string, at int) float64 {
	m := pbCelTS.FindStringSubmatch(s)
	if m == nil {
		pbRej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at)
	}
	dt := strings.Split(m[1], "T")
	dp := strings.Split(dt[0], "-")
	tp := strings.Split(dt[1], ":")
	atoi := func(x string) int { v, _ := strconv.Atoi(x); return v }
	y, mo, d := atoi(dp[0]), atoi(dp[1]), atoi(dp[2])
	h, mi, sec := atoi(tp[0]), atoi(tp[1]), atoi(tp[2])
	frac := m[2]
	for len(frac) < 3 {
		frac += "0"
	}
	ms := atoi(frac)
	leap := y%4 == 0 && (y%100 != 0 || y%400 == 0)
	feb := 28
	if leap {
		feb = 29
	}
	dim := []int{31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if !(mo >= 1 && mo <= 12 && d >= 1 && d <= dim[mo-1] && h <= 23 && mi <= 59 && sec <= 59) {
		pbRej("unsupported", "timestamp() is not a real instant", at)
	}
	return float64((((int64(pbDaysFromCivil(y, mo, d))*24+int64(h))*60+int64(mi))*60+int64(sec))*1000 + int64(ms))
}

type pbParser struct {
	toks   []pbTok
	srcLen int
	pos    int
	nodes  int
}

func (p *pbParser) peek() *pbTok {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *pbParser) isP(v string) bool {
	t := p.peek()
	return t != nil && t.k == "p" && t.v == v
}

func (p *pbParser) eat(v string) bool {
	if p.isP(v) {
		p.pos++
		return true
	}
	return false
}

func (p *pbParser) need(v string) {
	if !p.eat(v) {
		at := p.srcLen
		if t := p.peek(); t != nil {
			at = t.at
		}
		pbRej("syntax", "expected '"+v+"'", at)
	}
}

func (p *pbParser) tick(at int) {
	p.nodes++
	if p.nodes > pbCelMaxNodes {
		pbRej("too_complex", fmt.Sprintf("more than %d nodes", pbCelMaxNodes), at)
	}
}

func (p *pbParser) expr(d int) map[string]any {
	if d > pbCelMaxDepth {
		at := 0
		if t := p.peek(); t != nil {
			at = t.at
		}
		pbRej("too_complex", fmt.Sprintf("nesting deeper than %d", pbCelMaxDepth), at)
	}
	return p.or(d)
}

func (p *pbParser) or(d int) map[string]any {
	left := p.and(d)
	for p.isP("||") {
		at := p.peek().at
		p.pos++
		p.tick(at)
		left = map[string]any{"t": "or", "l": left, "r": p.and(d), "at": at}
	}
	return left
}

func (p *pbParser) and(d int) map[string]any {
	left := p.rel(d)
	for p.isP("&&") {
		at := p.peek().at
		p.pos++
		p.tick(at)
		left = map[string]any{"t": "and", "l": left, "r": p.rel(d), "at": at}
	}
	return left
}

func pbIsRelop(t *pbTok) bool {
	return (t.k == "p" && pbCelRelops[t.v]) || (t.k == "id" && t.v == "in")
}

func (p *pbParser) rel(d int) map[string]any {
	left := p.unary(d)
	t := p.peek()
	if t == nil || !pbIsRelop(t) {
		return left
	}
	op, at := t.v, t.at
	p.pos++
	p.tick(at)
	n := map[string]any{"t": "rel", "op": op, "l": left, "r": p.unary(d), "at": at}
	if u := p.peek(); u != nil && pbIsRelop(u) {
		pbRej("unsupported", "chained comparison", u.at)
	}
	return n
}

func (p *pbParser) unary(d int) map[string]any {
	t := p.peek()
	if t != nil && t.k == "p" && t.v == "!" {
		at := t.at
		p.pos++
		p.tick(at)
		if d+1 > pbCelMaxDepth {
			pbRej("too_complex", fmt.Sprintf("nesting deeper than %d", pbCelMaxDepth), at)
		}
		return map[string]any{"t": "not", "e": p.unary(d + 1), "at": at}
	}
	if t != nil && t.k == "p" && t.v == "-" {
		at := t.at
		if p.pos+1 >= len(p.toks) || p.toks[p.pos+1].k != "int" {
			pbRej("unsupported", "unary minus on a non-literal", at)
		}
		nx := p.toks[p.pos+1]
		p.pos += 2
		return p.intNode("-"+nx.v, at)
	}
	return p.member(d)
}

func (p *pbParser) intNode(text string, at int) map[string]any {
	p.tick(at)
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil || v > 9007199254740991 || v < -9007199254740991 {
		pbRej("unsupported", "integer literal outside the safe-integer range", at)
	}
	return map[string]any{"t": "int", "v": float64(v), "at": at}
}

func (p *pbParser) args(d int) []map[string]any {
	a := []map[string]any{}
	if !p.isP(")") {
		a = append(a, p.expr(d+1))
		for p.eat(",") {
			a = append(a, p.expr(d+1))
		}
	}
	p.need(")")
	return a
}

func (p *pbParser) member(d int) map[string]any {
	n := p.primary(d)
	for p.isP(".") {
		dot := *p.peek()
		p.pos++
		ident := p.peek()
		if ident == nil || ident.k != "id" {
			pbRej("syntax", "expected a name after '.'", dot.at)
		}
		id := *ident
		p.pos++
		if p.isP("(") {
			p.pos++
			a := p.args(d)
			if id.v != "startsWith" && id.v != "endsWith" && id.v != "contains" {
				pbRej("unsupported", "method '"+id.v+"'", id.at)
			}
			if len(a) != 1 {
				pbRej("syntax", "'"+id.v+"' takes one argument", id.at)
			}
			p.tick(id.at)
			n = map[string]any{"t": "method", "target": n, "fn": id.v, "arg": a[0], "at": id.at}
		} else {
			if n["t"] != "var" {
				pbRej("unsupported", "field selection on something that is not a declared variable", dot.at)
			}
			c := map[string]any{}
			for k, v := range n {
				c[k] = v
			}
			c["name"] = n["name"].(string) + "." + id.v
			n = c
		}
	}
	if p.isP("[") {
		pbRej("unsupported", "index operator", p.peek().at)
	}
	return n
}

func (p *pbParser) primary(d int) map[string]any {
	t := p.peek()
	if t == nil {
		pbRej("syntax", "unexpected end of expression", p.srcLen)
	}
	tk := *t
	switch {
	case tk.k == "int":
		p.pos++
		return p.intNode(tk.v, tk.at)
	case tk.k == "str":
		p.pos++
		p.tick(tk.at)
		return map[string]any{"t": "str", "v": tk.v, "at": tk.at}
	case tk.k == "p" && tk.v == "(":
		p.pos++
		e := p.expr(d + 1)
		p.need(")")
		return e
	case tk.k == "p" && tk.v == "[":
		p.pos++
		items := []any{}
		if !p.isP("]") {
			for {
				if len(items) >= pbCelMaxList {
					pbRej("too_complex", fmt.Sprintf("list longer than %d", pbCelMaxList), tk.at)
				}
				items = append(items, p.expr(d+1))
				if !p.eat(",") {
					break
				}
			}
		}
		p.need("]")
		p.tick(tk.at)
		return map[string]any{"t": "list", "items": items, "at": tk.at}
	case tk.k == "id":
		p.pos++
		if tk.v == "true" || tk.v == "false" {
			p.tick(tk.at)
			return map[string]any{"t": "bool", "v": tk.v == "true", "at": tk.at}
		}
		if tk.v == "null" {
			pbRej("unsupported", "null", tk.at)
		}
		if p.isP("(") {
			p.pos++
			a := p.args(d)
			if tk.v == "has" {
				if len(a) != 1 || a[0]["t"] != "var" {
					pbRej("syntax", "has() takes one declared variable", tk.at)
				}
				p.tick(tk.at)
				return map[string]any{"t": "has", "e": a[0], "at": tk.at}
			}
			if tk.v == "timestamp" {
				if len(a) != 1 || a[0]["t"] != "str" {
					pbRej("unsupported", "timestamp() of a non-literal", tk.at)
				}
				return map[string]any{"t": "ts", "v": pbParseTimestamp(a[0]["v"].(string), tk.at), "at": tk.at}
			}
			if pbCelRejectedFuncs[tk.v] {
				pbRej("unsupported", "function '"+tk.v+"'", tk.at)
			}
			pbRej("unsupported", "unknown function '"+tk.v+"'", tk.at)
		}
		if tk.v == "in" {
			pbRej("syntax", "unexpected 'in'", tk.at)
		}
		p.tick(tk.at)
		return map[string]any{"t": "var", "name": tk.v, "at": tk.at}
	}
	pbRej("syntax", "unexpected '"+tk.v+"'", tk.at)
	return nil
}

func pbCelParse(src any) map[string]any {
	s, ok := src.(string)
	if !ok || len(s) == 0 {
		pbRej("syntax", "empty expression", 0)
	}
	u := utf16Units(s)
	if len(u) > pbCelMaxExpr {
		pbRej("too_complex", fmt.Sprintf("expression longer than %d characters", pbCelMaxExpr), 0)
	}
	p := &pbParser{toks: pbLex(u), srcLen: len(u)}
	root := p.expr(0)
	if p.pos < len(p.toks) {
		pbRej("syntax", "unexpected '"+p.toks[p.pos].v+"'", p.toks[p.pos].at)
	}
	return root
}

func pbCelErr(e *pbReject) map[string]any {
	return map[string]any{"ok": false, "code": e.code, "message": e.message, "at": e.at}
}

func pbCelInternal() map[string]any {
	return map[string]any{"ok": false, "code": "syntax", "message": "internal error", "at": 0}
}

// pbCelGuard runs f and turns a rejection into its error result and any other failure into the internal-error result.
func pbCelGuard(f func() map[string]any) (res map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			if rj, ok := r.(*pbReject); ok {
				res = pbCelErr(rj)
			} else {
				res = pbCelInternal()
			}
		}
	}()
	return f()
}

// ParseCel parses a CEL expression of the supported subset: {ok: true, ast} or {ok: false, code, message, at}.
func ParseCel(expression any) map[string]any {
	return pbCelGuard(func() map[string]any { return map[string]any{"ok": true, "ast": pbCelParse(expression)} })
}

func pbCelSchemaError(s any) string {
	sm, ok := s.(map[string]any)
	if !ok {
		return "the schema must be an object"
	}
	vars, ok := sm["vars"].(map[string]any)
	if !ok {
		return "the schema needs a vars object"
	}
	for _, name := range jsKeys(vars) {
		v := vars[name]
		bad := !pbCelIdent.MatchString(name)
		for _, seg := range strings.Split(name, ".") {
			if pbForbidden[seg] {
				bad = true
			}
		}
		if bad {
			return "bad variable name '" + name + "'"
		}
		vm, isMap := v.(map[string]any)
		path, isStr := "", false
		if isMap {
			path, isStr = vm["path"].(string)
		}
		pathBad := !isStr || !pbCelPath.MatchString(path)
		for _, seg := range strings.Split(path, ".") {
			if pbForbidden[seg] {
				pathBad = true
			}
		}
		if !isMap || pathBad {
			return "variable '" + name + "' needs a path rooted at action, subject or env"
		}
		t, isT := vm["type"].(string)
		if !isT || (t != "string" && t != "int" && t != "bool" && t != "timestamp_ms") {
			return "variable '" + name + "' has an unsupported type"
		}
		if o, has := vm["optional"]; has {
			if _, isBool := o.(bool); !isBool {
				return "variable '" + name + "': optional must be a boolean"
			}
		}
	}
	return ""
}

type pbOperand struct {
	isVar bool
	v     map[string]any // the schema variable
	name  string
	typ   string // literal type
	value any
}

func (o pbOperand) typeOf() string {
	if o.isVar {
		return o.v["type"].(string)
	}
	return o.typ
}

// CelToCondition translates ONE boolean CEL expression as a PCA condition: {ok: true, condition, fields} or {ok: false,
// code, message, at}. schema is {vars: {name: {path, type, optional?}}}.
func CelToCondition(expression any, schema any) map[string]any {
	if se := pbCelSchemaError(schema); se != "" {
		return map[string]any{"ok": false, "code": "bad_schema", "message": se, "at": 0}
	}
	svars := schema.(map[string]any)["vars"].(map[string]any)
	return pbCelGuard(func() map[string]any {
		ast := pbCelParse(expression)
		fields := map[string]bool{}
		operand := func(n map[string]any) pbOperand {
			at := n["at"].(int)
			switch n["t"] {
			case "var":
				name := n["name"].(string)
				v, ok := svars[name].(map[string]any)
				if !ok {
					pbRej("unknown_identifier", "'"+name+"' is not declared in the schema", at)
				}
				return pbOperand{isVar: true, v: v, name: name}
			case "int":
				return pbOperand{typ: "int", value: n["v"]}
			case "str":
				return pbOperand{typ: "string", value: n["v"]}
			case "bool":
				return pbOperand{typ: "bool", value: n["v"]}
			case "ts":
				return pbOperand{typ: "timestamp_ms", value: n["v"]}
			}
			pbRej("unsupported", "a computed value as a comparison operand", at)
			return pbOperand{}
		}
		read := func(o pbOperand) string {
			p := o.v["path"].(string)
			fields[p] = true
			return p
		}
		var flat func(n map[string]any, t string, out []any) []any
		flat = func(n map[string]any, t string, out []any) []any {
			if n["t"] == t {
				out = flat(n["l"].(map[string]any), t, out)
				return flat(n["r"].(map[string]any), t, out)
			}
			return append(out, n)
		}
		var tr func(n map[string]any) map[string]any
		tr = func(n map[string]any) map[string]any {
			t := n["t"].(string)
			at := n["at"].(int)
			switch t {
			case "or", "and":
				kids := []any{}
				for _, x := range flat(n, t, nil) {
					kids = append(kids, tr(x.(map[string]any)))
				}
				if t == "or" {
					return map[string]any{"any_of": kids}
				}
				return map[string]any{"all_of": kids}
			case "not":
				return map[string]any{"not": tr(n["e"].(map[string]any))}
			case "has":
				o := operand(n["e"].(map[string]any))
				if !o.isVar {
					pbRej("syntax", "has() takes a declared variable", at)
				}
				if opt, _ := o.v["optional"].(bool); !opt {
					pbRej("has_requires_optional", "has("+o.name+"): mark the variable optional in the schema (its container must always be present)", at)
				}
				return map[string]any{"field": read(o), "op": "exists", "value": true}
			case "var":
				o := operand(n)
				hint := ""
				if o.isVar && o.v["type"] == "bool" {
					hint = " (write " + n["name"].(string) + " == true)"
				}
				pbRej("unsupported", "a bare variable '"+n["name"].(string)+"' as a condition"+hint, at)
			case "method":
				tg := operand(n["target"].(map[string]any))
				fn := n["fn"].(string)
				if !tg.isVar || tg.v["type"] != "string" {
					pbRej("type_mismatch", fn+" needs a string variable", at)
				}
				arg := n["arg"].(map[string]any)
				lit, isStr := arg["v"].(string)
				if arg["t"] != "str" || !isStr || len(lit) == 0 {
					pbRej("unsupported", fn+" of anything but a non-empty string literal", at)
				}
				if fn == "startsWith" {
					return map[string]any{"field": read(tg), "op": "prefix", "value": lit}
				}
				esc := pbEscapeGlob(lit)
				glob := "*" + esc + "*"
				if fn == "endsWith" {
					glob = "*" + esc
				}
				if jsLen(glob) > 512 {
					pbRej("too_complex", "literal too long for a glob", at)
				}
				return map[string]any{"field": read(tg), "op": "like", "value": glob}
			case "rel":
				op := n["op"].(string)
				if op == "in" {
					left := operand(n["l"].(map[string]any))
					if !left.isVar {
						pbRej("constant_expression", "the left side of \"in\" must be a declared variable", at)
					}
					r := n["r"].(map[string]any)
					list, _ := r["items"].([]any)
					if r["t"] != "list" || len(list) == 0 {
						pbRej("unsupported", "\"in\" against anything but a non-empty list literal", at)
					}
					items := []pbOperand{}
					for _, x := range list {
						items = append(items, operand(x.(map[string]any)))
					}
					for _, i := range items {
						if i.isVar || i.typ != left.typeOf() {
							pbRej("type_mismatch", "list items must be "+left.typeOf()+" literals", at)
						}
					}
					vals := []any{}
					for _, i := range items {
						vals = append(vals, i.value)
					}
					return map[string]any{"field": read(left), "op": "in", "value": vals}
				}
				left := operand(n["l"].(map[string]any))
				right := operand(n["r"].(map[string]any))
				if !left.isVar && !right.isVar {
					pbRej("constant_expression", "a comparison of two literals", at)
				}
				if left.typeOf() != right.typeOf() {
					pbRej("type_mismatch", left.typeOf()+" against "+right.typeOf(), at)
				}
				if op != "==" && op != "!=" && left.typeOf() == "bool" {
					pbRej("type_mismatch", "ordering of booleans", at)
				}
				pcaOp := map[string]string{"==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[op]
				flip := map[string]string{"eq": "eq", "ne": "ne", "lt": "gt", "lte": "gte", "gt": "lt", "gte": "lte"}
				if left.isVar && right.isVar {
					return map[string]any{"field": read(left), "op": pcaOp, "ref": read(right)}
				}
				if left.isVar {
					return map[string]any{"field": read(left), "op": pcaOp, "value": right.value}
				}
				return map[string]any{"field": read(right), "op": flip[pcaOp], "value": left.value}
			}
			pbRej("constant_expression", "a bare constant is not a condition", at)
			return nil
		}
		condition := tr(ast)
		if len(fields) == 0 {
			pbRej("constant_expression", "the expression reads no variable", 0)
		}
		names := make([]string, 0, len(fields))
		for f := range fields {
			names = append(names, f)
		}
		sort.Slice(names, func(i, j int) bool { return pbLess(names[i], names[j]) })
		fl := make([]any, len(names))
		for i, f := range names {
			fl[i] = f
		}
		return map[string]any{"ok": true, "condition": condition, "fields": fl}
	})
}

// CelToPredicate translates one CEL expression as a permit predicate for scope["verb"] (and optionally scope["resource"]).
func CelToPredicate(expression any, schema any, scope map[string]any) map[string]any {
	r := CelToCondition(expression, schema)
	if r["ok"] != true {
		return r
	}
	p := map[string]any{"verb": scope["verb"]}
	if res, has := scope["resource"]; has {
		p["resource"] = res
	}
	p["where"] = []any{r["condition"]}
	return map[string]any{"ok": true, "predicate": p, "fields": r["fields"]}
}

// CelConditionsToPca translates a batch of named CEL expressions: every one is translated or REPORTED; one rejection makes
// report.errors non-empty, and PolicyBridgeDecide then denies everything (an incomplete import never grants).
func CelConditionsToPca(items any, schema any) (map[string]any, error) {
	list, ok := items.([]any)
	if !ok {
		return nil, fmt.Errorf("items is not iterable")
	}
	predicates, translated, errs := []any{}, []any{}, []any{}
	for _, x := range list {
		it, isMap := x.(map[string]any)
		if !isMap {
			return nil, fmt.Errorf("item is not an object")
		}
		scope := map[string]any{"verb": it["verb"]}
		if res, has := it["resource"]; has {
			scope["resource"] = res
		}
		r := CelToPredicate(it["expression"], schema, scope)
		name := jsMemberString(it, "name")
		if r["ok"] == true {
			predicates = append(predicates, r["predicate"])
			fs := []string{}
			for _, f := range r["fields"].([]any) {
				fs = append(fs, f.(string))
			}
			translated = append(translated, name+": translated exactly (reads "+strings.Join(fs, ", ")+")")
		} else {
			errs = append(errs, fmt.Sprintf("%s: rejected (%s) at %d: %s", name, r["code"], r["at"], r["message"]))
		}
	}
	return map[string]any{"predicates": predicates, "denies": []any{}, "caveats": []any{}, "report": map[string]any{"source": "cel", "translated": translated, "skipped": []any{}, "errors": errs}}, nil
}
