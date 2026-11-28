package pca

// YAML text for the authoring-file loader (loadActionsText). The syntax layer is gopkg.in/yaml.v3's scanner and parser through its
// Node API (never struct decoding, so no merge, alias or tag handling of the library runs). Everything the reference decides
// about meaning is done here: the tree is built from the nodes, plain scalars are resolved with the YAML 1.2 core schema (null,
// bool, int, 0o / 0x, float, .inf, .nan; everything else a string), mapping keys are stringified the way JavaScript does,
// aliases are refused, `<<` is an ordinary key, and positions are the 1-based start of each action and each param key.
//
// Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex
// (non-scalar) mapping key, two keys that are equal once stringified (the reference keeps the last of 1 and "1"), a bare carriage
// return used as a line break, more than one document. Syntax error wording and the line of a syntax error are the parser's own.
// JSON text is read by a small JSON-only scanner (the grammar of JSON.parse: a duplicate member keeps the first position and the
// last value) that also records positions, so JSON never depends on the YAML parser.

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// YamlLoadError is a refusal of the text loader with its 1-based position.
type YamlLoadError struct {
	Message string
	Line    int
	Column  int
}

func (e *YamlLoadError) Error() string { return e.Message }

// ydNode is a parsed node: kind "scalar" | "map" | "seq", its resolved scalar value, children and 1-based start position.
// A map keeps its members flat: key, value, key, value, ...
type ydNode struct {
	kind  string
	value any
	items []*ydNode
	line  int
	col   int
}

var (
	reYdInt   = regexp.MustCompile(`^[-+]?[0-9]+$`)
	reYdOct   = regexp.MustCompile(`^0o[0-7]+$`)
	reYdHex   = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	reYdFloat = regexp.MustCompile(`^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?$`)
	reYdInf   = regexp.MustCompile(`^[-+]?\.(?:inf|Inf|INF)$`)
	reYdNaN   = regexp.MustCompile(`^\.(?:nan|NaN|NAN)$`)
	reYdBareR = regexp.MustCompile(`\r(?:[^\n]|$)`)
	reYdV12   = regexp.MustCompile(`(?m)^%YAML 1\.2([ \t]|\r?$)`)
	reYdLine  = regexp.MustCompile(`line (\d+)`)
)

// ydBigNumber is the number whose digits are s in the given base, as the nearest binary64 (a JavaScript number).
func ydBigNumber(s string, base int, neg bool) float64 {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return math.NaN()
	}
	f, _ := new(big.Float).SetInt(n).Float64()
	if neg {
		f = -f
	}
	return f
}

// yamlResolveCorePlain is the YAML 1.2 core schema value of a plain scalar, as a JavaScript number / boolean / null / string.
// Numbers are json.Number lexemes of the binary64 (so -0 stays "-0", .inf is "Infinity" and .nan is "NaN").
func yamlResolveCorePlain(text string) any {
	switch text {
	case "", "~", "null", "Null", "NULL":
		return nil
	case "true", "True", "TRUE":
		return true
	case "false", "False", "FALSE":
		return false
	}
	num := func(f float64) any { return jsNumber(f) }
	switch {
	case reYdInt.MatchString(text):
		f, _ := strconv.ParseFloat(strings.TrimPrefix(text, "+"), 64)
		return num(f)
	case reYdOct.MatchString(text):
		return num(ydBigNumber(text[2:], 8, false))
	case reYdHex.MatchString(text):
		return num(ydBigNumber(text[2:], 16, false))
	case reYdInf.MatchString(text):
		if text[0] == '-' {
			return num(math.Inf(-1))
		}
		return num(math.Inf(1))
	case reYdNaN.MatchString(text):
		return num(math.NaN())
	case reYdFloat.MatchString(text):
		f, _ := strconv.ParseFloat(strings.TrimPrefix(text, "+"), 64) // an out-of-range value is +-Inf, as in JavaScript
		return num(f)
	}
	return text
}

// yamlKeyString is String(key) of a resolved scalar key.
func yamlKeyString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		return t
	}
	f, _ := jsNum(v)
	if f == 0 {
		return "0"
	}
	return jsNumberString(f)
}

func ydFail(msg string, line, col int) error { return &YamlLoadError{msg, line, col} }

// ---- YAML -------------------------------------------------------------------------------------------------------------

// ydSourceChar is the rune at a 1-based (line, column) of the text, or -1.
func ydSourceChar(lines [][]rune, line, col int) rune {
	if line < 1 || line > len(lines) || col < 1 || col > len(lines[line-1]) {
		return -1
	}
	return lines[line-1][col-1]
}

func yamlParseDocument(text string, strict bool) (*ydNode, error) {
	if reYdBareR.MatchString(text) {
		return nil, ydFail("bare carriage return is not accepted as a line break", 1, 1)
	}
	text = reYdV12.ReplaceAllString(text, "%YAML 1.1$1") // the parser takes only the 1.1 directive; the scalars are resolved here, as 1.2
	dec := yaml.NewDecoder(strings.NewReader(text))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		// YAML 1.2 double-quoted scalars know the escape \/ ; the 1.1 scanner does not: read it as the slash it stands for
		if fixed := ydSlashEscapes(text); fixed != text && strings.Contains(err.Error(), "found unknown escape character") {
			return yamlParseDocument(fixed, strict)
		}
		return nil, ydSyntax(err)
	}
	var second yaml.Node
	switch err := dec.Decode(&second); {
	case err == nil:
		return nil, ydFail("Source contains multiple documents; please use YAML.parseAllDocuments()", 1, 1)
	case !errors.Is(err, io.EOF):
		return nil, ydSyntax(err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, ydFail("unexpected parser node", 1, 1)
	}
	var lines [][]rune
	if strings.Contains(text, "!") {
		for _, l := range strings.Split(text, "\n") {
			lines = append(lines, []rune(l))
		}
	}
	return ydConvert(doc.Content[0], strict, lines, 0)
}

// ydSlashEscapes rewrites the YAML 1.2 escape \/ as a plain slash, only where it is one: inside a double-quoted scalar, as an
// unescaped backslash (an odd run: \\/ is a backslash followed by a slash). Single-quoted scalars, comments and plain text are left
// alone. A quote opens a scalar only at the start of one (after the line start, whitespace, [ { or ,).
func ydSlashEscapes(text string) string {
	var sb strings.Builder
	const (
		plain = iota
		double
		single
		comment
	)
	state := plain
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch state {
		case plain:
			switch {
			case c == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t' || text[i-1] == '\n'):
				state = comment
			case (c == '"' || c == '\'') && (i == 0 || strings.IndexByte(" \t\n[{,", text[i-1]) >= 0):
				state = single
				if c == '"' {
					state = double
				}
			}
			sb.WriteByte(c)
		case comment:
			if c == '\n' {
				state = plain
			}
			sb.WriteByte(c)
		case single:
			sb.WriteByte(c)
			if c == '\'' {
				if i+1 < len(text) && text[i+1] == '\'' { // '' is an escaped quote
					sb.WriteByte('\'')
					i++
				} else {
					state = plain
				}
			}
		case double:
			switch c {
			case '\\':
				if i+1 < len(text) && text[i+1] == '/' {
					sb.WriteByte('/')
				} else if i+1 < len(text) {
					sb.WriteByte(c)
					sb.WriteByte(text[i+1]) // an escaped character (including a backslash) is consumed as a pair
				} else {
					sb.WriteByte(c)
				}
				i++
			case '"':
				sb.WriteByte(c)
				state = plain
			default:
				sb.WriteByte(c)
			}
		}
	}
	return sb.String()
}

func ydSyntax(err error) error {
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	line := 1
	if m := reYdLine.FindStringSubmatch(msg); m != nil {
		line, _ = strconv.Atoi(m[1])
	}
	return ydFail(msg, line, 1)
}

const ydMaxDepth = 10000

func ydConvert(n *yaml.Node, strict bool, lines [][]rune, depth int) (*ydNode, error) {
	if depth > ydMaxDepth {
		return nil, ydFail("exceeded max depth", n.Line, n.Column)
	}
	if n.Kind == yaml.AliasNode {
		return nil, ydFail("Alias resolution is disabled", n.Line, n.Column)
	}
	explicit := n.Style&yaml.TaggedStyle != 0
	if explicit {
		if n.Tag != "!!str" && n.Tag != "!!map" && n.Tag != "!!seq" {
			return nil, ydFail("Unresolved or unsupported tag: "+n.Tag, n.Line, n.Column)
		}
	} else if n.Kind == yaml.ScalarNode && ydSourceChar(lines, n.Line, n.Column) == '!' { // a non-specific tag (!) is not kept in the node
		return nil, ydFail("Unresolved or unsupported tag: !", n.Line, n.Column)
	}
	out := &ydNode{line: n.Line, col: n.Column}
	switch n.Kind {
	case yaml.ScalarNode:
		out.kind = "scalar"
		plain := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0 && !explicit
		if plain {
			out.value = yamlResolveCorePlain(n.Value)
		} else {
			out.value = n.Value
		}
	case yaml.SequenceNode:
		out.kind = "seq"
		for _, c := range n.Content {
			x, err := ydConvert(c, strict, lines, depth+1)
			if err != nil {
				return nil, err
			}
			out.items = append(out.items, x)
		}
	case yaml.MappingNode:
		out.kind = "map"
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := ydConvert(n.Content[i], strict, lines, depth+1)
			if err != nil {
				return nil, err
			}
			v, err := ydConvert(n.Content[i+1], strict, lines, depth+1)
			if err != nil {
				return nil, err
			}
			if strict {
				if k.kind != "scalar" {
					return nil, ydFail("complex mapping keys are not accepted", k.line, k.col)
				}
				s := yamlKeyString(k.value)
				if seen[s] {
					return nil, ydFail("Map keys must be unique", k.line, k.col)
				}
				seen[s] = true
			}
			out.items = append(out.items, k, v)
		}
	default:
		return nil, ydFail("unexpected parser node", n.Line, n.Column)
	}
	return out, nil
}

// ---- JSON -------------------------------------------------------------------------------------------------------------

type ydJSON struct {
	s    string
	i    int
	line int
	col  int
}

func (p *ydJSON) fail(msg string) error {
	return ydFail(msg+" in JSON at position "+strconv.Itoa(p.i), 1, 1)
}

func (p *ydJSON) next() { // advance one rune, keeping the position
	_, w := utf8.DecodeRuneInString(p.s[p.i:])
	switch {
	case p.s[p.i] == '\n', p.s[p.i] == '\r' && !(p.i+1 < len(p.s) && p.s[p.i+1] == '\n'):
		p.line++
		p.col = 1
	case p.s[p.i] == '\r':
		p.col++
	default:
		p.col++
	}
	p.i += w
}

func (p *ydJSON) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.next()
		default:
			return
		}
	}
}

func (p *ydJSON) str() (string, error) {
	p.next() // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.fail("Unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.next()
			return sb.String(), nil
		case c < 0x20:
			return "", p.fail("Bad control character in string literal")
		case c == '\\':
			p.next()
			if p.i >= len(p.s) {
				return "", p.fail("Unterminated string")
			}
			e := p.s[p.i]
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, ok := hex4(p.s[p.i+1:])
				if !ok {
					return "", p.fail("Bad Unicode escape")
				}
				for k := 0; k < 4; k++ {
					p.next()
				}
				switch {
				case r >= 0xD800 && r <= 0xDBFF && strings.HasPrefix(p.s[p.i+1:], `\u`):
					lo, ok2 := hex4(p.s[p.i+3:])
					if ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
						sb.WriteRune(0x10000 + (r-0xD800)<<10 + (lo - 0xDC00))
						for k := 0; k < 7; k++ { // \uXXXX of the low half and the digit the escape ends on
							p.next()
						}
						continue
					}
					writeWTF8(&sb, r)
				case r >= 0xD800 && r <= 0xDFFF:
					writeWTF8(&sb, r)
				default:
					sb.WriteRune(r)
				}
			default:
				return "", p.fail("Bad escaped character")
			}
			p.next()
		default:
			_, w := utf8.DecodeRuneInString(p.s[p.i:])
			sb.WriteString(p.s[p.i : p.i+w])
			p.next()
		}
	}
}

func (p *ydJSON) number() (*ydNode, error) {
	n := &ydNode{kind: "scalar", line: p.line, col: p.col}
	start := p.i
	digits := func() int {
		c := 0
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.next()
			c++
		}
		return c
	}
	if p.s[p.i] == '-' {
		p.next()
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.next()
	} else if digits() == 0 {
		return nil, p.fail("No number after minus sign")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.next()
		if digits() == 0 {
			return nil, p.fail("Unterminated fractional number")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.next()
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.next()
		}
		if digits() == 0 {
			return nil, p.fail("Exponent part is missing a number")
		}
	}
	n.value = json.Number(p.s[start:p.i])
	return n, nil
}

func (p *ydJSON) value(depth int) (*ydNode, error) {
	if depth > ydMaxDepth {
		return nil, p.fail("Nesting too deep")
	}
	p.ws()
	if p.i >= len(p.s) {
		return nil, p.fail("Unexpected end of JSON input")
	}
	line, col := p.line, p.col
	switch c := p.s[p.i]; {
	case c == '{':
		out := &ydNode{kind: "map", line: line, col: col}
		p.next()
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.next()
			return out, nil
		}
		for {
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return nil, p.fail("Expected double-quoted property name")
			}
			kl, kc := p.line, p.col
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, p.fail("Expected ':' after property name")
			}
			p.next()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out.items = append(out.items, &ydNode{kind: "scalar", value: k, line: kl, col: kc}, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.next()
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.next()
				return out, nil
			}
			return nil, p.fail("Expected ',' or '}' after property value")
		}
	case c == '[':
		out := &ydNode{kind: "seq", line: line, col: col}
		p.next()
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.next()
			return out, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out.items = append(out.items, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.next()
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.next()
				return out, nil
			}
			return nil, p.fail("Expected ',' or ']' after array element")
		}
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &ydNode{kind: "scalar", value: s, line: line, col: col}, nil
	case c == '-' || isDigit(c):
		return p.number()
	case strings.HasPrefix(p.s[p.i:], "true"):
		for k := 0; k < 4; k++ {
			p.next()
		}
		return &ydNode{kind: "scalar", value: true, line: line, col: col}, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		for k := 0; k < 5; k++ {
			p.next()
		}
		return &ydNode{kind: "scalar", value: false, line: line, col: col}, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		for k := 0; k < 4; k++ {
			p.next()
		}
		return &ydNode{kind: "scalar", value: nil, line: line, col: col}, nil
	}
	return nil, p.fail("Unexpected token")
}

// yamlParseJSON reads JSON text (JSON.parse grammar) into the same node tree.
func yamlParseJSON(text string) (*ydNode, error) {
	if !utf8.ValidString(text) {
		return nil, ydFail("invalid UTF-8", 1, 1)
	}
	p := &ydJSON{s: text, line: 1, col: 1}
	n, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i < len(p.s) {
		return nil, p.fail("Unexpected non-whitespace character after JSON")
	}
	return n, nil
}

// ---- values and positions ---------------------------------------------------------------------------------------------

// yamlToValue is the plain value of a node tree: maps are map[string]any in member order (a repeated key keeps its first place and
// its last value), sequences []any.
func yamlToValue(n *ydNode) (any, error) {
	if n == nil {
		return nil, nil
	}
	switch n.kind {
	case "scalar":
		return n.value, nil
	case "seq":
		out := make([]any, 0, len(n.items))
		for _, x := range n.items {
			v, err := yamlToValue(x)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	out := make(map[string]any, len(n.items)/2)
	var keys []string
	for i := 0; i+1 < len(n.items); i += 2 {
		k := n.items[i]
		if k.kind != "scalar" {
			return nil, ydFail("complex mapping keys are not accepted", k.line, k.col)
		}
		v, err := yamlToValue(n.items[i+1])
		if err != nil {
			return nil, err
		}
		ks := yamlKeyString(k.value)
		if _, dup := out[ks]; !dup {
			keys = append(keys, ks)
		}
		out[ks] = v
	}
	recordKeyOrder(out, keys)
	return out, nil
}

// yamlPos is the position of one authoring entry and of the keys of its params.
type yamlPos struct {
	line, col int
	params    map[string][2]int
}

// yamlPositionsOf: per-entry positions of an authoring document (`actions` items and their `params` keys), by entry index;
// nil when the root is not a mapping.
func yamlPositionsOf(root *ydNode) []yamlPos {
	if root == nil || root.kind != "map" {
		return nil
	}
	lastMember := func(m *ydNode, name string) *ydNode {
		var found *ydNode
		for i := 0; i+1 < len(m.items); i += 2 {
			if k := m.items[i]; k.kind == "scalar" {
				if s, ok := k.value.(string); ok && s == name {
					found = m.items[i+1]
				}
			}
		}
		return found
	}
	items := []*ydNode{root}
	if actions := lastMember(root, "actions"); actions != nil && actions.kind == "seq" {
		items = actions.items
	}
	out := make([]yamlPos, 0, len(items))
	for _, it := range items {
		p := yamlPos{line: it.line, col: it.col, params: map[string][2]int{}}
		if it.kind == "map" {
			if pm := lastMember(it, "params"); pm != nil && pm.kind == "map" {
				for i := 0; i+1 < len(pm.items); i += 2 {
					if k := pm.items[i]; k.kind == "scalar" {
						name := ""
						if k.value != nil {
							name = yamlKeyString(k.value)
						}
						p.params[name] = [2]int{k.line, k.col}
					}
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// yamlAttachPositions adds locs and the line / column of every error to a load result.
func yamlAttachPositions(res map[string]any, pos []yamlPos) {
	errs, _ := res["errors"].([]any)
	failed := map[int]bool{}
	for _, e := range errs {
		if idx, ok := e.(map[string]any)["index"].(int); ok {
			failed[idx] = true
		}
	}
	var order []int
	for i := range pos {
		if !failed[i] {
			order = append(order, i)
		}
	}
	locs, _ := res["locs"].(map[string]any)
	defs, _ := res["defs"].([]any)
	for k, d := range defs {
		if k >= len(order) {
			break
		}
		p := pos[order[k]]
		params := map[string]any{}
		for name, lc := range p.params {
			params[name] = map[string]any{"line": lc[0], "column": lc[1]}
		}
		verb, _ := d.(map[string]any)["verb"].(string)
		locs[verb] = map[string]any{"line": p.line, "column": p.col, "params": params}
	}
	for _, e := range errs {
		em := e.(map[string]any)
		idx, has := em["index"].(int)
		switch {
		case has && idx >= 0 && idx < len(pos):
			em["line"], em["column"] = pos[idx].line, pos[idx].col
		case !has:
			em["line"], em["column"] = 1, 1
		}
	}
}
