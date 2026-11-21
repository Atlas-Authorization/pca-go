package pca

// AP2 JSON plumbing: a JSON.parse-faithful parser that records member order and the first duplicate key, JSON.stringify with the
// order a JavaScript object would have (array-index keys first, then insertion order), an insertion-ordered builder, and the
// "undefined" marker. Claims are JSON values (map[string]any, []any, string, bool, nil, json.Number); a member that is absent reads as
// ap2U, which is neither null nor a value.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// Ap2Error is every failure raised while parsing or verifying an AP2 credential; Msg is the human-readable reason.
type Ap2Error struct{ Msg string }

func (e *Ap2Error) Error() string { return e.Msg }

func ap2Fail(format string, a ...any) error { return &Ap2Error{Msg: fmt.Sprintf(format, a...)} }

type ap2Undef struct{}

// ap2U is the value of an absent member (JavaScript undefined).
var ap2U any = ap2Undef{}

func ap2IsU(v any) bool { _, ok := v.(ap2Undef); return ok }

// ap2Get is `v.k` (ap2U when v is not an object or the member is absent).
func ap2Get(v any, k string) any {
	if m, ok := v.(map[string]any); ok {
		if x, has := m[k]; has {
			return x
		}
	}
	return ap2U
}

func ap2Has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// ap2Obj is isObject: a non-null, non-array object.
func ap2Obj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func ap2Truthy(v any) bool {
	if ap2IsU(v) {
		return false
	}
	return jsTruthy(v)
}

func ap2StrictEq(a, b any) bool {
	au, bu := ap2IsU(a), ap2IsU(b)
	if au || bu {
		return au && bu
	}
	return jsStrictEq(a, b)
}

// ap2Str is String(v).
func ap2Str(v any) string {
	if ap2IsU(v) {
		return "undefined"
	}
	return jsValueString(v)
}

// ap2JSON is JSON.stringify(v) as it prints inside a template literal ("undefined" for undefined).
func ap2JSON(v any) string {
	if ap2IsU(v) {
		return "undefined"
	}
	s, err := ap2Stringify(v)
	if err != nil {
		return "null"
	}
	return s
}

func ap2IsStr(v any) bool { _, ok := v.(string); return ok }

func ap2IsNonEmptyStr(v any) bool { s, ok := v.(string); return ok && len(s) > 0 }

// ap2Alpha3 is /^[A-Z]{3}$/.
func ap2Alpha3(s string) bool {
	if len(s) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// ---- ordered builder ---------------------------------------------------------------------------------------------------

// ap2B builds an object in insertion order; an undefined value is not stored (JSON never carries it).
type ap2B struct {
	m    map[string]any
	keys []string
}

func ap2New() *ap2B { return &ap2B{m: map[string]any{}} }

func (b *ap2B) set(k string, v any) *ap2B {
	if ap2IsU(v) {
		return b
	}
	if _, ok := b.m[k]; !ok {
		b.keys = append(b.keys, k)
	}
	b.m[k] = v
	return b
}

// spread is `{...src}`: the members in Object.keys order.
func (b *ap2B) spread(src map[string]any) *ap2B {
	for _, k := range jsKeys(src) {
		b.set(k, src[k])
	}
	return b
}

func (b *ap2B) done() map[string]any {
	recordKeyOrder(b.m, b.keys)
	return b.m
}

func ap2Map(kv ...any) map[string]any {
	b := ap2New()
	for i := 0; i+1 < len(kv); i += 2 {
		b.set(kv[i].(string), kv[i+1])
	}
	return b.done()
}

// ap2Num is the JSON value of a computed number.
func ap2Num(f float64) any { return jsNumber(f) }

// ---- JSON.stringify ----------------------------------------------------------------------------------------------------

func ap2Stringify(v any) (string, error) {
	var sb strings.Builder
	if err := ap2Write(&sb, v, false); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ap2StringifySorted is JSON.stringify with every object's members sorted by UTF-16 code units (two values print alike iff they
// are deeply equal).
func ap2StringifySorted(v any) string {
	var sb strings.Builder
	if err := ap2Write(&sb, v, true); err != nil {
		return "\x00unserializable"
	}
	return sb.String()
}

func ap2Write(sb *strings.Builder, v any, sorted bool) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case ap2Undef:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		lenientString(sb, t)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ap2Write(sb, x, sorted); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		var keys []string
		if sorted {
			keys = make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return compareUnits(utf16Units(keys[i]), utf16Units(keys[j])) < 0 })
		} else {
			keys = jsKeys(t)
		}
		sb.WriteByte('{')
		first := true
		for _, k := range keys {
			x := t[k]
			if ap2IsU(x) {
				continue
			}
			if !first {
				sb.WriteByte(',')
			}
			first = false
			lenientString(sb, k)
			sb.WriteByte(':')
			if err := ap2Write(sb, x, sorted); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		if f, ok := jsNum(v); ok {
			if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
				sb.WriteString("null")
			} else {
				sb.WriteString(jsLenientNumber(f))
			}
			return nil
		}
		// typed slices / structs a builder produced: round-trip through encoding/json
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		x, _, _, err := ap2ParseText(string(b))
		if err != nil {
			return err
		}
		return ap2Write(sb, x, sorted)
	}
	return nil
}

// ---- JSON.parse --------------------------------------------------------------------------------------------------------

type ap2JP struct {
	s      string
	i      int
	dup    string
	hasDup bool
}

var errAp2Eof = fmt.Errorf("Unexpected end of JSON input")

func (p *ap2JP) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *ap2JP) bad() error { return fmt.Errorf("Unexpected token in JSON at position %d", p.i) }

// ap2ParseText is JSON.parse (standard JSON only; a lone surrogate escape is kept as WTF-8). dup names the first object member that
// repeated an earlier one in the same object (the last value is kept, as JSON.parse does).
func ap2ParseText(text string) (v any, dup string, hasDup bool, err error) {
	p := &ap2JP{s: text}
	v, err = p.value(0)
	if err != nil {
		return nil, "", false, err
	}
	p.ws()
	if p.i < len(p.s) {
		return nil, "", false, p.bad()
	}
	return v, p.dup, p.hasDup, nil
}

func (p *ap2JP) value(depth int) (any, error) {
	if depth > 1<<16 {
		return nil, fmt.Errorf("JSON nesting too deep")
	}
	p.ws()
	if p.i >= len(p.s) {
		return nil, errAp2Eof
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.i++
		o := map[string]any{}
		var keys []string
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		for {
			p.ws()
			if p.i >= len(p.s) {
				return nil, errAp2Eof
			}
			if p.s[p.i] != '"' {
				return nil, p.bad()
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			p.ws()
			if p.i >= len(p.s) {
				return nil, errAp2Eof
			}
			if p.s[p.i] != ':' {
				return nil, p.bad()
			}
			p.i++
			x, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, has := o[k]; has {
				if !p.hasDup {
					p.dup, p.hasDup = k, true
				}
			} else {
				keys = append(keys, k)
			}
			o[k] = x
			p.ws()
			if p.i >= len(p.s) {
				return nil, errAp2Eof
			}
			if p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.s[p.i] == '}' {
				p.i++
				recordKeyOrder(o, keys)
				return o, nil
			}
			return nil, p.bad()
		}
	case c == '[':
		p.i++
		a := []any{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		for {
			x, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, x)
			p.ws()
			if p.i >= len(p.s) {
				return nil, errAp2Eof
			}
			if p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.s[p.i] == ']' {
				p.i++
				return a, nil
			}
			return nil, p.bad()
		}
	case c == '"':
		return p.str()
	case c == '-' || isDigit(c):
		return p.num()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	}
	return nil, p.bad()
}

func (p *ap2JP) num() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
		return nil, p.bad()
	}
	if p.s[p.i] == '0' {
		p.i++
	} else {
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, p.bad()
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, p.bad()
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	return json.Number(p.s[start:p.i]), nil
}

func (p *ap2JP) str() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", errAp2Eof
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", p.bad()
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", errAp2Eof
			}
			switch e := p.s[p.i]; e {
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
					return "", p.bad()
				}
				p.i += 4
				switch {
				case r >= 0xD800 && r <= 0xDBFF:
					if strings.HasPrefix(p.s[p.i+1:], `\u`) {
						if lo, ok2 := hex4(p.s[p.i+3:]); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
							sb.WriteRune(0x10000 + (r-0xD800)<<10 + (lo - 0xDC00))
							p.i += 6
							break
						}
					}
					writeWTF8(&sb, r)
				case r >= 0xDC00 && r <= 0xDFFF:
					writeWTF8(&sb, r)
				default:
					sb.WriteRune(r)
				}
			default:
				return "", p.bad()
			}
			p.i++
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
}

// ap2ParseJson is the reference parseJson: JSON.parse that also refuses an object repeating a key (JSON.parse would silently keep the
// last one, letting two parties read different claims out of the same signed bytes).
func ap2ParseJson(text, what string) (any, error) {
	v, dup, hasDup, err := ap2ParseText(text)
	if err != nil {
		return nil, ap2Fail("%s: invalid JSON (%s)", what, err.Error())
	}
	if hasDup {
		var sb strings.Builder
		lenientString(&sb, dup)
		return nil, ap2Fail("%s: duplicate key %s", what, sb.String())
	}
	return v, nil
}

// ---- base64url / UTF-8 -------------------------------------------------------------------------------------------------

// ap2WellFormed is what Buffer.from(s, "utf8") encodes: a lone surrogate (WTF-8 in a Go string) becomes U+FFFD.
func ap2WellFormed(s string) string {
	if !hasLoneSurrogate(s) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			sb.WriteString("�")
			i += 2
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func ap2B64uEnc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Ap2B64uEncode is base64url of the UTF-8 text.
func Ap2B64uEncode(s string) string { return ap2B64uEnc([]byte(ap2WellFormed(s))) }

// Ap2B64uDecode is a strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip.
func Ap2B64uDecode(s, what string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return nil, ap2Fail("%s: not base64url", what)
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ap2Fail("%s: non-canonical base64url", what)
	}
	return b, nil
}

// ap2Utf8Text is the fatal UTF-8 decode (the BOM is kept, so JSON.parse refuses it).
func ap2Utf8Text(b []byte, what string) (string, error) {
	if !utf8.Valid(b) {
		return "", ap2Fail("%s: not valid UTF-8", what)
	}
	return string(b), nil
}

func ap2DecodeJSONSegment(segment, what string) (map[string]any, error) {
	raw, err := Ap2B64uDecode(segment, what)
	if err != nil {
		return nil, err
	}
	text, err := ap2Utf8Text(raw, what)
	if err != nil {
		return nil, err
	}
	v, err := ap2ParseJson(text, what)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ap2Fail("%s: must be a JSON object", what)
	}
	return m, nil
}

// ap2N is Number(v) (NaN for undefined): the operand of a relational comparison.
func ap2N(v any) float64 {
	if ap2IsU(v) {
		return math.NaN()
	}
	return jsToNumber(v)
}

// Ap2ParseJson is JSON.parse that also refuses an object repeating a key (JSON.parse would silently keep the last one, letting two
// parties read different claims out of the same signed bytes). Numbers stay as their written lexeme (json.Number); 1000.0 is accepted.
func Ap2ParseJson(text, what string) (any, error) { return ap2ParseJson(text, what) }
