package pca

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Strict JSON profile (PCActn wire v2). Hand-written RFC 8259 parser; NOT encoding/json.
const (
	MaxJSONChars     = 1 << 20
	MaxJSONDepth     = 32
	MaxDecimalDigits = 15
	maxSafeInt       = 9007199254740991
)

// StrictParse parses signed bytes under the strict profile. Numbers are returned as json.Number
// holding the (already validated, canonical) lexeme; objects as map[string]any; arrays as []any.
func StrictParse(text string) (any, error) { return parseJSON(text, true) }

// ParseJSONLenient is for loading trusted fixture files only (no size/depth/number limits; lone
// surrogate escapes are kept as WTF-8 so that the verifier can detect them). Never use on untrusted input.
func ParseJSONLenient(data []byte) (any, error) { return parseJSON(string(data), false) }

// ParseJSON strictly parses a JSON object (kept for API compatibility).
func ParseJSON(data []byte) (map[string]any, error) {
	v, err := StrictParse(string(data))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("strict JSON: top level is not an object")
	}
	return m, nil
}

type jparser struct {
	s      string
	i      int
	strict bool
}

func (p *jparser) err(m string) error { return fmt.Errorf("strict JSON: %s (at offset %d)", m, p.i) }

func parseJSON(text string, strict bool) (any, error) {
	if strict {
		if !utf8.ValidString(text) {
			return nil, fmt.Errorf("strict JSON: invalid UTF-8")
		}
		if len(text) > MaxJSONChars {
			return nil, fmt.Errorf("strict JSON: input too large")
		}
	}
	p := &jparser{s: text, strict: strict}
	v, err := p.value(1)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i < len(p.s) {
		return nil, p.err("trailing characters after the JSON value")
	}
	return v, nil
}

func (p *jparser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func hex4(s string) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var r rune
	for k := 0; k < 4; k++ {
		c := s[k]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(d)
	}
	return r, true
}

func (p *jparser) str() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.err("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20 && p.strict:
			return "", p.err("raw control character in string")
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", p.err("unterminated string")
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
					return "", p.err("bad \\u escape")
				}
				p.i += 4
				if r >= 0xD800 && r <= 0xDBFF {
					// high surrogate: needs an immediately following low-surrogate escape
					if strings.HasPrefix(p.s[p.i+1:], `\u`) {
						if lo, ok2 := hex4(p.s[p.i+3:]); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
							sb.WriteRune(0x10000 + (r-0xD800)<<10 + (lo - 0xDC00))
							p.i += 6
							break
						}
					}
					if p.strict {
						return "", p.err("lone surrogate in string")
					}
					writeWTF8(&sb, r)
				} else if r >= 0xDC00 && r <= 0xDFFF {
					if p.strict {
						return "", p.err("lone surrogate in string")
					}
					writeWTF8(&sb, r)
				} else {
					sb.WriteRune(r)
				}
			default:
				if p.strict {
					return "", p.err("unknown escape")
				}
				sb.WriteByte(e)
			}
			p.i++
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
}

func writeWTF8(sb *strings.Builder, r rune) {
	sb.WriteByte(0xE0 | byte(r>>12))
	sb.WriteByte(0x80 | byte((r>>6)&0x3f))
	sb.WriteByte(0x80 | byte(r&0x3f))
}

// hasLoneSurrogate detects WTF-8 encoded surrogate code points (ED A0..BF xx), which valid UTF-8 never contains.
func hasLoneSurrogate(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 {
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *jparser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
		return nil, p.err("bad number")
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
			return nil, p.err("bad number")
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
			return nil, p.err("bad number")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	lex := p.s[start:p.i]
	if p.strict {
		if e := numberLexemeError(lex); e != "" {
			return nil, p.err(e)
		}
	}
	return json.Number(lex), nil
}

// numberLexemeError returns "" when lex is in the canonical wire-number form.
func numberLexemeError(lex string) string {
	if strings.ContainsAny(lex, "eE") {
		return "exponent form is not allowed (use a plain decimal)"
	}
	if lex == "-0" {
		return "negative zero is not allowed"
	}
	if strings.Contains(lex, ".") {
		if strings.HasSuffix(lex, "0") {
			return "trailing fractional zero is not canonical"
		}
		digits := strings.TrimLeft(strings.ReplaceAll(strings.ReplaceAll(lex, "-", ""), ".", ""), "0")
		if len(digits) > MaxDecimalDigits {
			return "more than 15 significant digits"
		}
		f, err := strconv.ParseFloat(lex, 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return "non-finite number"
		}
		if f != 0 && math.Abs(f) < 1e-6 {
			return "non-integer magnitude below 1e-6 is not allowed"
		}
		return ""
	}
	abs := strings.TrimPrefix(lex, "-")
	if abs == "" || len(abs) > 16 {
		return "integer outside the safe range"
	}
	n, err := strconv.ParseInt(abs, 10, 64)
	if err != nil || n > maxSafeInt {
		return "integer outside the safe range"
	}
	return ""
}

func (p *jparser) value(depth int) (any, error) {
	p.ws()
	if p.i >= len(p.s) {
		return nil, p.err("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		if p.strict && depth > MaxJSONDepth {
			return nil, p.err("nesting too deep")
		}
		p.i++
		o := map[string]any{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		for {
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return nil, p.err("expected a string key")
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			if _, dup := o[k]; dup {
				return nil, p.err("duplicate key")
			}
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, p.err(`expected ":"`)
			}
			p.i++
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			o[k] = v
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return o, nil
			}
			return nil, p.err(`expected "," or "}"`)
		}
	case c == '[':
		if p.strict && depth > MaxJSONDepth {
			return nil, p.err("nesting too deep")
		}
		p.i++
		a := []any{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return a, nil
			}
			return nil, p.err(`expected "," or "]"`)
		}
	case c == '"':
		return p.str()
	case c == '-' || isDigit(c):
		return p.number()
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
	return nil, p.err("unexpected token")
}
