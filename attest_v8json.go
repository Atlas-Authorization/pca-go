package pca

// The wording of the reference's JSON.parse failures. The token verifiers embed the engine's message for a malformed header
// or payload segment into the reason they return (`malformed JSON segment: <message>`), so a native verifier that answers
// the same reason text reproduces it: v8JSONError validates a document with the grammar of JSON.parse and, when it is not
// valid, returns the message V8 reports for it. It returns "" for a valid document. Only the reason text depends on this;
// whether a segment parses never does.

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

type v8JSON struct {
	src []uint16
	pos int
	err string
}

func v8JSONError(text string) string {
	p := &v8JSON{src: utf16.Encode([]rune(strings.ToValidUTF8(text, "�")))}
	p.value()
	if p.err != "" {
		return p.err
	}
	p.ws()
	if p.pos < len(p.src) {
		p.fail("Unexpected non-whitespace character after JSON at position %d (line %d column %d)", p.pos)
	}
	return p.err
}

func (p *v8JSON) location(pos int) (int, int) {
	line, last := 1, -1
	for i := 0; i < pos && i < len(p.src); i++ {
		c := p.src[i]
		if c == '\n' || (c == '\r' && !(i+1 < len(p.src) && p.src[i+1] == '\n')) {
			line++
			last = i
		}
	}
	return line, pos - last
}

// fail records the message; its format takes position, line and column.
func (p *v8JSON) fail(format string, pos int) {
	if p.err != "" {
		return
	}
	line, col := p.location(pos)
	p.err = fmt.Sprintf(format, pos, line, col)
}

func (p *v8JSON) failExpected(what string, pos int) {
	p.fail(what+" in JSON at position %d (line %d column %d)", pos)
}

func (p *v8JSON) unexpectedEnd() {
	if p.err == "" {
		p.err = "Unexpected end of JSON input"
	}
}

func (p *v8JSON) unexpectedToken(pos int) {
	if p.err != "" {
		return
	}
	whole := string(utf16.Decode(p.src))
	switch whole {
	case "NaN", "Infinity", "undefined", "[object Object]":
		p.err = fmt.Sprintf("%q is not valid JSON", whole)
		return
	}
	const ctx = 10
	tok := string(utf16.Decode(p.src[pos : pos+1]))
	n := len(p.src)
	sub := func(a, b int) string { return string(utf16.Decode(p.src[a:b])) }
	switch {
	case n < ctx*2+1:
		p.err = fmt.Sprintf("Unexpected token '%s', \"%s\" is not valid JSON", tok, whole)
	case pos < ctx:
		p.err = fmt.Sprintf("Unexpected token '%s', \"%s\"... is not valid JSON", tok, sub(0, pos+ctx))
	case pos < n-ctx:
		p.err = fmt.Sprintf("Unexpected token '%s', ...\"%s\"... is not valid JSON", tok, sub(pos-ctx, pos+ctx))
	default:
		p.err = fmt.Sprintf("Unexpected token '%s', ...\"%s\" is not valid JSON", tok, sub(pos-ctx, n))
	}
}

func (p *v8JSON) ws() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *v8JSON) peek() int {
	if p.pos >= len(p.src) {
		return -1
	}
	return int(p.src[p.pos])
}

func (p *v8JSON) value() {
	p.ws()
	if p.err != "" {
		return
	}
	switch c := p.peek(); {
	case c < 0:
		p.unexpectedEnd()
	case c == '"':
		p.str()
	case c == '{':
		p.object()
	case c == '[':
		p.array()
	case c == '-' || (c >= '0' && c <= '9'):
		p.number()
	case c == 't':
		p.literal("true")
	case c == 'f':
		p.literal("false")
	case c == 'n':
		p.literal("null")
	default:
		p.unexpectedToken(p.pos)
	}
}

func (p *v8JSON) literal(word string) {
	for i := 0; i < len(word); i++ {
		if p.pos >= len(p.src) {
			p.unexpectedEnd()
			return
		}
		if p.src[p.pos] != uint16(word[i]) {
			p.unexpectedToken(p.pos)
			return
		}
		p.pos++
	}
}

func isDigit16(c int) bool { return c >= '0' && c <= '9' }

func (p *v8JSON) number() {
	if p.peek() == '-' {
		p.pos++
		if !isDigit16(p.peek()) {
			p.failExpected("No number after minus sign", p.pos)
			return
		}
	}
	if p.peek() == '0' {
		p.pos++
		if isDigit16(p.peek()) {
			p.fail("Unexpected number in JSON at position %d (line %d column %d)", p.pos)
			return
		}
	} else {
		for isDigit16(p.peek()) {
			p.pos++
		}
	}
	if p.peek() == '.' {
		p.pos++
		if !isDigit16(p.peek()) {
			p.failExpected("Unterminated fractional number", p.pos)
			return
		}
		for isDigit16(p.peek()) {
			p.pos++
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.pos++
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if !isDigit16(p.peek()) {
			p.failExpected("Exponent part is missing a number", p.pos)
			return
		}
		for isDigit16(p.peek()) {
			p.pos++
		}
	}
}

func (p *v8JSON) str() {
	p.pos++ // opening quote
	for {
		c := p.peek()
		switch {
		case c < 0:
			p.failExpected("Unterminated string", p.pos)
			return
		case c == '"':
			p.pos++
			return
		case c < 0x20:
			p.failExpected("Bad control character in string literal", p.pos)
			return
		case c == '\\':
			p.pos++
			e := p.peek()
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.pos++
			case 'u':
				p.pos++
				for i := 0; i < 4; i++ {
					h := p.peek()
					if !(isDigit16(h) || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')) {
						p.failExpected("Bad Unicode escape", p.pos)
						return
					}
					p.pos++
				}
			case -1:
				p.failExpected("Unterminated string", p.pos)
				return
			default:
				p.failExpected("Bad escaped character", p.pos)
				return
			}
		default:
			p.pos++
		}
	}
}

func (p *v8JSON) object() {
	p.pos++ // {
	p.ws()
	if p.peek() == '}' {
		p.pos++
		return
	}
	if p.peek() != '"' {
		p.failExpected("Expected property name or '}'", p.pos)
		return
	}
	for {
		p.str()
		if p.err != "" {
			return
		}
		p.ws()
		if p.peek() != ':' {
			p.failExpected("Expected ':' after property name", p.pos)
			return
		}
		p.pos++
		p.value()
		if p.err != "" {
			return
		}
		p.ws()
		switch p.peek() {
		case ',':
			p.pos++
			p.ws()
			if p.peek() != '"' {
				p.failExpected("Expected double-quoted property name", p.pos)
				return
			}
		case '}':
			p.pos++
			return
		default:
			p.failExpected("Expected ',' or '}' after property value", p.pos)
			return
		}
	}
}

func (p *v8JSON) array() {
	p.pos++ // [
	p.ws()
	if p.peek() == ']' {
		p.pos++
		return
	}
	for {
		p.value()
		if p.err != "" {
			return
		}
		p.ws()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return
		default:
			p.failExpected("Expected ',' or ']' after array element", p.pos)
			return
		}
	}
}
