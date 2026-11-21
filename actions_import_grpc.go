package pca

// The gRPC importer: protobuf services to unreviewed defs, from `.proto` text or a binary FileDescriptorSet (`.binpb`).
// `service.method` becomes the verb; `google.api.http` gives method and path; `idempotency_level` gives read / idempotent; field
// behavior (REQUIRED, OUTPUT_ONLY) refines params; streaming methods get `pca.bulk`. Offline, bounded, no code generation: the
// `.proto` lexer and parser and the descriptor reader are written out here.

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ---- model ---------------------------------------------------------------------------------------------------------------

type aimPField struct {
	name, typ, scope string
	repeated         bool
	optional         bool
	hasMap           bool
	mapK, mapV       string
	behavior         []string
}

type aimPMsg struct {
	full     string
	fields   []aimPField
	mapEntry bool
}

type aimPEnum struct {
	full   string
	values []string
}

type aimPHTTP struct {
	method, path, body string
	hasBody            bool
}

type aimPMethod struct {
	name, input, output string
	cs, ss              bool
	http                *aimPHTTP
	idem                string
	hasIdem             bool
	scope               string
}

type aimPService struct {
	full, name string
	methods    []aimPMethod
}

// aimProtoModel keeps messages and enums in insertion order (the reference's Maps).
type aimProtoModel struct {
	msgOrder, enumOrder []string
	messages            map[string]*aimPMsg
	enums               map[string]*aimPEnum
	services            []aimPService
}

func newAimProtoModel() *aimProtoModel {
	return &aimProtoModel{messages: map[string]*aimPMsg{}, enums: map[string]*aimPEnum{}}
}

func (m *aimProtoModel) setMsg(msg *aimPMsg) {
	if _, has := m.messages[msg.full]; !has {
		m.msgOrder = append(m.msgOrder, msg.full)
	}
	m.messages[msg.full] = msg
}

func (m *aimProtoModel) setEnum(e *aimPEnum) {
	if _, has := m.enums[e.full]; !has {
		m.enumOrder = append(m.enumOrder, e.full)
	}
	m.enums[e.full] = e
}

// toJSON is the model as the reference oracle prints it: {messages: [[full, msg]...], enums: [[full, values]...], services}.
func (m *aimProtoModel) toJSON() map[string]any {
	msgs := make([]any, 0, len(m.msgOrder))
	for _, n := range m.msgOrder {
		msg := m.messages[n]
		fields := make([]any, 0, len(msg.fields))
		for _, f := range msg.fields {
			fm := map[string]any{"name": f.name, "type": f.typ, "scope": f.scope, "repeated": f.repeated, "optional": f.optional, "behavior": aimStrAny(f.behavior)}
			if f.hasMap {
				fm["map"] = []any{f.mapK, f.mapV}
			}
			fields = append(fields, fm)
		}
		msgs = append(msgs, []any{n, map[string]any{"full": msg.full, "fields": fields, "mapEntry": msg.mapEntry}})
	}
	enums := make([]any, 0, len(m.enumOrder))
	for _, n := range m.enumOrder {
		enums = append(enums, []any{n, aimStrAny(m.enums[n].values)})
	}
	svcs := make([]any, 0, len(m.services))
	for _, s := range m.services {
		methods := make([]any, 0, len(s.methods))
		for _, me := range s.methods {
			mm := map[string]any{"name": me.name, "input": me.input, "output": me.output, "cs": me.cs, "ss": me.ss, "scope": me.scope}
			if me.http != nil {
				h := map[string]any{"method": me.http.method, "path": me.http.path}
				if me.http.hasBody {
					h["body"] = me.http.body
				}
				mm["http"] = h
			}
			if me.hasIdem {
				mm["idem"] = me.idem
			}
			methods = append(methods, mm)
		}
		svcs = append(svcs, map[string]any{"full": s.full, "name": s.name, "methods": methods})
	}
	return map[string]any{"messages": msgs, "enums": enums, "services": svcs}
}

var aimProtoScalars = setOf("double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes")

// ---- .proto text ---------------------------------------------------------------------------------------------------------

type aimProtoTok struct {
	t string // id | str | num | p
	v string
}

func aimProtoLex(src string, maxTokens int) []aimProtoTok {
	var out []aimProtoTok
	n, i := len(src), 0
	push := func(t aimProtoTok) {
		if len(out) >= maxTokens {
			aimFail("import_limit", "the proto source has too many tokens")
		}
		out = append(out, t)
	}
	isIDStart := func(c byte) bool { return c == '_' || c == '.' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for i < n {
		ch := src[i]
		if r, w := utf8.DecodeRuneInString(src[i:]); isJSSpace(r) {
			i += w
			continue
		}
		switch {
		case strings.HasPrefix(src[i:], "//"):
			for i < n && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				aimFail("bad_source", "unterminated comment in proto source")
			}
			i += 2 + j + 2
		case ch == '"' || ch == '\'':
			j := i + 1
			var s strings.Builder
			for j < n && src[j] != ch {
				if src[j] == '\n' {
					aimFail("bad_source", "unterminated string in proto source")
				}
				if src[j] == '\\' {
					if j+1 < n {
						_, w := utf8.DecodeRuneInString(src[j+1:])
						s.WriteString(src[j+1 : j+1+w])
						j += 1 + w
					} else {
						j += 2
					}
				} else {
					s.WriteByte(src[j])
					j++
				}
			}
			if j >= n {
				aimFail("bad_source", "unterminated string in proto source")
			}
			push(aimProtoTok{"str", s.String()})
			i = j + 1
		case isIDStart(ch):
			j := i + 1
			for j < n && (isIDStart(src[j]) || isDigit(src[j])) {
				j++
			}
			push(aimProtoTok{"id", src[i:j]})
			i = j
		case ch == '-' || isDigit(ch):
			j := i + 1
			for j < n && (src[j] == '-' || src[j] == '+' || src[j] == '.' || isDigit(src[j]) || (src[j] >= 'A' && src[j] <= 'Z') || (src[j] >= 'a' && src[j] <= 'z')) {
				j++
			}
			push(aimProtoTok{"num", src[i:j]})
			i = j
		case strings.IndexByte("{}[]()<>=;,:", ch) >= 0:
			push(aimProtoTok{"p", string(ch)})
			i++
		default:
			aimFail("bad_source", fmt.Sprintf("unexpected character in proto source at offset %d", i))
		}
	}
	return out
}

type aimProtoParser struct {
	i        int
	pkg      string
	toks     []aimProtoTok
	m        *aimProtoModel
	maxDepth int
}

// cur is the current token; ok is false past the end.
func (p *aimProtoParser) cur() (aimProtoTok, bool) {
	if p.i < len(p.toks) {
		return p.toks[p.i], true
	}
	return aimProtoTok{}, false
}

func (p *aimProtoParser) is(v string) bool { t, ok := p.cur(); return ok && t.t != "str" && t.v == v }

func (p *aimProtoParser) eat(v string) bool {
	if p.is(v) {
		p.i++
		return true
	}
	return false
}

func (p *aimProtoParser) fail(msg string) {
	t, ok := p.cur()
	shown := "<end>"
	if ok {
		shown = t.v
	}
	aimFail("bad_source", "proto parse error: "+msg+" near '"+aimClip(shown, 30)+"'")
}

func (p *aimProtoParser) expect(v string) {
	if !p.eat(v) {
		p.fail("expected '" + v + "'")
	}
}

func (p *aimProtoParser) id() string {
	t, ok := p.cur()
	if !ok || t.t != "id" {
		p.fail("expected an identifier")
	}
	p.i++
	return t.v
}

// tok consumes and returns the next token (nil past the end), like `this.toks[this.i++]`.
func (p *aimProtoParser) tok() (aimProtoTok, bool) {
	t, ok := p.cur()
	p.i++
	return t, ok
}

// skipTo skips to the matching close of an already-opened bracket.
func (p *aimProtoParser) skipTo(open, close string) {
	for depth := 1; depth > 0; {
		t, ok := p.tok()
		if !ok {
			p.i--
			p.fail("unterminated block")
		}
		if t.t == "p" {
			if t.v == open {
				depth++
			} else if t.v == close {
				depth--
			}
		}
	}
}

func (p *aimProtoParser) skipStatement() {
	for {
		if _, ok := p.cur(); !ok || p.is(";") {
			break
		}
		if p.is("{") {
			p.i++
			p.skipTo("{", "}")
			return
		}
		p.i++
	}
	p.eat(";")
}

func (p *aimProtoParser) file() {
	for {
		if _, ok := p.cur(); !ok {
			return
		}
		if p.eat(";") {
			continue
		}
		switch kw := p.id(); kw {
		case "package":
			p.pkg = p.id()
			p.expect(";")
		case "message":
			p.message(p.pkg, 0)
		case "enum":
			p.enumDef(p.pkg)
		case "service":
			p.service()
		case "extend":
			p.id()
			p.expect("{")
			p.skipTo("{", "}")
		default:
			p.skipStatement()
		}
	}
}

func aimQual(scope, name string) string {
	if scope == "" {
		return name
	}
	return scope + "." + name
}

func (p *aimProtoParser) enumDef(scope string) {
	full := aimQual(scope, p.id())
	p.expect("{")
	values := []string{}
	for !p.is("}") {
		if _, ok := p.cur(); !ok {
			p.fail("unterminated enum")
		}
		if p.is("option") || p.is("reserved") {
			p.skipStatement()
			continue
		}
		values = append(values, p.id())
		p.skipStatement()
	}
	p.expect("}")
	p.m.setEnum(&aimPEnum{full: full, values: values})
}

var reAimUpperName = regexp.MustCompile(`^[A-Z_]+$`)

// fieldOptions collects the `field_behavior` names of a field's options; everything else is skipped.
func (p *aimProtoParser) fieldOptions() []string {
	behavior := []string{}
	if !p.eat("[") {
		return behavior
	}
	depth, inBehavior := 1, false
	for depth > 0 {
		t, ok := p.tok()
		if !ok {
			p.i--
			p.fail("unterminated field options")
		}
		switch t.t {
		case "p":
			switch t.v {
			case "[", "{":
				depth++
			case "]", "}":
				depth--
			case ",":
				inBehavior = false
			}
		case "id":
			if strings.HasSuffix(t.v, "field_behavior") {
				inBehavior = true
			} else if inBehavior && reAimUpperName.MatchString(t.v) {
				behavior = append(behavior, t.v)
			}
		}
	}
	return behavior
}

func (p *aimProtoParser) message(scope string, depth int) {
	if depth > p.maxDepth {
		aimFail("import_limit", "proto message nesting is too deep")
	}
	full := aimQual(scope, p.id())
	msg := &aimPMsg{full: full, fields: []aimPField{}}
	p.m.setMsg(msg)
	p.expect("{")
	field := func(label string, oneof bool) {
		repeated := label == "repeated"
		typ := p.id()
		f := aimPField{}
		if typ == "map" && p.eat("<") {
			k := p.id()
			p.expect(",")
			v := p.id()
			p.expect(">")
			f.hasMap, f.mapK, f.mapV = true, k, v
			typ, repeated = "map", false
		}
		fname := p.id()
		p.expect("=")
		p.i++ // field number
		behavior := p.fieldOptions()
		p.expect(";")
		f.name, f.typ, f.scope, f.repeated, f.optional, f.behavior = fname, typ, full, repeated, label == "optional" || oneof, behavior
		msg.fields = append(msg.fields, f)
	}
	for !p.is("}") {
		t, ok := p.cur()
		if !ok {
			p.fail("unterminated message")
		}
		if p.eat(";") {
			continue
		}
		kw := ""
		if t.t == "id" {
			kw = t.v
		}
		switch kw {
		case "message":
			p.i++
			p.message(full, depth+1)
		case "enum":
			p.i++
			p.enumDef(full)
		case "oneof":
			p.i++
			p.id()
			p.expect("{")
			for !p.is("}") {
				if _, ok := p.cur(); !ok {
					p.fail("unterminated oneof")
				}
				if p.is("option") {
					p.skipStatement()
					continue
				}
				field("", true)
			}
			p.expect("}")
		case "option", "reserved", "extensions", "group":
			p.skipStatement()
		case "extend":
			p.i++
			p.id()
			p.expect("{")
			p.skipTo("{", "}")
		case "repeated", "optional", "required":
			p.i++
			field(kw, false)
		default:
			field("", false)
		}
	}
	p.expect("}")
}

func (p *aimProtoParser) stream() bool {
	if t, ok := p.cur(); ok && t.v == "stream" && t.t == "id" {
		p.i++
		return true
	}
	return false
}

func (p *aimProtoParser) service() {
	name := p.id()
	svc := aimPService{full: aimQual(p.pkg, name), name: name, methods: []aimPMethod{}}
	p.expect("{")
	for !p.is("}") {
		if _, ok := p.cur(); !ok {
			p.fail("unterminated service")
		}
		if p.eat(";") {
			continue
		}
		if p.id() != "rpc" {
			p.skipStatement()
			continue
		}
		mname := p.id()
		p.expect("(")
		cs := p.stream()
		input := p.id()
		p.expect(")")
		if p.id() != "returns" {
			p.fail("expected 'returns'")
		}
		p.expect("(")
		ss := p.stream()
		output := p.id()
		p.expect(")")
		m := aimPMethod{name: mname, input: input, output: output, cs: cs, ss: ss, scope: p.pkg}
		if p.eat("{") {
			for !p.is("}") {
				if _, ok := p.cur(); !ok {
					p.fail("unterminated rpc body")
				}
				if !p.is("option") {
					p.skipStatement()
					continue
				}
				p.i++
				oname := ""
				if p.eat("(") {
					oname = p.id()
					p.expect(")")
				} else {
					oname = p.id()
				}
				p.expect("=")
				if p.is("{") {
					p.i++
					depth := 1
					for depth > 0 {
						t, ok := p.tok()
						if !ok {
							p.i--
							p.fail("unterminated option")
						}
						if t.t == "p" {
							if t.v == "{" {
								depth++
							} else if t.v == "}" {
								depth--
							}
							continue
						}
						isHTTP := depth == 1 && strings.HasSuffix(oname, "http") && t.t == "id"
						if isHTTP && (t.v == "get" || t.v == "put" || t.v == "post" || t.v == "delete" || t.v == "patch") && p.is(":") {
							p.i++
							path := ""
							if c, ok := p.cur(); ok && c.t == "str" {
								path = c.v
							}
							p.i++
							if m.http == nil {
								m.http = &aimPHTTP{method: strings.ToUpper(t.v), path: path}
							}
						} else if isHTTP && t.v == "body" && p.is(":") {
							p.i++
							if c, ok := p.cur(); ok && c.t == "str" && m.http != nil {
								m.http.body, m.http.hasBody = c.v, true
							}
							p.i++
						}
					}
					p.eat(";")
				} else {
					v, ok := p.tok()
					if strings.HasSuffix(oname, "idempotency_level") && ok {
						m.idem, m.hasIdem = v.v, true
					}
					p.eat(";")
				}
			}
			p.expect("}")
			p.eat(";")
		} else {
			p.expect(";")
		}
		svc.methods = append(svc.methods, m)
	}
	p.expect("}")
	p.m.services = append(p.m.services, svc)
}

func aimParseProto(src string, maxTokens int) *aimProtoModel {
	m := newAimProtoModel()
	p := &aimProtoParser{toks: aimProtoLex(src, maxTokens), m: m, maxDepth: 32}
	p.file()
	return m
}

// ---- binary descriptor set -----------------------------------------------------------------------------------------------

type aimPbReader struct {
	b      []byte
	p, end int
}

func (r *aimPbReader) more() bool { return r.p < r.end }

func (r *aimPbReader) varint() float64 {
	res, mul := 0.0, 1.0
	for k := 0; k < 10; k++ {
		if r.p >= r.end {
			aimFail("bad_source", "truncated descriptor")
		}
		byt := r.b[r.p]
		r.p++
		res += float64(byt&0x7f) * mul
		if byt&0x80 == 0 {
			return res
		}
		mul *= 128
	}
	aimFail("bad_source", "overlong varint in descriptor")
	return 0
}

func (r *aimPbReader) sub() *aimPbReader {
	n := r.varint()
	if n > float64(r.end-r.p) {
		aimFail("bad_source", "descriptor length exceeds the buffer")
	}
	s := &aimPbReader{b: r.b, p: r.p, end: r.p + int(n)}
	r.p += int(n)
	return s
}

func (r *aimPbReader) adv(n int) {
	if n > r.end-r.p {
		aimFail("bad_source", "truncated descriptor")
	}
	r.p += n
}

func (r *aimPbReader) skip(wt int) {
	switch wt {
	case 0:
		r.varint()
	case 1:
		r.adv(8)
	case 2:
		r.sub()
	case 5:
		r.adv(4)
	default:
		aimFail("bad_source", fmt.Sprintf("unsupported wire type %d in descriptor", wt))
	}
}

func (r *aimPbReader) str() string {
	s := r.sub()
	return aimDecodeUTF8Lossy(r.b[s.p:s.end])
}

// tag reads a field tag: the field number and the wire type.
func (r *aimPbReader) tag() (float64, int) {
	t := r.varint()
	return math.Floor(t / 8), int(math.Mod(t, 8))
}

// aimDecodeUTF8Lossy is `new TextDecoder('utf-8', {fatal: false}).decode(b)`: a leading byte order mark is dropped and every
// maximal invalid subpart becomes one U+FFFD.
func aimDecodeUTF8Lossy(b []byte) string {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	var sb strings.Builder
	var cp rune
	needed, seen := 0, 0
	lower, upper := byte(0x80), byte(0xBF)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if needed == 0 {
			switch {
			case c <= 0x7F:
				sb.WriteByte(c)
			case c >= 0xC2 && c <= 0xDF:
				needed, cp = 1, rune(c&0x1F)
			case c >= 0xE0 && c <= 0xEF:
				if c == 0xE0 {
					lower = 0xA0
				}
				if c == 0xED {
					upper = 0x9F
				}
				needed, cp = 2, rune(c&0xF)
			case c >= 0xF0 && c <= 0xF4:
				if c == 0xF0 {
					lower = 0x90
				}
				if c == 0xF4 {
					upper = 0x8F
				}
				needed, cp = 3, rune(c&0x7)
			default:
				sb.WriteRune(utf8.RuneError)
			}
			continue
		}
		if c < lower || c > upper {
			cp, needed, seen, lower, upper = 0, 0, 0, 0x80, 0xBF
			i--
			sb.WriteRune(utf8.RuneError)
			continue
		}
		lower, upper = 0x80, 0xBF
		cp = cp<<6 | rune(c&0x3F)
		seen++
		if seen == needed {
			sb.WriteRune(cp)
			cp, needed, seen = 0, 0, 0
		}
	}
	if needed != 0 {
		sb.WriteRune(utf8.RuneError)
	}
	return sb.String()
}

var aimPbFieldTypes = map[int]string{1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 12: "bytes", 13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}

func aimParseDescriptorSet(bytes []byte) *aimProtoModel {
	m := newAimProtoModel()
	top := &aimPbReader{b: bytes, end: len(bytes)}
	readEnum := func(r *aimPbReader, scope string) {
		name := ""
		values := []string{}
		for r.more() {
			f, wt := r.tag()
			switch {
			case f == 1 && wt == 2:
				name = r.str()
			case f == 2 && wt == 2:
				v := r.sub()
				for v.more() {
					vf, vw := v.tag()
					if vf == 1 && vw == 2 {
						values = append(values, v.str())
					} else {
						v.skip(vw)
					}
				}
			default:
				r.skip(wt)
			}
		}
		m.setEnum(&aimPEnum{full: aimQual(scope, name), values: values})
	}
	behav := map[string]string{"2": "REQUIRED", "3": "OUTPUT_ONLY", "4": "INPUT_ONLY", "5": "IMMUTABLE"}
	type fieldDesc struct {
		name, typeName string
		typ, label     float64
		proto3opt      bool
		behavior       []string
	}
	var readMsg func(r *aimPbReader, scope string, depth int)
	readMsg = func(r *aimPbReader, scope string, depth int) {
		if depth > 32 {
			aimFail("import_limit", "descriptor message nesting is too deep")
		}
		name := ""
		var fields []fieldDesc
		var nested, enums []*aimPbReader
		mapEntry := false
		for r.more() {
			f, wt := r.tag()
			switch {
			case f == 1 && wt == 2:
				name = r.str()
			case f == 2 && wt == 2:
				fr := r.sub()
				fd := fieldDesc{label: 1, behavior: []string{}}
				for fr.more() {
					ff, fw := fr.tag()
					switch {
					case ff == 1 && fw == 2:
						fd.name = fr.str()
					case ff == 4 && fw == 0:
						fd.label = fr.varint()
					case ff == 5 && fw == 0:
						fd.typ = fr.varint()
					case ff == 6 && fw == 2:
						fd.typeName = fr.str()
					case ff == 17 && fw == 0:
						fd.proto3opt = fr.varint() == 1
					case ff == 8 && fw == 2:
						o := fr.sub()
						for o.more() {
							of, ow := o.tag()
							switch {
							case of == 1052 && ow == 0:
								fd.behavior = append(fd.behavior, jsNumberString(o.varint()))
							case of == 1052 && ow == 2:
								pk := o.sub()
								for pk.more() {
									fd.behavior = append(fd.behavior, jsNumberString(pk.varint()))
								}
							default:
								o.skip(ow)
							}
						}
					default:
						fr.skip(fw)
					}
				}
				fields = append(fields, fd)
			case f == 3 && wt == 2:
				nested = append(nested, r.sub())
			case f == 4 && wt == 2:
				enums = append(enums, r.sub())
			case f == 7 && wt == 2:
				o := r.sub()
				for o.more() {
					of, ow := o.tag()
					if of == 7 && ow == 0 {
						mapEntry = o.varint() == 1
					} else {
						o.skip(ow)
					}
				}
			default:
				r.skip(wt)
			}
		}
		full := aimQual(scope, name)
		msg := &aimPMsg{full: full, mapEntry: mapEntry, fields: []aimPField{}}
		for _, f := range fields {
			t := f.typeName
			if t == "" {
				t = "bytes"
				if ft, ok := aimPbFieldTypes[int(f.typ)]; ok && f.typ == math.Floor(f.typ) {
					t = ft
				}
			}
			bs := make([]string, len(f.behavior))
			for i, b := range f.behavior {
				bs[i] = behav[b]
			}
			msg.fields = append(msg.fields, aimPField{name: f.name, scope: full, repeated: f.label == 3, optional: f.proto3opt, typ: t, behavior: bs})
		}
		m.setMsg(msg)
		for _, n := range nested {
			readMsg(n, full, depth+1)
		}
		for _, e := range enums {
			readEnum(e, full)
		}
	}
	httpVerbs := map[float64]string{2: "GET", 3: "PUT", 4: "POST", 5: "DELETE", 6: "PATCH"}
	for top.more() {
		f, wt := top.tag()
		if f != 1 || wt != 2 {
			top.skip(wt)
			continue
		}
		fr := top.sub()
		pkg := ""
		var msgs, enums, svcs []*aimPbReader
		// package may follow the messages in the wire order: collect first, then resolve scopes
		for fr.more() {
			ff, fw := fr.tag()
			switch {
			case ff == 2 && fw == 2:
				pkg = fr.str()
			case ff == 4 && fw == 2:
				msgs = append(msgs, fr.sub())
			case ff == 5 && fw == 2:
				enums = append(enums, fr.sub())
			case ff == 6 && fw == 2:
				svcs = append(svcs, fr.sub())
			default:
				fr.skip(fw)
			}
		}
		for _, r := range msgs {
			readMsg(r, pkg, 0)
		}
		for _, r := range enums {
			readEnum(r, pkg)
		}
		for _, r := range svcs {
			name := ""
			methods := []aimPMethod{}
			for r.more() {
				sf, sw := r.tag()
				switch {
				case sf == 1 && sw == 2:
					name = r.str()
				case sf == 2 && sw == 2:
					mr := r.sub()
					me := aimPMethod{scope: pkg}
					for mr.more() {
						mf, mw := mr.tag()
						switch {
						case mf == 1 && mw == 2:
							me.name = mr.str()
						case mf == 2 && mw == 2:
							me.input = mr.str()
						case mf == 3 && mw == 2:
							me.output = mr.str()
						case mf == 5 && mw == 0:
							me.cs = mr.varint() == 1
						case mf == 6 && mw == 0:
							me.ss = mr.varint() == 1
						case mf == 4 && mw == 2:
							o := mr.sub()
							for o.more() {
								of, ow := o.tag()
								switch {
								case of == 34 && ow == 0:
									switch o.varint() {
									case 1:
										me.idem = "NO_SIDE_EFFECTS"
									case 2:
										me.idem = "IDEMPOTENT"
									default:
										me.idem = "IDEMPOTENCY_UNKNOWN"
									}
									me.hasIdem = true
								case of == 72295728 && ow == 2:
									h := o.sub()
									for h.more() {
										hf, hw := h.tag()
										verb, isVerb := httpVerbs[hf]
										switch {
										case isVerb && hw == 2:
											if me.http == nil {
												me.http = &aimPHTTP{method: verb, path: h.str()}
											} else {
												h.str()
											}
										case hf == 7 && hw == 2:
											b := h.str()
											if me.http != nil {
												me.http.body, me.http.hasBody = b, true
											}
										default:
											h.skip(hw)
										}
									}
								default:
									o.skip(ow)
								}
							}
						default:
							mr.skip(mw)
						}
					}
					methods = append(methods, me)
				default:
					r.skip(sw)
				}
			}
			m.services = append(m.services, aimPService{full: aimQual(pkg, name), name: name, methods: methods})
		}
	}
	return m
}

// ---- model -> params -----------------------------------------------------------------------------------------------------

func aimProtoResolveName(m *aimProtoModel, name, scope string) (string, bool) {
	has := func(n string) bool { _, a := m.messages[n]; _, b := m.enums[n]; return a || b }
	if strings.HasPrefix(name, ".") {
		return name[1:], true
	}
	var parts []string
	if scope != "" {
		parts = strings.Split(scope, ".")
	}
	for k := len(parts); k >= 0; k-- {
		cand := strings.Join(append(append([]string{}, parts[:k]...), name), ".")
		if has(cand) {
			return cand, true
		}
	}
	if has(name) {
		return name, true
	}
	return "", false
}

var reAimIntFixed = regexp.MustCompile(`int|fixed`)

func aimProtoFieldSchema(m *aimProtoModel, f aimPField, c *aimCtx, stack []string, where string, budget *int64) map[string]any {
	one := func(typ, scope string) map[string]any {
		if aimProtoScalars[typ] {
			switch {
			case reAimIntFixed.MatchString(typ):
				return map[string]any{"type": "integer", "format": "int64"}
			case typ == "bool":
				return map[string]any{"type": "boolean"}
			case typ == "string" || typ == "bytes":
				return map[string]any{"type": "string"}
			}
			return map[string]any{"type": "number"}
		}
		bare := strings.TrimPrefix(typ, ".")
		if typ == "google.protobuf.Timestamp" || (strings.HasPrefix(typ, ".") && bare == "google.protobuf.Timestamp") {
			return map[string]any{"type": "string", "format": "date-time"}
		}
		switch bare {
		case "google.protobuf.StringValue", "google.protobuf.BytesValue":
			return map[string]any{"type": "string"}
		case "google.protobuf.Int32Value", "google.protobuf.Int64Value", "google.protobuf.UInt32Value", "google.protobuf.UInt64Value":
			return map[string]any{"type": "integer", "format": "int64"}
		case "google.protobuf.BoolValue":
			return map[string]any{"type": "boolean"}
		}
		if strings.HasPrefix(bare, "google.protobuf.") {
			return map[string]any{}
		}
		full, ok := aimProtoResolveName(m, typ, scope)
		if !ok {
			aimAddTodo(c, where, "unknown_type", "type '"+aimClip(typ, 60)+"' is not defined in the proto source (declared string)")
			return map[string]any{}
		}
		if en, isEnum := m.enums[full]; isEnum {
			return map[string]any{"type": "string", "enum": aimDedupe(en.values)}
		}
		return aimProtoMsgSchema(m, full, c, stack, where, budget)
	}
	if f.hasMap {
		return map[string]any{"type": "object"}
	}
	s := one(f.typ, f.scope)
	if f.repeated {
		return map[string]any{"type": "array", "items": s}
	}
	return s
}

func aimProtoMsgSchema(m *aimProtoModel, full string, c *aimCtx, stack []string, where string, budget *int64) map[string]any {
	msg := m.messages[full]
	if msg == nil {
		return map[string]any{}
	}
	if contains(stack, full) {
		aimAddTodo(c, where, "cyclic_ref", "message '"+aimClip(full, 80)+"' is recursive (declared string; refine or drop)")
		return map[string]any{}
	}
	stop := int64(len(stack)) > c.lim.maxRefDepth
	if !stop {
		*budget--
		stop = *budget <= 0
	}
	if stop {
		aimAddTodo(c, where, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)")
		return map[string]any{}
	}
	properties := map[string]any{}
	required := []any{}
	inner := append(append([]string{}, stack...), full)
	for _, f := range msg.fields {
		if contains(f.behavior, "OUTPUT_ONLY") {
			continue
		}
		properties[f.name] = aimProtoFieldSchema(m, f, c, inner, where+"."+f.name, budget)
		if contains(f.behavior, "REQUIRED") {
			required = append(required, f.name)
		}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required}
}

var reAimCamelTitle = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// ActionImportGRPC imports `.proto` text (a string) or a binary FileDescriptorSet (a []byte) into unreviewed defs, one per rpc.
func ActionImportGRPC(source any, opts map[string]any) (rep *ActionImportReport, err error) {
	defer aimRecover(&err)
	return aimImportGRPC(source, opts), nil
}

func aimImportGRPC(source any, opts any) *ActionImportReport {
	c := aimNewCtx("grpc", source, opts)
	var m *aimProtoModel
	switch s := source.(type) {
	case string:
		m = aimParseProto(s, 2_000_000)
	case []byte:
		m = aimParseDescriptorSet(s)
	default:
		aimFail("bad_source", "a gRPC source is .proto text or a binary FileDescriptorSet")
	}
	svcs := append([]aimPService{}, m.services...)
	sort.SliceStable(svcs, func(i, j int) bool { return compareUtf8(svcs[i].full, svcs[j].full) < 0 })
	for _, svc := range svcs {
		methods := append([]aimPMethod{}, svc.methods...)
		sort.SliceStable(methods, func(i, j int) bool { return compareUtf8(methods[i].name, methods[j].name) < 0 })
		for _, me := range methods {
			where := svc.name + "/" + me.name
			c.root = nil
			bud := aimNewBudget(c)
			input, ok := aimProtoResolveName(m, me.input, me.scope)
			if !ok {
				input = strings.TrimPrefix(me.input, ".")
			}
			budget := c.lim.maxRefNodes
			schema := aimProtoMsgSchema(m, input, c, nil, where, &budget)
			params := map[string]any{}
			if _, isMsg := schema["properties"]; isMsg {
				aimFlattenObject(schema, c, bud, where, params, nil, true)
			} else if _, known := m.messages[input]; !known && !strings.HasPrefix(input, "google.protobuf.") {
				aimAddTodo(c, where, "unknown_type", "request type '"+aimClip(me.input, 60)+"' is not defined in the source (no parameters)")
			}
			hm := ""
			if me.http != nil {
				hm = me.http.method
			}
			effects := []string{"update"}
			switch {
			case hm == "GET":
				effects = []string{"read"}
			case hm == "DELETE":
				effects = []string{"delete"}
			case hm == "POST":
				effects = []string{"create"}
			case hm == "PUT" || hm == "PATCH":
				effects = []string{"update"}
			case me.hasIdem && me.idem == "NO_SIDE_EFFECTS":
				effects = []string{"read"}
			}
			natural := (me.hasIdem && (me.idem == "NO_SIDE_EFFECTS" || me.idem == "IDEMPOTENT")) || hm == "GET" || hm == "PUT" || hm == "DELETE"
			var traits []string
			if me.cs || me.ss {
				traits = aimWithTrait(traits, "pca.bulk")
				aimAddTodo(c, where, "streaming", "a streaming method: acts on many messages (pca.bulk added)")
			}
			bindings := map[string]any{"grpc": map[string]any{"service": aimClip(svc.full, 250), "method": aimClip(me.name, 250)}}
			if me.http != nil && me.http.path != "" {
				bindings["http"] = map[string]any{"method": me.http.method, "path": aimClip(me.http.path, 250)}
			}
			d := aimDraft{name: svc.name + " " + me.name, title: reAimCamelTitle.ReplaceAllString(me.name, "$1 $2"), effects: effects, scope: "one", params: params, traits: traits, bindings: bindings}
			if natural {
				d.idempotency = map[string]any{"mode": "natural"}
			}
			aimEmitDef(c, d)
		}
	}
	return aimFinish(c)
}
