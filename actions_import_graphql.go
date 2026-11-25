package pca

// The GraphQL importer: SDL text or introspection JSON to unreviewed defs. Query fields are reads, Mutation fields are writes,
// Subscription fields are streaming reads; arguments and input objects are flattened to dotted params. There is no method signal,
// so the name tokens drive the suggestion engine and everything stays `unreviewed`.

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ---- model ---------------------------------------------------------------------------------------------------------------

// aimGqlType is a GraphQL type reference: k is "named" (name), "list" or "nonnull" (of).
type aimGqlType struct {
	k, name string
	of      *aimGqlType
}

type aimGqlArg struct {
	name    string
	typ     *aimGqlType
	desc    string
	hasDesc bool
}

type aimGqlField struct {
	name       string
	args       []aimGqlArg
	typ        *aimGqlType
	desc       string
	hasDesc    bool
	deprecated bool
}

type aimGqlTypeDef struct {
	kind, name string
	fields     []aimGqlField
	values     []string
}

// aimGqlSchema keeps its types in insertion order (the reference's Map).
type aimGqlSchema struct {
	order                         []string
	types                         map[string]*aimGqlTypeDef
	query, mutation, subscription string
}

func newAimGqlSchema() *aimGqlSchema { return &aimGqlSchema{types: map[string]*aimGqlTypeDef{}} }

func (s *aimGqlSchema) set(d *aimGqlTypeDef) {
	if _, has := s.types[d.name]; !has {
		s.order = append(s.order, d.name)
	}
	s.types[d.name] = d
}

func (t *aimGqlType) toJSON() map[string]any {
	if t.k == "named" {
		return map[string]any{"k": "named", "name": t.name}
	}
	return map[string]any{"k": t.k, "of": t.of.toJSON()}
}

func aimStrAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// toJSON is the schema as the reference oracle prints it: {types: [[name, def], ...], query?, mutation?, subscription?}.
func (s *aimGqlSchema) toJSON() map[string]any {
	types := make([]any, 0, len(s.order))
	for _, n := range s.order {
		d := s.types[n]
		fields := make([]any, 0, len(d.fields))
		for _, f := range d.fields {
			args := make([]any, 0, len(f.args))
			for _, a := range f.args {
				am := map[string]any{"name": a.name, "type": a.typ.toJSON()}
				if a.hasDesc {
					am["desc"] = a.desc
				}
				args = append(args, am)
			}
			fm := map[string]any{"name": f.name, "args": args, "type": f.typ.toJSON(), "deprecated": f.deprecated}
			if f.hasDesc {
				fm["desc"] = f.desc
			}
			fields = append(fields, fm)
		}
		types = append(types, []any{n, map[string]any{"kind": d.kind, "name": d.name, "fields": fields, "values": aimStrAny(d.values)}})
	}
	out := map[string]any{"types": types}
	if s.query != "" {
		out["query"] = s.query
	}
	if s.mutation != "" {
		out["mutation"] = s.mutation
	}
	if s.subscription != "" {
		out["subscription"] = s.subscription
	}
	return out
}

// ---- SDL lexer -----------------------------------------------------------------------------------------------------------

type aimGqlTok struct {
	t string // name | int | str | punct | eof
	v string
}

func aimGqlLex(src string, maxTokens int) []aimGqlTok {
	var out []aimGqlTok
	i, n := 0, len(src)
	push := func(t aimGqlTok) {
		if len(out) >= maxTokens {
			aimFail("import_limit", "the GraphQL source has too many tokens")
		}
		out = append(out, t)
	}
	for i < n {
		ch := src[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',':
			i++
			continue
		case strings.HasPrefix(src[i:], "\xef\xbb\xbf"):
			i += 3
			continue
		case ch == '#':
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		case ch == '"':
			if strings.HasPrefix(src[i:], `"""`) {
				j := i + 3
				var s strings.Builder
				for j < n && !strings.HasPrefix(src[j:], `"""`) {
					if strings.HasPrefix(src[j:], `\"""`) {
						s.WriteString(`"""`)
						j += 4
					} else {
						s.WriteByte(src[j])
						j++
					}
				}
				if j >= n {
					aimFail("bad_source", "unterminated GraphQL block string")
				}
				push(aimGqlTok{"str", s.String()})
				i = j + 3
			} else {
				j := i + 1
				var s strings.Builder
				for j < n && src[j] != '"' {
					if src[j] == '\n' {
						aimFail("bad_source", "unterminated GraphQL string")
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
					aimFail("bad_source", "unterminated GraphQL string")
				}
				push(aimGqlTok{"str", s.String()})
				i = j + 1
			}
			continue
		case ch == '_' || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'):
			j := i + 1
			for j < n && (src[j] == '_' || (src[j] >= '0' && src[j] <= '9') || (src[j] >= 'A' && src[j] <= 'Z') || (src[j] >= 'a' && src[j] <= 'z')) {
				j++
			}
			push(aimGqlTok{"name", src[i:j]})
			i = j
			continue
		case ch == '-' || (ch >= '0' && ch <= '9'):
			j := i + 1
			for j < n && (src[j] == '-' || src[j] == '+' || src[j] == '.' || (src[j] >= '0' && src[j] <= '9') || src[j] == 'e' || src[j] == 'E') {
				j++
			}
			push(aimGqlTok{"int", src[i:j]})
			i = j
			continue
		case strings.HasPrefix(src[i:], "..."):
			push(aimGqlTok{"punct", "..."})
			i += 3
			continue
		case strings.IndexByte("!$&():=@[]{|}", ch) >= 0:
			push(aimGqlTok{"punct", string(ch)})
			i++
			continue
		}
		aimFail("bad_source", fmt.Sprintf("unexpected character in GraphQL source at offset %d", i))
	}
	push(aimGqlTok{"eof", ""})
	return out
}

// ---- SDL parser (type system definitions only; executable documents are rejected) -----------------------------------------

type aimGqlParser struct {
	i        int
	toks     []aimGqlTok
	schema   *aimGqlSchema
	maxDepth int
}

func (p *aimGqlParser) cur() aimGqlTok { return p.toks[p.i] }

func (p *aimGqlParser) next() aimGqlTok {
	t := p.toks[p.i]
	if t.t != "eof" {
		p.i++
	}
	return t
}

func (p *aimGqlParser) is(v string) bool { c := p.cur(); return c.t != "str" && c.v == v }

func (p *aimGqlParser) eat(v string) bool {
	if p.is(v) {
		p.i++
		return true
	}
	return false
}

func (p *aimGqlParser) expect(v string) {
	if !p.eat(v) {
		aimFail("bad_source", "GraphQL parse error: expected '"+v+"' near '"+aimClip(p.cur().v, 30)+"'")
	}
}

func (p *aimGqlParser) name() string {
	t := p.next()
	if t.t != "name" {
		aimFail("bad_source", "GraphQL parse error: expected a name near '"+aimClip(t.v, 30)+"'")
	}
	return t.v
}

func (p *aimGqlParser) desc() (string, bool) {
	if p.cur().t == "str" {
		return p.next().v, true
	}
	return "", false
}

func (p *aimGqlParser) typ(depth int) *aimGqlType {
	if depth > p.maxDepth {
		aimFail("import_limit", "GraphQL type nesting is too deep")
	}
	var t *aimGqlType
	if p.eat("[") {
		t = &aimGqlType{k: "list", of: p.typ(depth + 1)}
		p.expect("]")
	} else {
		t = &aimGqlType{k: "named", name: p.name()}
	}
	if p.eat("!") {
		return &aimGqlType{k: "nonnull", of: t}
	}
	return t
}

// value skips a constant value (default values, directive arguments).
func (p *aimGqlParser) value(depth int) {
	if depth > p.maxDepth {
		aimFail("import_limit", "GraphQL value nesting is too deep")
	}
	t := p.cur()
	switch {
	case t.t == "str" || t.t == "int" || t.t == "name":
		p.i++
	case p.eat("["):
		for !p.is("]") && p.cur().t != "eof" {
			p.value(depth + 1)
		}
		p.expect("]")
	case p.eat("{"):
		for !p.is("}") && p.cur().t != "eof" {
			p.name()
			p.expect(":")
			p.value(depth + 1)
		}
		p.expect("}")
	case p.eat("$"):
		p.name()
	default:
		aimFail("bad_source", "GraphQL parse error: unexpected '"+aimClip(t.v, 30)+"'")
	}
}

func (p *aimGqlParser) directives() bool {
	deprecated := false
	for p.eat("@") {
		if p.name() == "deprecated" {
			deprecated = true
		}
		if p.eat("(") {
			for !p.is(")") && p.cur().t != "eof" {
				p.name()
				p.expect(":")
				p.value(0)
			}
			p.expect(")")
		}
	}
	return deprecated
}

func (p *aimGqlParser) args() []aimGqlArg {
	out := []aimGqlArg{}
	if !p.eat("(") {
		return out
	}
	for !p.is(")") {
		if p.cur().t == "eof" {
			aimFail("bad_source", "GraphQL parse error: unterminated argument list")
		}
		d, _ := p.desc()
		name := p.name()
		p.expect(":")
		typ := p.typ(0)
		if p.eat("=") {
			p.value(0)
		}
		p.directives()
		out = append(out, aimGqlArg{name: name, typ: typ, desc: d, hasDesc: d != ""})
	}
	p.expect(")")
	return out
}

func (p *aimGqlParser) fields(input bool) []aimGqlField {
	out := []aimGqlField{}
	if !p.eat("{") {
		return out
	}
	for !p.is("}") {
		if p.cur().t == "eof" {
			aimFail("bad_source", "GraphQL parse error: unterminated field list")
		}
		d, _ := p.desc()
		name := p.name()
		args := []aimGqlArg{}
		if !input {
			args = p.args()
		}
		p.expect(":")
		typ := p.typ(0)
		if input && p.eat("=") {
			p.value(0)
		}
		dep := p.directives()
		out = append(out, aimGqlField{name: name, args: args, typ: typ, deprecated: dep, desc: d, hasDesc: d != ""})
	}
	p.expect("}")
	return out
}

func (p *aimGqlParser) def() {
	p.desc()
	kw := p.name()
	switch kw {
	case "extend":
		p.def()
		return
	case "schema":
		p.directives()
		p.expect("{")
		for !p.is("}") {
			if p.cur().t == "eof" {
				aimFail("bad_source", "GraphQL parse error: unterminated schema block")
			}
			op := p.name()
			p.expect(":")
			ty := p.name()
			switch op {
			case "query":
				p.schema.query = ty
			case "mutation":
				p.schema.mutation = ty
			case "subscription":
				p.schema.subscription = ty
			}
		}
		p.expect("}")
		return
	case "scalar":
		n := p.name()
		p.directives()
		p.merge(&aimGqlTypeDef{kind: "scalar", name: n})
		return
	case "directive":
		p.expect("@")
		p.name()
		p.args()
		if p.cur().v == "repeatable" {
			p.i++
		}
		if p.cur().v == "on" {
			p.i++
		}
		p.eat("|")
		p.name()
		for p.eat("|") {
			p.name()
		}
		return
	case "type", "interface", "input":
		n := p.name()
		if p.cur().v == "implements" {
			p.i++
			p.eat("&")
			p.name()
			for p.eat("&") {
				p.name()
			}
		}
		p.directives()
		kind := "interface"
		if kw == "type" {
			kind = "object"
		} else if kw == "input" {
			kind = "input"
		}
		p.merge(&aimGqlTypeDef{kind: kind, name: n, fields: p.fields(kw == "input")})
		return
	case "union":
		n := p.name()
		p.directives()
		if p.eat("=") {
			p.eat("|")
			p.name()
			for p.eat("|") {
				p.name()
			}
		}
		p.merge(&aimGqlTypeDef{kind: "union", name: n})
		return
	case "enum":
		n := p.name()
		p.directives()
		var values []string
		if p.eat("{") {
			for !p.is("}") {
				if p.cur().t == "eof" {
					aimFail("bad_source", "GraphQL parse error: unterminated enum")
				}
				p.desc()
				values = append(values, p.name())
				p.directives()
			}
			p.expect("}")
		}
		p.merge(&aimGqlTypeDef{kind: "enum", name: n, values: values})
		return
	}
	aimFail("bad_source", "GraphQL parse error: unsupported definition '"+aimClip(kw, 30)+"' (only type-system definitions are imported)")
}

func (p *aimGqlParser) merge(d *aimGqlTypeDef) {
	old, has := p.schema.types[d.name]
	if !has {
		p.schema.set(d)
		return
	}
	old.fields = append(old.fields, d.fields...)
	old.values = append(old.values, d.values...)
}

func aimGqlParseSDL(src string, maxTokens int) *aimGqlSchema {
	toks := aimGqlLex(src, maxTokens)
	schema := newAimGqlSchema()
	p := &aimGqlParser{toks: toks, schema: schema, maxDepth: 32}
	for p.cur().t != "eof" {
		p.def()
	}
	return schema
}

// ---- introspection -> model ----------------------------------------------------------------------------------------------

func aimGqlIntrospectType(t any, depth int) *aimGqlType {
	m, ok := t.(map[string]any)
	if depth > 16 || !ok {
		aimFail("bad_source", "malformed introspection type reference")
	}
	switch {
	case aimStrEq(m["kind"], "NON_NULL"):
		return &aimGqlType{k: "nonnull", of: aimGqlIntrospectType(m["ofType"], depth+1)}
	case aimStrEq(m["kind"], "LIST"):
		return &aimGqlType{k: "list", of: aimGqlIntrospectType(m["ofType"], depth+1)}
	}
	n, isName := m["name"].(string)
	if !isName {
		aimFail("bad_source", "malformed introspection type reference")
	}
	return &aimGqlType{k: "named", name: n}
}

var aimGqlKinds = map[string]string{"OBJECT": "object", "INPUT_OBJECT": "input", "ENUM": "enum", "SCALAR": "scalar", "INTERFACE": "interface", "UNION": "union"}

func aimGqlFromIntrospection(doc any) *aimGqlSchema {
	root := doc
	if dm, ok := doc.(map[string]any); ok {
		if d, isD := dm["data"].(map[string]any); isD {
			root = d
		}
	}
	rm, _ := root.(map[string]any)
	s, isSchema := rm["__schema"].(map[string]any)
	var types []any
	hasTypes := false
	if isSchema {
		types, hasTypes = s["types"].([]any)
	}
	if !isSchema || !hasTypes {
		aimFail("bad_source", "not a GraphQL introspection result (no __schema.types)")
	}
	schema := newAimGqlSchema()
	rootName := func(k string) string {
		if m, ok := s[k].(map[string]any); ok {
			if n, isS := m["name"].(string); isS {
				return n
			}
		}
		return ""
	}
	schema.query, schema.mutation, schema.subscription = rootName("queryType"), rootName("mutationType"), rootName("subscriptionType")
	fieldOf := func(f any) (aimGqlField, bool) {
		fm, isM := f.(map[string]any)
		name, isName := fm["name"].(string)
		if !isM || !isName {
			return aimGqlField{}, false
		}
		out := aimGqlField{name: name, args: []aimGqlArg{}}
		argsRaw, _ := fm["args"].([]any)
		for _, a := range argsRaw {
			am, isA := a.(map[string]any)
			an, isAN := am["name"].(string)
			if !isA || !isAN {
				continue
			}
			arg := aimGqlArg{name: an, typ: aimGqlIntrospectType(am["type"], 0)}
			if d, isS := am["description"].(string); isS {
				arg.desc, arg.hasDesc = d, true
			}
			out.args = append(out.args, arg)
		}
		if tv, has := fm["type"]; !has {
			out.typ = &aimGqlType{k: "named", name: "String"}
		} else {
			out.typ = aimGqlIntrospectType(tv, 0)
		}
		out.deprecated = aimIsTrue(fm["isDeprecated"])
		if d, isS := fm["description"].(string); isS {
			out.desc, out.hasDesc = d, true
		}
		return out, true
	}
	for _, tv := range types {
		t, isT := tv.(map[string]any)
		name, isName := t["name"].(string)
		kindS, isKind := t["kind"].(string)
		if !isT || !isName || !isKind || strings.HasPrefix(name, "__") {
			continue
		}
		kind, known := aimGqlKinds[kindS]
		if !known {
			continue
		}
		fieldsRaw := t["fields"]
		if kind == "input" {
			fieldsRaw = t["inputFields"]
		}
		def := &aimGqlTypeDef{kind: kind, name: name, fields: []aimGqlField{}, values: []string{}}
		fr, _ := fieldsRaw.([]any)
		for _, f := range fr {
			if fd, ok := fieldOf(f); ok {
				def.fields = append(def.fields, fd)
			}
		}
		ev, _ := t["enumValues"].([]any)
		for _, e := range ev {
			if em, isE := e.(map[string]any); isE {
				if n, isS := em["name"].(string); isS {
					def.values = append(def.values, n)
				}
			}
		}
		schema.set(def)
	}
	return schema
}

// ---- model -> JSON-schema-like -> params ---------------------------------------------------------------------------------

var aimGqlScalars = map[string]map[string]any{
	"Int": {"type": "integer", "format": "int32"}, "String": {"type": "string"}, "ID": {"type": "string"}, "Boolean": {"type": "boolean"},
	"Float": {"type": "number"}, "Date": {"type": "string", "format": "date"}, "DateTime": {"type": "string", "format": "date-time"}, "Email": {"type": "string", "format": "email"},
	"UUID": {"type": "string", "format": "uuid"}, "URL": {"type": "string", "format": "url"}, "URI": {"type": "string", "format": "url"},
}

// aimGqlSchemaOf is a GraphQL type as a JSON-schema-like node; input objects expand with a cycle guard and a node budget.
func aimGqlSchemaOf(t *aimGqlType, gs *aimGqlSchema, c *aimCtx, bud *aimBudget, stack []string, where string) (map[string]any, bool) {
	nonnull := false
	cur := t
	for cur.k == "nonnull" {
		nonnull = true
		cur = cur.of
	}
	if cur.k == "list" {
		items, _ := aimGqlSchemaOf(cur.of, gs, c, bud, stack, where)
		return map[string]any{"type": "array", "items": items}, nonnull
	}
	name := cur.name
	old := bud.left
	bud.left--
	if old <= 0 {
		if !bud.exhausted {
			bud.exhausted = true
			aimAddTodo(c, where, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)")
		}
		return map[string]any{}, nonnull
	}
	if sc, ok := aimGqlScalars[name]; ok {
		return aimOverlay(sc, nil), nonnull
	}
	def := gs.types[name]
	if def == nil {
		aimAddTodo(c, where, "unknown_type", "type '"+aimClip(name, 60)+"' is not defined in the schema (declared string)")
		return map[string]any{}, nonnull
	}
	switch def.kind {
	case "enum":
		return map[string]any{"type": "string", "enum": aimDedupe(def.values)}, nonnull
	case "scalar":
		return map[string]any{"type": "string"}, nonnull
	case "input":
		if contains(stack, name) {
			aimAddTodo(c, where, "cyclic_ref", "input type '"+aimClip(name, 60)+"' is recursive (declared string; refine or drop)")
			return map[string]any{}, nonnull
		}
		properties := map[string]any{}
		required := []any{}
		inner := append(append([]string{}, stack...), name)
		for _, f := range def.fields {
			r, nn := aimGqlSchemaOf(f.typ, gs, c, bud, inner, where)
			if f.desc != "" {
				r = aimOverlay(r, map[string]any{"description": f.desc})
			}
			properties[f.name] = r
			if nn {
				required = append(required, f.name)
			}
		}
		return map[string]any{"type": "object", "properties": properties, "required": required}, nonnull
	}
	aimAddTodo(c, where, "output_type", "type '"+aimClip(name, 60)+"' is an output type and cannot be an argument (declared string)")
	return map[string]any{}, nonnull
}

// ActionImportGraphQL imports GraphQL SDL text or an introspection result (parsed JSON) into unreviewed defs, one per root field.
func ActionImportGraphQL(source any, opts map[string]any) (rep *ActionImportReport, err error) {
	defer aimRecover(&err)
	return aimImportGraphQL(source, opts), nil
}

func aimImportGraphQL(source any, opts any) *ActionImportReport {
	c := aimNewCtx("graphql", source, opts)
	var gs *aimGqlSchema
	if text, isText := source.(string); isText {
		gs = aimGqlParseSDL(text, 2_000_000)
	} else {
		gs = aimGqlFromIntrospection(source)
	}
	pick := func(name, dflt string) string {
		if name == "" {
			return dflt
		}
		return name
	}
	roots := [][2]string{{pick(gs.query, "Query"), "query"}, {pick(gs.mutation, "Mutation"), "mutation"}, {pick(gs.subscription, "Subscription"), "subscription"}}
	for _, r := range roots {
		rt := gs.types[r[0]]
		if rt == nil {
			continue
		}
		op := r[1]
		fields := append([]aimGqlField{}, rt.fields...)
		sort.SliceStable(fields, func(i, j int) bool { return compareUtf8(fields[i].name, fields[j].name) < 0 })
		for _, f := range fields {
			where := op + " " + aimClip(f.name, 80)
			c.root = nil
			bud := aimNewBudget(c)
			properties := map[string]any{}
			required := []any{}
			for _, a := range f.args {
				s, nn := aimGqlSchemaOf(a.typ, gs, c, bud, nil, where+"("+a.name+")")
				if a.desc != "" {
					s = aimOverlay(s, map[string]any{"description": a.desc})
				}
				properties[a.name] = s
				if nn {
					required = append(required, a.name)
				}
			}
			params := map[string]any{}
			// args are flattened exactly as an object schema's properties are; nesting stops at maxParamPathDepth segments
			aimFlattenObject(map[string]any{"type": "object", "properties": properties, "required": required}, c, bud, where, params, nil, true)
			if f.deprecated {
				aimAddTodo(c, where, "deprecated", "the field is marked @deprecated")
			}
			effects := []string{"read"}
			if op == "mutation" {
				effects = []string{"update"}
			}
			var title any = f.name
			if f.desc != "" {
				title = strings.SplitN(f.desc, "\n", 2)[0]
			}
			var description any
			if f.hasDesc {
				description = f.desc
			}
			d := aimDraft{name: f.name, title: title, description: description, effects: effects, scope: "one", params: params,
				bindings: map[string]any{"graphql": map[string]any{"op": op, "field": aimClip(f.name, 200)}}}
			if op == "subscription" {
				d.traits = aimWithTrait(nil, "pca.bulk")
			}
			if op != "mutation" {
				d.idempotency = map[string]any{"mode": "natural"}
			}
			aimEmitDef(c, d)
		}
	}
	return aimFinish(c)
}
