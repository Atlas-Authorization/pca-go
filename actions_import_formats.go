package pca

// The OpenAPI / Swagger 2, MCP, JSON Schema and AsyncAPI importers (the `$ref`-resolving, schema-flattening family). Every def is
// `unreviewed`: annotations and hints from the source are untrusted and can only add restriction.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// aimASCIILower lowers ASCII letters only (a JavaScript case-insensitive match never equates a non-ASCII letter with an ASCII one).
func aimASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// aimTruthy is JavaScript truthiness of a JSON value.
func aimTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return len(t) > 0
	case []any, map[string]any:
		return true
	}
	f, ok := jsNum(v)
	return ok && f != 0 && f == f
}

// ---- OpenAPI -------------------------------------------------------------------------------------------------------------

var (
	aimMethods  = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}
	aimEffectOf = map[string]string{"get": "read", "head": "read", "options": "read", "trace": "read", "post": "create", "put": "update", "patch": "update", "delete": "delete"}
	aimNatural  = setOf("get", "head", "options", "trace", "put", "delete")
	aimBodyTyps = []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}

	reAimVersionNum = regexp.MustCompile(`^v[0-9]+(\.[0-9]+)?$`)
	reAimParamSeg   = regexp.MustCompile(`^\{[^\n\r\x{2028}\x{2029}]+\}$`)
	reAimJSONPlus   = regexp.MustCompile(`^application/[^;]*\+json(;|$)`)
)

func aimVersionish(s string) bool {
	l := aimASCIILower(s)
	return l == "api" || l == "rest" || l == "public" || l == "latest" || reAimVersionNum.MatchString(l)
}

// aimDerefChain is the object a `$ref` chain ends at (an array is possible: callers read members through aimGet); ok is false when
// it does not resolve.
func aimDerefChain(c *aimCtx, x any, where string) (any, bool) {
	m, isM := x.(map[string]any)
	if !isM {
		return nil, false
	}
	if _, isRef := m["$ref"].(string); !isRef {
		return x, true
	}
	seen := map[string]bool{}
	cur := x
	for {
		cm, isM := cur.(map[string]any)
		if !isM {
			break
		}
		ref, isRef := cm["$ref"].(string)
		if !isRef {
			break
		}
		if seen[ref] || int64(len(seen)) > c.lim.maxRefDepth {
			aimAddTodo(c, where, "cyclic_ref", "a reference chain is cyclic or too deep")
			return nil, false
		}
		seen[ref] = true
		t, found := aimPointer(c.root, ref)
		if !found {
			aimAddTodo(c, where, "unresolved_ref", "reference '"+aimClip(ref, 120)+"' does not resolve locally")
			return nil, false
		}
		cur = t
	}
	return cur, true
}

// aimPathFacts is the path's noun tokens and whether it ends with a `{param}` segment.
func aimPathFacts(path string) ([]string, bool) {
	var segs []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	ends := len(segs) > 0 && reAimParamSeg.MatchString(segs[len(segs)-1])
	var nouns []string
	for _, s := range segs {
		if !strings.ContainsAny(s, "{}") && !aimVersionish(s) {
			nouns = append(nouns, aimTokensOf(s)...)
		}
	}
	return nouns, ends
}

// aimSwagger2Param is a Swagger 2 parameter in the OpenAPI 3 shape the rest of the importer reads.
func aimSwagger2Param(p map[string]any) map[string]any {
	if _, has := p["schema"]; has || aimStrEq(p["in"], "body") {
		return p
	}
	out := map[string]any{}
	sch := map[string]any{}
	for k, v := range p {
		switch k {
		case "name", "in", "required", "description":
			out[k] = v
		default:
			sch[k] = v
		}
	}
	out["schema"] = sch
	return out
}

func aimBodySchema(c *aimCtx, op map[string]any, params []map[string]any, swagger bool, where string) (any, bool) {
	if swagger {
		for _, q := range params {
			if aimStrEq(q["in"], "body") {
				v, has := q["schema"]
				return v, has
			}
		}
		return nil, false
	}
	rb, ok := aimDerefChain(c, op["requestBody"], where)
	if !ok {
		return nil, false
	}
	cv, _ := aimGet(rb, "content")
	content, isObjC := cv.(map[string]any)
	if !isObjC {
		return nil, false
	}
	keys := aimSortedKeys(content)
	pick, found := "", false
	for _, t := range aimBodyTyps {
		for _, k := range keys {
			if jsTrim(strings.SplitN(aimASCIILower(k), ";", 2)[0]) == t {
				pick, found = k, true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		for _, k := range keys {
			if reAimJSONPlus.MatchString(aimASCIILower(k)) {
				pick, found = k, true
				break
			}
		}
	}
	if !found {
		if len(keys) > 0 {
			var shown []string
			for i, k := range keys {
				if i == 3 {
					break
				}
				shown = append(shown, aimClip(k, 40))
			}
			aimAddTodo(c, where, "body_type", "request body media types ("+strings.Join(shown, ", ")+") are not form or JSON; the body is not declared")
		}
		return nil, false
	}
	return aimGet(content[pick], "schema")
}

// ActionImportOpenAPI imports an OpenAPI 3.x or Swagger 2 document (parsed JSON) into unreviewed defs, one per operation.
func ActionImportOpenAPI(source any, opts map[string]any) (rep *ActionImportReport, err error) {
	defer aimRecover(&err)
	return aimImportOpenAPI(source, opts), nil
}

func aimImportOpenAPI(source any, opts any) *ActionImportReport {
	c := aimNewCtx("openapi", source, opts)
	src, ok := source.(map[string]any)
	if !ok {
		aimFail("bad_source", "an OpenAPI document must be an object")
	}
	sw, swIsStr := src["swagger"].(string)
	o3, o3IsStr := src["openapi"].(string)
	swagger := swIsStr && strings.HasPrefix(sw, "2")
	v3 := o3IsStr && strings.HasPrefix(o3, "3.")
	if !swagger && !v3 {
		aimFail("bad_source", "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')")
	}
	paths, _ := src["paths"].(map[string]any)
	globalSecurity, hasGlobalSecurity := src["security"].([]any)
	for _, path := range aimSortedKeys(paths) {
		item0, found := aimDerefChain(c, paths[path], path)
		if !found {
			continue
		}
		sharedV, _ := aimGet(item0, "parameters")
		shared, _ := sharedV.([]any)
		for _, method := range aimMethods {
			opV, _ := aimGet(item0, method)
			op, isOp := opV.(map[string]any)
			if !isOp {
				continue
			}
			where := strings.ToUpper(method) + " " + aimClip(path, 120)
			operationID, hasOID := op["operationId"].(string)
			hasOID = hasOID && jsLen(operationID) > 0 && jsLen(operationID) <= 200
			nouns, endsWithParam := aimPathFacts(path)
			nameRaw, hasNameRaw := op["x-pca-verb"].(string)
			hasNameRaw = hasNameRaw && c.ext["x-pca-verb"]
			var verb string
			switch {
			case hasNameRaw && reVerb.MatchString(nameRaw) && strings.HasPrefix(nameRaw, c.ns+"."):
				verb = nameRaw
			case hasOID:
				verb = aimVerbOf(c.ns, operationID)
			default:
				tail := nouns
				if len(tail) > 2 {
					tail = tail[len(tail)-2:]
				}
				last := method
				if method == "get" && !endsWithParam {
					last = "list"
				}
				verb = aimVerbOf(c.ns, strings.Join(append(append([]string{}, tail...), last), " "))
			}
			c.root = source
			bud := aimNewBudget(c)
			// parameters: the operation's own win over the path item's (by in+name)
			merged := map[string]map[string]any{}
			var order []string
			own, _ := op["parameters"].([]any)
			for _, raw := range append(append([]any{}, shared...), own...) {
				q0v, okq := aimDerefChain(c, raw, where)
				q0, isQ := q0v.(map[string]any)
				if !okq || !isQ {
					continue
				}
				_, nameOK := q0["name"].(string)
				_, inOK := q0["in"].(string)
				if !nameOK || !inOK {
					continue
				}
				q := q0
				if swagger {
					q = aimSwagger2Param(q0)
				}
				key := q["in"].(string) + ":" + q["name"].(string)
				if _, dup := merged[key]; !dup {
					order = append(order, key)
				}
				merged[key] = q
			}
			all := make([]map[string]any, 0, len(order))
			for _, k := range order {
				all = append(all, merged[k])
			}
			params := map[string]any{}
			idemParam := ""
			// request body first (it wins a name clash)
			if body, hasBody := aimBodySchema(c, op, all, swagger, where); hasBody {
				b := aimResolveSchema(body, c, bud, where+": request body", nil, 0)
				_, bProps := b["properties"].(map[string]any)
				if aimStrEq(b["type"], "object") || bProps {
					aimFlattenObject(b, c, bud, where, params, nil, true)
				} else {
					aimAddTodo(c, where, "body_shape", "the request body is not an object schema; it is not declared")
				}
			}
			sorted := append([]map[string]any{}, all...)
			sort.SliceStable(sorted, func(i, j int) bool {
				return compareUtf8(sorted[i]["in"].(string)+":"+sorted[i]["name"].(string), sorted[j]["in"].(string)+":"+sorted[j]["name"].(string)) < 0
			})
			for _, q := range sorted {
				name, loc := q["name"].(string), q["in"].(string)
				if loc == "header" && aimASCIILower(name) == "idempotency-key" {
					idemParam = "idempotency_key"
					continue
				}
				if loc == "body" {
					continue
				}
				if loc != "path" && loc != "query" && loc != "formData" {
					aimAddTodo(c, where, "param_location", aimClip(loc, 12)+" parameter '"+aimClip(name, 60)+"' is not an action parameter (path, query and body only)")
					continue
				}
				sname := aimParamSeg(name)
				if sname != name {
					aimAddTodo(c, where+": "+name, "renamed_param", "parameter '"+aimClip(name, 80)+"' is declared as '"+sname+"'")
				}
				clash := false
				if _, has := params[sname]; has {
					clash = true
				}
				for k := range params {
					if strings.HasPrefix(k, sname+".") {
						clash = true
					}
				}
				if clash {
					aimAddTodo(c, where+": "+name, "skipped_param", "'"+sname+"' is declared by the body and by a "+loc+" parameter; kept the body's")
					continue
				}
				if len(params) >= 64 {
					aimAddTodo(c, where, "too_many_params", "more than 64 parameters; the rest are dropped")
					break
				}
				sq := q["schema"]
				if sq == nil {
					sq = map[string]any{}
				}
				extra := map[string]any{}
				if qd := q["description"]; aimTruthy(qd) {
					if d, _ := aimGet(sq, "description"); !aimTruthy(d) {
						extra["description"] = qd
					}
				}
				sch := aimResolveSchema(aimOverlay(aimSpreadObj(sq), extra), c, bud, where+": "+name, nil, 0)
				params[sname] = aimLeafParam(sch, loc == "path" || aimIsTrue(q["required"]), c, bud, where+": "+name)
			}
			if _, has := params[idemParam]; idemParam != "" && !has {
				params[idemParam] = map[string]any{"type": "string", "required": false, "max_len": aimNum(255)}
			} else {
				idemParam = ""
			}
			scope := "set"
			if endsWithParam || method == "post" {
				scope = "one"
			}
			sec, hasSec := op["security"].([]any)
			if !hasSec {
				sec, hasSec = globalSecurity, hasGlobalSecurity
			}
			scopeSet := map[string]bool{}
			if hasSec {
				for _, r := range sec {
					if rm, isR := r.(map[string]any); isR {
						for _, v := range rm {
							if a, isA := v.([]any); isA {
								for _, x := range a {
									if s, isS := x.(string); isS {
										scopeSet[s] = true
									}
								}
							}
						}
					}
				}
			}
			if len(scopeSet) > 0 {
				scopes := make([]string, 0, len(scopeSet))
				for s := range scopeSet {
					scopes = append(scopes, s)
				}
				sort.Slice(scopes, func(i, j int) bool { return compareUtf8(scopes[i], scopes[j]) < 0 })
				if len(scopes) > 12 {
					scopes = scopes[:12]
				}
				for i, s := range scopes {
					scopes[i] = aimClip(s, 60)
				}
				aimAddTodo(c, where, "required_scope", "requires scope: "+strings.Join(scopes, ", "))
			}
			if aimIsTrue(op["deprecated"]) {
				aimAddTodo(c, where, "deprecated", "the operation is marked deprecated")
			}
			for _, k := range jsKeys(op) {
				if strings.HasPrefix(k, "x-") && !c.ext[k] {
					aimAddTodo(c, where, "extension_ignored", "extension '"+aimClip(k, 60)+"' is ignored (not allow-listed)")
					break
				}
			}
			summary, hasSummary := op["summary"].(string)
			desc, hasDesc := op["description"].(string)
			var title, description any
			switch {
			case hasSummary && len(summary) > 0:
				title = summary
			case hasOID:
				title = operationID
			}
			switch {
			case hasDesc:
				description = desc
			case hasSummary:
				description = summary
			}
			name, bindID := where, aimClip(method+"_"+path, 200)
			if hasOID {
				name, bindID = operationID, operationID
			}
			draft := aimDraft{
				name: name, noAlias: !hasOID, verb: verb, title: title, description: description,
				effects: []string{aimEffectOf[method]}, scope: scope, params: params,
				bindings: map[string]any{"openapi": map[string]any{"operationId": bindID, "method": strings.ToUpper(method), "path": aimClip(path, 240)}},
			}
			switch {
			case idemParam != "":
				draft.idempotency = map[string]any{"mode": "key_param", "param": idemParam}
			case aimNatural[method]:
				draft.idempotency = map[string]any{"mode": "natural"}
			}
			aimEmitDef(c, draft)
		}
	}
	return aimFinish(c)
}

// ---- MCP -----------------------------------------------------------------------------------------------------------------

// ActionImportMCP imports an MCP `tools/list` result ({tools: [...]}) or the tool array itself into unreviewed defs.
func ActionImportMCP(source any, opts map[string]any) (rep *ActionImportReport, err error) {
	defer aimRecover(&err)
	return aimImportMCP(source, opts), nil
}

func aimImportMCP(source any, opts any) *ActionImportReport {
	c := aimNewCtx("mcp", source, opts)
	var tools []any
	isTools := false
	switch s := source.(type) {
	case []any:
		tools, isTools = s, true
	case map[string]any:
		tools, isTools = s["tools"].([]any)
	}
	if !isTools {
		aimFail("bad_source", "an MCP source is a tool array or a tools/list result {tools: [...]}")
	}
	seen := map[string]bool{}
	for _, raw := range tools {
		t, isT := raw.(map[string]any)
		name, isName := t["name"].(string)
		if !isT || !isName || jsLen(name) == 0 || jsLen(name) > 256 {
			aimAddTodo(c, "(tool)", "skipped_op", "an entry without a usable name is skipped")
			continue
		}
		if seen[name] {
			aimAddTodo(c, name, "duplicate_tool", "a tool name listed twice; the first is kept")
			continue
		}
		seen[name] = true
		c.root = t["inputSchema"]
		bud := aimNewBudget(c)
		input := aimResolveSchema(t["inputSchema"], c, bud, name+": inputSchema", nil, 0)
		params := map[string]any{}
		aimFlattenObject(input, c, bud, name, params, nil, true)
		a, _ := t["annotations"].(map[string]any)
		// readOnly claims safety, so it is honoured only when nothing contradicts it
		read := aimIsTrue(a["readOnlyHint"]) && !aimIsTrue(a["destructiveHint"])
		effects := []string{"update"}
		if read {
			effects = []string{"read"}
		} else if aimIsTrue(a["destructiveHint"]) {
			effects = []string{"update", "delete"}
		}
		var title any = t["title"]
		if at, isS := a["title"].(string); isS && len(at) > 0 {
			title = at
		}
		d := aimDraft{name: name, title: title, description: t["description"], effects: effects, scope: "one", params: params, bindings: map[string]any{"mcp": map[string]any{"tool": aimClip(name, 256)}}}
		if aimIsTrue(a["idempotentHint"]) {
			d.idempotency = map[string]any{"mode": "natural"}
		}
		if aimIsTrue(a["openWorldHint"]) {
			d.traits = aimWithTrait(nil, "pca.network_egress")
		}
		aimEmitDef(c, d)
	}
	return aimFinish(c)
}

// ---- JSON Schema ---------------------------------------------------------------------------------------------------------

// ActionImportJSONSchema imports one JSON Schema plus the caller's verb into one def. opts: the common options plus verb (required,
// `<ns>.<noun>.<action>`), title, description and effects (default ["update"]).
func ActionImportJSONSchema(schema any, opts map[string]any) (rep *ActionImportReport, err error) {
	defer aimRecover(&err)
	return aimImportJSONSchema(schema, opts), nil
}

func aimImportJSONSchema(schema any, opts any) *ActionImportReport {
	c := aimNewCtx("jsonschema", schema, opts)
	verb, isVerb := aimOpt(opts, "verb").(string)
	if !isVerb || !reVerb.MatchString(verb) || !strings.HasPrefix(verb, c.ns+".") {
		aimFail("bad_verb", "verb must be a valid verb in namespace '"+c.ns+"'")
	}
	effects := []string{"update"}
	if ev := aimOpt(opts, "effects"); ev != nil {
		ea, isArr := ev.([]any)
		ok := isArr && len(ea) > 0
		effects = nil
		for _, x := range ea {
			s, isS := x.(string)
			if !isS || !contains(defEffects, s) {
				ok = false
				break
			}
			effects = append(effects, s)
		}
		if !ok {
			aimFail("bad_effects", "effects must be 1+ known effects")
		}
	}
	sm, isSchema := schema.(map[string]any)
	if !isSchema {
		aimFail("bad_source", "a JSON Schema must be an object")
	}
	bud := aimNewBudget(c)
	root := aimResolveSchema(sm, c, bud, verb, nil, 0)
	params := map[string]any{}
	_, rProps := root["properties"].(map[string]any)
	if aimStrEq(root["type"], "object") || rProps {
		aimFlattenObject(root, c, bud, verb, params, nil, true)
	} else {
		aimAddTodo(c, verb, "not_object", "the schema is not an object schema: the def has no parameters")
	}
	title := aimOpt(opts, "title")
	if title == nil {
		if t, isS := root["title"].(string); isS {
			title = t
		}
	}
	description := aimOpt(opts, "description")
	if description == nil {
		description = aimClip(root["description"], 600)
	}
	aimEmitDef(c, aimDraft{
		name: strings.Join(strings.Split(verb, ".")[1:], "_"), verb: verb, title: title, description: description,
		effects: effects, scope: "one", params: params, bindings: map[string]any{},
	})
	return aimFinish(c)
}

// ---- AsyncAPI ------------------------------------------------------------------------------------------------------------

func aimAsyncDeref(c *aimCtx, x any, where string, depth int64) map[string]any {
	m, ok := x.(map[string]any)
	if !ok {
		return nil
	}
	ref, isRef := m["$ref"].(string)
	if !isRef {
		return m
	}
	if depth > c.lim.maxRefDepth {
		aimAddTodo(c, where, "ref_depth", "a reference chain is too deep")
		return nil
	}
	t, found := aimPointer(c.root, ref)
	if !found {
		aimAddTodo(c, where, "unresolved_ref", "reference '"+aimClip(ref, 120)+"' does not resolve locally")
		return nil
	}
	return aimAsyncDeref(c, t, where, depth+1)
}

func aimAsyncPayload(c *aimCtx, msgs []any, where string, params map[string]any, bud *aimBudget) {
	var resolved []map[string]any
	for _, m := range msgs {
		if r := aimAsyncDeref(c, m, where, 0); r != nil {
			resolved = append(resolved, r)
		}
	}
	if len(resolved) == 0 {
		return
	}
	if len(resolved) > 1 {
		aimAddTodo(c, where, "message_variants", fmt.Sprintf("%d message variants: only the first is declared", len(resolved)))
	}
	payload, has := resolved[0]["payload"]
	if !has {
		return
	}
	s := aimResolveSchema(payload, c, bud, where+": payload", nil, 0)
	_, sProps := s["properties"].(map[string]any)
	if aimStrEq(s["type"], "object") || sProps {
		aimFlattenObject(s, c, bud, where, params, nil, true)
	} else {
		aimAddTodo(c, where, "payload_shape", "the message payload is not an object schema; it is not declared")
	}
}

func aimAsyncChannelParams(c *aimCtx, ch map[string]any, where string, params map[string]any) {
	ps := aimAsyncDeref(c, ch["parameters"], where, 0)
	if ps == nil {
		return
	}
	for _, name := range aimSortedKeys(ps) {
		s := aimParamSeg(name)
		if _, has := params[s]; has {
			continue
		}
		params[s] = map[string]any{"type": "string", "max_len": aimNum(256)}
	}
}

// ActionImportAsyncAPI imports an AsyncAPI 2.x or 3.x document into unreviewed defs: sending to a channel is effect `send`, receiving
// is `read`; a broker publish leaves the trust domain, so it stays `send` unless the channel carries the allow-listed `x-pca-internal: true`.
func ActionImportAsyncAPI(source any, opts map[string]any) (rep *ActionImportReport, err error) {
	defer aimRecover(&err)
	return aimImportAsyncAPI(source, opts), nil
}

func aimImportAsyncAPI(source any, opts any) *ActionImportReport {
	c := aimNewCtx("asyncapi", source, opts)
	src, isSrc := source.(map[string]any)
	ver, isVer := src["asyncapi"].(string)
	if !isSrc || !isVer || len(ver) < 2 || (ver[0] != '2' && ver[0] != '3') || ver[1] != '.' {
		aimFail("bad_source", "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')")
	}
	v3 := strings.HasPrefix(ver, "3")
	channels, _ := src["channels"].(map[string]any)
	internal := func(ch map[string]any) bool { return c.ext["x-pca-internal"] && aimIsTrue(ch["x-pca-internal"]) }
	emit := func(opName string, hasOpName bool, chName string, ch map[string]any, action string, op map[string]any, msgs []any) {
		where := action + " " + aimClip(chName, 100)
		bud := aimNewBudget(c)
		c.root = source
		params := map[string]any{}
		aimAsyncChannelParams(c, ch, where, params)
		aimAsyncPayload(c, msgs, where, params, bud)
		effects := []string{"send"}
		if action == "receive" {
			effects = []string{"read"}
		} else if internal(ch) {
			effects = []string{"create"}
		}
		d := aimDraft{name: where, noAlias: !hasOpName, effects: effects, scope: "one", params: params,
			bindings: map[string]any{"asyncapi": map[string]any{"channel": aimClip(chName, 250), "op": action}}}
		if hasOpName {
			d.name = opName
		} else {
			d.verb = aimVerbOf(c.ns, chName+" "+action)
		}
		if s, isS := op["summary"].(string); isS {
			d.title = s
		}
		if s, isS := op["description"].(string); isS {
			d.description = s
		}
		aimEmitDef(c, d)
	}
	if v3 {
		ops, _ := src["operations"].(map[string]any)
		for _, id := range aimSortedKeys(ops) {
			op := aimAsyncDeref(c, ops[id], id, 0)
			if op == nil || (!aimStrEq(op["action"], "send") && !aimStrEq(op["action"], "receive")) {
				aimAddTodo(c, id, "skipped_op", "an operation without action send|receive is skipped")
				continue
			}
			chRef := aimAsyncDeref(c, op["channel"], id, 0)
			if chRef == nil {
				continue
			}
			chName := id
			if addr, isS := chRef["address"].(string); isS {
				chName = addr
			} else if cm, isM := op["channel"].(map[string]any); isM {
				if r, isRef := cm["$ref"].(string); isRef {
					parts := strings.Split(r, "/")
					chName = parts[len(parts)-1]
				}
			}
			var msgs []any
			if ms, isL := op["messages"].([]any); isL && len(ms) > 0 {
				msgs = ms
			} else if cm, isM := chRef["messages"].(map[string]any); isM {
				for _, k := range aimSortedKeys(cm) {
					msgs = append(msgs, cm[k])
				}
			}
			emit(id, true, chName, chRef, op["action"].(string), op, msgs)
		}
	} else {
		for _, chName := range aimSortedKeys(channels) {
			ch := aimAsyncDeref(c, channels[chName], chName, 0)
			if ch == nil {
				continue
			}
			// 2.x: `publish` is what a client does to the channel (a send); `subscribe` is what a client receives
			for _, ka := range [][2]string{{"publish", "send"}, {"subscribe", "receive"}} {
				op := aimAsyncDeref(c, ch[ka[0]], chName, 0)
				if op == nil {
					continue
				}
				m := aimAsyncDeref(c, op["message"], chName, 0)
				var msgs []any
				if m != nil {
					if one, isL := m["oneOf"].([]any); isL {
						msgs = one
					} else {
						msgs = []any{m}
					}
				}
				oid, isOID := op["operationId"].(string)
				emit(oid, isOID && len(oid) > 0, chName, ch, ka[1], op, msgs)
			}
		}
	}
	return aimFinish(c)
}
