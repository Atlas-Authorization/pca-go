package pca

// Lint a policy against the action schema / action definitions it is written for.

import (
	"fmt"
	"strings"
)

var anlDefType = map[string]bool{"string": true, "integer": true, "boolean": true, "date": true, "set": true, "array": true}

func anlDefShape(p any) map[string]any {
	out := map[string]any{}
	if t, ok := anlGet(p, "type").(string); ok && anlDefType[t] {
		out["type"] = t
	}
	if v := anlGet(p, "role"); anlTruthy(v) {
		out["semantic"] = v
	}
	if v := anlGet(p, "values"); anlTruthy(v) {
		out["values"] = v
	}
	for _, k := range []string{"min", "max"} {
		if v := anlGet(p, k); !anlIsUndef(v) {
			out[k] = v
		}
	}
	if v := anlGet(p, "sensitivity"); anlTruthy(v) {
		out["sensitivity"] = v
	}
	if v := anlGet(p, "required"); !anlIsUndef(v) {
		out["required"] = v
	}
	return out
}

// anlEntryKeys is Object.entries(nn(o, {})): the object and its keys in JavaScript order.
func anlEntryKeys(o any) (map[string]any, []string) {
	m, ok := anlNN(o, map[string]any{}).(map[string]any)
	if !ok {
		anlFail("Object.entries requires an object")
	}
	return m, jsKeys(m)
}

func anlParamShapes(params any) map[string]any {
	m, keys := anlEntryKeys(params)
	out := map[string]any{}
	for _, k := range keys {
		out[k] = anlDefShape(m[k])
	}
	return out
}

func anlVerbShapesFromActionDefs(defs any) []any {
	out := []any{}
	for _, d := range anlReqList(defs) {
		out = append(out, anlU(map[string]any{"verb": anlGet(d, "verb"), "params": anlParamShapes(anlGet(d, "params"))}))
	}
	return out
}

// anlVerbShapes are the verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of action definitions.
func anlVerbShapes(src any) []any {
	if sm, ok := src.(map[string]any); ok && anlHas(sm, "verbs") {
		out := []any{}
		for _, v := range anlReqList(sm["verbs"]) {
			params := map[string]any{}
			pm, keys := anlEntryKeys(anlGet(v, "params"))
			for _, k := range keys {
				d := pm[k]
				s := map[string]any{"type": anlGet(d, "type")}
				if x := anlGet(d, "values"); anlTruthy(x) {
					s["values"] = x
				}
				for _, f := range []string{"min", "max"} {
					if x := anlGet(d, f); !anlIsUndef(x) {
						s[f] = x
					}
				}
				if x := anlGet(d, "unit"); anlTruthy(x) {
					s["unit"] = x
				}
				s["semantic"] = anlGet(d, "semantic")
				s["sensitivity"] = anlGet(d, "sensitivity")
				if x := anlGet(d, "required"); !anlIsUndef(x) {
					s["required"] = x
				}
				params[k] = anlU(s)
			}
			out = append(out, anlU(map[string]any{"verb": anlGet(v, "verb"), "params": params}))
		}
		return out
	}
	lst := anlReqList(src)
	shapes := []any{}
	for _, d := range lst {
		var v any = false
		if dm, ok := d.(map[string]any); ok && anlHas(dm, "verb") {
			v = dm["verb"]
		}
		if !anlTruthy(v) {
			v = false
			if dm, ok := d.(map[string]any); ok && anlHas(dm, "id") {
				v = dm["id"]
			}
		}
		if !anlTruthy(v) {
			v = ""
		}
		shapes = append(shapes, map[string]any{"verb": v, "params": anlParamShapes(anlGet(d, "params"))})
	}
	for i, sv := range shapes {
		v := sv.(map[string]any)
		orig := anlNN(anlGet(lst[i], "params"), map[string]any{})
		for k, ps := range v["params"].(map[string]any) {
			pm := ps.(map[string]any)
			for _, f := range []string{"semantic", "unit"} {
				if !anlIsUndef(anlOget(anlOwn(orig, k), f)) {
					pm[f] = anlGet(anlGet(orig, k), f)
				}
			}
		}
	}
	return shapes
}

func anlLeaves(c any, into *[]any) {
	m, ok := c.(map[string]any)
	if !ok {
		return
	}
	if anlIsGroup(m) {
		if xs, ok := m["all_of"].([]any); ok {
			for _, x := range xs {
				anlLeaves(x, into)
			}
		} else if xs, ok := m["any_of"].([]any); ok {
			for _, x := range xs {
				anlLeaves(x, into)
			}
		} else if n, has := m["not"]; has {
			anlLeaves(n, into)
		}
		return
	}
	*into = append(*into, c)
}

func anlTypeOK(t, v any) bool {
	if anlIsUndef(t) {
		return true
	}
	switch t {
	case "integer":
		return anlIsFin(v)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "string", "date":
		_, ok := v.(string)
		return ok
	}
	return true
}

func anlSemanticMoney(d any) bool {
	s, ok := anlNN(anlGet(d, "semantic"), "").(string)
	if !ok {
		anlFail("startsWith is not a function")
	}
	return strings.HasPrefix(s, "money.")
}

func anlGrants(p, verb any) bool {
	pv := anlGet(p, "verb")
	if anlStrictEq(pv, "*") || anlStrictEq(pv, verb) {
		return true
	}
	if l, ok := pv.([]any); ok {
		return anlIncludes(l, "*") || anlIncludes(l, verb)
	}
	return false
}

func anlNumOf(v any) string { return anlNumStr(anlToNumber(v)) }

func anlIsNumericOp(op any) bool { return op == "lt" || op == "lte" || op == "gt" || op == "gte" }

// anlValidatePolicyAgainstSchema lints a policy against the schema it is written for: {ok, findings}; ok is false when a finding is
// an error.
func anlValidatePolicyAgainstSchema(policy, src, optsIn any) map[string]any {
	o := optsIn
	if o == nil || anlIsUndef(o) {
		o = map[string]any{}
	}
	shapes := anlVerbShapes(src)
	byVerb := map[string]map[string]any{}
	var shapeVerbs []any
	for _, sv := range shapes {
		s := sv.(map[string]any)
		shapeVerbs = append(shapeVerbs, anlOwn(s, "verb"))
		if vs, ok := s["verb"].(string); ok {
			byVerb[vs] = s
		}
	}
	schemaUnits := anlGet(o, "schemaUnits")
	if anlIsUndef(schemaUnits) || schemaUnits == nil {
		schemaUnits = anlOwn(src, "units")
	}
	model := anlToModel(policy)
	findings := []any{}
	units := anlGet(o, "units")
	listUngranted := anlTruthy(anlGet(o, "listUngranted"))
	add := func(code, severity, where, message string) {
		findings = append(findings, map[string]any{"code": code, "severity": severity, "where": where, "message": message})
	}
	lookup := func(v any) (map[string]any, bool) {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		sh, ok := byVerb[s]
		return sh, ok
	}

	check := func(p any, where string, isVeto bool) {
		pv := anlGet(p, "verb")
		var verbs []any
		if l, isList := pv.([]any); anlStrictEq(pv, "*") || (isList && anlIncludes(l, "*")) {
			verbs = shapeVerbs
		} else if isList {
			verbs = l
		} else {
			verbs = []any{pv}
		}
		for _, v := range verbs {
			if _, ok := lookup(v); !ok {
				sev := "error"
				if isVeto {
					sev = "warn"
				}
				add("undeclared-verb", sev, where, fmt.Sprintf("verb '%s' is not declared by the schema", anlJS(v)))
			}
		}
		var declared []map[string]any
		for _, v := range verbs {
			if s, ok := lookup(v); ok {
				declared = append(declared, s)
			}
		}
		if len(declared) == 0 {
			return
		}
		for wi, w := range anlReqList(anlNN(anlGet(p, "where"), []any{})) {
			var leaves []any
			anlLeaves(w, &leaves)
			for _, cv := range leaves {
				c, ok := anlLeaf(cv)
				if !ok || !strings.HasPrefix(c["field"].(string), "action.params.") {
					continue
				}
				name := strings.Split(c["field"].(string)[len("action.params."):], ".")[0]
				at := fmt.Sprintf("%s.where[%d]", where, wi)
				var having, lacking []map[string]any
				for _, s := range declared {
					if _, has := s["params"].(map[string]any)[name]; has {
						having = append(having, s)
					} else {
						lacking = append(lacking, s)
					}
				}
				verbNames := func(xs []map[string]any) string {
					parts := make([]string, len(xs))
					for i, s := range xs {
						parts[i] = anlJS(anlOwn(s, "verb"))
					}
					return strings.Join(parts, ", ")
				}
				if len(having) == 0 {
					add("undeclared-param", "error", at, fmt.Sprintf("parameter '%s' is declared by none of %s", name, verbNames(declared)))
					continue
				}
				if len(having) < len(declared) {
					add("undeclared-param", "warn", at, fmt.Sprintf("parameter '%s' is not declared by %s", name, verbNames(lacking)))
				}
				d := having[0]["params"].(map[string]any)[name]
				op, val := anlOwn(c, "op"), anlOwn(c, "value")
				vals := []any{val}
				if l, isList := val.([]any); isList && (op == "in" || op == "nin") {
					vals = l
				}
				dtype := anlOwn(d, "type")
				hasRef := anlHas(c, "ref")
				if !hasRef && (op == "eq" || op == "ne" || op == "in" || op == "nin" || anlIsNumericOp(op)) {
					for _, x := range vals {
						if !anlTypeOK(dtype, x) {
							add("type-mismatch", "error", at, fmt.Sprintf("'%s' is %s but is compared (%s) with %s", name, anlJS(dtype), anlJS(op), anlTypeof(x)))
						}
					}
				}
				if anlIsNumericOp(op) && !anlIsUndef(dtype) && dtype != "integer" {
					if dtype == "string" || dtype == "date" {
						add("ordering-on-string", "warn", at, fmt.Sprintf("'%s' is %s: ordering follows UTF-8 byte order", name, anlJS(dtype)))
					} else {
						add("type-mismatch", "error", at, fmt.Sprintf("ordering operator %s on %s parameter '%s'", anlJS(op), anlJS(dtype), name))
					}
				}
				dvals := anlOwn(d, "values")
				var first any = anlUndef
				if len(vals) > 0 {
					first = vals[0]
				}
				if _, firstStr := first.(string); anlTruthy(dvals) && (op == "eq" || op == "in") && firstStr {
					var missing []any
					for _, x := range vals {
						if _, isStr := x.(string); isStr && !anlIncludes(dvals, x) {
							missing = append(missing, x)
						}
					}
					if len(missing) == len(vals) {
						add("value-not-in-enum", "error", at, fmt.Sprintf("no value of %s %s is in the schema's set for '%s'", anlJS(op), anlJSON(vals), name))
					} else if len(missing) > 0 {
						add("value-not-in-enum", "warn", at, fmt.Sprintf("%s are not in the schema's set for '%s'", anlJSON(missing), name))
					}
				}
				dmin, dmax := anlOwn(d, "min"), anlOwn(d, "max")
				if dtype == "integer" && anlIsNum(val) && !hasRef {
					v := anlToNumber(val)
					hasMin, hasMax := !anlIsUndef(dmin), !anlIsUndef(dmax)
					mn, mx := anlToNumber(dmin), anlToNumber(dmax)
					dead := (op == "eq" && ((hasMax && v > mx) || (hasMin && v < mn))) ||
						(op == "gt" && hasMax && v >= mx) || (op == "gte" && hasMax && v > mx) ||
						(op == "lt" && hasMin && v <= mn) || (op == "lte" && hasMin && v < mn)
					lo, hi := "-inf", "inf"
					if hasMin && dmin != nil {
						lo = anlNumOf(dmin)
					}
					if hasMax && dmax != nil {
						hi = anlNumOf(dmax)
					}
					if dead {
						add("out-of-range", "error", at, fmt.Sprintf("'%s' %s %s can never hold: the schema bounds it to [%s, %s]", name, anlJS(op), anlNumOf(val), lo, hi))
					} else if (op == "lte" && hasMax && v >= mx) || (op == "gte" && hasMin && v <= mn) {
						add("redundant-bound", "info", at, fmt.Sprintf("'%s' %s %s never binds: the schema already bounds it to [%s, %s]", name, anlJS(op), anlNumOf(val), lo, hi))
					}
				}
				dunit := anlOwn(d, "unit")
				if anlTruthy(dunit) && !anlIsUndef(units) && (anlIsNumericOp(op) || op == "eq") && !isVeto {
					tag := anlOwn(units, c["field"].(string))
					if anlIsUndef(tag) || tag == nil {
						tag = anlOwn(units, "action.params."+name)
					}
					sch := anlUndef
					if sm, ok := schemaUnits.(map[string]any); ok {
						if us, ok := dunit.(string); ok {
							if x, has := sm[us]; has {
								sch = x
							}
						}
					}
					if anlIsUndef(tag) || tag == nil {
						add("unit-missing", "error", at, fmt.Sprintf("'%s' carries unit '%s' but the policy has no unit tag for it (rule 20)", name, anlJS(dunit)))
					} else if anlTruthy(sch) && (!anlStrictEq(anlGet(tag, "kind"), anlGet(sch, "kind")) || !anlStrictEq(anlGet(tag, "currency"), anlGet(sch, "currency")) ||
						!anlStrictEq(anlGet(tag, "exponent"), anlGet(sch, "exponent"))) {
						add("unit-mismatch", "error", at, fmt.Sprintf("'%s': policy unit %s differs from the schema's %s (rule 20)", name, anlJSON(tag), anlJSON(sch)))
					}
				}
			}
		}
	}

	for i, p := range model["predicates"].([]any) {
		if _, isMap := p.(map[string]any); !isMap {
			if _, isList := p.([]any); !isList {
				continue
			}
		}
		check(p, fmt.Sprintf("predicates[%d]", i), false)
		r := anlAlwaysDenies(map[string]any{"predicates": []any{p}}, nil, nil)
		if r["alwaysDenies"] == true && !anlTruthy(r["approximate"]) {
			add("unreachable-predicate", "warn", fmt.Sprintf("predicates[%d]", i), "no action can ever match this predicate")
		}
	}
	for i, v := range model["vetoes"].([]any) {
		check(anlGet(v, "when"), fmt.Sprintf("vetoes[%d]", i), true)
	}

	// a money verb with no ceiling in any predicate that grants it
	for _, sv := range shapes {
		s := sv.(map[string]any)
		sverb := anlOwn(s, "verb")
		params := s["params"].(map[string]any)
		var money []string
		for _, name := range jsKeys(params) {
			if anlSemanticMoney(params[name]) {
				money = append(money, name)
			}
		}
		if len(money) == 0 {
			continue
		}
		var granting []any
		for _, p := range model["predicates"].([]any) {
			if anlGrants(p, sverb) {
				granting = append(granting, p)
			}
		}
		if len(granting) == 0 {
			if listUngranted {
				add("verb-not-granted", "info", anlJS(sverb), fmt.Sprintf("the schema declares '%s' but no predicate grants it", anlJS(sverb)))
			}
			continue
		}
		for _, name := range money {
			path := "action.params." + name
			bounded := func(p any) bool {
				for _, w := range anlReqList(anlNN(anlGet(p, "where"), []any{})) {
					var srcW any = w
					if anlIsGroup(w) {
						all := anlOwn(w, "all_of")
						if anlIsUndef(all) {
							all = []any{}
						}
						srcW = map[string]any{"all_of": all}
					}
					var ls []any
					anlLeaves(srcW, &ls)
					for _, cv := range ls {
						if c, ok := anlLeaf(cv); ok && c["field"] == path {
							if op := anlOwn(c, "op"); op == "lt" || op == "lte" || op == "eq" || op == "in" {
								return true
							}
						}
					}
				}
				return false
			}
			all := true
			for _, p := range granting {
				if !bounded(p) {
					all = false
					break
				}
			}
			if !all {
				add("unbounded-money", "warn", anlJS(sverb), fmt.Sprintf("'%s' can move '%s' with no per-action ceiling in at least one granting predicate", anlJS(sverb), name))
			}
		}
	}
	if listUngranted {
		for _, sv := range shapes {
			s := sv.(map[string]any)
			isMoney := false
			for _, d := range s["params"].(map[string]any) {
				if anlSemanticMoney(d) {
					isMoney = true
					break
				}
			}
			if isMoney {
				continue
			}
			sverb := anlOwn(s, "verb")
			granted := false
			for _, p := range model["predicates"].([]any) {
				if anlGrants(p, sverb) {
					granted = true
					break
				}
			}
			if !granted {
				add("verb-not-granted", "info", anlJS(sverb), fmt.Sprintf("the schema declares '%s' but no predicate grants it", anlJS(sverb)))
			}
		}
	}
	ok := true
	for _, f := range findings {
		if f.(map[string]any)["severity"] == "error" {
			ok = false
		}
	}
	return map[string]any{"ok": ok, "findings": findings}
}
