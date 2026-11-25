package pca

// What an approver sees and what the other layers read about a def: the canonical approval render (the fields a person approves,
// with money units resolved), its digest bound to the PCActn, the facade spec of a def, and the provenance floors of its parameters.

import (
	"fmt"
	"math"
	"strings"
)

func renderErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func renderFlatten(params map[string]any) (map[string]any, []string, error) {
	out := map[string]any{}
	var order []string
	set := func(k string, v any) {
		if _, has := out[k]; !has {
			order = append(order, k)
		}
		out[k] = v
	}
	var walk func(prefix string, depth int, v any) error
	walk = func(prefix string, depth int, v any) error {
		if m, ok := v.(map[string]any); ok && depth < maxParamPathDepth && len(m) > 0 {
			for _, k := range jsKeys(m) {
				if strings.Contains(k, ".") {
					return renderErr("render_bad_params", fmt.Sprintf("the parameter key '%s' contains a dot", k))
				}
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				if err := walk(p, depth+1, m[k]); err != nil {
					return err
				}
			}
			return nil
		}
		set(prefix, v)
		return nil
	}
	for _, k := range jsKeys(params) {
		if strings.Contains(k, ".") {
			return nil, nil, renderErr("render_bad_params", fmt.Sprintf("the parameter key '%s' contains a dot", k))
		}
		if err := walk(k, 1, params[k]); err != nil {
			return nil, nil, err
		}
	}
	return out, order, nil
}

func renderSafeInt(v any) bool {
	f, ok := jsNum(v)
	return ok && f == math.Trunc(f) && math.Abs(f) <= 9007199254740991 && !(f == 0 && math.Signbit(f))
}

func renderLeaf(v any) bool {
	switch t := v.(type) {
	case string:
		return !hasLoneSurrogate(t)
	case bool:
		return true
	case []any:
		for _, x := range t {
			if !renderLeaf(x) {
				return false
			}
		}
		return true
	}
	return renderSafeInt(v)
}

func actionsRenderValueOK(typ string, v any) bool {
	switch typ {
	case "integer", "duration":
		return renderSafeInt(v)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "string", "date", "datetime", "object_ref":
		s, ok := v.(string)
		return ok && !hasLoneSurrogate(s)
	case "set", "array":
		l, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range l {
			if !renderLeaf(x) {
				return false
			}
		}
		return true
	}
	return false
}

// ActionRenderApproval is the canonical approval render of a call to the def: every parameter as {id, class, value, unit?} sorted by
// id, bound to the def digest, flagged unreviewed unless the def is confirmed.
func ActionRenderApproval(def, params map[string]any, confirmed ActionDiffConfirmed) (map[string]any, error) {
	if params == nil {
		return nil, renderErr("render_bad_params", "params must be an object")
	}
	n := normalizeDef(def)
	np := adParamsOf(n)
	verb := jsAnyString(n["verb"])
	flat, order, err := renderFlatten(params)
	if err != nil {
		return nil, err
	}
	for _, k := range order {
		if _, has := np[k]; !has {
			return nil, renderErr("render_undeclared_param", fmt.Sprintf("'%s' is not a parameter of %s", k, verb))
		}
	}
	pnames := make([]string, 0, len(np))
	for k := range np {
		pnames = append(pnames, k)
	}
	adSortU16(pnames)
	for _, k := range pnames {
		if p, _ := np[k].(map[string]any); p["required"] == true {
			if _, has := flat[k]; !has {
				return nil, renderErr("render_missing_param", fmt.Sprintf("required parameter '%s' of %s is missing", k, verb))
			}
		}
	}
	ids := append([]string{}, order...)
	adSortU16(ids)
	fields := make([]any, 0, len(ids))
	for _, id := range ids {
		p, _ := np[id].(map[string]any)
		typ := jsAnyString(p["type"])
		if !actionsRenderValueOK(typ, flat[id]) {
			return nil, renderErr("render_bad_value", fmt.Sprintf("'%s' is not a %s in the canonical domain (no floats, no null, no lone surrogates)", id, typ))
		}
		class := "param"
		if r, ok := p["role"].(string); ok {
			class = r
		}
		f := map[string]any{"id": id, "class": class, "value": flat[id]}
		if u, ok := p["unit"].(map[string]any); ok {
			if u["kind"] == "money" {
				ccy, isS := u["ccy"].(string)
				if !isS {
					from := ""
					if cm, ok := u["ccy"].(map[string]any); ok {
						from = jsAnyString(cm["from"])
					}
					ccy, isS = flat[from].(string)
				}
				if !isS || ccy == "" {
					return nil, renderErr("render_unresolved_currency", fmt.Sprintf("the currency of '%s' is not a string", id))
				}
				unit := map[string]any{"kind": "money", "ccy": ccy}
				if e, has := u["exp"]; has {
					unit["exp"] = e
				}
				f["unit"] = unit
			} else {
				f["unit"] = map[string]any{"kind": u["kind"]}
			}
		}
		fields = append(fields, f)
	}
	dg, err := defDigest(def)
	if err != nil {
		return nil, err
	}
	return map[string]any{"v": jsNumber(1), "kind": "pca-approval-render", "verb": n["verb"], "def_digest": dg,
		"unreviewed": !(confirmed != nil && confirmed(def)), "fields": fields}, nil
}

// ActionRenderDigestForAction is the digest of the render of params, after checking that the PCActn is for this def and signed
// exactly these params.
func ActionRenderDigestForAction(def, params, pcactn map[string]any, confirmed ActionDiffConfirmed) (string, error) {
	act, _ := pcactn["action"].(map[string]any)
	if act["verb"] != def["verb"] {
		return "", renderErr("render_verb_mismatch", fmt.Sprintf("the PCActn is for '%s', the definition for '%s'", jsAnyString(act["verb"]), jsAnyString(def["verb"])))
	}
	pd, err := ParamsDigest(params)
	if err != nil {
		return "", err
	}
	if act["params_digest"] != pd {
		return "", renderErr("render_params_mismatch", "the supplied params are not the params the PCActn signed")
	}
	r, err := ActionRenderApproval(def, params, confirmed)
	if err != nil {
		return "", err
	}
	return ApprovalRenderDigest(r)
}

// ActionApproverRenderCheck recomputes the render digest and refuses a request that committed to another render.
func ActionApproverRenderCheck(def, params map[string]any, requested any, confirmed ActionDiffConfirmed) (string, error) {
	r, err := ActionRenderApproval(def, params, confirmed)
	if err != nil {
		return "", err
	}
	d, err := ApprovalRenderDigest(r)
	if err != nil {
		return "", err
	}
	if d != requested {
		return "", renderErr("render_mismatch", "the approval request commits to a render this definition and these params do not produce")
	}
	return d, nil
}

// ActionSingleTapAllowed is whether a render may be approved with a single tap (only a reviewed def).
func ActionSingleTapAllowed(render map[string]any) bool { return !jsTruthy(render["unreviewed"]) }

// ActionRenderersFromDefs is the renderer over pinned defs, looked up by verb or alias.
func ActionRenderersFromDefs(defs []any, confirmed ActionDiffConfirmed) func(verb string, params map[string]any) (map[string]any, error) {
	byVerb := map[string]map[string]any{}
	for _, x := range defs {
		d, _ := x.(map[string]any)
		byVerb[jsAnyString(d["verb"])] = d
		al, _ := strsOf(d["aliases"])
		for _, a := range al {
			if _, has := byVerb[a]; !has {
				byVerb[a] = d
			}
		}
	}
	return func(verb string, params map[string]any) (map[string]any, error) {
		d := byVerb[verb]
		if d == nil {
			return nil, renderErr("render_unknown_verb", fmt.Sprintf("no pinned action definition for '%s'", verb))
		}
		if params == nil {
			params = map[string]any{}
		}
		return ActionRenderApproval(d, params, confirmed)
	}
}

// ActionSpecOfDef is the facade spec of a def (connector, action, verb, effective reversibility and blast, amount field, aliases,
// traits). reviewed reads the def as a reviewer would sign it (the hint view) instead of its effective (unconfirmed = worst) view.
func ActionSpecOfDef(d map[string]any, reg Registry, reviewed bool, confirmed ActionDiffConfirmed) (map[string]any, error) {
	full, err := adEffective(d, reg, confirmed)
	if err != nil {
		return nil, err
	}
	eff, cl := full.eff, full.closure
	if reviewed {
		eff, cl = full.hintEff, full.hintCl
	}
	verb := jsAnyString(d["verb"])
	connector, action, _ := strings.Cut(verb, ".")
	out := map[string]any{"connector": connector, "action": action, "verb": d["verb"], "reversibility": eff.Rev,
		"blastRadius": jsNumber(float64(eff.Blast) / 1_000_000)}
	if name, err := ActionParamByRole(d, "money.amount"); err == nil {
		out["amountField"] = name
	}
	if desc, has := d["description"]; has {
		out["description"] = desc
	} else {
		out["description"] = d["title"]
	}
	if al, _ := strsOf(d["aliases"]); len(al) > 0 {
		s := append([]string{}, al...)
		adSortU16(s)
		out["aliases"] = anyStrs(s)
	}
	out["traits"] = anyStrs(cl)
	return out, nil
}

// ActionProvenanceInfoOf is what the provenance gate reads about a def: its effects, effective traits and the provenance floor of
// each parameter. An unconfirmed def has no effects (and the worst traits).
func ActionProvenanceInfoOf(d map[string]any, reg Registry, confirmed ActionDiffConfirmed) (map[string]any, error) {
	eff, err := adEffective(d, reg, confirmed)
	if err != nil {
		return nil, err
	}
	if !eff.confirmed {
		return map[string]any{"effects": []any{}, "traits": anyStrs(eff.traits)}, nil
	}
	n := normalizeDef(d)
	params := map[string]any{}
	for name, pv := range adParamsOf(n) {
		if p, _ := pv.(map[string]any); p != nil {
			if pm, has := p["provenance_min"]; has {
				params[name] = pm
			}
		}
	}
	out := map[string]any{"effects": anyStrs(adStrs(n, "effects")), "traits": anyStrs(eff.traits)}
	if len(params) > 0 {
		out["params"] = params
	}
	return out, nil
}

// ActionProvenanceActions is the provenance lookup over a set of defs (by verb or alias); two defs claiming one verb are an error.
func ActionProvenanceActions(defs []any, reg Registry, confirmed ActionDiffConfirmed) (func(verb string) map[string]any, error) {
	byVerb := map[string]map[string]any{}
	for _, x := range defs {
		d, _ := x.(map[string]any)
		n := normalizeDef(d)
		info, err := ActionProvenanceInfoOf(d, reg, confirmed)
		if err != nil {
			return nil, err
		}
		for _, v := range append([]string{jsAnyString(n["verb"])}, adStrs(n, "aliases")...) {
			if _, has := byVerb[v]; has {
				return nil, fmt.Errorf("provenanceActions: two definitions claim the verb '%s'", v)
			}
			byVerb[v] = info
		}
	}
	return func(verb string) map[string]any { return byVerb[verb] }, nil
}
