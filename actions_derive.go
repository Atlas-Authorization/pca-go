package pca

// Derivations from action definitions: the flattened call parameters, the operation a call is (verb, resource, params), the
// schema verb / document and ontology, the risk inputs, the human card, escalation tier and MCP annotations. Definitions are JSON
// objects (map[string]any); `confirmed` is the attestation check (nil = never: an unconfirmed def is the most dangerous kind).

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

var (
	actionEscTiers  = []string{"auto", "confirm", "cosign", "stepup"}
	actionRiskNames = []string{"low", "elevated", "high", "critical"}
)

const maxParamPathDepth = 3

// ActionReversibilityScore is the score of each reversibility class.
func ActionReversibilityScore() map[string]any {
	return map[string]any{"reversible": jsNumber(1), "rate_limited": jsNumber(0.4), "irreversible": jsNumber(0)}
}

// ActionFlattenParams turns nested call parameters into dotted names, up to depth 3; arrays, null, scalars and empty objects are leaves.
func ActionFlattenParams(params map[string]any) map[string]any {
	out := map[string]any{}
	var walk func(prefix string, depth int, v any)
	walk = func(prefix string, depth int, v any) {
		if m, ok := v.(map[string]any); ok && depth < maxParamPathDepth && len(m) > 0 {
			for _, k := range jsKeys(m) {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, depth+1, m[k])
			}
			return
		}
		out[prefix] = v
	}
	for _, k := range jsKeys(params) {
		walk(k, 1, params[k])
	}
	return out
}

func adParamsOf(d map[string]any) map[string]any { m, _ := d["params"].(map[string]any); return m }

func adNamesWithRole(d map[string]any, role string) []string {
	var hits []string
	for name, pv := range adParamsOf(d) {
		if p, _ := pv.(map[string]any); p["role"] == role {
			hits = append(hits, name)
		}
	}
	adSortU16(hits)
	return hits
}

// ActionParamByRole is the one parameter of the def with the role (an error when none or several).
func ActionParamByRole(d map[string]any, role string) (string, error) {
	hits := adNamesWithRole(d, role)
	switch {
	case len(hits) == 0:
		return "", &CodedError{Code: "no_param", Msg: fmt.Sprintf("'%s' has no parameter with role %s", jsAnyString(d["verb"]), role)}
	case len(hits) > 1:
		return "", &CodedError{Code: "ambiguous_param", Msg: fmt.Sprintf("'%s' has several parameters with role %s", jsAnyString(d["verb"]), role)}
	}
	return hits[0], nil
}

// ActionEffectClass is read, reversible, external_send or irreversible.
func ActionEffectClass(d map[string]any) string {
	n := normalizeDef(d)
	ef := adStrs(n, "effects")
	if isReadOnlyEffects(ef) {
		return "read"
	}
	if worstReversibility(n["reversibility"], adParamsOf(n)) == "irreversible" {
		return "irreversible"
	}
	for _, e := range ef {
		if e == "send" || e == "publish" || e == "export" {
			return "external_send"
		}
	}
	return "reversible"
}

func adUnitID(p map[string]any) (string, bool) {
	u, ok := p["unit"].(map[string]any)
	if !ok {
		return "", false
	}
	if u["kind"] != "money" {
		k, isS := u["kind"].(string)
		return k, isS
	}
	if c, ok := u["ccy"].(string); ok {
		return "money." + strings.ToLower(c), true
	}
	return "", false
}

func adUnitDecl(p map[string]any) map[string]any {
	u, _ := p["unit"].(map[string]any)
	if u["kind"] != "money" {
		return map[string]any{"kind": u["kind"]}
	}
	out := map[string]any{"kind": "money", "currency": u["ccy"]}
	if e, has := u["exp"]; has {
		out["exponent"] = e
	}
	return out
}

func adParamDecl(n map[string]any) map[string]any {
	role, hasRole := n["role"].(string)
	semantic := "generic." + jsAnyString(n["type"])
	if hasRole {
		semantic = role
	}
	d := map[string]any{"type": n["type"], "semantic": semantic, "sensitivity": n["sensitivity"]}
	if n["required"] == false {
		d["required"] = false
	}
	if v, ok := n["values"].([]any); ok {
		d["values"] = append([]any{}, v...)
	}
	for _, k := range []string{"min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description"} {
		if v, has := n[k]; has {
			d[k] = v
		}
	}
	if id, ok := adUnitID(n); ok {
		d["unit"] = id
	}
	if a, ok := n["accumulates"].([]any); ok {
		d["accumulates_into"] = append([]any{}, a...)
	}
	if hasRole {
		d["role"] = role
	}
	if t, ok := n["tags"].([]any); ok {
		d["tags"] = append([]any{}, t...)
	}
	return d
}

// ActionToSchemaVerb is the schema verb declaration of a def and the units its parameters use.
func ActionToSchemaVerb(d map[string]any, reg Registry, confirmed ActionDiffConfirmed) (verb map[string]any, units map[string]any, err error) {
	n := normalizeDef(d)
	eff, err := adEffective(d, reg, confirmed)
	if err != nil {
		return nil, nil, err
	}
	params, units := map[string]any{}, map[string]any{}
	np := adParamsOf(n)
	for _, name := range jsKeys(np) {
		p, _ := np[name].(map[string]any)
		params["action.params."+name] = adParamDecl(p)
		if id, ok := adUnitID(p); ok {
			units[id] = adUnitDecl(p)
		}
	}
	ef := adStrs(n, "effects")
	kind := "write"
	if isReadOnlyEffects(ef) {
		kind = "read"
	}
	dg, err := defDigest(d)
	if err != nil {
		return nil, nil, err
	}
	v := map[string]any{"verb": n["verb"], "kind": kind, "params": params, "effects": anyStrs(ef), "traits": anyStrs(eff.traits), "def": dg,
		"floors": eff.eff.raw()}
	if rv, _ := d["review"].(map[string]any); eff.confirmed {
		if a, ok := rv["attestation"].(map[string]any); ok {
			if _, signed := a["sig"]; signed {
				v["confirmation"] = a
			}
		}
	}
	switch r := n["reversibility"].(type) {
	case string:
		v["reversibility"] = r
	case map[string]any:
		by := map[string]any{"param": "action.params." + jsAnyString(r["by"]), "map": deepCopy(r["map"])}
		if dv, has := r["default"]; has {
			by["default"] = dv
		}
		v["reversibility_by"] = by
	}
	b, _ := n["bindings"].(map[string]any)
	if m, ok := b["mcp"].(map[string]any); ok && m != nil {
		v["mcp"] = map[string]any{"tool": m["tool"]}
	}
	if m, ok := b["openapi"].(map[string]any); ok && m != nil {
		v["openapi"] = map[string]any{"operationId": m["operationId"]}
	}
	if desc, has := n["description"]; has {
		v["description"] = desc
	}
	return v, units, nil
}

// ActionToSchemaDoc is the unsigned action schema document of a set of defs; meta is {site, aud, version, pack?}.
func ActionToSchemaDoc(defs []any, reg Registry, meta map[string]any, confirmed ActionDiffConfirmed) (map[string]any, error) {
	sorted := append([]any{}, defs...)
	verbOf := func(x any) string { m, _ := x.(map[string]any); return jsAnyString(m["verb"]) }
	sort.SliceStable(sorted, func(i, j int) bool { return u16Less(verbOf(sorted[i]), verbOf(sorted[j])) })
	verbs := []any{}
	units := map[string]any{}
	seen := map[string]bool{}
	for _, x := range sorted {
		d, _ := x.(map[string]any)
		v := jsAnyString(d["verb"])
		if seen[v] {
			return nil, &CodedError{Code: "duplicate_verb", Msg: fmt.Sprintf("verb '%s' appears twice", v)}
		}
		seen[v] = true
		sv, su, err := ActionToSchemaVerb(d, reg, confirmed)
		if err != nil {
			return nil, err
		}
		verbs = append(verbs, sv)
		for id, uv := range su {
			u := uv.(map[string]any)
			if prev, has := units[id].(map[string]any); has {
				if !jsStrictEq(prev["kind"], u["kind"]) || !jsStrictEq(prev["currency"], u["currency"]) || !jsStrictEq(prev["exponent"], u["exponent"]) {
					return nil, &CodedError{Code: "unit_conflict", Msg: fmt.Sprintf("unit '%s' is declared with two different definitions", id)}
				}
			}
			units[id] = u
		}
	}
	var custom []string
	for id := range reg {
		if !strings.HasPrefix(id, "pca.") {
			custom = append(custom, id)
		}
	}
	adSortU16(custom)
	td, err := traitsDigest(reg)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{"v": jsNumber(2), "kind": "pca-action-schema", "site": meta["site"], "aud": meta["aud"], "version": meta["version"]}
	if len(units) > 0 {
		doc["units"] = units
	}
	doc["verbs"] = verbs
	doc["traits_digest"] = td
	if len(custom) > 0 {
		defsOut := make([]any, len(custom))
		for i, id := range custom {
			defsOut[i] = reg[id].raw()
		}
		doc["trait_defs"] = defsOut
	}
	if p, has := meta["pack"]; has {
		doc["pack"] = p
	}
	return doc, nil
}

// ActionOperationOf is the operation (verb, resource, the declared params) a call to the def is.
func ActionOperationOf(d map[string]any, callParams map[string]any) map[string]any {
	flat := ActionFlattenParams(callParams)
	pd := adParamsOf(d)
	declared := make([]string, 0, len(pd))
	for k := range pd {
		declared = append(declared, k)
	}
	adSortU16(declared)
	params := map[string]any{}
	for _, k := range declared {
		if v, has := flat[k]; has {
			params[k] = v
		}
	}
	res, _ := d["resource"].(map[string]any)
	typ := jsAnyString(res["type"])
	id, scope := res["id"], res["scope"]
	var resource string
	if e, ok := adExact(id); ok && id != "*" {
		resource = typ + ":" + e
	} else {
		var idParam string
		found := false
		for _, n := range declared {
			if p, _ := pd[n].(map[string]any); p["role"] == "id."+typ {
				idParam, found = n, true
				break
			}
		}
		val, isStr := any(nil), false
		if found {
			val = params[idParam]
			_, isStr = val.(string)
		}
		switch {
		case isStr:
			if !ActionIDMatches(id, val.(string)) {
				return map[string]any{"ok": false, "reason": fmt.Sprintf("the id '%s' does not match the resource pattern of %s", val.(string), jsAnyString(d["verb"]))}
			}
			resource = typ + ":" + val.(string)
		case scope != "one":
			resource = typ + ":*"
		default:
			return map[string]any{"ok": false, "reason": fmt.Sprintf("%s needs a parameter with role id.%s to name its resource", jsAnyString(d["verb"]), typ)}
		}
	}
	return map[string]any{"ok": true, "op": map[string]any{"verb": d["verb"], "resource": resource, "params": params}}
}

func adUnit01(x float64) float64 { return math.Min(1, math.Max(0, x)) }

// ActionRiskOf is the risk inputs of a call: the reversibility score, the blast radius (from the amount against kappa for a money
// action) and the confidence; opts carries kappa and taint (nil = absent).
func ActionRiskOf(d map[string]any, confirmed ActionDiffConfirmed, params map[string]any, kappa, taint any) (map[string]any, error) {
	eff, err := adEffective(d, coreRegistry, confirmed)
	if err != nil {
		return nil, err
	}
	blast := adUnit01(float64(eff.eff.Blast) / 1_000_000)
	if hits := adNamesWithRole(d, "money.amount"); len(hits) > 0 {
		var flat map[string]any
		if params != nil {
			flat = ActionFlattenParams(params)
		}
		amount, has := flat[hits[0]]
		af, aok := jsNum(amount)
		kf, kok := jsNum(kappa)
		if has && aok && !math.IsNaN(af) && !math.IsInf(af, 0) && af >= 0 && kok && kf > 0 {
			blast = adUnit01(af / kf)
		} else {
			blast = 1
		}
	}
	score, _ := jsNum(ActionReversibilityScore()[eff.eff.Rev])
	out := map[string]any{"reversibility": jsNumber(score), "blastRadius": jsNumber(blast), "confidence": jsNumber(1)}
	if tf, ok := jsNum(taint); ok && !math.IsNaN(tf) && !math.IsInf(tf, 0) {
		out["taint"] = jsNumber(adUnit01(tf))
	}
	return out, nil
}

// ActionResourceMatcher is the resource pattern string of a def (type:*, type:exact or type:prefix*).
func ActionResourceMatcher(d map[string]any) string {
	res, _ := d["resource"].(map[string]any)
	typ := jsAnyString(res["type"])
	if res["id"] == "*" {
		return typ + ":*"
	}
	if e, ok := adExact(res["id"]); ok {
		return typ + ":" + e
	}
	prefix, _, _, _ := adIDParts(res["id"])
	return typ + ":" + prefix + "*"
}

// ActionPredicatesOf is the grant predicate of a def; with maxAmount (a non-negative safe integer) it carries the amount bounds.
func ActionPredicatesOf(d map[string]any, maxAmount any) (map[string]any, error) {
	out := map[string]any{"verb": d["verb"], "resource": ActionResourceMatcher(d)}
	if maxAmount != nil {
		f, ok := jsNum(maxAmount)
		if !ok || f != math.Trunc(f) || math.Abs(f) > 9007199254740991 || f < 0 {
			return nil, &CodedError{Code: "bad_limit", Msg: "max_amount must be a non-negative safe integer"}
		}
		name, err := ActionParamByRole(d, "money.amount")
		if err != nil {
			return nil, err
		}
		field := "action.params." + name
		out["where"] = []any{map[string]any{"field": field, "op": "lte", "value": maxAmount}, map[string]any{"field": field, "op": "gte", "value": jsNumber(0)}}
	}
	return out, nil
}

func adOntParam(d map[string]any, p map[string]any) map[string]any {
	if u, ok := p["unit"].(map[string]any); ok {
		if u["kind"] == "money" {
			if c, ok := u["ccy"].(string); ok {
				return map[string]any{"kind": "money", "ccys": []any{c}}
			}
			from := ""
			if cm, ok := u["ccy"].(map[string]any); ok {
				from = jsAnyString(cm["from"])
			}
			ccys := []string{}
			if cp, _ := adParamsOf(d)[from].(map[string]any); cp != nil {
				if vs, ok := strsOf(cp["values"]); ok {
					ccys = append(ccys, vs...)
					adSortU16(ccys)
				}
			}
			return map[string]any{"kind": "money", "ccys": anyStrs(ccys)}
		}
		switch u["kind"] {
		case "duration", "bytes", "ratio":
			return map[string]any{"kind": u["kind"]}
		}
		return map[string]any{"kind": "count"}
	}
	if r, ok := p["role"].(string); ok && strings.HasPrefix(r, "id.") {
		return map[string]any{"kind": "id", "of": r[3:]}
	}
	if f, ok := p["format"].(string); ok && strings.HasPrefix(f, "id:") {
		return map[string]any{"kind": "id", "of": f[3:]}
	}
	sortedVals := func() []any {
		vs, _ := strsOf(p["values"])
		vs = append([]string{}, vs...)
		adSortU16(vs)
		return anyStrs(vs)
	}
	switch p["type"] {
	case "duration":
		return map[string]any{"kind": "duration"}
	case "datetime", "date":
		return map[string]any{"kind": "instant"}
	case "integer":
		return map[string]any{"kind": "count"}
	case "boolean":
		return map[string]any{"kind": "enum", "values": []any{"false", "true"}}
	case "set":
		return map[string]any{"kind": "enum", "values": sortedVals()}
	case "string":
		if _, has := p["values"]; has && p["values"] != nil {
			return map[string]any{"kind": "enum", "values": sortedVals()}
		}
	}
	return map[string]any{"kind": "text"}
}

// ActionToOntology is the ontology (types, units, verbs, aliases, effective traits) of a set of defs.
func ActionToOntology(defs []any, reg Registry, confirmed ActionDiffConfirmed) (map[string]any, error) {
	sorted := append([]any{}, defs...)
	verbOf := func(x any) string { m, _ := x.(map[string]any); return jsAnyString(m["verb"]) }
	sort.SliceStable(sorted, func(i, j int) bool { return u16Less(verbOf(sorted[i]), verbOf(sorted[j])) })
	var typeOrder []string
	typePrefix := map[string]string{}
	units, aliases, traits := map[string]any{}, map[string]any{}, map[string]any{}
	verbs := []any{}
	for _, x := range sorted {
		d, _ := x.(map[string]any)
		res, _ := d["resource"].(map[string]any)
		typ := jsAnyString(res["type"])
		prefix := ""
		if _, isExact := adExact(res["id"]); res["id"] != "*" && !isExact {
			prefix, _, _, _ = adIDParts(res["id"])
		}
		if _, seen := typePrefix[typ]; !seen {
			typePrefix[typ] = prefix
			typeOrder = append(typeOrder, typ)
		}
		pd := adParamsOf(d)
		params := map[string]any{}
		names := make([]string, 0, len(pd))
		for k := range pd {
			names = append(names, k)
		}
		adSortU16(names)
		for _, name := range names {
			p, _ := pd[name].(map[string]any)
			params[name] = adOntParam(d, p)
			if u, ok := p["unit"].(map[string]any); ok {
				if c, isS := u["ccy"].(string); u["kind"] == "money" && isS {
					m := map[string]any{"kind": "money"}
					if e, has := u["exp"]; has {
						m["exponent"] = e
					}
					units[c] = m
				} else if u["kind"] != "money" {
					units[jsAnyString(u["kind"])] = map[string]any{"kind": u["kind"]}
				}
			}
		}
		verbs = append(verbs, map[string]any{"id": d["verb"], "effect": ActionEffectClass(d), "resource_type": res["type"], "params": params})
		if al, ok := strsOf(d["aliases"]); ok {
			for _, a := range al {
				if prev, has := aliases[a]; has && prev != d["verb"] {
					return nil, &CodedError{Code: "alias_collision", Msg: fmt.Sprintf("alias '%s' names two verbs", a)}
				}
				aliases[a] = d["verb"]
			}
		}
		eff, err := adEffective(d, reg, confirmed)
		if err != nil {
			return nil, err
		}
		traits[jsAnyString(d["verb"])] = anyStrs(eff.traits)
	}
	types := make([]any, len(typeOrder))
	for i, t := range typeOrder {
		types[i] = map[string]any{"id": t, "id_prefix": typePrefix[t]}
	}
	return map[string]any{"types": types, "units": units, "verbs": verbs, "aliases": aliases, "traits": traits}, nil
}

func adSentence(s string) string {
	if s != "" && strings.ContainsRune(".!?", rune(s[len(s)-1])) {
		return s
	}
	return s + "."
}

func adList(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

// ActionCardOf is the human card of a def: its title, a sentence on what the effective traits do, and the floors.
func ActionCardOf(d map[string]any, confirmed ActionDiffConfirmed, reg Registry) (map[string]any, error) {
	eff, err := adEffective(d, reg, confirmed)
	if err != nil {
		return nil, err
	}
	ids := append([]string{}, eff.closure...)
	sort.SliceStable(ids, func(i, j int) bool {
		a, b := reg[ids[i]], reg[ids[j]]
		if a.Floor.Risk != b.Floor.Risk {
			return a.Floor.Risk > b.Floor.Risk
		}
		return u16Less(a.ID, b.ID)
	})
	var phrases []string
	seen := map[string]bool{}
	for _, id := range ids {
		if c := reg[id].Card; !seen[c] {
			seen[c] = true
			phrases = append(phrases, c)
		}
	}
	e := eff.eff
	var second string
	switch {
	case eff.confirmed && len(phrases) > 0:
		second = "This action " + adList(phrases) + "."
	case eff.confirmed:
		second = "This action only reads."
	default:
		second = "This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it " + adList(phrases) + "."
	}
	return map[string]any{"verb": d["verb"], "title": d["title"], "text": adSentence(jsAnyString(d["title"])) + " " + second,
		"risk": actionRiskNames[e.Risk], "escalation": actionEscTiers[e.Esc], "reversibility": e.Rev, "blast_ppm": jsNumber(float64(e.Blast)),
		"needs": anyStrs(e.Caveats), "context": anyStrs(e.Context)}, nil
}

// ActionEscalationOf is the escalation tier (number and name) of a def.
func ActionEscalationOf(d map[string]any, confirmed ActionDiffConfirmed) (map[string]any, error) {
	eff, err := adEffective(d, coreRegistry, confirmed)
	if err != nil {
		return nil, err
	}
	return map[string]any{"tier": jsNumber(float64(eff.eff.Esc)), "name": actionEscTiers[eff.eff.Esc]}, nil
}

// ActionMcpAnnotationsOf is the MCP tool annotations of a def (the hints that depend on review are false until confirmed).
func ActionMcpAnnotationsOf(d map[string]any, confirmed ActionDiffConfirmed) (map[string]any, error) {
	eff, err := adEffective(d, coreRegistry, confirmed)
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, t := range eff.closure {
		has[t] = true
	}
	ef := adStrs(d, "effects")
	idem := "none"
	if im, ok := d["idempotency"].(map[string]any); ok {
		idem = jsAnyString(im["mode"])
	}
	return map[string]any{
		"readOnlyHint":    eff.confirmed && isReadOnlyEffects(ef),
		"destructiveHint": has["pca.destructive"],
		"idempotentHint":  eff.confirmed && (idem != "none" || isReadOnlyEffects(ef)),
		"openWorldHint":   has["pca.network_egress"] || has["pca.external_communication"],
	}, nil
}

func adBlastText(ppm int) string {
	if ppm%1000 == 0 {
		return fmt.Sprintf("%dk", ppm/1000)
	}
	return fmt.Sprintf("%dppm", ppm)
}

// ActionExplainDef is the plain-language explanation of a def: its card, effective floors, what a grant and a call must carry,
// the traits and the review state (an unconfirmed def also says what it would be as written).
func ActionExplainDef(d map[string]any, reg Registry, confirmed ActionDiffConfirmed) (string, error) {
	eff, err := adEffective(d, reg, confirmed)
	if err != nil {
		return "", err
	}
	card, err := ActionCardOf(d, confirmed, reg)
	if err != nil {
		return "", err
	}
	e := eff.eff
	rev := "reversible"
	switch e.Rev {
	case "irreversible":
		rev = "irreversible"
	case "rate_limited":
		rev = "rate limited"
	}
	needs := "nothing"
	if len(e.Caveats) > 0 {
		needs = strings.Join(e.Caveats, ", ")
	}
	none := func(xs []string) string {
		if len(xs) == 0 {
			return "none"
		}
		return strings.Join(xs, ", ")
	}
	lines := []string{
		card["text"].(string),
		fmt.Sprintf("effective: risk %d, %s, blast %s, escalation: %s", e.Risk, rev, adBlastText(e.Blast), card["escalation"]),
		"grant must carry: " + needs,
	}
	if len(e.Context) > 0 {
		lines = append(lines, "call must carry: "+strings.Join(e.Context, ", "))
	}
	state := jsAnyString(eff2(d)["state"])
	lines = append(lines, "traits: "+none(eff.closure))
	if eff.confirmed {
		lines = append(lines, "review: "+state)
	} else {
		lines = append(lines, "review: "+state+", not confirmed by a signed review")
		lines = append(lines, fmt.Sprintf("until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk %d, escalation tier %d, traits: %s",
			eff.hintEff.Risk, eff.hintEff.Esc, none(eff.hintCl)))
	}
	return strings.Join(lines, "\n"), nil
}

func eff2(d map[string]any) map[string]any { r, _ := d["review"].(map[string]any); return r }
