package pca

// The example and property runner of the action packs (`pca actions test`): every def's executable examples go through the
// pipeline in process (derive the schema, conform the params, expand the floors, decide), plus the generic property checks of the
// pack: monotonicity over trait additions and subsets, one digest across the JSON and YAML forms, and the schema round trip (the
// example conforms; every mutation of it is refused). The example policy (`under`) is a small allow selector evaluated here
// ({allow: {trait|verb, where?, caveats?, context?}}); it can only pre-authorize.

import (
	"encoding/json"
	"math"
	"strings"
)

var trMeta = map[string]any{"site": "https://example.invalid", "aud": "example", "version": "0"}

// trHint is the view of the action AS REVIEWED (its hint traits): examples and properties are authoring tests, not enforcement.
func trHint(d map[string]any, reg Registry) (traits, closure []string, eff Profile, err error) {
	traits = hintTraits(d)
	if closure, err = reg.closure(traits); err != nil {
		return nil, nil, Profile{}, err
	}
	fl, err := reg.floorOf(traits)
	if err != nil {
		return nil, nil, Profile{}, err
	}
	return traits, closure, joinProfile(declProfile(d), fl), nil
}

type trSel struct {
	trait, verb string
	hasTrait    bool
	hasVerb     bool
	where       map[string]any
	caveats     []string
	context     []string
}

func trIsNum(v any) bool {
	if _, isB := v.(bool); isB {
		return false
	}
	_, ok := jsNum(v)
	return ok
}

// trParseUnder reads the example policy: the selectors, or the reason it is malformed.
func trParseUnder(under any, has bool) ([]trSel, string) {
	if !has {
		return nil, ""
	}
	u, ok := under.(map[string]any)
	if !ok {
		return nil, "under must be {allow: selector | [selector]}"
	}
	for k := range u {
		if k != "allow" {
			return nil, "under must be {allow: selector | [selector]}"
		}
	}
	list, isList := u["allow"].([]any)
	if !isList {
		list = []any{u["allow"]}
	}
	var out []trSel
	for _, x := range list {
		s, ok := x.(map[string]any)
		if !ok {
			return nil, "an allow selector has trait, verb, where, caveats, context"
		}
		for k := range s {
			if k != "trait" && k != "verb" && k != "where" && k != "caveats" && k != "context" {
				return nil, "an allow selector has trait, verb, where, caveats, context"
			}
		}
		_, hasT := s["trait"]
		_, hasV := s["verb"]
		if hasT == hasV {
			return nil, "an allow selector names exactly one of trait and verb"
		}
		sel := trSel{hasTrait: hasT, hasVerb: hasV}
		sel.trait, _ = s["trait"].(string)
		sel.verb, _ = s["verb"].(string)
		if w, has := s["where"]; has {
			wm, isM := w.(map[string]any)
			if !isM {
				return nil, "where must be an object"
			}
			sel.where = wm
		}
		if cv, has := s["caveats"]; has {
			cs, isL := strsOf(cv)
			if !isL {
				return nil, "caveats must be known caveat kinds"
			}
			for _, c := range cs {
				if !contains(caveatKinds, c) {
					return nil, "caveats must be known caveat kinds"
				}
			}
			sel.caveats = cs
		}
		sel.context, _ = strsOf(s["context"])
		out = append(out, sel)
	}
	return out, ""
}

func trDomainOf(v string) string { return strings.ToLower(v[strings.LastIndex(v, "@")+1:]) }

func trAddUniq(xs []string, add ...string) []string {
	for _, a := range add {
		if !contains(xs, a) {
			xs = append(xs, a)
		}
	}
	return xs
}

// trGrantOf is the caveats of the grant a matching allow selector stands for; ok is false when it does not match this call.
func trGrantOf(sel trSel, d map[string]any, flat map[string]any, closure []string) (caveats []string, ok bool) {
	if sel.hasTrait {
		t := sel.trait
		if !strings.Contains(t, ".") {
			t = "pca." + t
		}
		if !contains(closure, t) {
			return nil, false
		}
	}
	if sel.hasVerb && sel.verb != d["verb"] {
		return nil, false
	}
	caveats = trAddUniq(nil, sel.caveats...)
	params, _ := d["params"].(map[string]any)
	for _, key := range sortedKeysStd(sel.where) {
		cond := sel.where[key]
		dom := strings.HasSuffix(key, ".domain")
		name := key
		if dom {
			name = strings.TrimSuffix(key, ".domain")
		}
		pd, has := params[name].(map[string]any)
		if !has {
			return nil, false
		}
		v, present := flat[name]
		if !present {
			return nil, false
		}
		switch c := cond.(type) {
		case []any:
			s, isS := v.(string)
			if !isS {
				return nil, false
			}
			if dom {
				s = trDomainOf(s)
			}
			found := false
			for _, x := range c {
				if x == s {
					found = true
				}
			}
			if !found {
				return nil, false
			}
		case map[string]any:
			if !trIsNum(v) {
				return nil, false
			}
			f := jsF(v)
			if mx, has := c["max"]; has && f > jsF(mx) {
				return nil, false
			}
			if mn, has := c["min"]; has && f < jsF(mn) {
				return nil, false
			}
		default:
			return nil, false
		}
		role, _ := pd["role"].(string)
		switch {
		case strings.HasPrefix(role, "contact.") || role == "party.payee":
			caveats = trAddUniq(caveats, "recipient_scope")
		case role == "money.amount":
			caveats = trAddUniq(caveats, "amount_cap")
		case role == "count.limit":
			caveats = trAddUniq(caveats, "count_cap")
		case strings.HasPrefix(role, "id."):
			caveats = trAddUniq(caveats, "resource_scope")
		}
	}
	return caveats, true
}

// ActionDecideExample decides one example of def d ({params, expect, under?}) over the defs of its pack: {got, why}.
func ActionDecideExample(d, ex map[string]any, reg Registry, defs []any) map[string]any {
	doc, err := ActionToSchemaDoc(defs, reg, trMeta, nil)
	if err != nil {
		return map[string]any{"got": "deny", "why": err.Error()}
	}
	exParams, _ := ex["params"].(map[string]any)
	flat := ActionFlattenParams(exParams)
	c := conformAction(doc, jsAnyString(d["verb"]), flat)
	if !c.OK {
		why := "schema_violation " + c.Code
		if c.Path != "" {
			why += " (" + c.Path + ")"
		}
		return map[string]any{"got": "deny", "why": why}
	}
	if op := ActionOperationOf(d, exParams); op["ok"] != true {
		return map[string]any{"got": "deny", "why": jsAnyString(op["reason"])}
	}
	under, hasUnder := ex["under"]
	sels, bad := trParseUnder(under, hasUnder)
	if bad != "" {
		return map[string]any{"got": "deny", "why": "bad example policy: " + bad}
	}
	_, closure, eff, err := trHint(d, reg)
	if err != nil {
		return map[string]any{"got": "deny", "why": err.Error()}
	}
	var callCtx []string
	if idem, ok := d["idempotency"].(map[string]any); ok {
		if idem["mode"] == "natural" {
			callCtx = trAddUniq(callCtx, "idempotency")
		}
		if p, isS := idem["param"].(string); idem["mode"] == "key_param" && isS {
			if _, has := flat[p]; has {
				callCtx = trAddUniq(callCtx, "idempotency")
			}
		}
	}
	var grantCaveats []string
	pre := 0
	for _, s := range sels {
		g, ok := trGrantOf(s, d, flat, closure)
		if !ok {
			continue
		}
		pre = 3
		grantCaveats = trAddUniq(grantCaveats, g...)
		callCtx = trAddUniq(callCtx, s.context...)
	}
	got := floorDecision(GrantFacts{Caveats: grantCaveats, MaxEsc: 3, PreauthEsc: pre}, callCtx, eff)
	why := "floor satisfied"
	if got != "allow" {
		var need []string
		for _, k := range eff.Caveats {
			if !contains(grantCaveats, k) {
				need = append(need, k)
			}
		}
		for _, k := range eff.Context {
			if !contains(callCtx, k) {
				need = append(need, k)
			}
		}
		n := strings.Join(need, ", ")
		if n == "" {
			n = "escalation tier " + jsNumberString(float64(eff.Esc))
		}
		why = "floor needs " + n
	}
	return map[string]any{"got": got, "why": why}
}

type trMutation struct {
	name   string
	params map[string]any
}

func trCopyWith(flat map[string]any, k string, v any) map[string]any {
	c := make(map[string]any, len(flat)+1)
	for x, y := range flat {
		c[x] = y
	}
	c[k] = v
	return c
}

// trMutations are the single-fault mutations of a conforming example.
func trMutations(d, flat map[string]any) []trMutation {
	out := []trMutation{{"extra param", trCopyWith(flat, "zz_undeclared", "x")}}
	params, _ := d["params"].(map[string]any)
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	adSortU16(keys)
	for _, k := range keys {
		pd, ok := params[k].(map[string]any)
		if !ok {
			continue
		}
		if pd["required"] != false {
			c := make(map[string]any, len(flat))
			for x, y := range flat {
				if x != k {
					c[x] = y
				}
			}
			out = append(out, trMutation{"missing " + k, c})
		}
		v := flat[k]
		var swap any = map[string]any{}
		if _, isS := v.(string); isS {
			swap = jsNumber(12345)
		} else if _, isB := v.(bool); isB || trIsNum(v) {
			swap = "x"
		}
		out = append(out, trMutation{"type swap " + k, trCopyWith(flat, k, swap)})
		if trIsNum(v) && pd["type"] == "integer" {
			if mx, has := pd["max"]; has && mx != nil {
				out = append(out, trMutation{"above max " + k, trCopyWith(flat, k, jsNumber(jsF(mx)+1))})
			}
			if mn, has := pd["min"]; has && mn != nil {
				out = append(out, trMutation{"below min " + k, trCopyWith(flat, k, jsNumber(jsF(mn)-1))})
			}
		}
		if _, isS := v.(string); isS && pd["type"] == "string" {
			if vs, has := pd["values"]; has && meshTruthy(vs) {
				out = append(out, trMutation{"outside values " + k, trCopyWith(flat, k, "not_a_listed_value_zz")})
			}
			if ml, has := pd["max_len"]; has && ml != nil {
				out = append(out, trMutation{"too long " + k, trCopyWith(flat, k, strings.Repeat("x", int(jsF(ml))+1))})
			}
		}
	}
	return out
}

func trProp(verb, name string, ok bool, detail string) any {
	return map[string]any{"verb": verb, "name": name, "ok": ok, "detail": detail}
}

// trDigestOf is the digest of the first def a load result holds, "" when it has errors or none.
func trLoadedDigest(r map[string]any) (digest string, firstErr string, ok bool) {
	errs, _ := r["errors"].([]any)
	if len(errs) > 0 {
		m, _ := errs[0].(map[string]any)
		return "", jsAnyString(m["message"]), false
	}
	defs, _ := r["defs"].([]any)
	if len(defs) == 0 {
		return "", "", false
	}
	dm, _ := defs[0].(map[string]any)
	h, err := defDigest(dm)
	return h, "", err == nil
}

// ActionRunDefTests runs the examples and the property checks of a set of defs (one pack). propLimit bounds the trait subsets tried
// per def (0 means the default of 256). The report is {examples, props, ok}.
func ActionRunDefTests(defs []any, reg Registry, propLimit int) map[string]any {
	limit := 256
	if propLimit > 0 {
		limit = propLimit
	}
	examples, props := []any{}, []any{}
	allOK := true
	for _, dv := range defs {
		d, _ := dv.(map[string]any)
		verb := jsAnyString(d["verb"])
		exs, _ := d["examples"].([]any)
		for i, xv := range exs {
			ex, _ := xv.(map[string]any)
			r := ActionDecideExample(d, ex, reg, defs)
			ok := r["got"] == ex["expect"]
			allOK = allOK && ok
			examples = append(examples, map[string]any{"verb": verb, "index": i, "expect": ex["expect"], "got": r["got"], "ok": ok, "why": r["why"]})
		}
		add := func(name string, ok bool, detail string) {
			allOK = allOK && ok
			props = append(props, trProp(verb, name, ok, detail))
		}

		// T2: adding any core trait never lowers the effective profile
		ts, _, eff, herr := trHint(d, reg)
		var lowered []string
		for _, t := range ActionCoreTraitIDs() {
			p, err := ActionEffWithTrait(d, t, reg)
			if herr != nil || err != nil || !leqProfile(eff, p) {
				lowered = append(lowered, t)
			}
		}
		add("adding a trait never lowers the profile", len(lowered) == 0, strings.Join(lowered, ", "))

		// T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
		bad := 0
		total := int(math.Min(math.Pow(2, math.Min(float64(len(ts)), 20)), float64(limit)))
		top, terr := reg.floorOf(ts)
		for mask := 0; mask < total; mask++ {
			var sub []string
			for i, t := range ts {
				if (mask>>(uint(i)%32))&1 == 1 { // 32-bit shift counts, as in the reference
					sub = append(sub, t)
				}
			}
			fl, err := reg.floorOf(sub)
			if terr != nil || err != nil || !leqProfile(fl, top) {
				bad++
			}
		}
		add("floors are monotone over trait subsets", bad == 0, jsNumberString(float64(total))+" subsets, "+jsNumberString(float64(bad))+" violations")

		// one digest across the JSON and YAML forms
		want, _ := defDigest(d)
		jb, _ := json.Marshal(d)
		jd, jerr, jok := trLoadedDigest(ActionLoadText(string(jb), "json"))
		okJ := jok && jd == want
		var yd, yerr string
		okY := false
		if text, err := ActionsDefsToYaml(strings.SplitN(verb, ".", 2)[0], []any{d}, nil); err == nil {
			var yok bool
			yd, yerr, yok = trLoadedDigest(ActionLoadText(text, "yaml"))
			okY = yok && yd == want
		} else {
			yerr = err.Error()
		}
		detail := ""
		if !(okJ && okY) {
			side := func(ok bool, e string) string {
				switch {
				case ok:
					return "ok"
				case e != "":
					return e
				}
				return "digest differs"
			}
			detail = "json " + side(okJ, jerr) + "; yaml " + side(okY, yerr)
		}
		add("one digest across JSON and YAML forms", okJ && okY, detail)

		// schema round trip: each example conforms, every mutation is refused
		if len(exs) == 0 {
			add("schema round trip", true, "skipped: no examples")
			continue
		}
		doc, err := ActionToSchemaDoc(defs, reg, trMeta, nil)
		var accepted []string
		tried := 0
		if err == nil {
			for _, xv := range exs {
				ex, _ := xv.(map[string]any)
				exParams, _ := ex["params"].(map[string]any)
				flat := ActionFlattenParams(exParams)
				if !conformAction(doc, verb, flat).OK {
					continue // a deliberately non-conforming example is a deny example
				}
				for _, m := range trMutations(d, flat) {
					tried++
					if conformAction(doc, verb, m.params).OK {
						accepted = trAddUniq(accepted, m.name)
					}
				}
			}
		}
		if err != nil {
			add("schema round trip", false, err.Error())
		} else if len(accepted) == 0 {
			add("schema round trip", true, jsNumberString(float64(tried))+" mutations refused")
		} else {
			add("schema round trip", false, "accepted: "+strings.Join(accepted, ", "))
		}
	}
	return map[string]any{"examples": examples, "props": props, "ok": allOK}
}

// ActionTestText renders a test report as PASS / FAIL lines and a summary.
func ActionTestText(r map[string]any) string {
	var lines []string
	exs, _ := r["examples"].([]any)
	for _, x := range exs {
		e, _ := x.(map[string]any)
		st := "FAIL"
		if e["ok"] == true {
			st = "PASS"
		}
		lines = append(lines, st+"  "+jsAnyString(e["verb"])+" example "+jsNumberString(jsF(e["index"])+1)+": expected "+jsAnyString(e["expect"])+", got "+jsAnyString(e["got"])+" ("+jsAnyString(e["why"])+")")
	}
	ps, _ := r["props"].([]any)
	for _, x := range ps {
		q, _ := x.(map[string]any)
		st := "FAIL"
		if q["ok"] == true {
			st = "PASS"
		}
		l := st + "  " + jsAnyString(q["verb"]) + " " + jsAnyString(q["name"])
		if det := jsAnyString(q["detail"]); det != "" {
			l += ": " + det
		}
		lines = append(lines, l)
	}
	f := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "FAIL") {
			f++
		}
	}
	lines = append(lines, jsNumberString(float64(len(lines)-f))+" passed, "+jsNumberString(float64(f))+" failed")
	return strings.Join(lines, "\n")
}
