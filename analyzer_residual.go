package pca

// Partial evaluation, residual policies and "what may I do?" discovery. Everything here is advisory: the verifier stays authoritative.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	anlUnknownVerb     = "\x00unknown-verb\x00"
	anlUnknownResource = "\x00unknown-resource\x00"
)

// anlIsUnknownPath: a path is symbolic when it is an unknown path, below one, or an ancestor of one.
func anlIsUnknownPath(path any, unknown []string) bool {
	p, ok := path.(string)
	if !ok {
		return false
	}
	for _, u := range unknown {
		if p == u || strings.HasPrefix(p, u+".") || strings.HasPrefix(u, p+".") {
			return true
		}
	}
	return false
}

// anlPE is the partial evaluation of a condition: a constant ("true" | "false" | "unknown", with its source) or a symbolic condition.
type anlPE struct {
	cond bool
	v    string
	src  any
	c    any
}

func anlPeConst(v string, src any) anlPE { return anlPE{v: v, src: src} }

func (r anlPE) isConst(v string) bool { return !r.cond && r.v == v }

func (r anlPE) out() any {
	if r.cond {
		return r.c
	}
	return r.src
}

func anlTriName(t int) string {
	switch t {
	case triTrue:
		return "true"
	case triFalse:
		return "false"
	}
	return "unknown"
}

func anlPeGroup(list any, ctx map[string]any, unk []string, c any, key, absorbing, neutral string) anlPE {
	a, ok := list.([]any)
	if !ok || len(a) == 0 {
		return anlPeConst("unknown", c)
	}
	rs := make([]anlPE, len(a))
	for i, x := range a {
		rs[i] = anlPe(x, ctx, unk)
	}
	for _, r := range rs {
		if r.isConst(absorbing) {
			return anlPeConst(absorbing, c)
		}
	}
	var kept []anlPE
	for _, r := range rs {
		if !r.isConst(neutral) {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return anlPeConst(neutral, c)
	}
	allConst := true
	for _, r := range kept {
		if r.cond {
			allConst = false
		}
	}
	if allConst {
		return anlPeConst("unknown", c)
	}
	cs := make([]any, len(kept))
	for i, r := range kept {
		cs[i] = r.out()
	}
	if len(cs) == 1 {
		return anlPE{cond: true, c: cs[0]}
	}
	return anlPE{cond: true, c: map[string]any{key: cs}}
}

func anlPe(c any, ctx map[string]any, unk []string) anlPE {
	m, isMap := c.(map[string]any)
	if _, isList := c.([]any); !isMap && !isList {
		return anlPeConst("unknown", c)
	}
	if isMap && anlIsGroup(m) {
		if anlHas(m, "all_of") {
			return anlPeGroup(m["all_of"], ctx, unk, c, "all_of", "false", "true")
		}
		if anlHas(m, "any_of") {
			return anlPeGroup(m["any_of"], ctx, unk, c, "any_of", "true", "false")
		}
		r := anlPe(m["not"], ctx, unk)
		if r.cond {
			return anlPE{cond: true, c: map[string]any{"not": r.c}}
		}
		switch r.v {
		case "true":
			return anlPeConst("false", c)
		case "false":
			return anlPeConst("true", c)
		}
		return anlPeConst("unknown", c)
	}
	if leaf, ok := anlLeaf(c); ok && (anlIsUnknownPath(leaf["field"], unk) || anlIsUnknownPath(anlOwn(leaf, "ref"), unk) || anlIsUnknownPath(anlOwn(leaf, "collection"), unk)) {
		return anlPE{cond: true, c: c}
	}
	return anlPeConst(anlTriName(evaluateConditionTri(c, ctx, &regexBudget{})), c)
}

// anlPeAll is the AND of a `where` list: ("v", "true" | "false" | "unknown", nil) or ("cs", "", symbolic conditions).
func anlPeAll(where any, ctx map[string]any, unk []string) (string, string, []any) {
	if anlIsUndef(where) {
		return "v", "true", nil
	}
	list, ok := where.([]any)
	if !ok {
		return "v", "unknown", nil
	}
	rs := make([]anlPE, len(list))
	for i, w := range list {
		rs[i] = anlPe(w, ctx, unk)
	}
	for _, r := range rs {
		if r.isConst("false") {
			return "v", "false", nil
		}
	}
	var kept []anlPE
	for _, r := range rs {
		if !r.isConst("true") {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return "v", "true", nil
	}
	allConst := true
	for _, r := range kept {
		if r.cond {
			allConst = false
		}
	}
	if allConst {
		return "v", "unknown", nil
	}
	cs := make([]any, len(kept))
	for i, r := range kept {
		cs[i] = r.out()
	}
	return "cs", "", cs
}

func anlContextOfKnown(k any) map[string]any {
	verb, resource := anlGet(k, "verb"), anlGet(k, "resource")
	params, subj, env, rc := anlGet(k, "params"), anlGet(k, "subject"), anlGet(k, "env"), anlGet(k, "reversibilityClass")
	action := map[string]any{"verb": verb, "resource": resource, "params": anlSpread(anlUndefToNil(params))}
	if anlIsUndef(verb) || verb == nil {
		action["verb"] = anlUnknownVerb
	}
	if anlIsUndef(resource) || resource == nil {
		action["resource"] = anlUnknownResource
	}
	if !anlIsUndef(rc) {
		action["reversibility_class"] = rc
	}
	return map[string]any{"action": action, "subject": anlSpread(anlUndefToNil(subj)), "env": anlSpread(anlUndefToNil(env))}
}

func anlPolicyDigestOf(model map[string]any) string {
	meet := []any{}
	for _, m := range model["meets"].([]any) {
		meet = append(meet, anlPolicyDigestOf(m.(map[string]any)))
	}
	h, err := HashCanonical(map[string]any{
		"predicates": model["predicates"], "caveats": model["caveats"], "vetoes": model["vetoes"], "tighten": model["tighten"], "meet": meet,
	})
	if err != nil {
		anlFail("policy digest: %v", err)
	}
	return h
}

func anlFlatten(m map[string]any) []map[string]any {
	out := []map[string]any{m}
	for _, x := range m["meets"].([]any) {
		out = append(out, anlFlatten(x.(map[string]any))...)
	}
	return out
}

// anlPm is predicate_matches over a {verb, resource} pattern (an undefined member is left out).
func anlPm(verb, resource any, ctx map[string]any) bool {
	pat := map[string]any{}
	if !anlIsUndef(verb) {
		pat["verb"] = verb
	}
	if !anlIsUndef(resource) {
		pat["resource"] = resource
	}
	return predicateMatches(pat, ctx, &regexBudget{})
}

func anlResidualPart(part map[string]any, ctx map[string]any, unk []string, verbKnown, resKnown bool) map[string]any {
	predicates := []any{}
	for _, p := range part["predicates"].([]any) {
		_, isMap := p.(map[string]any)
		_, isList := p.([]any)
		if !isMap && !isList {
			continue
		}
		pv, pr := anlGet(p, "verb"), anlGet(p, "resource")
		if verbKnown && !anlPm(pv, "*", ctx) {
			continue
		}
		if resKnown && !anlPm("*", pr, ctx) {
			continue
		}
		kind, v, cs := anlPeAll(anlGet(p, "where"), ctx, unk)
		if kind == "v" && v != "true" {
			continue // false and unknown both fail closed for a permit
		}
		var verb any = pv
		if verbKnown {
			verb = "*"
		}
		item := anlU(map[string]any{"verb": verb})
		if !resKnown && !anlIsUndef(pr) {
			item["resource"] = pr
		}
		if kind == "cs" {
			item["where"] = cs
		}
		predicates = append(predicates, item)
	}
	vetoes := []any{}
	for _, v := range part["vetoes"].([]any) {
		if r := anlPeVeto(v, ctx, unk, verbKnown, resKnown); r != nil {
			vetoes = append(vetoes, r)
		}
	}
	tighten := []any{}
	for _, t := range part["tighten"].([]any) {
		tw := anlGet(t, "when")
		var in any = tw
		if anlIsUndef(tw) {
			in = nil
		}
		r := anlPe(in, ctx, unk)
		if r.isConst("false") {
			continue // a veto-polarity rule that cleanly cannot hold
		}
		nt := anlSpread(t)
		if r.cond {
			nt["when"] = r.c
		} else {
			nt["when"] = tw
		}
		tighten = append(tighten, anlU(nt))
	}
	return map[string]any{"predicates": predicates, "caveats": part["caveats"], "vetoes": vetoes, "tighten": tighten}
}

func anlPeVeto(v any, ctx map[string]any, unk []string, verbKnown, resKnown bool) map[string]any {
	when := anlGet(v, "when")
	wv := anlGet(when, "verb")
	if verbKnown && !anlPm(wv, "*", ctx) {
		return nil
	}
	wr := anlGet(when, "resource")
	if resKnown && !anlIsUndef(wr) && !anlPm("*", wr, ctx) {
		return nil
	}
	kind, val, cs := anlPeAll(anlGet(when, "where"), ctx, unk)
	if kind == "v" && val == "false" {
		return nil // veto polarity: a clean false removes the veto; true and unknown mean it applies
	}
	var verb any = wv
	if verbKnown {
		verb = "*"
	}
	nw := anlU(map[string]any{"verb": verb})
	if !resKnown && !anlIsUndef(wr) {
		nw["resource"] = wr
	}
	if kind == "cs" {
		nw["where"] = cs
	}
	out := anlU(map[string]any{"id": anlGet(v, "id"), "kind": anlGet(v, "kind"), "when": nw})
	if over := anlGet(v, "over"); anlTruthy(over) {
		if anlIsUnknownPath(anlGet(over, "path"), unk) {
			out["over"] = over
		} else {
			val, found := resolvePath(ctx, anlGet(over, "path"))
			isOver := !found || !anlIsFin(val) || anlToNumber(val) < 0 || anlGt(val, anlGet(over, "threshold"))
			if !isOver {
				return nil
			}
		}
	}
	unless := anlGet(v, "unless")
	if anlTruthy(unless) && anlGet(v, "kind") == "approval" {
		out["unless"] = unless // the evidence of approval: carried, never used to drop the veto
	} else if anlTruthy(unless) {
		uk, uv, ucs := anlPeAll(unless, ctx, unk)
		if uk == "cs" {
			out["unless"] = ucs
		} else if uv == "true" {
			return nil // the exception certainly holds: the veto never applies
		}
	}
	return out
}

// anlResidual specialises `policy` to `known`; everything under `opts.unknown` stays symbolic. Returns {decision: 'never' | 'always' |
// 'conditional', reason?, policy, policyDigest}.
func anlResidual(policy, known, optsIn any) map[string]any {
	opts := optsIn
	if opts == nil || anlIsUndef(opts) {
		opts = map[string]any{}
	}
	model := anlToModel(policy)
	digest := anlPolicyDigestOf(model)
	verbKnown := !anlIsUndef(anlGet(known, "verb"))
	resKnown := !anlIsUndef(anlGet(known, "resource")) && anlGet(opts, "resourceUnknown") != true
	var unk []string
	for _, u := range anlReqList(anlNN(anlGet(opts, "unknown"), []any{"action.params"})) {
		unk = append(unk, anlStr(u, "unknown path"))
	}
	if !verbKnown {
		unk = append(unk, "action.verb")
	}
	if !resKnown {
		unk = append(unk, "action.resource")
	}
	ctx := anlContextOfKnown(known)
	empty := func() map[string]any {
		return map[string]any{"predicates": []any{}, "caveats": []any{}, "vetoes": []any{}, "tighten": []any{}}
	}
	never := func(reason string) map[string]any {
		return map[string]any{"decision": "never", "reason": reason, "policy": empty(), "policyDigest": digest}
	}
	if model["caveatSat"] != true {
		return never("caveats unsatisfiable: " + anlJS(anlReasonOf(model)))
	}
	rc := anlGet(known, "reversibilityClass")
	if capv, has := model["revCap"].(int); has && !anlIsUndef(rc) {
		if idx := anlRevIndex(rc); idx < 0 || idx > capv {
			return never("reversibility class exceeds the caveat cap")
		}
	}
	var parts []map[string]any
	for _, m := range anlFlatten(model) {
		parts = append(parts, anlResidualPart(m, ctx, unk, verbKnown, resKnown))
	}
	pol := anlCopy(parts[0])
	if len(parts) > 1 {
		rest := make([]any, 0, len(parts)-1)
		for _, p := range parts[1:] {
			rest = append(rest, p)
		}
		pol["meet"] = rest
	}
	res := map[string]any{"decision": "conditional", "policy": pol, "policyDigest": digest}
	for _, p := range parts {
		if len(p["predicates"].([]any)) == 0 {
			return never("no permit survives the known facts")
		}
	}
	for _, p := range parts {
		for _, v := range p["vetoes"].([]any) {
			vm := v.(map[string]any)
			w := vm["when"].(map[string]any)
			wr, hasRes := w["resource"]
			wh, hasWhere := w["where"].([]any)
			if vm["kind"] == "deny" && (!hasRes || wr == "*") && (!hasWhere || len(wh) == 0) && !anlHas(vm, "unless") && !anlHas(vm, "over") {
				return never("veto " + anlJS(anlOwn(vm, "id")) + " applies to every completion")
			}
		}
	}
	always := true
	for _, p := range parts {
		unconditional := false
		for _, x := range p["predicates"].([]any) {
			if !anlHas(x, "where") {
				unconditional = true
			}
		}
		if !unconditional || len(p["vetoes"].([]any)) != 0 || len(p["tighten"].([]any)) != 0 {
			always = false
		}
	}
	if always {
		res["decision"] = "always"
	}
	return res
}

// anlResidualPolicy is the residual as a policy the analyzer and the real evaluator both understand.
func anlResidualPolicy(r any) map[string]any {
	pol, ok := anlGet(r, "policy").(map[string]any)
	if !ok {
		anlFail("policy is not an object")
	}
	own := anlCopy(pol)
	delete(own, "meet")
	if meet := pol["meet"]; anlTruthy(meet) {
		ms := []any{}
		for _, m := range anlReqList(meet) {
			ms = append(ms, anlSpread(m))
		}
		own["meet"] = ms
	}
	return own
}

// anlEvaluateResidual is the ternary decision of a residual once the unknown fields are bound.
func anlEvaluateResidual(r, ctx any) string {
	if anlGet(r, "decision") == "never" {
		return "deny"
	}
	a := anlGet(ctx, "action")
	action := anlU(map[string]any{"verb": anlGet(a, "verb"), "resource": anlGet(a, "resource")})
	if v := anlGet(a, "params"); anlTruthy(v) {
		action["params"] = v
	}
	if v := anlGet(ctx, "subject"); anlTruthy(v) {
		action["subject"] = v
	}
	if v := anlGet(ctx, "env"); anlTruthy(v) {
		action["env"] = v
	}
	if v := anlGet(a, "reversibility_class"); anlTruthy(v) {
		action["reversibilityClass"] = v
	}
	return anlDecideAction(anlToModel(anlResidualPolicy(r)), action)
}

// ---- "what may I do?" ---------------------------------------------------------------------------------------------------------

func anlRangeLo(r map[string]any) float64 {
	if v, ok := r["lo"]; ok {
		return anlToNumber(v)
	}
	return math.Inf(-1)
}

func anlRangeHi(r map[string]any) float64 {
	if v, ok := r["hi"]; ok {
		return anlToNumber(v)
	}
	return anlInf
}

func anlB2i(v any) int {
	if anlTruthy(v) {
		return 1
	}
	return 0
}

func anlMergeRanges(rs []map[string]any) []map[string]any {
	cmp := func(a, b map[string]any) float64 {
		la, lb := anlRangeLo(a), anlRangeLo(b)
		d := math.NaN()
		if !(la == lb && math.IsInf(la, 0)) {
			d = la - lb
		}
		if math.IsNaN(d) || d == 0 {
			return float64(anlB2i(anlOwn(b, "loInclusive")) - anlB2i(anlOwn(a, "loInclusive")))
		}
		return d
	}
	sorted := append([]map[string]any{}, rs...)
	sort.SliceStable(sorted, func(i, j int) bool { return cmp(sorted[i], sorted[j]) < 0 })
	var out []map[string]any
	for _, r := range sorted {
		rlo, rhi := anlRangeLo(r), anlRangeHi(r)
		var last map[string]any
		lhi := 0.0
		if len(out) > 0 {
			last = out[len(out)-1]
			lhi = anlRangeHi(last)
		}
		if last != nil && lhi >= rlo && !(lhi == rlo && !anlTruthy(anlOwn(last, "hiInclusive")) && !anlTruthy(anlOwn(r, "loInclusive"))) {
			if rhi > lhi || (rhi == lhi && anlTruthy(anlOwn(r, "hiInclusive"))) {
				if hv, has := r["hi"]; !has {
					delete(last, "hi")
				} else {
					last["hi"] = hv
				}
				if anlTruthy(anlOwn(r, "hiInclusive")) {
					last["hiInclusive"] = true
				} else {
					delete(last, "hiInclusive")
				}
			}
		} else {
			out = append(out, anlCopy(r))
		}
	}
	return out
}

func anlCellRange(value any, T []any) map[string]any {
	vf := anlToNumber(value)
	for _, t := range T {
		if anlToNumber(t) == vf {
			return map[string]any{"lo": value, "hi": value, "loInclusive": true, "hiInclusive": true}
		}
	}
	out := map[string]any{}
	for i := len(T) - 1; i >= 0; i-- {
		if anlLt(T[i], value) {
			out["lo"] = T[i]
			break
		}
	}
	for _, t := range T {
		if anlGt(t, value) {
			out["hi"] = t
			break
		}
	}
	return out
}

type anlSeenVal struct {
	value           any
	allow, escalate bool
}

type anlSeenSet struct {
	order []*anlSeenVal
	idx   map[string]*anlSeenVal
}

func anlSortedUnits(xs []string) []any {
	sort.SliceStable(xs, func(i, j int) bool { return anlUnitLess(xs[i], xs[j]) })
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// anlWhatMayIDo: per verb shape ({verb, params}): autonomous / approval-only / denied for the known principal, and which parameter
// values and resources are still allowed. Advisory; sound on the decided fragment, otherwise `approximate`.
func anlWhatMayIDo(policy, verbs, knownIn, oIn any) []any {
	known, o := knownIn, oIn
	if known == nil || anlIsUndef(known) {
		known = map[string]any{}
	}
	if o == nil || anlIsUndef(o) {
		o = map[string]any{}
	}
	out := []any{}
	mx := anlDefaultMaxCombinations
	if mc := anlGet(o, "maxCombinations"); anlIsNum(mc) {
		mx = anlToNumber(mc)
	}
	for _, shape := range anlReqList(verbs) {
		sverb := anlGet(shape, "verb")
		kn := anlSpread(known)
		kn["verb"] = sverb
		res := anlResidual(policy, anlU(kn), nil)
		env := anlU(map[string]any{
			"verb": sverb, "status": "denied", "params": map[string]any{},
			"resources":    map[string]any{"autonomous": []any{}, "withApproval": []any{}, "other": false},
			"policyDigest": res["policyDigest"], "advisory": true,
		})
		if rem := anlGet(o, "remaining"); anlTruthy(rem) {
			env["remaining"] = anlSpread(rem)
		}
		if md := anlGet(o, "missingDischarges"); anlTruthy(md) {
			env["missingDischarges"] = append([]any{}, anlReqList(md)...)
		}
		if res["decision"] == "never" {
			if r, has := res["reason"]; has {
				env["reason"] = r
			}
			out = append(out, env)
			continue
		}
		rp := anlToModel(anlResidualPolicy(res))
		sparams, ok := anlGet(shape, "params").(map[string]any)
		if !ok {
			anlFail("Object.entries requires an object")
		}
		names := jsKeys(sparams)
		extra := []any{}
		for _, name := range names {
			d := sparams[name]
			if vals := anlGet(d, "values"); !anlIsUndef(vals) {
				p := "action.params." + name
				extra = append(extra, map[string]any{"path": p, "cond": map[string]any{"field": p, "op": "in", "value": vals}})
			}
		}
		for _, name := range names {
			d := sparams[name]
			p := "action.params." + name
			if v := anlGet(d, "min"); !anlIsUndef(v) {
				extra = append(extra, map[string]any{"path": p, "cond": map[string]any{"field": p, "op": "gte", "value": v}})
			}
			if v := anlGet(d, "max"); !anlIsUndef(v) {
				extra = append(extra, map[string]any{"path": p, "cond": map[string]any{"field": p, "op": "lte", "value": v}})
			}
		}
		_, hasCap := rp["revCap"]
		pr := anlCollectProbes(map[string]any{"predicateSets": []any{anlProbeSet(rp)}, "extraFieldConditions": extra, "varyReversibility": hasCap})
		pr.verbs = []any{sverb}
		if anlProductSize(pr) > mx {
			env["status"] = "needs-approval"
			env["approximate"] = true
			env["reason"] = "representative grid exceeded the bound; no domain is claimed"
			out = append(out, env)
			continue
		}
		if kres := anlGet(known, "resource"); !anlIsUndef(kres) {
			pr.resources = []any{kres}
		}
		seen := map[string]*anlSeenSet{}
		type resFlags struct{ allow, escalate bool }
		resSeen := map[string]*resFlags{}
		anyAllow, anyEscalate, freshRes := false, false, false
		anlEachRep(pr, func(rep *anlRep) bool {
			d := anlDecide(rp, rep)
			if d == "deny" {
				return false
			}
			if d == "allow" {
				anyAllow = true
			} else {
				anyEscalate = true
			}
			act := anlRepToAction(rep)
			params, _ := act["params"].(map[string]any)
			for _, name := range names {
				v, has := params[name]
				if !has {
					v = anlUndef
				}
				m := seen[name]
				if m == nil {
					m = &anlSeenSet{idx: map[string]*anlSeenVal{}}
					seen[name] = m
				}
				k := "\x00absent"
				if has {
					k = anlJSON(v)
				}
				cur := m.idx[k]
				if cur == nil {
					cur = &anlSeenVal{value: v}
					m.idx[k] = cur
					m.order = append(m.order, cur)
				}
				if d == "allow" {
					cur.allow = true
				} else {
					cur.escalate = true
				}
			}
			rname := anlJS(act["resource"])
			rr := resSeen[rname]
			if rr == nil {
				rr = &resFlags{}
				resSeen[rname] = rr
			}
			if d == "allow" {
				rr.allow = true
			} else {
				rr.escalate = true
			}
			if strings.HasPrefix(rname, "\x00") {
				freshRes = true
			}
			return false
		})
		switch {
		case anyAllow:
			env["status"] = "autonomous"
		case anyEscalate:
			env["status"] = "needs-approval"
		}
		envParams := env["params"].(map[string]any)
		for _, name := range names {
			decl := sparams[name]
			T := anlThresholdsOf(rp, "action.params."+name)
			var vals []*anlSeenVal
			if s := seen[name]; s != nil {
				vals = s.order
			}
			dmin, dmax := anlGet(decl, "min"), anlGet(decl, "max")
			var nums, strs []*anlSeenVal
			for _, x := range vals {
				if anlIsNum(x.value) && (anlIsUndef(dmin) || anlToNumber(x.value) >= anlToNumber(dmin)) && (anlIsUndef(dmax) || anlToNumber(x.value) <= anlToNumber(dmax)) {
					nums = append(nums, x)
				}
				if _, ok := x.value.(string); ok {
					strs = append(strs, x)
				}
			}
			dvalues := anlGet(decl, "values")
			if anlGet(decl, "type") == "integer" || len(nums) > 0 {
				clip := func(r map[string]any) map[string]any {
					n := anlCopy(r)
					if !anlIsUndef(dmin) {
						if lo, has := r["lo"]; !has || anlToNumber(lo) < anlToNumber(dmin) {
							n["lo"] = dmin
							n["loInclusive"] = true
						}
					}
					if !anlIsUndef(dmax) {
						if hi, has := r["hi"]; !has || anlToNumber(hi) > anlToNumber(dmax) {
							n["hi"] = dmax
							n["hiInclusive"] = true
						}
					}
					return n
				}
				ranges := func(pick func(*anlSeenVal) bool) []any {
					var rs []map[string]any
					for _, x := range nums {
						if pick(x) {
							rs = append(rs, clip(anlCellRange(x.value, T)))
						}
					}
					res := []any{}
					for _, r := range anlMergeRanges(rs) {
						res = append(res, r)
					}
					return res
				}
				envParams[name] = map[string]any{
					"kind":         "numeric",
					"autonomous":   ranges(func(x *anlSeenVal) bool { return x.allow }),
					"withApproval": ranges(func(x *anlSeenVal) bool { return x.escalate && !x.allow }),
				}
			} else if !anlIsUndef(dvalues) || len(strs) > 0 {
				pickList := func(f func(*anlSeenVal) bool) []any {
					var l []string
					for _, x := range strs {
						if s := x.value.(string); f(x) && !strings.HasPrefix(s, "\x00") {
							l = append(l, s)
						}
					}
					return anlSortedUnits(l)
				}
				var fresh *anlSeenVal
				for _, x := range strs {
					if strings.HasPrefix(x.value.(string), "\x00") {
						fresh = x
						break
					}
				}
				envParams[name] = map[string]any{
					"kind":              "enum",
					"autonomous":        pickList(func(x *anlSeenVal) bool { return x.allow }),
					"withApproval":      pickList(func(x *anlSeenVal) bool { return x.escalate && !x.allow }),
					"otherAutonomous":   anlIsUndef(dvalues) && fresh != nil && fresh.allow,
					"otherWithApproval": anlIsUndef(dvalues) && fresh != nil && fresh.escalate && !fresh.allow,
				}
			} else {
				envParams[name] = map[string]any{"kind": "unconstrained"}
			}
		}
		var rAuto, rApp []string
		for r, v := range resSeen {
			if strings.HasPrefix(r, "\x00") {
				continue
			}
			if v.allow {
				rAuto = append(rAuto, r)
			}
			if v.escalate && !v.allow {
				rApp = append(rApp, r)
			}
		}
		env["resources"] = map[string]any{"autonomous": anlSortedUnits(rAuto), "withApproval": anlSortedUnits(rApp), "other": freshRes}
		if und := rp["undecidable"].([]any); len(und) > 0 {
			env["approximate"] = true
			env["reason"] = fmt.Sprintf("over-approximated (%s)", anlJoin(und, "; "))
		}
		out = append(out, env)
	}
	return out
}
