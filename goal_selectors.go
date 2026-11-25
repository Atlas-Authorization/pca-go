package pca

// Trait selectors and role-addressed parameters for the Goal IR (the TypeScript reference is @atlasauth/pca-goal `selectors`). A
// selector goal ("SelGoal") names a verb or a trait class in its grants, prohibitions and bounds, and may name a parameter by ROLE; it
// is lowered against the PINNED catalog to an ordinary goal (one grant per verb). Fail-closed rules: a grant verb with no unique
// parameter of a named role is dropped from the grant (reported); a prohibition whose role term is unresolved for a verb applies to
// that verb unconditionally; a bound whose role value cannot be resolved for every selected verb is a type error; an allow selector is
// positive (no `none_of`, at least one trait); an unconfirmed verb carries `pca.unreviewed`: a class ALLOW never covers it, a class
// prohibition or bound over a trait selector ALWAYS covers it; an unknown trait id is a type error. The typed front door of the proved
// compiler (goalCompileSelGoal) takes the compiler as an argument: the proved one is wired in the pcagoalkernel build.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const goalUnreviewed = "pca.unreviewed"

var goalSelIDRE = regexp.MustCompile(`^[0-9A-Za-z_]{1,64}$`)

func goalSelectorsStrs(xs []string) []any { return anyStrs(xs) }

func goalSelectorsSortVerbs(verbs []any) {
	sort.SliceStable(verbs, func(i, j int) bool {
		a, _ := verbs[i].(map[string]any)["verb"].(string)
		b, _ := verbs[j].(map[string]any)["verb"].(string)
		return utf16Less(a, b)
	})
}

func goalSelectorsKnown(reg Registry) []any {
	ks := make([]string, 0, len(reg))
	for k := range reg {
		ks = append(ks, k)
	}
	return anyStrs(goalSortU16(ks))
}

// goalSelCatalogOfDefs is the catalog of a pack of defs (verb ids and parameter paths are the defs' own): {known, verbs}. A nil reg
// is the core registry; review is the verifier's pinned reviewer keys (nil: none).
func goalSelCatalogOfDefs(defs any, reg Registry, review any) map[string]any {
	if reg == nil {
		reg = coreRegistry
	}
	verbs := []any{}
	for _, dv := range anlReqList(defs) {
		d, ok := dv.(map[string]any)
		if !ok {
			anlFail("def is not an object")
		}
		pm, ok := d["params"].(map[string]any)
		if !ok {
			anlFail("def.params is not an object")
		}
		names := make([]string, 0, len(pm))
		for n := range pm {
			names = append(names, n)
		}
		roles := map[string]any{}
		order := []string{}
		for _, name := range goalSortU16(names) {
			r := anlGet(pm[name], "role")
			if r == nil || anlIsUndef(r) {
				continue
			}
			rs, ok := r.(string)
			if !ok {
				anlFail("role is not a string")
			}
			if _, had := roles[rs]; !had {
				roles[rs] = []any{}
				order = append(order, rs)
			}
			roles[rs] = append(roles[rs].([]any), name)
		}
		recordKeyOrder(roles, order)
		e, err := effective(d, reg, review)
		if err != nil {
			panic(goalSelectorsCoded(err))
		}
		verbs = append(verbs, map[string]any{"verb": d["verb"], "traits": goalSelectorsStrs(e.Closure), "roles": roles})
	}
	goalSelectorsSortVerbs(verbs)
	return map[string]any{"known": goalSelectorsKnown(reg), "verbs": verbs}
}

// goalSelectorsCoded turns a registry error "code: message" into a *CodedError carrying the code.
func goalSelectorsCoded(err error) error {
	if i := strings.Index(err.Error(), ": "); i > 0 && !strings.ContainsAny(err.Error()[:i], " \t") {
		return &CodedError{Code: err.Error()[:i], Msg: err.Error()}
	}
	return err
}

// goalSelCatalogOfDomain is the catalog of one domain ontology: the NL short ids and NL parameter names, with the traits of the defs
// behind them. shortcut: reads the shipped derivation (core registry, no review pins), not a recomputation from the defs.
func goalSelCatalogOfDomain(domain any) any {
	c := goalShippedCatalog(domain)
	if c == nil {
		anlFail("unknown domain %s", anlJS(domain))
	}
	return c
}

// goalSelCatalogDigest is the digest of the catalog (what SelGoal.catDigest must equal).
func goalSelCatalogDigest(c any) string {
	return goalReviewHash(map[string]any{"d": "atlas-pca/goal-sel-catalog/v1", "catalog": c})
}

func goalSelGoalDigest(g any) string {
	return goalReviewHash(map[string]any{"d": "atlas-pca/goal-ir-sel/v1", "goal": g})
}

// ---- G-A4: the verbs of a Class selector ------------------------------------------------------------------------------------------

func goalSelectorsHasAll(ts, req any) bool {
	for _, t := range anlReqList(req) {
		if !anlIncludes(ts, t) {
			return false
		}
	}
	return true
}

func goalSelectorsHasNone(ts, ex any) bool {
	for _, t := range anlReqList(ex) {
		if anlIncludes(ts, t) {
			return false
		}
	}
	return true
}

// goalClassVerbs are the verbs of the catalog, in catalog order, whose trait closure contains every allOf trait and none of the noneOf traits.
func goalClassVerbs(cat, allOf, noneOf any) []any {
	out := []any{}
	for _, v := range anlReqList(anlGet(cat, "verbs")) {
		if goalSelectorsHasAll(anlGet(v, "traits"), allOf) && goalSelectorsHasNone(anlGet(v, "traits"), noneOf) {
			out = append(out, anlGet(v, "verb"))
		}
	}
	return out
}

// goalAllowClassVerbs are the verbs a class ALLOW covers: the class, minus every unconfirmed verb.
func goalAllowClassVerbs(cat, allOf, noneOf any) []any {
	return goalClassVerbs(cat, allOf, append(append([]any{}, anlReqList(noneOf)...), goalUnreviewed))
}

// goalFloatClassVerbs are the verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says.
func goalFloatClassVerbs(cat, allOf, noneOf any) []any {
	out := []any{}
	for _, v := range anlReqList(anlGet(cat, "verbs")) {
		if anlIncludes(anlGet(v, "traits"), goalUnreviewed) || (goalSelectorsHasAll(anlGet(v, "traits"), allOf) && goalSelectorsHasNone(anlGet(v, "traits"), noneOf)) {
			out = append(out, anlGet(v, "verb"))
		}
	}
	return out
}

// ---- role resolution --------------------------------------------------------------------------------------------------------------

func goalSelectorsFind(list any, key string, want any) any {
	for _, v := range anlReqList(list) {
		if anlStrictEq(anlGet(v, key), want) {
			return v
		}
	}
	return nil
}

func goalSelectorsDeclOf(ont, verb any) any {
	return goalSelectorsFind(anlGet(ont, "verbs"), "verb", verb)
}

func goalSelectorsInfoOf(cat, verb any) any {
	return goalSelectorsFind(anlGet(cat, "verbs"), "verb", verb)
}

// goalResolveRole is the one parameter of verb carrying role, with its declared type; none, several or undeclared: nil.
func goalResolveRole(ont, cat, verb, role any) map[string]any {
	info, decl := goalSelectorsInfoOf(cat, verb), goalSelectorsDeclOf(ont, verb)
	if info == nil || decl == nil {
		return nil
	}
	var paths []any
	if rm, ok := anlGet(info, "roles").(map[string]any); ok {
		if rs, ok := role.(string); ok {
			if p, has := rm[rs]; has {
				l, isList := p.([]any)
				if !isList {
					anlFail("role paths is not an array")
				}
				paths = l
			}
		}
	}
	if len(paths) != 1 {
		return nil
	}
	p := goalSelectorsFind(anlGet(decl, "params"), "path", paths[0])
	if p == nil {
		return nil
	}
	return anlU(map[string]any{"path": anlGet(p, "path"), "ty": anlGet(p, "ty")})
}

func goalSelectorsResolveTerm(ont, cat, verb, t any) any {
	switch k := anlGet(t, "k"); {
	case goalReviewEqS(k, "param"):
		return anlU(map[string]any{"k": "param", "path": anlGet(t, "path"), "ty": anlGet(t, "ty")})
	case goalReviewEqS(k, "lit"):
		return anlU(map[string]any{"k": "lit", "v": anlGet(t, "v")})
	case goalReviewEqS(k, "hist"):
		return anlU(map[string]any{"k": "hist", "bid": anlGet(t, "bid"), "u": anlGet(t, "u")})
	case goalReviewEqS(k, "role"):
		if r := goalResolveRole(ont, cat, verb, anlGet(t, "role")); r != nil {
			return anlU(map[string]any{"k": "param", "path": r["path"], "ty": r["ty"]})
		}
	}
	return nil
}

// goalSelectorsResolveCond is nil as soon as one role term is unresolved for the verb.
func goalSelectorsResolveCond(ont, cat, verb, c any) any {
	switch k := anlGet(c, "k"); {
	case goalReviewEqS(k, "true"):
		return map[string]any{"k": "true"}
	case goalReviewEqS(k, "cmp"):
		l, r := goalSelectorsResolveTerm(ont, cat, verb, anlGet(c, "l")), goalSelectorsResolveTerm(ont, cat, verb, anlGet(c, "r"))
		if l != nil && r != nil {
			return anlU(map[string]any{"k": "cmp", "op": anlGet(c, "op"), "l": l, "r": r})
		}
	case goalReviewEqS(k, "and") || goalReviewEqS(k, "or"):
		a, b := goalSelectorsResolveCond(ont, cat, verb, anlGet(c, "a")), goalSelectorsResolveCond(ont, cat, verb, anlGet(c, "b"))
		if a != nil && b != nil {
			return map[string]any{"k": k, "a": a, "b": b}
		}
	case goalReviewEqS(k, "not"):
		if a := goalSelectorsResolveCond(ont, cat, verb, anlGet(c, "c")); a != nil {
			return map[string]any{"k": "not", "c": a}
		}
	}
	return nil
}

// ---- the expansion ------------------------------------------------------------------------------------------------------------------

type goalSelEntry struct {
	src any
	g   map[string]any
}

func goalSelectorsReportAdd(report map[string]any, key string, v any) {
	report[key] = append(report[key].([]any), v)
}

func goalSelectorsGrantVerbs(cat, s any) []any {
	if goalReviewEqS(anlGet(s, "k"), "verb") {
		return []any{anlGet(s, "verb")}
	}
	return goalAllowClassVerbs(cat, anlGet(s, "all_of"), anlGet(s, "none_of"))
}

func goalSelectorsExpandGrants(ont, cat, gs any, report map[string]any) []goalSelEntry {
	out := []goalSelEntry{}
	for _, gr := range anlReqList(gs) {
		sel := anlGet(gr, "sel")
		verbs := goalSelectorsGrantVerbs(cat, sel)
		dropped := []any{}
		for _, v := range verbs {
			c := goalSelectorsResolveCond(ont, cat, v, anlGet(gr, "cond"))
			if c == nil {
				dropped = append(dropped, map[string]any{"verb": v, "reason": "role_unresolved"})
				continue
			}
			gid := anlGet(gr, "gid")
			if goalReviewEqS(anlGet(sel, "k"), "class") {
				gid = anlJS(gid) + "." + anlJS(v)
			}
			out = append(out, goalSelEntry{anlGet(gr, "gid"), anlU(map[string]any{"gid": gid, "verb": v, "res": anlGet(gr, "res"), "cond": c})})
		}
		goalSelectorsReportAdd(report, "grants", anlU(map[string]any{"gid": anlGet(gr, "gid"), "verbs": verbs, "dropped": dropped}))
	}
	return out
}

func goalSelectorsProhVerbs(ont, cat, t any) []any {
	k := anlGet(t, "k")
	if goalReviewEqS(k, "verb") {
		return []any{anlGet(t, "verb")}
	}
	if goalReviewEqS(k, "effect") {
		return goalSelectorsVerbsOfClass(ont, anlGet(t, "cls"))
	}
	return goalFloatClassVerbs(cat, anlGet(t, "all_of"), anlGet(t, "none_of"))
}

func goalSelectorsVerbsOfClass(ont, cls any) []any {
	out := []any{}
	for _, v := range anlReqList(anlGet(ont, "verbs")) {
		if anlStrictEq(anlGet(v, "cls"), cls) {
			out = append(out, anlGet(v, "verb"))
		}
	}
	return out
}

func goalSelectorsExpandProhibits(ont, cat, ps any, report map[string]any) []any {
	out := []any{}
	for _, p := range anlReqList(ps) {
		target := anlGet(p, "target")
		verbs := goalSelectorsProhVerbs(ont, cat, target)
		unconditional := []any{}
		for _, v := range verbs {
			c := goalSelectorsResolveCond(ont, cat, v, anlGet(p, "cond"))
			if c == nil {
				unconditional = append(unconditional, v)
			}
			pid := anlGet(p, "pid")
			if !goalReviewEqS(anlGet(target, "k"), "verb") {
				pid = anlJS(pid) + "." + anlJS(v)
			}
			var cond any = map[string]any{"k": "true"}
			if c != nil {
				cond = c
			}
			out = append(out, anlU(map[string]any{"pid": pid, "target": map[string]any{"k": "verb", "verb": v}, "res": anlGet(p, "res"), "cond": cond}))
		}
		goalSelectorsReportAdd(report, "prohibits", anlU(map[string]any{"pid": anlGet(p, "pid"), "verbs": verbs, "unconditional": unconditional}))
	}
	return out
}

func goalSelectorsIdsOf(es []goalSelEntry, srcs any) []any {
	out := []any{}
	for _, e := range es {
		if anlIncludes(srcs, e.src) {
			out = append(out, e.g["gid"])
		}
	}
	return out
}

func goalSelectorsGidsOfVerbs(es []goalSelEntry, vs any) []any {
	out := []any{}
	for _, e := range es {
		if anlIncludes(vs, e.g["verb"]) {
			out = append(out, e.g["gid"])
		}
	}
	return out
}

func goalSelectorsVerbsOfGids(es []goalSelEntry, gids any) []any {
	out := []any{}
	for _, e := range es {
		if anlIncludes(gids, e.g["gid"]) {
			out = append(out, e.g["verb"])
		}
	}
	return out
}

func goalSelectorsBoundRoleVerbs(ont, cat any, es []goalSelEntry, s any) []any {
	k := anlGet(s, "k")
	if goalReviewEqS(k, "gids") {
		return goalSelectorsVerbsOfGids(es, goalSelectorsIdsOf(es, anlGet(s, "gids")))
	}
	if goalReviewEqS(k, "effect") {
		return goalSelectorsVerbsOfClass(ont, anlGet(s, "cls"))
	}
	return goalSelectorsVerbsOfGids(es, goalSelectorsGidsOfVerbs(es, goalFloatClassVerbs(cat, anlGet(s, "all_of"), anlGet(s, "none_of"))))
}

// goalSelectorsBoundValue is one value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when
// the paths differ but the type is one. nil when there is none.
func goalSelectorsBoundValue(ont, cat any, vs []any, t any) map[string]any {
	switch k := anlGet(t, "k"); {
	case goalReviewEqS(k, "param"):
		return map[string]any{"term": anlU(map[string]any{"k": "param", "path": anlGet(t, "path"), "ty": anlGet(t, "ty")}), "how": "literal"}
	case goalReviewEqS(k, "lit"):
		return map[string]any{"term": anlU(map[string]any{"k": "lit", "v": anlGet(t, "v")}), "how": "literal"}
	case goalReviewEqS(k, "hist"):
		return map[string]any{"term": anlU(map[string]any{"k": "hist", "bid": anlGet(t, "bid"), "u": anlGet(t, "u")}), "how": "literal"}
	case goalReviewEqS(k, "role"):
		rs := []map[string]any{}
		for _, v := range vs {
			r := goalResolveRole(ont, cat, v, anlGet(t, "role"))
			if r == nil {
				return nil
			}
			rs = append(rs, r)
		}
		if len(rs) == 0 {
			return nil
		}
		same := func(a, b any) bool { return anlJSON(a) == anlJSON(b) }
		shared, tySame := true, true
		for _, r := range rs {
			if !(anlStrictEq(r["path"], rs[0]["path"]) && same(r["ty"], rs[0]["ty"])) {
				shared = false
			}
			if !same(r["ty"], rs[0]["ty"]) {
				tySame = false
			}
		}
		if shared {
			return map[string]any{"term": anlU(map[string]any{"k": "param", "path": rs[0]["path"], "ty": rs[0]["ty"]}), "how": "shared_path"}
		}
		if tySame {
			return map[string]any{"term": anlU(map[string]any{"k": "param", "path": "@" + anlJS(anlGet(t, "role")), "ty": rs[0]["ty"]}), "how": "role_key"}
		}
	}
	return nil
}

func goalSelectorsExpandBounds(ont, cat any, es []goalSelEntry, bs any, report map[string]any) []any {
	out := []any{}
	for _, b := range anlReqList(bs) {
		bsel := anlGet(b, "sel")
		bv := goalSelectorsBoundValue(ont, cat, goalSelectorsBoundRoleVerbs(ont, cat, es, bsel), anlGet(b, "value"))
		if bv == nil {
			continue // a type error (goalSelReasons), never reached when the goal is well typed
		}
		mk := func(sel map[string]any) map[string]any {
			return anlU(map[string]any{"bid": anlGet(b, "bid"), "sel": sel, "agg": anlGet(b, "agg"), "value": bv["term"], "key": anlGet(b, "key"),
				"window": anlGet(b, "window"), "scope": anlGet(b, "scope"), "cap": anlGet(b, "cap"), "onExceed": anlGet(b, "onExceed")})
		}
		k := anlGet(bsel, "k")
		var gids []any
		haveGids := false
		if goalReviewEqS(k, "gids") {
			gids, haveGids = goalSelectorsIdsOf(es, anlGet(bsel, "gids")), true
		} else if goalReviewEqS(k, "trait") {
			gids, haveGids = goalSelectorsGidsOfVerbs(es, goalFloatClassVerbs(cat, anlGet(bsel, "all_of"), anlGet(bsel, "none_of"))), true
		}
		if goalReviewEqS(k, "effect") {
			out = append(out, mk(anlU(map[string]any{"k": "effect", "cls": anlGet(bsel, "cls")})))
			goalSelectorsReportAdd(report, "bounds", anlU(map[string]any{"bid": anlGet(b, "bid"), "gids": []any{}, "dropped": false, "value": bv["how"]}))
			continue
		}
		if !haveGids {
			anlFail("object of type NoneType has no len()")
		}
		if len(gids) == 0 {
			goalSelectorsReportAdd(report, "bounds", anlU(map[string]any{"bid": anlGet(b, "bid"), "gids": []any{}, "dropped": true, "value": bv["how"]}))
			continue
		}
		out = append(out, mk(map[string]any{"k": "gids", "gids": gids}))
		goalSelectorsReportAdd(report, "bounds", anlU(map[string]any{"bid": anlGet(b, "bid"), "gids": gids, "dropped": false, "value": bv["how"]}))
	}
	return out
}

// goalExpandSelGoal lowers a selector goal to an ordinary Goal against the PINNED catalog. Pure and total; typing is goalSelReasons plus
// the core typechecker.
func goalExpandSelGoal(sg, ont, cat any) map[string]any {
	report := map[string]any{"grants": []any{}, "prohibits": []any{}, "bounds": []any{}}
	es := goalSelectorsExpandGrants(ont, cat, anlGet(sg, "grants"), report)
	prohibits := goalSelectorsExpandProhibits(ont, cat, anlGet(sg, "prohibits"), report)
	bounds := goalSelectorsExpandBounds(ont, cat, es, anlGet(sg, "bounds"), report)
	deleg := anlGet(sg, "deleg")
	grants := []any{}
	for _, e := range es {
		grants = append(grants, e.g)
	}
	d := anlSpread(deleg)
	d["mayTouch"] = goalSelectorsIdsOf(es, anlGet(deleg, "mayTouch"))
	wack := goalSelectorsIdsOf(es, anlGet(sg, "wildcardAck"))
	holes := []any{}
	for _, h := range anlReqList(anlGet(sg, "holes")) {
		c := anlSpread(h)
		c["affects"] = goalSelectorsIdsOf(es, anlGet(h, "affects"))
		holes = append(holes, c)
	}
	goal := anlU(map[string]any{"v": goalNum(1), "principal": anlGet(sg, "principal"), "ontDigest": anlGet(sg, "ontDigest"), "nlDigest": anlGet(sg, "nlDigest"),
		"sources": anlGet(sg, "sources"), "grants": grants, "prohibits": prohibits, "bounds": bounds, "validity": anlGet(sg, "validity"), "deleg": anlU(d),
		"escalateOn": anlGet(sg, "escalateOn"), "wildcardAck": wack, "holes": holes})
	return map[string]any{"goal": goal, "report": report}
}

// ---- typing of the selector layer ---------------------------------------------------------------------------------------------------

// goalSelectorsLen is JavaScript `.length` of a string or array (undefined for anything else: ok false).
func goalSelectorsLen(v any) (int, bool) {
	switch t := v.(type) {
	case string:
		return jsLen(t), true
	case []any:
		return len(t), true
	case nil:
		anlFail("cannot read properties of null (reading 'length')")
	}
	if anlIsUndef(v) {
		anlFail("cannot read properties of undefined (reading 'length')")
	}
	return 0, false
}

func goalSelectorsLenGt0(v any) bool { n, ok := goalSelectorsLen(v); return ok && n > 0 }

func goalSelectorsLenIs0(v any) bool { n, ok := goalSelectorsLen(v); return ok && n == 0 }

func goalSelectorsAllKnown(known, ids any) bool {
	for _, i := range anlReqList(ids) {
		if !(goalSelectorsLenGt0(i) && anlIncludes(known, i)) {
			return false
		}
	}
	return true
}

func goalSelectorsGrantSelOK(cat, g any) bool {
	s := anlGet(g, "sel")
	return goalReviewEqS(anlGet(s, "k"), "verb") || (goalSelectorsLenGt0(anlGet(s, "all_of")) && goalSelectorsLenIs0(anlGet(s, "none_of")) &&
		goalSelectorsAllKnown(anlGet(cat, "known"), anlGet(s, "all_of")))
}

func goalSelectorsProhSelOK(cat, p any) bool {
	t := anlGet(p, "target")
	return !goalReviewEqS(anlGet(t, "k"), "trait") || (goalSelectorsAllKnown(anlGet(cat, "known"), anlGet(t, "all_of")) && goalSelectorsAllKnown(anlGet(cat, "known"), anlGet(t, "none_of")))
}

func goalSelectorsBoundSelOK(cat, gs, b any) bool {
	s := anlGet(b, "sel")
	k := anlGet(s, "k")
	if goalReviewEqS(k, "gids") {
		for _, i := range anlReqList(anlGet(s, "gids")) {
			found := false
			for _, g := range anlReqList(gs) {
				if anlStrictEq(anlGet(g, "gid"), i) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	if goalReviewEqS(k, "effect") {
		return true
	}
	return goalSelectorsAllKnown(anlGet(cat, "known"), anlGet(s, "all_of")) && goalSelectorsAllKnown(anlGet(cat, "known"), anlGet(s, "none_of"))
}

// goalSelReasons are the type reasons of the selector layer, preceded by the wire checks (`catalog_digest_mismatch`, `bad_id`). [] = well
// typed at this layer.
func goalSelReasons(sg, ont, cat any) []any {
	out := []any{}
	if !anlStrictEq(anlGet(sg, "catDigest"), goalSelCatalogDigest(cat)) {
		out = append(out, "catalog_digest_mismatch")
	}
	ids := []any{}
	for _, g := range anlReqList(anlGet(sg, "grants")) {
		ids = append(ids, anlGet(g, "gid"))
	}
	for _, p := range anlReqList(anlGet(sg, "prohibits")) {
		ids = append(ids, anlGet(p, "pid"))
	}
	for _, b := range anlReqList(anlGet(sg, "bounds")) {
		ids = append(ids, anlGet(b, "bid"))
	}
	for _, i := range ids {
		if !goalSelIDRE.MatchString(anlJS(i)) {
			out = append(out, "bad_id")
			break
		}
	}
	for _, v := range anlReqList(anlGet(cat, "verbs")) {
		if goalSelectorsDeclOf(ont, anlGet(v, "verb")) == nil {
			out = append(out, "catalog_mismatch")
			break
		}
	}
	for _, g := range anlReqList(anlGet(sg, "grants")) {
		if !goalSelectorsGrantSelOK(cat, g) {
			out = append(out, "bad_grant_selector")
			break
		}
	}
	for _, p := range anlReqList(anlGet(sg, "prohibits")) {
		if !goalSelectorsProhSelOK(cat, p) {
			out = append(out, "bad_prohibit_selector")
			break
		}
	}
	for _, b := range anlReqList(anlGet(sg, "bounds")) {
		if !goalSelectorsBoundSelOK(cat, anlGet(sg, "grants"), b) {
			out = append(out, "bad_bound_selector")
			break
		}
	}
	es := goalSelectorsExpandGrants(ont, cat, anlGet(sg, "grants"), map[string]any{"grants": []any{}, "prohibits": []any{}, "bounds": []any{}})
	for _, b := range anlReqList(anlGet(sg, "bounds")) {
		if goalSelectorsBoundValue(ont, cat, goalSelectorsBoundRoleVerbs(ont, cat, es, anlGet(b, "sel")), anlGet(b, "value")) == nil {
			out = append(out, "unresolved_role_bound")
			break
		}
	}
	return out
}

// goalCompileSelGoal is CompileX: selector reasons first (fail closed), then expansion and the core compiler. compile is the proved
// compiler (goalCompileGoal in the pcagoalkernel build); with nil, a goal that passes the selector layer panics.
func goalCompileSelGoal(sg, ont, cat any, compile func(goal, ont any) map[string]any) map[string]any {
	if rs := goalSelReasons(sg, ont, cat); len(rs) > 0 {
		return map[string]any{"ok": false, "reasons": rs}
	}
	x := goalExpandSelGoal(sg, ont, cat)
	if compile == nil {
		anlFail("compile_sel_goal needs a core compiler (compile_goal)")
	}
	c := compile(x["goal"], ont)
	if anlTruthy(goalReviewReq(c, "ok")) {
		return map[string]any{"ok": true, "policy": c["policy"], "goal": x["goal"], "report": x["report"]}
	}
	return map[string]any{"ok": false, "reasons": c["reasons"]}
}

// ---- acts ---------------------------------------------------------------------------------------------------------------------------

// goalWithRoleParams adds the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter
// that the act supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first (a caller cannot forge a role value).
func goalWithRoleParams(act, cat any) map[string]any {
	pm, ok := anlGet(act, "params").(map[string]any)
	if !ok {
		anlFail("params is not an object")
	}
	params := map[string]any{}
	for _, k := range jsKeys(pm) {
		if !strings.HasPrefix(k, "@") {
			params[k] = pm[k]
		}
	}
	if info := goalSelectorsInfoOf(cat, anlGet(act, "verb")); info != nil {
		rm, ok := anlGet(info, "roles").(map[string]any)
		if !ok {
			anlFail("roles is not an object")
		}
		for _, role := range jsKeys(rm) {
			paths, isList := rm[role].([]any)
			if !isList {
				anlFail("role paths is not an array")
			}
			if len(paths) == 1 {
				if p, isStr := paths[0].(string); isStr {
					if v, has := params[p]; has {
						params["@"+role] = v
					}
				}
			}
		}
	}
	out := anlCopy(act.(map[string]any))
	out["params"] = params
	return out
}

// ---- the policy card ---------------------------------------------------------------------------------------------------------------

func goalSelectorsText(all, none any, reg Registry) string {
	phrase := func(i any) string {
		if s, ok := i.(string); ok {
			if t, has := reg[s]; has && t.Card != "" {
				return t.Card
			}
		}
		return anlJS(i)
	}
	join := func(xs any, sep string) string {
		parts := []string{}
		for _, i := range anlReqList(xs) {
			parts = append(parts, phrase(i))
		}
		return strings.Join(parts, sep)
	}
	nAll, _ := goalSelectorsLen(all)
	a := "every action"
	if nAll > 0 {
		a = "every action that " + join(all, " and ")
	}
	if nNone, _ := goalSelectorsLen(none); nNone > 0 {
		return a + ", except those that " + join(none, " or ")
	}
	return a
}

func goalSelectorsJoinQ(xs []any) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = goalJq(x)
	}
	return strings.Join(parts, ", ")
}

// goalRenderSelCard is the card of a selector goal: one line per selector clause in the words of the trait phrases (never a model), with
// the verbs the pinned catalog gives it, then the card of the expansion (the exact clauses that run). A nil reg is the core registry.
func goalRenderSelCard(sg, ont, cat any, reg Registry) map[string]any {
	if reg == nil {
		reg = coreRegistry
	}
	x := goalExpandSelGoal(sg, ont, cat)
	goal, report := x["goal"], x["report"].(map[string]any)
	lines := []any{}
	warnings := []any{}
	for i, g := range anlReqList(anlGet(sg, "grants")) {
		r := report["grants"].([]any)[i]
		s := anlGet(g, "sel")
		if goalReviewEqS(anlGet(s, "k"), "class") {
			verbs := anlReqList(anlGet(r, "verbs"))
			lines = append(lines, fmt.Sprintf("ALLOW %s: %s [%d verb(s) in the pinned catalog: %s]", goalJq(anlGet(g, "gid")),
				goalSelectorsText(anlGet(s, "all_of"), []any{}, reg), len(verbs), goalSelectorsJoinQ(verbs)))
		}
		for _, d := range anlReqList(anlGet(r, "dropped")) {
			warnings = append(warnings, fmt.Sprintf("grant %s does not cover %s: it has no unique parameter for a role the condition names", goalJq(anlGet(g, "gid")), goalJq(anlGet(d, "verb"))))
		}
	}
	for i, p := range anlReqList(anlGet(sg, "prohibits")) {
		r := report["prohibits"].([]any)[i]
		t := anlGet(p, "target")
		if goalReviewEqS(anlGet(t, "k"), "trait") {
			verbs := anlReqList(anlGet(r, "verbs"))
			lines = append(lines, fmt.Sprintf("NEVER %s: %s, today %d verb(s) [%s]; it also covers every verb added to the catalog later", goalJq(anlGet(p, "pid")),
				goalSelectorsText(anlGet(t, "all_of"), anlGet(t, "none_of"), reg), len(verbs), goalSelectorsJoinQ(verbs)))
		}
		for _, v := range anlReqList(anlGet(r, "unconditional")) {
			warnings = append(warnings, fmt.Sprintf("prohibition %s applies to %s without its condition: the verb has no unique parameter for a role the condition names", goalJq(anlGet(p, "pid")), goalJq(v)))
		}
	}
	for i, b := range anlReqList(anlGet(sg, "bounds")) {
		var r any
		if rl := report["bounds"].([]any); i < len(rl) {
			r = rl[i]
		}
		s := anlGet(b, "sel")
		if goalReviewEqS(anlGet(s, "k"), "trait") && r != nil {
			lines = append(lines, fmt.Sprintf("LIMIT %s: over %s (%d grant(s))", goalJq(anlGet(b, "bid")),
				goalSelectorsText(anlGet(s, "all_of"), anlGet(s, "none_of"), reg), len(anlReqList(anlGet(r, "gids")))))
		}
		if r != nil && anlTruthy(anlGet(r, "dropped")) {
			warnings = append(warnings, fmt.Sprintf("limit %s selects no grant and bounds nothing", goalJq(anlGet(b, "bid"))))
		}
		if r != nil && goalReviewEqS(anlGet(r, "value"), "role_key") {
			warnings = append(warnings, fmt.Sprintf("limit %s sums a role the verbs carry on different parameters: the action must supply the role key", goalJq(anlGet(b, "bid"))))
		}
	}
	core := goalRenderCard(goal)
	return map[string]any{"lines": append(lines, core["lines"].([]any)...), "warnings": append(warnings, core["warnings"].([]any)...)}
}

// goalTraitClosure is the closure of a trait id list under the registry (a selector written with a parent trait covers the children by
// `implies`). A nil reg is the core registry; an unknown trait panics with the code unknown_trait.
func goalTraitClosure(ids any, reg Registry) []any {
	if reg == nil {
		reg = coreRegistry
	}
	l := anlReqList(ids)
	in := make([]string, len(l))
	for i, x := range l {
		s, ok := x.(string)
		if !ok {
			panic(&CodedError{Code: "unknown_trait", Msg: "unknown_trait: unknown trait " + anlJSON(x)})
		}
		in[i] = s
	}
	cl, err := reg.closure(in)
	if err != nil {
		panic(goalSelectorsCoded(err))
	}
	return anyStrs(cl)
}

// ---- the carrier form ---------------------------------------------------------------------------------------------------------------

const goalSelRoleMark = "\u0001role:"

func goalSelectorsStr(v any) string {
	s, ok := v.(string)
	if !ok {
		anlFail("must be str, not %s", anlJS(v))
	}
	return s
}

func goalSelectorsCarryTerm(t any) map[string]any {
	k := anlGet(t, "k")
	switch {
	case goalReviewEqS(k, "role"):
		return map[string]any{"k": "param", "path": goalSelRoleMark + goalSelectorsStr(anlGet(t, "role")), "ty": map[string]any{"k": "s"}}
	case goalReviewEqS(k, "param"):
		return anlU(map[string]any{"k": "param", "path": anlGet(t, "path"), "ty": anlGet(t, "ty")})
	case goalReviewEqS(k, "lit"):
		return anlU(map[string]any{"k": "lit", "v": anlGet(t, "v")})
	}
	return anlU(map[string]any{"k": "hist", "bid": anlGet(t, "bid"), "u": anlGet(t, "u")})
}

func goalSelectorsCarryCond(c any) map[string]any {
	k := anlGet(c, "k")
	switch {
	case goalReviewEqS(k, "true"):
		return map[string]any{"k": "true"}
	case goalReviewEqS(k, "cmp"):
		return anlU(map[string]any{"k": "cmp", "op": anlGet(c, "op"), "l": goalSelectorsCarryTerm(anlGet(c, "l")), "r": goalSelectorsCarryTerm(anlGet(c, "r"))})
	case goalReviewEqS(k, "and") || goalReviewEqS(k, "or"):
		return map[string]any{"k": k, "a": goalSelectorsCarryCond(anlGet(c, "a")), "b": goalSelectorsCarryCond(anlGet(c, "b"))}
	}
	return map[string]any{"k": "not", "c": goalSelectorsCarryCond(anlGet(c, "c"))}
}

func goalSelectorsSel2(all, none any) string {
	join := func(xs any) string {
		parts := []string{}
		for _, x := range anlReqList(xs) {
			parts = append(parts, goalSelectorsStr(x))
		}
		return strings.Join(parts, "\u0002")
	}
	return join(all) + "\u0001" + join(none)
}

// goalSelCarrier is an ordinary Goal's worth of data carrying a selector goal (selectors ride in strings and role-marked params), so the
// extracted model decodes it with its existing Goal decoder.
func goalSelCarrier(sg any) map[string]any {
	grants := []any{}
	for _, g := range anlReqList(anlGet(sg, "grants")) {
		s := anlGet(g, "sel")
		var verb string
		if goalReviewEqS(anlGet(s, "k"), "verb") {
			verb = "V\u0001" + goalSelectorsStr(anlGet(s, "verb"))
		} else {
			verb = "C\u0001" + goalSelectorsSel2(anlGet(s, "all_of"), anlGet(s, "none_of"))
		}
		grants = append(grants, anlU(map[string]any{"gid": anlGet(g, "gid"), "verb": verb, "res": anlGet(g, "res"), "cond": goalSelectorsCarryCond(anlGet(g, "cond"))}))
	}
	prohibits := []any{}
	for _, p := range anlReqList(anlGet(sg, "prohibits")) {
		t := anlGet(p, "target")
		var verb string
		switch k := anlGet(t, "k"); {
		case goalReviewEqS(k, "verb"):
			verb = "V\u0001" + goalSelectorsStr(anlGet(t, "verb"))
		case goalReviewEqS(k, "effect"):
			verb = "E\u0001" + goalSelectorsStr(anlGet(t, "cls"))
		default:
			verb = "T\u0001" + goalSelectorsSel2(anlGet(t, "all_of"), anlGet(t, "none_of"))
		}
		prohibits = append(prohibits, anlU(map[string]any{"pid": anlGet(p, "pid"), "res": anlGet(p, "res"), "cond": goalSelectorsCarryCond(anlGet(p, "cond")),
			"target": map[string]any{"k": "verb", "verb": verb}}))
	}
	bounds := []any{}
	for _, b := range anlReqList(anlGet(sg, "bounds")) {
		s := anlGet(b, "sel")
		var sel map[string]any
		switch k := anlGet(s, "k"); {
		case goalReviewEqS(k, "gids"):
			sel = anlU(map[string]any{"k": "gids", "gids": anlGet(s, "gids")})
		case goalReviewEqS(k, "effect"):
			sel = anlU(map[string]any{"k": "effect", "cls": anlGet(s, "cls")})
		default:
			sel = map[string]any{"k": "effect", "cls": "T\u0001" + goalSelectorsSel2(anlGet(s, "all_of"), anlGet(s, "none_of"))}
		}
		bounds = append(bounds, anlU(map[string]any{"bid": anlGet(b, "bid"), "key": anlGet(b, "key"), "window": anlGet(b, "window"), "scope": anlGet(b, "scope"),
			"cap": anlGet(b, "cap"), "onExceed": anlGet(b, "onExceed"), "agg": anlGet(b, "agg"), "value": goalSelectorsCarryTerm(anlGet(b, "value")), "sel": sel}))
	}
	return anlU(map[string]any{"v": goalNum(1), "principal": anlGet(sg, "principal"), "ontDigest": anlGet(sg, "ontDigest"), "nlDigest": anlGet(sg, "nlDigest"),
		"sources": anlGet(sg, "sources"), "grants": grants, "prohibits": prohibits, "bounds": bounds, "validity": anlGet(sg, "validity"), "deleg": anlGet(sg, "deleg"),
		"escalateOn": anlGet(sg, "escalateOn"), "wildcardAck": anlGet(sg, "wildcardAck"), "holes": anlGet(sg, "holes")})
}

// goalEncodeSelCatalog is the catalog tape the extracted model reads: known trait ids, then per verb: verb, traits, number of roles,
// (role, paths)*. Tokens are [tag, value] pairs.
func goalEncodeSelCatalog(c any) []any {
	tokI := func(n int) any { return []any{"i", goalNum(int64(n))} }
	tokS := func(s any) any { return []any{"s", s} }
	strs := func(xs any) []any {
		l := anlReqList(xs)
		out := []any{tokI(len(l))}
		for _, x := range l {
			out = append(out, tokS(x))
		}
		return out
	}
	out := strs(anlGet(c, "known"))
	verbs := anlReqList(anlGet(c, "verbs"))
	out = append(out, tokI(len(verbs)))
	for _, v := range verbs {
		roles, ok := anlGet(v, "roles").(map[string]any)
		if !ok {
			anlFail("roles is not an object")
		}
		keys := jsKeys(roles)
		out = append(out, tokS(anlGet(v, "verb")))
		out = append(out, strs(anlGet(v, "traits"))...)
		out = append(out, tokI(len(keys)))
		for _, r := range keys {
			out = append(out, tokS(r))
			out = append(out, strs(roles[r])...)
		}
	}
	return out
}

// GoalSelCatalogDigest is goalSelCatalogDigest.
func GoalSelCatalogDigest(c any) (s string, err error) {
	_, err = anlTry(func() any { s = goalSelCatalogDigest(c); return nil })
	return
}

// GoalSelGoalDigest is goalSelGoalDigest.
func GoalSelGoalDigest(g any) (s string, err error) {
	_, err = anlTry(func() any { s = goalSelGoalDigest(g); return nil })
	return
}

// GoalExpandSelGoal is goalExpandSelGoal.
func GoalExpandSelGoal(sg, ont, cat any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalExpandSelGoal(sg, ont, cat); return nil })
	return
}

// GoalSelReasons is goalSelReasons.
func GoalSelReasons(sg, ont, cat any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalSelReasons(sg, ont, cat); return nil })
	return
}

// GoalCompileSelGoal is goalCompileSelGoal with the compiler of the caller (GoalCompileSelGoalProved in the pcagoalkernel build).
func GoalCompileSelGoal(sg, ont, cat any, compile func(goal, ont any) map[string]any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalCompileSelGoal(sg, ont, cat, compile); return nil })
	return
}

// GoalRenderSelCard is goalRenderSelCard (nil reg: the core registry).
func GoalRenderSelCard(sg, ont, cat any, reg Registry) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalRenderSelCard(sg, ont, cat, reg); return nil })
	return
}

// GoalWithRoleParams is goalWithRoleParams.
func GoalWithRoleParams(act, cat any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalWithRoleParams(act, cat); return nil })
	return
}

// GoalSelCarrier is goalSelCarrier.
func GoalSelCarrier(sg any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalSelCarrier(sg); return nil })
	return
}

// GoalEncodeSelCatalog is goalEncodeSelCatalog.
func GoalEncodeSelCatalog(c any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalEncodeSelCatalog(c); return nil })
	return
}

// GoalResolveRole is goalResolveRole.
func GoalResolveRole(ont, cat, verb, role any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalResolveRole(ont, cat, verb, role); return nil })
	return
}

// GoalTraitClosure is goalTraitClosure (nil reg: the core registry).
func GoalTraitClosure(ids any, reg Registry) (r []any, err error) {
	_, err = anlTry(func() any { r = goalTraitClosure(ids, reg); return nil })
	return
}
