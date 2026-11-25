package pca

// liftLegacy: the total, conservative lift of the facade's {permissions, limits} input to a Goal and its ontology (the
// TypeScript reference is @atlasauth/pca-goal `legacy`). `$200/day` is a SLIDING 86 400 000 ms sum bound (explicit window), not a
// per-call ceiling plus a one-day grant lifetime; a `$` limit on a verb with no amount field is an error; every limit is its own
// bound, so adding a limit only narrows; money parameters are integers in MINOR units of USD (cents).

import (
	"math"
	"sort"
	"strings"
)

func goalLegacyUSD() map[string]any { return map[string]any{"k": "money", "ccy": "USD"} }

func goalLegacyQ() map[string]any { return map[string]any{"k": "q", "u": goalLegacyUSD()} }

// goalLegacyIsSafe is a finite integer within +-(2^53 - 1).
func goalLegacyIsSafe(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f) && math.Abs(f) <= maxSafeInt
}

// goalLiftLegacy takes {permissions, limits?, principal, notAfter?, notBefore?, nlDigest?}; catalog nil is the built-in catalog.
// It returns {goal, ontology}.
func goalLiftLegacy(o any, catalog *Catalog) map[string]any {
	om, ok := o.(map[string]any)
	if !ok {
		anlFail("liftLegacy: input must be an object")
	}
	raw := om["limits"]
	own := func(k string) any {
		if m, ok := raw.(map[string]any); ok {
			if v, ok := m[k]; ok {
				return v
			}
		}
		return anlUndef
	}
	perms, hasPerms := om["permissions"]
	if !hasPerms {
		anlFail("liftLegacy: permissions is required")
	}
	principal, hasPrincipal := om["principal"]
	if !hasPrincipal {
		anlFail("liftLegacy: principal is required")
	}
	// the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
	cp, err := CompilePolicy(PolicyOptions{Permissions: perms, Catalog: catalog})
	if err != nil {
		anlFail("%s", err.Error())
	}
	grants := []map[string]any{}
	bounds := []map[string]any{}
	verbs := []map[string]any{}
	for _, s := range cp.Actions {
		gid := "g:" + s.Verb
		params := []any{}
		if s.AmountField != "" {
			params = append(params, map[string]any{"path": s.AmountField, "ty": goalLegacyQ()})
		}
		verbs = append(verbs, map[string]any{"verb": s.Verb, "cls": s.Reversibility, "params": params})
		resource := "*"
		if s.Resource != "" {
			resource = s.Resource
		}
		// the unexpressible patterns are `[*?]` and a leading `re:`
		if resource != "*" && (strings.ContainsAny(resource, "*?") || strings.HasPrefix(resource, "re:")) {
			anlFail("liftLegacy: resource pattern '%s' of %s is not expressible; name exact resources or acknowledge a wildcard", resource, s.Verb)
		}
		rawLimit := own(s.Verb)
		if rawLimit == nil || anlIsUndef(rawLimit) { // `??`: a JSON null is no limit here
			rawLimit = own(s.Action)
		}
		cond := map[string]any{"k": "true"}
		if !anlIsUndef(rawLimit) {
			ls, ok := rawLimit.(string)
			if !ok {
				anlFail("liftLegacy: limit for %s must be a string", s.Verb)
			}
			lim, err := ParseLimit(ls)
			if err != nil {
				anlFail("%s", err.Error())
			}
			if lim.Unit == "usd" {
				if s.AmountField == "" {
					anlFail("liftLegacy: '$' limit on '%s' but the catalog gives that verb no amount field, so the limit could not be enforced", s.Verb)
				}
				// the explicit conversion keeps the product rounded before jsRound reads it (no fused multiply-add on arm64)
				minorF := jsRound(float64(lim.Amount * 100))
				if !goalLegacyIsSafe(minorF) {
					anlFail("liftLegacy: limit for %s is out of range", s.Verb)
				}
				minor := int64(minorF)
				amt := func() map[string]any {
					return map[string]any{"k": "param", "path": s.AmountField, "ty": goalLegacyQ()}
				}
				lit := func(n int64) map[string]any {
					return map[string]any{"k": "lit", "v": map[string]any{"k": "q", "q": map[string]any{"u": goalLegacyUSD(), "n": goalNum(n)}}}
				}
				cond = map[string]any{"k": "and",
					"a": map[string]any{"k": "cmp", "op": "gte", "l": amt(), "r": lit(0)},
					"b": map[string]any{"k": "cmp", "op": "lte", "l": amt(), "r": lit(minor)}}
				if lim.PeriodMs != 0 {
					bounds = append(bounds, map[string]any{"bid": "b:" + s.Verb, "sel": map[string]any{"k": "gids", "gids": []any{gid}}, "agg": "sum", "value": amt(), "key": "",
						"window": map[string]any{"k": "sliding", "ms": goalNum(lim.PeriodMs)}, "scope": map[string]any{"k": "session"},
						"cap": map[string]any{"u": goalLegacyUSD(), "n": goalNum(minor)}, "onExceed": "deny"})
				}
			} else {
				if !goalLegacyIsSafe(lim.Amount) {
					anlFail("liftLegacy: count limit for %s must be a whole number", s.Verb)
				}
				window := map[string]any{"k": "lifetime"}
				if lim.PeriodMs != 0 {
					window = map[string]any{"k": "sliding", "ms": goalNum(lim.PeriodMs)}
				}
				bounds = append(bounds, map[string]any{"bid": "b:" + s.Verb, "sel": map[string]any{"k": "gids", "gids": []any{gid}}, "agg": "count",
					"value": map[string]any{"k": "lit", "v": map[string]any{"k": "q", "q": map[string]any{"u": map[string]any{"k": "count"}, "n": goalNum(1)}}}, "key": "",
					"window": window, "scope": map[string]any{"k": "session"}, "cap": map[string]any{"u": map[string]any{"k": "count"}, "n": goalNum(int64(lim.Amount))},
					"onExceed": "deny"})
			}
		}
		res := map[string]any{"k": "exact", "id": resource}
		if resource == "*" {
			res = map[string]any{"k": "any", "reason": "legacy default: no resource scope given"}
		}
		grants = append(grants, map[string]any{"gid": gid, "verb": s.Verb, "res": res, "cond": cond})
	}
	sort.SliceStable(grants, func(i, j int) bool { return utf16Less(grants[i]["gid"].(string), grants[j]["gid"].(string)) })
	sort.SliceStable(bounds, func(i, j int) bool { return utf16Less(bounds[i]["bid"].(string), bounds[j]["bid"].(string)) })
	for i := 1; i < len(grants); i++ {
		if grants[i]["gid"] == grants[i-1]["gid"] {
			anlFail("liftLegacy: duplicate grant %s", grants[i]["gid"].(string))
		}
	}
	or := func(k string, d any) any {
		if v := om[k]; v != nil {
			return v
		}
		return d
	}
	gl, mayTouch, wildcard := []any{}, []any{}, []any{}
	for _, g := range grants {
		gl = append(gl, g)
		mayTouch = append(mayTouch, g["gid"])
		if g["res"].(map[string]any)["k"] == "any" {
			wildcard = append(wildcard, g["gid"])
		}
	}
	bl := []any{}
	for _, b := range bounds {
		bl = append(bl, b)
	}
	goal := map[string]any{
		"v": goalNum(1), "principal": principal, "ontDigest": "legacy-catalog", "nlDigest": or("nlDigest", ""), "sources": []any{},
		"grants": gl, "prohibits": []any{}, "bounds": bl,
		"validity":   map[string]any{"notBefore": or("notBefore", goalNum(0)), "notAfter": or("notAfter", goalNum(maxSafeInt)), "maxIdle": goalNum(0)},
		"deleg":      map[string]any{"maxDepth": goalNum(16), "narrowOnly": true, "mayTouch": mayTouch},
		"escalateOn": []any{}, "wildcardAck": wildcard, "holes": []any{}}
	sort.SliceStable(verbs, func(i, j int) bool { return utf16Less(verbs[i]["verb"].(string), verbs[j]["verb"].(string)) })
	vl := []any{}
	for i, v := range verbs {
		if i == 0 || verbs[i-1]["verb"] != v["verb"] {
			vl = append(vl, v)
		}
	}
	return map[string]any{"goal": goal, "ontology": map[string]any{"verbs": vl, "rels": []any{}}}
}

// GoalLiftLegacy is the error-returning form (catalog nil: the built-in catalog).
func GoalLiftLegacy(o any, catalog *Catalog) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalLiftLegacy(o, catalog); return nil })
	return
}
