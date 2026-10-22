package pca

// Policy-layer caveat helpers (0.4.1), mirroring policyCaveats (packages/pca/src/policy-vm.ts) and the stock
// caveat evaluator plus `max_spend` (predicates.ts envelopeCaveatEvaluator, agent-native.ts).
//
// The core verifier (VerifyPCActnCore / VerifyPCActnCorePolicy, the nine checks) and the RequirePCA middleware
// treat caveats as opaque and do NOT evaluate them. A resource server that enforces a grant's caveats calls
//
//	ok, failed := EvaluateCaveats(PolicyCaveats(grant, chain), ctx)
//
// with its own action params. PolicyCaveats includes the caveats on the ROOT grant (outside its envelope), which
// is the 0.4.1 security fix in the TypeScript policy layer: root caveats used to be signed but never evaluated.

import (
	"encoding/json"
	"math"
	"strconv"
)

// PolicyCaveats returns every caveat the policy layer evaluates for an action under grant delegated along chain
// (root first): grant.caveats with its FIRST `envelope` caveat removed (order kept; that one is the policy
// container read separately), followed by the caveats the hops appended (leaf.caveats beyond len(grant.caveats),
// leaf = the last element of chain). Nothing is appended when chain is not a non-empty array or either caveats
// list is not an array. A non-array grant.caveats is returned as is (EvaluateCaveats refuses it); a grant that is
// not an object yields nil. Never panics and never mutates its inputs.
func PolicyCaveats(grant any, chain any) any {
	g, _ := grant.(map[string]any)
	cs, isArr := g["caveats"].([]any)
	if !isArr {
		return g["caveats"]
	}
	out := make([]any, 0, len(cs))
	skipped := false
	for _, c := range cs {
		if !skipped {
			if m, ok := c.(map[string]any); ok {
				if t, ok := m["type"].(string); ok && t == "envelope" {
					skipped = true
					continue
				}
			}
		}
		out = append(out, c)
	}
	if ch, ok := chain.([]any); ok && len(ch) > 0 {
		if leaf, ok := ch[len(ch)-1].(map[string]any); ok {
			if lc, ok := leaf["caveats"].([]any); ok && len(lc) > len(cs) {
				out = append(out, lc[len(cs):]...)
			}
		}
	}
	return out
}

// EvaluateCaveats evaluates a caveat list against ctx. ok is true iff every caveat is satisfied; failed lists the
// unsatisfied caveats' `type` strings in order ("<malformed>" when `type` is not a string). A non-array list gives
// (false, ["<malformed caveats>"]). Total: never panics; anything unknown or malformed fails closed.
//
// ctx uses the conformance-vector field names (JSON numbers may be json.Number, float64 or any Go integer type;
// bool and string are never numbers; an absent field is absent and the caveat needing it is unsatisfied):
//
//	now (epoch ms), delegation_depth, blast_radius, reversibility_class, recent_action_times ([]any of numbers),
//	action: {verb, resource, reversibility_class, params}
//
// Implemented types: max_spend {usd} (own params.amount finite, 0 <= amount <= usd, own params.currency if present
// exactly "usd"/"USD"; does not need now), and, each requiring a finite now: expires {at}, not_before {at},
// rate {max, per_secs}, max_blast_radius {max}, reversibility_max {class} (against ctx.reversibility_class),
// delegation_depth {max}, budget_alloc {limit}. Every other type (note, envelope, resource_prefix, predicates,
// tool_schema, unknown) is unsatisfied.
func EvaluateCaveats(caveats any, ctx map[string]any) (ok bool, failed []string) {
	failed = []string{}
	list, isArr := caveats.([]any)
	if !isArr {
		return false, []string{"<malformed caveats>"}
	}
	for _, cv := range list {
		if !caveatSatisfied(cv, ctx) {
			name := "<malformed>"
			if m, isObj := cv.(map[string]any); isObj {
				if t, isStr := m["type"].(string); isStr {
					name = t
				}
			}
			failed = append(failed, name)
		}
	}
	return len(failed) == 0, failed
}

// finNum reads a finite JSON number. json.Number lexemes are parsed as float64 (overflow => not finite).
func finNum(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		x, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return 0, false
		}
		f = x
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int8:
		f = float64(n)
	case int16:
		f = float64(n)
	case int32:
		f = float64(n)
	case int64:
		f = float64(n)
	case uint:
		f = float64(n)
	case uint8:
		f = float64(n)
	case uint16:
		f = float64(n)
	case uint32:
		f = float64(n)
	case uint64:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

var reversibilityOrder = map[string]int{"reversible": 0, "rate_limited": 1, "irreversible": 2}

func caveatSatisfied(cv any, ctx map[string]any) (sat bool) {
	defer func() {
		if recover() != nil {
			sat = false
		}
	}()
	c, ok := cv.(map[string]any)
	if !ok {
		return false
	}
	typ, _ := c["type"].(string)
	if typ == "max_spend" {
		return maxSpendSatisfied(c, ctx)
	}
	now, ok := finNum(ctx["now"])
	if !ok {
		return false
	}
	switch typ {
	case "expires":
		at, ok := finNum(c["at"])
		return ok && now < at
	case "not_before":
		at, ok := finNum(c["at"])
		return ok && now >= at
	case "rate":
		max, ok1 := finNum(c["max"])
		per, ok2 := finNum(c["per_secs"])
		times, ok3 := ctx["recent_action_times"].([]any)
		if !ok1 || !ok2 || per <= 0 || !ok3 {
			return false
		}
		lo := now - per*1000
		n := 0
		for _, tv := range times {
			if t, ok := finNum(tv); ok && t > lo && t <= now {
				n++
			}
		}
		return float64(n) < max
	case "max_blast_radius":
		max, ok1 := finNum(c["max"])
		br, ok2 := finNum(ctx["blast_radius"])
		return ok1 && ok2 && br <= max
	case "reversibility_max":
		lim, ok1 := c["class"].(string)
		cur, ok2 := ctx["reversibility_class"].(string)
		if !ok1 || !ok2 {
			return false
		}
		li, ok1 := reversibilityOrder[lim]
		ci, ok2 := reversibilityOrder[cur]
		return ok1 && ok2 && ci <= li
	case "delegation_depth":
		max, ok1 := finNum(c["max"])
		d, ok2 := finNum(ctx["delegation_depth"])
		return ok1 && ok2 && d <= max
	case "budget_alloc":
		lim, ok := finNum(c["limit"])
		return ok && lim >= 0
	case intentSessionCaveat:
		// Intent Layer v2 session binding (rule 13): no per-action constraint; satisfied iff well-formed.
		return intentSessionCaveatError(c) == ""
	}
	return false
}

// maxSpendSatisfied: usd finite >= 0; ctx.action.params an object with an own finite amount, 0 <= amount <= usd;
// an own params.currency, when present, exactly "usd" or "USD".
func maxSpendSatisfied(c map[string]any, ctx map[string]any) bool {
	lim, ok := finNum(c["usd"])
	if !ok || lim < 0 {
		return false
	}
	action, ok := ctx["action"].(map[string]any)
	if !ok {
		return false
	}
	params, ok := action["params"].(map[string]any)
	if !ok {
		return false
	}
	amount, ok := finNum(params["amount"])
	if !ok || amount < 0 {
		return false
	}
	if cur, has := params["currency"]; has {
		s, isStr := cur.(string)
		if !isStr || (s != "usd" && s != "USD") {
			return false
		}
	}
	return amount <= lim
}
