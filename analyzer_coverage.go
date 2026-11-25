package pca

import "fmt"

// Which clause decided an action (policy coverage building block).

func anlPermitID(i int) string { return fmt.Sprintf("permit[%d]", i) }

func anlID(x any) any {
	if anlIsUndef(x) {
		return nil
	}
	return x
}

// anlWitnessOf is the decision with the clause that decided it: a forbid beats an approval rule, which beats a permit.
func anlWitnessOf(model map[string]any, action any) map[string]any {
	decision := anlDecideAction(model, action)
	ctx := anlContextOfAction(action)
	var permits []any
	for i, p := range model["predicates"].([]any) {
		if predicateMatches(p, ctx, &regexBudget{}) {
			permits = append(permits, anlPermitID(i))
		}
	}
	var vetoes, tighten []any
	for _, v := range model["vetoes"].([]any) {
		if anlVetoApplies(v, ctx) {
			vetoes = append(vetoes, v)
		}
	}
	for _, t := range model["tighten"].([]any) {
		w := anlGet(t, "when")
		if anlIsUndef(w) {
			w = nil
		}
		if evaluateConditionTri(w, ctx, &regexBudget{}) != triFalse {
			tighten = append(tighten, t)
		}
	}
	others := func(win any) []any {
		all := append([]any{}, permits...)
		for _, v := range vetoes {
			all = append(all, anlID(anlGet(v, "id")))
		}
		for _, t := range tighten {
			all = append(all, anlID(anlGet(t, "id")))
		}
		out := []any{}
		for _, i := range all {
			if !anlStrictEq(i, win) {
				out = append(out, i)
			}
		}
		return out
	}
	done := func(kind string, id any) map[string]any {
		id = anlID(id)
		return map[string]any{"decision": decision, "winner": map[string]any{"kind": kind, "id": id}, "also": others(id)}
	}
	first := func(xs []any, key string, want string) (any, bool) {
		for _, x := range xs {
			if anlGet(x, key) == want {
				return x, true
			}
		}
		return nil, false
	}
	if model["caveatSat"] != true || decision == "deny" {
		if model["caveatSat"] != true {
			return done("caveat", "caveats")
		}
		if len(permits) == 0 {
			return map[string]any{"decision": decision, "winner": map[string]any{"kind": "none", "id": nil}, "also": others(nil)}
		}
		if v, ok := first(vetoes, "kind", "deny"); ok {
			return done("veto", anlGet(v, "id"))
		}
		if t, ok := first(tighten, "signal", "deny"); ok {
			return done("tighten", anlGet(t, "id"))
		}
		return done("caveat", "caveats") // reversibility cap or an ancestor of the chain
	}
	if decision == "escalate" {
		if v, ok := first(vetoes, "kind", "approval"); ok {
			return done("veto", anlGet(v, "id"))
		}
		if len(tighten) > 0 {
			return done("tighten", anlGet(tighten[0], "id"))
		}
		return done("tighten", nil)
	}
	if len(permits) > 0 {
		return done("permit", permits[0])
	}
	return done("permit", nil)
}
