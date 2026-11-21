package pca

import (
	"errors"
	"math"
)

// The tighten-or-escalate typing of the intent-frontier results (semantic judge threshold, objective risk, proof of progress). What
// those modules compute are PROXIES for "does this action serve the principal's goal"; none of them is a judgement that may grant
// anything. Each result becomes a signal, "ok", "escalate" or "deny", that can only LOWER a decision; "ok" is neutral, never a grant.
// Every signal function is total: a missing, malformed or unrecognised result is "deny", never "ok". Results are decoded JSON values.

func frontierObj(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// SemanticSignal is "ok" iff the ensemble met its quorum and the calibrated gate (`ok` is a real boolean true), "escalate" for a
// clean "not faithful", and "deny" for anything that is no result.
func SemanticSignal(result any) string {
	m, ok := frontierObj(result)
	if !ok {
		return "deny"
	}
	b, isBool := m["ok"].(bool)
	switch {
	case !isBool:
		return "deny"
	case b:
		return "ok"
	}
	return "escalate"
}

// ProgressSignal is "ok" iff the step verified; running out of exploration budget escalates (reason exactly "exploration-exhausted"
// or "budget-exceeded"); every other denial (forgery, gap, mismatch, malformed) denies.
func ProgressSignal(result any) string {
	m, ok := frontierObj(result)
	if !ok {
		return "deny"
	}
	b, isBool := m["ok"].(bool)
	if !isBool {
		return "deny"
	}
	if b {
		return "ok"
	}
	if r, isStr := m["reason"].(string); isStr && (r == "exploration-exhausted" || r == "budget-exceeded") {
		return "escalate"
	}
	return "deny"
}

// ObjectiveSignal: nothing committed ("none") and a reproduced objective ("objective") are "ok"; a committed fact that cannot be
// reproduced ("mismatch") is "deny", unless the grant's own onMismatch is exactly "heuristic" (the class heuristic, the server-held
// baseline: "ok"). A reproduced result adds no signal of its own: it enters the decision through TightenRiskInputs.
func ObjectiveSignal(res any) string {
	m, ok := frontierObj(res)
	if !ok {
		return "deny"
	}
	switch m["mode"] {
	case "none", "objective":
		return "ok"
	case "mismatch":
		if m["onMismatch"] == "heuristic" {
			return "ok"
		}
	}
	return "deny"
}

func frontierFinite(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// TightenRiskInputs combines the server-held baseline risk inputs with the objective ones so the objective path can only RAISE
// risk: reversibility is the lower of the two, blast radius the higher, and a non-finite or non-numeric value on either side is the
// worst case (0 and 1, both). semanticDistance is the objective's when a finite number, else 1 (it is not a baseline input). Nothing
// is clamped. A null baseline or objective is an error. Inputs and the result are decoded JSON objects.
func TightenRiskInputs(baseline, objective any) (map[string]any, error) {
	if baseline == nil || objective == nil {
		return nil, errors.New("Cannot read properties of null (reading 'reversibility')")
	}
	b, _ := frontierObj(baseline)
	o, _ := frontierObj(objective)
	br, ok1 := frontierFinite(b["reversibility"])
	or, ok2 := frontierFinite(o["reversibility"])
	bb, ok3 := frontierFinite(b["blastRadius"])
	ob, ok4 := frontierFinite(o["blastRadius"])
	rev, blast := 0.0, 1.0
	if ok1 && ok2 && ok3 && ok4 {
		rev, blast = math.Min(br, or), math.Max(bb, ob)
	}
	sd := 1.0
	if f, ok := frontierFinite(o["semanticDistance"]); ok {
		sd = f
	}
	return map[string]any{"reversibility": jsNumber(rev), "blastRadius": jsNumber(blast), "semanticDistance": jsNumber(sd)}, nil
}
