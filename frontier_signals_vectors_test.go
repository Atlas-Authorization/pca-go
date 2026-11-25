package pca

import "testing"

// Replay of the intent-frontier signals against the reference (ref-frontier-signals), every case: the three signal functions and
// the tightening of risk inputs (signed zero included). A reference throw requires a refusal.
func TestFrontierSignalsMatchTheReference(t *testing.T) {
	one := func(f func(any) string) vecFn {
		return func(a []any) (any, error) { return f(scDecode(vecArg(a, 0))), nil }
	}
	fns := map[string]vecFn{
		"semanticSignal":  one(SemanticSignal),
		"progressSignal":  one(ProgressSignal),
		"objectiveSignal": one(ObjectiveSignal),
		"tightenRiskInputs": func(a []any) (any, error) {
			return TightenRiskInputs(scDecode(vecArg(a, 0)), scDecode(vecArg(a, 1)))
		},
	}
	replayAll(t, "ref-frontier-signals.json.gz", 690, fns, nil, nil)
}
