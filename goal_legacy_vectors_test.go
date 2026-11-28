package pca

// Replays the legacy-lift corpus: the facade's {permissions, limits} lifted to a Goal and its ontology.

import "testing"

func TestGoalLegacyReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-goal-legacy.json.gz", map[string]vecFn{
		"liftLegacy": func(a []any) (any, error) {
			o := map[string]any{"permissions": vecArg(a, 0), "principal": vecArg(a, 2)}
			if l := vecArg(a, 1); anlTruthy(l) {
				o["limits"] = l
			}
			if v := vecArg(a, 3); v != nil {
				o["notAfter"] = v
			}
			if v := vecArg(a, 4); v != nil {
				o["notBefore"] = v
			}
			if v := vecArg(a, 5); v != nil {
				o["nlDigest"] = v
			}
			return anlTry(func() any { return goalLiftLegacy(o, nil) })
		},
	})
}
