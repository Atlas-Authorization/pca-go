package pca

// Replays the reference corpus for trait selectors, the policy decision, the blank-reason rule, the review message / signature and
// the signed-verb confirmation check. Signing seeds are labels ({"$bytes": {"$seed": label}}, see packTestSeed).

import "testing"

func vecIsNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func vecBytesOut(b []byte) map[string]any { return map[string]any{"$bytes": b64.EncodeToString(b)} }

func TestActionSelectorVectors(t *testing.T) {
	closure := func(v any) []string {
		s, _ := strsOf(v)
		return s
	}
	replayVectors(t, "ref-actions-sel-conf.json.gz", vecSeeded(map[string]vecFn{
		"selectorMatches": func(a []any) (any, error) { return ActionSelectorMatches(vecArg(a, 0), closure(vecArg(a, 1))), nil },
		"selectorMatchesFor": func(a []any) (any, error) {
			mode, _ := vecArg(a, 1).(string)
			conf, _ := vecArg(a, 3).(bool)
			return ActionSelectorMatchesFor(vecArg(a, 0), mode, closure(vecArg(a, 2)), conf), nil
		},
		"selectorHasNot": func(a []any) (any, error) { return ActionSelectorHasNot(vecArg(a, 0)), nil },
		"allowSelectorError": func(a []any) (any, error) {
			pinned, _ := vecArg(a, 1).(bool)
			return vecIsNull(ActionAllowSelectorError(vecArg(a, 0), pinned)), nil
		},
		"policyDecision": func(a []any) (any, error) {
			verb, _ := vecArg(a, 1).(string)
			conf, _ := vecArg(a, 3).(bool)
			return ActionPolicyDecision(vecObj(vecArg(a, 0)), verb, closure(vecArg(a, 2)), conf), nil
		},
		"blankReason": func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return blankReason(s), nil },
		"reviewMessage": func(a []any) (any, error) {
			m, err := ActionReviewMessage(vecObj(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(m), nil
		},
		"signReview": func(a []any) (any, error) {
			seed, err := packTestSeed(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return ActionSignReview(vecObj(vecArg(a, 0)), seed)
		},
		"verbConfirmationError": func(a []any) (any, error) {
			reg := coreRegistry
			if rd, ok := vecArg(a, 1).([]any); ok {
				var err error
				if reg, err = extendRegistry(coreRegistry, rd); err != nil {
					return nil, err
				}
			}
			pins := vecArg(a, 2)
			if len(a) > 2 && pins == nil { // JSON null is a value (a bad pins object); only an absent argument is "no pins"
				pins = map[string]any(nil)
			}
			return vecIsNull(verbConfirmationError(vecObj(vecArg(a, 0)), reg, pins)), nil
		},
	}))
}
