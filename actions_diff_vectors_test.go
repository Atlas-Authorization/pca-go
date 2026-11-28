package pca

// Replays the reference corpus for action id patterns and semantic diffs: idMatches, idPatternContains, diffDefs (confirmed =
// the attestation check answers that constant), diffDefsAuthoring, diffIsFree, diffPacks. The effective-profile functions of the
// same corpus (effective, hintTraits, effWithTrait, prulesViolations, ...) are covered by the action-kit vectors.

import (
	"errors"
	"testing"
)

func TestActionDiffVectors(t *testing.T) {
	skip := func([]any) (any, error) { return nil, vecSkip("covered by the action-kit vectors") }
	replayVectors(t, "ref-actions-diff.json.gz", map[string]vecFn{
		"idMatches": func(a []any) (any, error) {
			id, ok := vecArg(a, 1).(string)
			if !ok {
				return nil, errors.New("id is not a string")
			}
			return ActionIDMatches(vecArg(a, 0), id), nil
		},
		"idPatternContains": func(a []any) (any, error) { return ActionIDPatternContains(vecArg(a, 0), vecArg(a, 1)), nil },
		"diffDefs": func(a []any) (any, error) {
			var confirmed ActionDiffConfirmed
			if c, ok := vecArg(a, 2).(bool); ok {
				confirmed = func(map[string]any) bool { return c }
			}
			return ActionDiffDefs(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), coreRegistry, confirmed)
		},
		"diffDefsAuthoring": func(a []any) (any, error) {
			return ActionDiffDefsAuthoring(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), coreRegistry)
		},
		"diffIsFree": func(a []any) (any, error) {
			c, _ := vecArg(a, 0).(string)
			return ActionDiffIsFree(c), nil
		},
		"diffPacks": func(a []any) (any, error) {
			o, _ := vecArg(a, 0).([]any)
			n, _ := vecArg(a, 1).([]any)
			return ActionDiffPacks(o, n, coreRegistry)
		},
		"effective": skip, "hintTraits": skip,
		"join": func(a []any) (any, error) {
			return joinProfile(profileFromRaw(vecArg(a, 0)), profileFromRaw(vecArg(a, 1))).raw(), nil
		},
		"leq": func(a []any) (any, error) {
			return leqProfile(profileFromRaw(vecArg(a, 0)), profileFromRaw(vecArg(a, 1))), nil
		},
		"profileEq": func(a []any) (any, error) {
			return leqProfile(profileFromRaw(vecArg(a, 0)), profileFromRaw(vecArg(a, 1))) && leqProfile(profileFromRaw(vecArg(a, 1)), profileFromRaw(vecArg(a, 0))), nil
		},
		"effWithTrait": func(a []any) (any, error) {
			t, _ := vecArg(a, 1).(string)
			p, err := ActionEffWithTrait(vecObj(vecArg(a, 0)), t, coreRegistry)
			if err != nil {
				return nil, err
			}
			return p.raw(), nil
		},
		"prulesViolations": func(a []any) (any, error) { return anyStrs(ActionPrulesViolations(vecObj(vecArg(a, 0)), nil)), nil },
		"requiredPrulesViolated": func(a []any) (any, error) {
			return anyStrs(ActionRequiredPrulesViolated(vecObj(vecArg(a, 0)), profileFromRaw(vecArg(a, 1)))), nil
		},
	})
}
