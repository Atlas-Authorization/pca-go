package pca

// Replays the reference corpus for the action linter and the structural half of the undo engine.

import "testing"

func TestActionLintVectors(t *testing.T) {
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-lint.json.gz", map[string]vecFn{
		"lintRulesDigest": func([]any) (any, error) { return ActionLintRulesDigest() },
		"LINT_RULES":      func([]any) (any, error) { return ActionLintRules(), nil },
		"lintDefs":        func(a []any) (any, error) { return ActionLintDefs(list(vecArg(a, 0)), vecObj(vecArg(a, 1))) },
		"lintFails": func(a []any) (any, error) {
			strict, _ := vecArg(a, 1).(bool)
			return ActionLintFails(list(vecArg(a, 0)), strict), nil
		},
		"lintText":        func(a []any) (any, error) { return ActionLintText(list(vecArg(a, 0))), nil },
		"toSarif":         func(a []any) (any, error) { return ActionToSarif(list(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil },
		"mayBeReversible": func(a []any) (any, error) { return ActionMayBeReversible(vecObj(vecArg(a, 0))), nil },
		"reversibilityFor": func(a []any) (any, error) {
			return ActionReversibilityFor(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"compensationShape": func(a []any) (any, error) {
			return ActionCompensationShape(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
	})
}
