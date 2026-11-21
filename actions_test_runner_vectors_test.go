package pca

// Replays the reference corpus for the example and property runner of the action packs.

import "testing"

func TestActionTestRunnerVectors(t *testing.T) {
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-test-runner.json.gz", map[string]vecFn{
		"decideExample": func(a []any) (any, error) {
			return ActionDecideExample(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), coreRegistry, list(vecArg(a, 2))), nil
		},
		"runDefTests": func(a []any) (any, error) {
			limit := 0
			if f, ok := jsNum(vecArg(a, 1)); ok {
				limit = int(f)
			}
			return ActionRunDefTests(list(vecArg(a, 0)), coreRegistry, limit), nil
		},
		"testText": func(a []any) (any, error) { return ActionTestText(vecObj(vecArg(a, 0))), nil },
	})
}
