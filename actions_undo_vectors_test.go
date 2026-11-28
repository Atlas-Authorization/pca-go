package pca

// Replays the reference corpus for the undo engine and its attestation check (the core trait registry).

import "testing"

func TestActionUndoVectors(t *testing.T) {
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-undo-engine.json.gz", map[string]vecFn{
		"undoPlan": func(a []any) (any, error) {
			if p := ActionUndoPlan(list(vecArg(a, 0)), vecArg(a, 1), vecObj(vecArg(a, 2))); p != nil {
				return p, nil
			}
			return nil, nil
		},
		"attested": func(a []any) (any, error) { return defConfirmed(vecObj(vecArg(a, 0)), coreRegistry, vecArg(a, 1)), nil },
	})
}
