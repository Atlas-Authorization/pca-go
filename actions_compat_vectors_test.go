package pca

// Replays the reference corpus for the legacy-catalog bridges.

import "testing"

func TestActionCompatVectors(t *testing.T) {
	replayVectors(t, "ref-actions-compat.json.gz", map[string]vecFn{
		"normalizeReversibility": func(a []any) (any, error) { return ActionNormalizeReversibility(vecArg(a, 0)), nil },
		"legacyOperationsClass": func(a []any) (any, error) {
			r, _ := vecArg(a, 0).(string)
			return ActionLegacyOperationsClass(r), nil
		},
		"maxRevOf": func(a []any) (any, error) {
			x, _ := vecArg(a, 0).(string)
			y, _ := vecArg(a, 1).(string)
			return ActionMaxRev(x, y), nil
		},
		"unitTagOf":         func(a []any) (any, error) { return ActionUnitTag(vecObj(vecArg(a, 0))), nil },
		"blastOfFloat":      func(a []any) (any, error) { return ActionBlastOfFloat(vecArg(a, 0)), nil },
		"blastExactOfFloat": func(a []any) (any, error) { return ActionBlastExactOfFloat(vecArg(a, 0)), nil },
		"fromCatalogSpec": func(a []any) (any, error) {
			return ActionFromCatalogSpec(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"fromCatalog": func(a []any) (any, error) {
			specs, _ := vecArg(a, 0).([]any)
			out := make([]any, len(specs))
			for i, s := range specs {
				out[i] = ActionFromCatalogSpec(vecObj(s), vecObj(vecArg(a, 1)))
			}
			return out, nil
		},
	})
}
