package pca

// Replays the sync cases of the reference corpus (`confirmed` is the attestation check answering that constant).

import "testing"

func TestActionSyncVectors(t *testing.T) {
	confirmedOf := func(v any) ActionDiffConfirmed {
		if c, ok := v.(bool); ok {
			return func(map[string]any) bool { return c }
		}
		return nil
	}
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-sync.json.gz", map[string]vecFn{
		"syncSource": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 0))
			spec, _ := o["specDigest"].(string)
			return ActionSyncSource(ActionSyncArgs{Current: list(o["current"]), Imported: list(o["imported"]), SpecDigest: spec,
				Lock: vecObj(o["lock"]), Now: o["now"], Confirmed: confirmedOf(vecArg(a, 1))})
		},
		"syncText": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 0))
			spec, _ := o["specDigest"].(string)
			r, err := ActionSyncSource(ActionSyncArgs{Current: list(o["current"]), Imported: list(o["imported"]), SpecDigest: spec,
				Lock: vecObj(o["lock"]), Now: o["now"], Confirmed: confirmedOf(vecArg(a, 1))})
			if err != nil {
				return nil, err
			}
			return ActionSyncText(r), nil
		},
	})
}
