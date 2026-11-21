package pca

// Replays the reference corpus for evolution records. The registry signing seeds are labels ({"$bytes": {"$seed": label}}): the key
// is sha256("atlas-pca-conformance/" + label).

import "testing"

func TestActionEvolveVectors(t *testing.T) {
	confirmedOf := func(v any) ActionDiffConfirmed {
		if c, ok := v.(bool); ok {
			return func(map[string]any) bool { return c }
		}
		return nil
	}
	replayVectors(t, "ref-actions-evolve.json.gz", vecSeeded(map[string]vecFn{
		"evolutionRecords": func(a []any) (any, error) {
			ns, _ := vecArg(a, 0).(string)
			p, _ := vecArg(a, 1).([]any)
			n, _ := vecArg(a, 2).([]any)
			return ActionEvolutionRecords(ns, p, n, coreRegistry, confirmedOf(vecArg(a, 3)))
		},
		"signEvolution": func(a []any) (any, error) {
			recs, _ := vecArg(a, 0).([]any)
			kid, _ := vecArg(a, 1).(string)
			seed, err := packTestSeed(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return ActionSignEvolution(recs, kid, seed)
		},
		"evolutionError": func(a []any) (any, error) {
			ns, _ := vecArg(a, 0).(string)
			p, _ := vecArg(a, 1).([]any)
			n, _ := vecArg(a, 2).([]any)
			recs, _ := vecArg(a, 3).([]any)
			if r := ActionEvolutionError(ns, p, n, recs, vecArg(a, 4), coreRegistry, confirmedOf(vecArg(a, 5))); r != "" {
				return r, nil
			}
			return nil, nil
		},
	}))
}
