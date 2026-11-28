package pca

// Replays the layered-lattice corpus over a task learner and the org layer built from approver maps.

import "testing"

func TestIntentLatticeReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-lattice.json.gz", map[string]vecFn{
		"latticeScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			c := ixMkMust(IntentCeilingAdmitters(a[3]))
			decisions := []any{}
			for _, o := range ixL(a[4]) {
				decisions = append(decisions, IntentDecideOutcomeLayers(l, c, ixM(o)))
			}
			return map[string]any{"view": ixMkMust(IntentLatticeView(l, c)), "decisions": decisions}
		}),
		"orgScenario": ixWrap(func(a []any) any { return ixMkMust(IntentOrgLayerFromMaps(ixL(a[0]), a[1])) }),
	})
}
