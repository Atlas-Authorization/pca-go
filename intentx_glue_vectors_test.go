package pca

// Replays the learner-feedback glue corpus: outcome verification, frame reports and the org layer built from approver maps.

import "testing"

func TestIntentGlueReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-glue-py.json.gz", map[string]vecFn{
		"verifyScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			if len(a) == 5 { // the oracle's variant: verify, then record the outcome as an elicited allow and ask whether it is still admitted
				r := ixMkMust(IntentVerifyOutcome(l, ixM(a[3]), a[4], nil))
				l.observe(ixM(a[3]), 1, "elicitation", nil)
				return map[string]any{"r": r, "vetoed": l.vetoedCells(), "metrics": l.Metrics(), "observations": l.ObservationsJSON(), "again": l.AdmitsOutcome(ixM(a[3]))}
			}
			pcs := ixL(ixArg(a, 5))
			res := ixMkMust(IntentVerifyOutcome(l, ixM(a[3]), a[4], pcs))
			return map[string]any{"result": res, "vetoed": l.vetoedCells(), "metrics": l.Metrics(), "observations": l.ObservationsJSON()}
		}),
		"frameScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			res := ixMkMust(IntentApplyFrameReport(l, ixM(a[3]), a[4]))
			return map[string]any{"result": res, "vetoed": l.vetoedCells(), "metrics": l.Metrics(), "observations": l.ObservationsJSON()}
		}),
		"orgScenario": ixWrap(func(a []any) any {
			var maps []any
			for _, pv := range ixL(a[1]) {
				p := ixM(pv)
				maps = append(maps, ixMaBuild(ixM(a[0]), ixM(ixArg(a, 3)), ixL(p["observations"]), p["ref"]))
			}
			return ixMkMust(IntentOrgLayerFromMaps(maps, a[2]))
		}),
	})
}
