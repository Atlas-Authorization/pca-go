package pca

// Replays the outcome corpus: verifying an executed action's effect against the learner, and the Monte Carlo residual-risk estimate.

import "testing"

func TestIntentOutcomeReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-outcome.json.gz", map[string]vecFn{
		"verifyScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			var pcs []any
			if len(a) > 5 {
				pcs = ixL(a[5])
				if pcs == nil {
					pcs = []any{}
				}
			}
			res := ixMkMust(IntentVerifyOutcome(l, ixM(a[3]), a[4], pcs))
			return map[string]any{"result": res, "metrics": l.Metrics()}
		}),
		"mcScenario": ixWrap(func(a []any) any {
			return ixMkMust(IntentEstimateResidualRiskMC(ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2])), ixF(a[3]), ixF(a[4])))
		}),
	})
}
