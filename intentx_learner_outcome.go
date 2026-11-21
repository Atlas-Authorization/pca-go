package pca

// An executed action's effect fed back into the learner, and the Monte Carlo form of the learner's residual-risk estimate.

// IntentVerifyOutcome checks an executed action's effect and feeds the result back: a violation is a negative runtime observation
// that vetoes the action's cell. ok and pending change nothing (a met postcondition is not the principal's endorsement). pcs nil
// takes the default postconditions.
func IntentVerifyOutcome(l *IntentLearner, o map[string]any, effect any, pcs []any) (map[string]any, error) {
	r, err := ixTry(func() any {
		vs := ixMaFindVerb(l.omega, o["verb"])
		if vs == nil {
			ixFail("verifyOutcome: no verb %s in Ω", jsValueString(o["verb"]))
		}
		report := ixCheckPostconditions(vs, o, effect, pcs)
		if report["status"] != "violated" {
			return map[string]any{"report": report}
		}
		div, err := IntentApplyDivergence(l, o, 0)
		if err != nil {
			panic(err)
		}
		return map[string]any{"report": report, "divergence": div}
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// IntentEstimateResidualRiskMC is the Monte Carlo residual-risk estimate of the learner's grant (samples and seed default to 20000 and 7).
func IntentEstimateResidualRiskMC(l *IntentLearner, samples, seed float64) (float64, error) {
	r, err := ixTry(func() any {
		rand := IntentRng(seed)
		g := ixAdmitter(l.Synthesize())
		R := 0.0
		for i := 0.0; i < samples; i++ {
			vs, o := ixSampleOutcome(l.omega, rand)
			if g.admits(vs, o) {
				R += float64((1 - l.Acceptance(o)) * ixHarmOf(vs, o, l.harm))
			}
		}
		return R / samples
	})
	if err != nil {
		return 0, err
	}
	return r.(float64), nil
}
