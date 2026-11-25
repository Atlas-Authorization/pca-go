package pca

// Replays the intent runtime digests, effect postconditions, drift detector and question cards.

import "testing"

func TestIntentRuntimeReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-runtime.json.gz", map[string]vecFn{
		"pcactnActionOf": ixWrap(func(a []any) any { return ixPcactnActionOf(ixM(a[0]), ixM(a[1])) }),
		"judgeInputOf": ixWrap(func(a []any) any {
			return ixJudgeInputOf(ixM(a[0]), ixM(a[1]), ixF(a[2]), ixM(a[3]), nil)
		}),
		"jitConsentRequest": ixWrap(func(a []any) any {
			return ixJitConsentRequest(ixM(a[0]), ixM(a[1]), ixF(a[2]), ixM(a[3]), nil)
		}),
		"jitConsentDigest":      ixWrap(func(a []any) any { return ixJitConsentDigest(ixM(a[0])) }),
		"calibrationDigest":     ixWrap(func(a []any) any { return ixCalibrationDigest(ixM(a[0])) }),
		"icAttDigest":           ixWrap(func(a []any) any { return ixICAttDigest(ixM(a[0])) }),
		"foldSemanticRisk":      ixWrap(func(a []any) any { return ixFoldSemanticRisk(ixF(a[0]), ixM(a[1])) }),
		"defaultPostconditions": ixWrap(func(a []any) any { return ixDefaultPostconditions() }),
		"checkPostconditions": ixWrap(func(a []any) any {
			return ixCheckPostconditions(ixM(a[0]), ixM(a[1]), ixArg(a, 2), ixL(ixArg(a, 3)))
		}),
		"effectContext": ixWrap(func(a []any) any { return ixEffectContext(ixM(a[0]), ixM(a[1]), ixArg(a, 2)) }),
		"signalLabel":   ixWrap(func(a []any) any { return float64(IntentSignalLabel(ixS(a[0]))) }),
		"narrowStart":   ixWrap(func(a []any) any { return ixNarrowStart(ixM(a[0]), ixM(a[1]), ixM(ixArg(a, 2))) }),
		"driftRun": ixWrap(func(a []any) any {
			d, err := ixNewDrift(ixM(ixArg(a, 0)))
			if err != nil {
				panic(err)
			}
			out := []any{}
			for _, x := range ixL(a[1]) {
				out = append(out, d.Update(x == true).toJSON())
			}
			out = append(out, d.State().toJSON())
			d.Reset()
			return append(out, d.State().toJSON())
		}),
		"questionCard":    ixWrap(func(a []any) any { return ixQuestionCard(ixM(a[0]), ixM(a[1]), ixArg(a, 2)) }),
		"parseCardAnswer": ixWrap(func(a []any) any { return ixParseCardAnswer(ixM(a[0]), ixM(a[1])) }),
	})
}
