package pca

// Replays the trust-ramp corpus: signed observations (sign, verify) and the ramp scenarios.

import "testing"

func TestIntentRampReferenceVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-intent-ramp.json.gz", map[string]vecFn{
		"signObservation": ixWrap(func(a []any) any { return ixMkMust(IntentSignObservation(ixM(a[0]), ixS(a[1]))) }),
		"verifyObservation": ixWrap(func(a []any) any {
			return IntentVerifyObservation(a[0], ixM(ixArg(a, 1)))
		}),
		"rampScenario": ixWrap(func(a []any) any {
			ramp, err := NewIntentTrustRamp(ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2])), ixM(a[3]))
			if err != nil {
				panic(err)
			}
			out := []any{}
			// the reference's state() hands out the live queue: a state taken before more signals were queued shows the queue as it is at
			// the end of that stretch (until a rebase replaces the array), so those states are patched when the stretch ends
			var live []map[string]any
			endStretch := func() {
				for _, st := range live {
					st["pending"] = ramp.Pending()
				}
				live = nil
			}
			for _, ov := range ixL(a[4]) {
				op := ixM(ov)
				switch op["op"] {
				case "record":
					out = append(out, ixMkMust(ramp.Record(ixM(op["outcome"]), ixS(op["signal"]))))
				case "observe":
					out = append(out, ixMkMust(ramp.RecordObservation(op["obs"], ixM(op["ctx"]))))
				case "rebase":
					endStretch()
					ramp.Rebase(ixRfMk(ixM(op["omega"]), ixM(op["mapOpts"]), ixL(op["observations"])))
					out = append(out, map[string]any{"frozen": ramp.Frozen(), "pending": float64(len(ramp.Pending()))})
				default:
					st := map[string]any{"frozen": ramp.Frozen(), "pending": ramp.Pending(), "drift": ramp.Drift().State().toJSON()}
					live = append(live, st)
					out = append(out, st)
				}
			}
			endStretch()
			return []any{out, map[string]any{"log": ramp.Log(), "frozen": ramp.Frozen(), "pending": ramp.Pending(), "metrics": ramp.Learner().Metrics()}}
		}),
	})
}
