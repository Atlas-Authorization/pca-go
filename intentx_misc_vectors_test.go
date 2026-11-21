package pca

// Replays the intent misc corpus: classifier calibration and risk, provenance, regret, the schema outcome space and the
// cell coordinates. Entries not yet native are skipped by name.

import (
	"errors"
	"testing"
)

func ixNotPorted(why string) vecFn {
	return func([]any) (any, error) { return nil, vecSkip(why) }
}

func TestIntentMiscReferenceVectors(t *testing.T) {
	regret := func(a []any) any {
		var cases []IntentRegretCase
		val := func(x any, k string) float64 { return ixFOr(ixM(ixM(x)["values"])[k], 0) }
		for _, cv := range ixL(a[0]) {
			c := ixM(cv)
			cases = append(cases, IntentRegretCase{Feasible: ixL(c["feasible"]), Chosen: c["chosen"],
				Admits:  func(x any) bool { return val(x, "ok") == 1 },
				Utility: func(x any) float64 { return val(x, "u") }})
		}
		scale := 1.0
		if len(a) > 1 {
			scale = ixF(a[1])
		}
		return IntentRegretReport(cases, scale)
	}
	replayVectorsSeeded(t, "ref-intent-misc.json.gz", map[string]vecFn{
		"calibrateConfusion": ixWrap(func(a []any) any {
			d := 0.05
			if len(a) > 2 {
				d = ixF(a[2])
			}
			return ixCalibrateConfusion(ixL(a[0]), ixL(a[1]), d)
		}),
		"confusionDigest":    ixWrap(func(a []any) any { return ixConfusionDigest(ixM(a[0])) }),
		"publishedErrorRate": ixWrap(func(a []any) any { return ixPublishedErrorRate(ixM(a[0])) }),
		"classifierCardNote": ixWrap(func(a []any) any { return ixClassifierCardNote(ixS(a[0]), ixM(a[1])) }),
		"classifierRisk":     ixWrap(func(a []any) any { return ixClassifierRisk(ixM(a[0])) }),
		"labelSound":         ixWrap(func(a []any) any { return ixLabelSound(ixM(a[0])) }),
		"labelSoundBound":    ixWrap(func(a []any) any { return ixLabelSoundBound(ixM(a[0]), ixF(a[1])) }),
		"provenanceBanner": ixWrap(func(a []any) any {
			what := "value"
			if len(a) > 1 {
				what = ixS(a[1])
			}
			return ixProvenanceBanner(a[0], what)
		}),
		"provenanceFriction":    ixWrap(func(a []any) any { return ixProvenanceFriction(a[0], a[1], a[2]) }),
		"regretReport":          ixWrap(regret),
		"deriveOmegaFromSchema": ixWrap(func(a []any) any { return ixDeriveOmegaFromSchema(ixM(a[0])) }),
		"canonValue":            ixWrap(func(a []any) any { return ixCanonValue(ixM(a[0]), a[1]) }),
		"cellCoords":            ixWrap(func(a []any) any { return ixCellCoords(ixM(a[0]), ixL(a[1])) }),
		"cellFromCoords":        ixWrap(func(a []any) any { return ixCellFromCoords(ixM(a[0]), a[1]) }),
		"intentRequiredBody":    ixWrap(func(a []any) any { return ixIntentRequiredBody(ixM(a[0])) }),
		"parseSlotsJSON":        ixWrap(func(a []any) any { return ixParseSlotsJSON(ixS(a[0]), ixArg(a, 1)) }),
		"slotsPrompt":           ixWrap(func(a []any) any { return ixSlotsPrompt(ixS(a[0]), ixArg(a, 1)) }),
		"runCompilers": ixWrap(func(a []any) any {
			var cs []IntentCompiler
			for _, sv := range ixL(a[1]) {
				spec := ixM(sv)
				id, fam := ixS(spec["id"]), ixS(spec["family"])
				switch spec["kind"] {
				case "captured":
					cs = append(cs, IntentCapturedSlotsCompiler(id))
				case "throws":
					cs = append(cs, IntentCompiler{ID: id, Family: fam, Compile: func(map[string]any) (map[string]any, error) { return nil, errors.New("boom") }})
				default:
					pol := spec["policy"]
					cs = append(cs, IntentFixedCompiler(id, fam, func(map[string]any) any { return pol }))
				}
			}
			return IntentRunCompilers(ixM(a[0]), cs)
		}),
		"analyzeDisagreement": ixWrap(func(a []any) any { return ixAnalyzeDisagreement(ixL(a[0]), ixM(ixArg(a, 1))) }),
		"panelFlags":          ixWrap(func(a []any) any { return ixPanelFlags(ixM(a[0])) }),
		"committeeAnchors":    ixWrap(func(a []any) any { return ixCommitteeAnchors(ixL(a[0]), a[1]) }),
		"dimKindOf":           ixWrap(func(a []any) any { return ixDimKindOf(ixS(a[0])) }),
		"describeAccCell": ixWrap(func(a []any) any {
			return ixDescribeAccCell(ixM(a[0]), ixIdx(a[1]), ixS(a[2]), ixArg(a, 3))
		}),
		"trajectoryHarmRange": ixWrap(func(a []any) any { return ixTrajectoryHarmRange(a[0], a[1]) }),
		"defaultAccumulators": ixWrap(func(a []any) any { return ixDefaultAccumulators(ixM(a[0]), ixM(a[1])) }),
		"augmentOmega":        ixWrap(func(a []any) any { return ixAugmentOmega(ixM(a[0]), ixM(a[1]), ixM(ixArg(a, 2))) }),
		"liftAction": ixWrap(func(a []any) any {
			r := ixLiftAction(ixM(a[0]), ixM(a[1]), ixL(a[2]), ixM(a[3]), ixM(ixArg(a, 4)))
			if r == nil {
				return nil
			}
			return r
		}),
		"stepTrajectory": ixWrap(func(a []any) any {
			allow := a[4]
			in := func(_ string, cell []any) bool {
				if allow == "all" {
					return true
				}
				if allow == "none" {
					return false
				}
				for _, x := range ixL(allow) {
					if ixCellKeyJoin(x) == ixCellKeyJoin(cell) {
						return true
					}
				}
				return false
			}
			cand := ixCopyMap(ixM(a[3]))
			cand["id"] = "new"
			return ixStepTrajectory(ixM(a[0]), ixM(a[1]), ixL(a[2]), cand, in, nil)
		}),
		"stateDigest": ixWrap(func(a []any) any { return ixStateDigest(ixArg(a, 0)) }),
		"snapshotState": ixWrap(func(a []any) any {
			keep := true
			if len(a) > 1 {
				keep = ixTruthy(a[1])
			}
			return ixSnapshotState(ixM(a[0]), keep)
		}),
		"writeSetOf":   ixWrap(func(a []any) any { return ixWriteSetOf(ixM(a[0]), ixM(a[1])) }),
		"checkFrame": ixWrap(func(a []any) any {
			if len(a) == 1 { // the oracle's spec-only variant supplies the action, pre and post itself
				return ixCheckFrame(a[0], map[string]any{"verb": "v", "resource": "r"}, map[string]any{}, map[string]any{}, nil)
			}
			return ixCheckFrame(a[0], a[1], a[2], a[3], ixM(ixArg(a, 4)))
		}),
		"signIntent":   ixWrap(func(a []any) any { return ixSignIntent(ixM(a[0]), ixS(a[1])) }),
		"intentRef":    ixWrap(func(a []any) any { return ixIntentRef(ixM(a[0])) }),
		"verifyIntent": ixWrap(func(a []any) any { return ixVerifyIntent(a[0], ixM(ixArg(a, 1))) }),
	})
}
