package pca

// Replays the intent outcome-space corpus (omega, policy plumbing, slots, regions).

import "testing"

func ixStatsOut(m, h float64) map[string]any { return map[string]any{"mass": m, "harm": h} }

func TestIntentOmegaReferenceVectors(t *testing.T) {
	rngSeq := func(seed float64, n int) []any {
		r := IntentRng(seed)
		out := make([]any, n)
		for i := range out {
			out[i] = r()
		}
		return out
	}
	cellRep := func(a []any) any { return ixCellRep(ixM(a[0]), ixL(a[1])) }
	replayVectorsApprox(t, "ref-intent-omega.json.gz", map[string]vecFn{
		"deriveOmega":   ixWrap(func(a []any) any { return ixDeriveOmega(ixM(a[0])) }),
		"harmMax":       ixWrap(func(a []any) any { return ixHarmMax(ixM(a[0]), ixDefaultHarm) }),
		"verbSpace":     ixWrap(func(a []any) any { return ixVerbSpace(ixM(a[0]), ixS(a[1])) }),
		"verbCellCount": ixWrap(func(a []any) any { return ixVerbCellCount(ixM(a[0])) }),
		"decodeCell":    ixWrap(func(a []any) any { return ixDecodeCell(ixM(a[0]), ixF(a[1])) }),
		"encodeCell":    ixWrap(func(a []any) any { return ixEncodeCell(ixM(a[0]), ixL(a[1])) }),
		"cellRep":       ixWrap(cellRep),
		"seeded":        ixWrap(cellRep),
		"cellStats": ixWrap(func(a []any) any {
			m, h := ixCellStats(ixM(a[0]), ixL(a[1]), ixDefaultHarm)
			return ixStatsOut(m, h)
		}),
		"cellOf":      ixWrap(func(a []any) any { return ixCellOf(ixM(a[0]), ixM(a[1])) }),
		"harmOf":      ixWrap(func(a []any) any { return ixHarmOf(ixM(a[0]), ixM(a[1]), ixDefaultHarm) }),
		"cellCount":   ixWrap(func(a []any) any { return float64(ixCellCount(ixM(a[0]))) }),
		"numCells":    ixWrap(func(a []any) any { return ixNumCellsJSON(ixM(a[0])) }),
		"numRep":      ixWrap(func(a []any) any { return ixNumRep(ixM(a[0]), ixIdx(a[1])) }),
		"repValue":    ixWrap(func(a []any) any { return ixRepValue(ixM(a[0]), ixIdx(a[1])) }),
		"catRep":      ixWrap(func(a []any) any { return ixCatRep(ixM(a[0]), ixIdx(a[1])) }),
		"catCellOf":   ixWrap(func(a []any) any { return float64(ixCatCellOf(ixM(a[0]), ixS(a[1]))) }),
		"cellOfValue": ixWrap(func(a []any) any { return float64(ixCellOfValue(ixM(a[0]), a[1])) }),
		"dimCellStats": ixWrap(func(a []any) any {
			m, h := ixDimCellStats(ixM(a[0]), ixIdx(a[1]), ixDefaultHarm)
			return ixStatsOut(m, h)
		}),
		"intervalWeight": ixWrap(func(a []any) any { return ixIntervalWeight(ixM(a[0]), ixF(a[1]), ixF(a[2])) }),
		"rngSeq":         ixWrap(func(a []any) any { return rngSeq(ixF(a[0]), ixIdx(a[1])) }),
		"sampleOutcomes": ixWrap(func(a []any) any {
			r := IntentRng(ixF(a[1]))
			out := []any{}
			for i, n := 0, ixIdx(a[2]); i < n; i++ {
				_, o := ixSampleOutcome(ixM(a[0]), r)
				out = append(out, o)
			}
			return out
		}),
		"normalizePolicy": ixWrap(func(a []any) any { return ixNormalizePolicy(a[0]) }),
		"slotsToPolicy":   ixWrap(func(a []any) any { return ixSlotsToPolicy(ixM(a[0])) }),
		"outcomeToAction": ixWrap(func(a []any) any { return ixOutcomeToAction(ixM(a[0]), ixM(a[1])) }),
		"admits": ixWrap(func(a []any) any {
			ad, err := IntentNewAdmitter(a[0])
			if err != nil {
				panic(err)
			}
			return ad.admits(ixM(a[1]), ixM(a[2]))
		}),
		"regionOfCell": ixWrap(func(a []any) any { return ixRegionOfCell(ixM(a[0]), ixL(a[1])) }),
		"regionCells":  ixWrap(func(a []any) any { return ixIntsOut(ixRegionCells(ixM(a[0]), ixM(a[1]), ixS(a[2]))) }),
		"dimCellsIn":   ixWrap(func(a []any) any { return ixIntsOut(ixDimCellsIn(ixM(a[0]), ixM(a[1]), ixS(a[2]))) }),
		"restrictRegion": ixWrap(func(a []any) any {
			return ixRestrictRegion(map[string]any{"verb": "v", "dims": map[string]any{}}, ixM(a[0]), ixM(a[1]))
		}),
		"valueInRegionDim": ixWrap(func(a []any) any { return ixValueInRegionDim(ixS(a[0]), ixM(a[1]), a[2]) }),
	}, "sampleOutcomes")
}
