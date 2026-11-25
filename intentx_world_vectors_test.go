package pca

// Replays the world-dimension corpus and the pure just-in-time parts of the misc corpus.

import "testing"

func TestIntentWorldReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-world.json.gz", map[string]vecFn{
		"worldDim": ixWrap(func(a []any) any { return ixWorldDim(ixS(a[0]), ixM(a[1])) }),
		"excessDim": ixWrap(func(a []any) any {
			var slacks []any
			if len(a) > 2 {
				slacks = ixL(a[2])
			}
			return ixExcessDim(ixS(a[0]), a[1], slacks)
		}),
		"optimalityCondition": ixWrap(func(a []any) any {
			var slack any = 0.0
			if len(a) > 1 {
				slack = a[1]
			}
			return ixOptimalityCondition(ixS(a[0]), slack)
		}),
		"provenanceDim": ixWrap(func(a []any) any { return ixProvenanceDim(ixS(a[0])) }),
		"classifierDim": ixWrap(func(a []any) any { return ixClassifierDim(ixS(a[0]), ixStrList(a[1])) }),
		"withDims":      ixWrap(func(a []any) any { return ixWithDims(ixM(a[0]), ixS(a[1]), ixL(a[2])) }),
		"liftOutcome":   ixWrap(func(a []any) any { return ixLiftOutcome(ixM(a[0]), ixM(a[1]), ixL(a[2])) }),
	})
}
