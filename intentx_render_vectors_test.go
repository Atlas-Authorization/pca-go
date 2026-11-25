package pca

// Replays the intent renderer, back-translation diff and boundary witnesses.

import "testing"

func TestIntentRenderReferenceVectors(t *testing.T) {
	oracle := func(mode string) func(w map[string]any) bool {
		return func(w map[string]any) bool {
			allows := w["grantAllows"] == true
			switch mode {
			case "agree":
				return allows
			case "flip":
				return !allows
			case "flip-boundary":
				if w["kind"] == "boundary" {
					return !allows
				}
				return allows
			}
			return w["side"] == "inside" && w["kind"] != "unconstrained"
		}
	}
	replayVectors(t, "ref-intent-render.json.gz", map[string]vecFn{
		"labelOf":         ixWrap(func(a []any) any { return ixLabelOf(ixS(a[0])) }),
		"renderCondition": ixWrap(func(a []any) any { return ixRenderCondition(a[0]) }),
		"renderCaveat":    ixWrap(func(a []any) any { return ixRenderCaveat(a[0]) }),
		"renderGrant":     ixWrap(func(a []any) any { return ixRenderGrant(a[0], ixArg(a, 1)) }),
		"renderQuestion":  ixWrap(func(a []any) any { return ixRenderQuestion(ixM(a[0]), ixL(a[1]), ixArg(a, 2)) }),
		"renderAction":    ixWrap(func(a []any) any { return ixRenderAction(ixM(a[0]), ixM(a[1]), ixArg(a, 2)) }),
		"claimsOf":        ixWrap(func(a []any) any { return ixClaimsOf(a[0], ixM(a[1])) }),
		"backTranslationDiff": ixWrap(func(a []any) any {
			return ixBackTranslationDiff(a[0], ixM(a[1]), ixM(a[2]))
		}),
		"claimDiff": ixWrap(func(a []any) any {
			n0, n1 := "the first reading", "the second reading"
			if names := ixL(ixArg(a, 3)); len(names) >= 2 {
				n0, n1 = jsValueString(names[0]), jsValueString(names[1])
			}
			return ixClaimDiff(a[0], a[1], ixM(a[2]), n0, n1)
		}),
		"boundaryWitnesses": ixWrap(func(a []any) any { return ixBoundaryWitnesses(a[0], ixM(a[1]), ixArg(a, 2)) }),
		"checkWitnesses": ixWrap(func(a []any) any {
			return ixCheckWitnesses(ixL(a[0]), oracle(ixS(a[1])))
		}),
	})
}
