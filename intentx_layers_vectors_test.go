package pca

// Replays the multi-principal rules, common refinement, wallet-side layer lattice, quorum approvals and grant measurement.

import "testing"

func TestIntentLayersReferenceVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-intent-layers.json.gz", map[string]vecFn{
		"normalizeRule":    ixWrap(func(a []any) any { return ixNormalizeRule(a[0], ixStrList(a[1])) }),
		"effectiveVetoers": ixWrap(func(a []any) any { return ixEffectiveVetoers(a[0], ixStrList(a[1])) }),
		"ruleAdmits":       ixWrap(func(a []any) any { return ixRuleAdmits(ixM(a[0]), ixL(a[1])) }),
		"jointAcceptance":  ixWrap(func(a []any) any { return ixJointAcceptance(ixM(a[0]), ixL(a[1])) }),
		"commonRefinement": ixWrap(func(a []any) any { return ixCommonRefinement(ixL(a[0])) }),
		"ceilingOf": ixWrap(func(a []any) any {
			return ixCeilingOf(ixCeilingAdmitters(a[0]), ixM(a[1]), ixM(a[2]))
		}),
		"assertAskable": ixWrap(func(a []any) any { ixAssertAskable(ixM(a[0]), ixM(a[1])); return nil }),
		"layerCells":    ixWrap(func(a []any) any { return ixLayerCells(ixM(a[0]), ixAdmitter(a[1])) }),
		"ownerRisk": ixWrap(func(a []any) any {
			return ixOwnerRisk(ixM(a[0]), ixL(a[1]), ixAcceptabilityOf(a[2]))
		}),
		"cellKeyOf":         ixWrap(func(a []any) any { return ixCellKeyOf(ixM(a[0]), ixM(a[1])) }),
		"signLayerApproval": ixWrap(func(a []any) any { return ixSignLayerApproval(ixM(a[0]), ixS(a[1])) }),
		"verifyQuorumApprovals": ixWrap(func(a []any) any {
			return ixVerifyQuorumApprovals(a[0], a[1], a[2], a[3])
		}),
		"measureGrantExact": ixWrap(func(a []any) any {
			return ixMeasureGrantExact(ixM(a[0]), a[1], ixAcceptabilityOf(a[2]))
		}),
		"measureGrant": ixWrap(func(a []any) any {
			return ixMeasureGrant(ixM(a[0]), a[1], ixAcceptabilityOf(a[2]), ixM(ixArg(a, 3)))
		}),
	})
}
