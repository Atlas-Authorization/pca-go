package pca

// Replay of the reference corpus for the goal package: token-tape codec, digests, canonical order, formatting, policy card,
// reference semantics, policy digest, decision-to-effect binding and the signing envelope. Seeds are the 32-byte signer seeds
// (base64url) the corpus carries for deterministic signatures.

import "testing"

// goalVecTry runs f the way the reference would throw: a panic becomes an error.
func goalVecTry(f func() any) (any, error) { return anlTry(f) }

func goalVecStr(v any) string { return anlStr(v, "argument") }

func TestGoalReferenceVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-goal.json.gz", map[string]vecFn{
		"encodeGoal": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalEncodeGoal(vecArg(a, 0)) })
		},
		"encodeOntology": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalEncodeOntology(vecArg(a, 0)) })
		},
		"encodeAct": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalEncodeAct(vecArg(a, 0)) })
		},
		"encodeHist": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalEncodeHist(vecArg(a, 0)) })
		},
		"decodeGoal": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalDecodeGoal(goalTapeFromJSON(vecArg(a, 0))) })
		},
		"decodePolicy": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalDecodePolicy(goalTapeFromJSON(vecArg(a, 0))) })
		},
		"goalDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalGoalDigest(vecArg(a, 0)) })
		},
		"nlDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalNlDigest(vecArg(a, 0)) })
		},
		"modelSetDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalModelSetDigest(vecArg(a, 0)) })
		},
		"approvalDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalApprovalDigest(vecArg(a, 0)) })
		},
		"canonicalizeGoal": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCanonicalizeGoal(vecArg(a, 0)) })
		},
		"stable": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalStable(vecArg(a, 0)) })
		},
		"fmtMoney": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalFmtMoney(vecArg(a, 0), vecArg(a, 1)) })
		},
		"fmtQuantity": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalFmtQuantity(vecArg(a, 0)) })
		},
		"fmtValue": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalFmtValue(vecArg(a, 0)) })
		},
		"fmtAct": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalFmtAct(vecArg(a, 0)) })
		},
		"renderCard": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalRenderCard(vecArg(a, 0)) })
		},
		"renderCond": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCond(vecArg(a, 0)) })
		},
		"refExplain": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalRefExplain(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3)) })
		},
		"refDecide": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalRefDecide(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3)) })
		},
		"canonicalPolicy": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCanonicalPolicy(vecArg(a, 0)) })
		},
		"policyDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalPolicyDigest(vecArg(a, 0)) })
		},
		"actionDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalActionDigest(vecArg(a, 0)) })
		},
		"bindDecision": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalBindDecision(vecArg(a, 0), goalVecStr(vecArg(a, 1))) })
		},
		"guardExecute": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalGuardExecute(vecArg(a, 0), vecArg(a, 1)) })
		},
		"claimGate": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalClaimGate(goalVecStr(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2)) })
		},
		"goalCommit": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalGoalCommit(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) })
		},
		"openCommit": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalOpenCommit(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3)) })
		},
		"signPayloadSeed": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalSignPayload(goalVecStr(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2)) })
		},
		"signGoalArtifactSeed": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalSignGoalArtifact(goalVecStr(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2)) })
		},
		"signerId": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalSignerId(vecArg(a, 0)) })
		},
		"goalDomain": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalDomainOf(goalVecStr(vecArg(a, 0))) })
		},
		"verifyPayload": func(a []any) (any, error) {
			return goalVecTry(func() any {
				return goalVerifyPayload(vecArg(a, 0), goalVecStr(vecArg(a, 1)), anlReqList(vecArg(a, 2)))
			})
		},
		"verifyGoalArtifact": func(a []any) (any, error) {
			return goalVecTry(func() any {
				return goalVerifyGoalArtifact(goalVecStr(vecArg(a, 0)), vecArg(a, 1), goalVecStr(vecArg(a, 2)), anlReqList(vecArg(a, 3)))
			})
		},
	})
}
