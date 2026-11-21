package pca

import "errors"

// Decide is the Policy VM decision of one party's own policy for an action: the envelope predicates (default deny), the caveats
// over the delegation chain, the risk score, the trust budget and the threshold band. The input is the parsed JSON object {grant,
// chain?, action, plan?, risk, budget, now, nodeId?, goalNodeId?, caveatContext?, rFloor?, ageHorizonMs?, chainVerified?, pqPins?,
// trustedRoot?}; the result has releaseGuardianShare, requiredThreshold {t, proof, optimisticAllowed}, r, admit, needStepUp,
// reasons and budget. Total: any fault is a denial carrying its reason (fail closed). A chain that carries a caveat-language type
// is refused here; DecideNative takes the caveat-language input.
func Decide(input map[string]any) map[string]any { return DecideNative(input, nil) }

// DeriveDecideInput assembles the Decide input from a PCActn plus the verifier's own context (grant REQUIRED, from the verifier's
// store; params, risk, budget, now, chain?, plan?, subject?, env?, goalNodeId?, pqPins?, caveatContext?, ageHorizonMs?), so the
// caller and the verifier derive action, nodeId and chain identically. The presented chain root is never used as the grant: without
// ctx.grant the error is DecideInputGrantRequired.
func DeriveDecideInput(pcactn map[string]any, ctx map[string]any) (map[string]any, error) {
	if ctx == nil {
		return nil, errors.New("deriveDecideInput: a context is required")
	}
	_, isMap := ctx["grant"].(map[string]any)
	_, isList := ctx["grant"].([]any)
	if (isMap || isList) && pcactn == nil {
		return nil, errors.New("deriveDecideInput: a PCActn is required")
	}
	return DeriveDecideInputNative(pcactn, ctx)
}
