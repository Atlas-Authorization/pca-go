package pca

// ActionBuiltinReviewOpts is the review option under which the released built-ins count as confirmed: the attestation verifier over
// the release pins, a signature by the pinned release key and nothing else. It is nil before the first release signing (then no
// built-in is confirmed). reg is the trait registry the attestation is checked against (nil: the core registry).
func ActionBuiltinReviewOpts(reg Registry) ActionDiffConfirmed {
	pins := ActionBuiltinReviewPins()
	if pins == nil {
		return nil
	}
	if reg == nil {
		reg = coreRegistry
	}
	return ActionAttestationVerifier(reg, pins)
}
