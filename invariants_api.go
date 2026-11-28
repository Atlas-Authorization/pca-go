package pca

// The remaining generators of the invariants registry as public API: a key pair, risk weights, risk deltas and the deterministic
// worsening of a risk input. The properties themselves are the Inv* functions (InvAttenuationMonotonicity, InvRiskMonotone,
// InvAdmissionSoundness, InvCumulativeBudgetBound, InvUndecidableLeafFailsClosed, InvUndecidableGroupsFailClosed,
// InvMemberOfCycleSafe, InvUnknownCaveatTypeDenies, InvForgedChainRejected, InvGarbageChainRejected, InvDeterminism,
// InvForbidMonotone), run by CheckInvariants over InvariantRegistry.

// InvArbKeyPair is a random Ed25519 identity from a generated 32-byte seed.
func InvArbKeyPair(r *InvRng) (*InvariantKeyPair, error) {
	return InvariantKeyPairFromSeed(InvArbSeed32(r))
}

// InvArbCondition is a random condition: a leaf comparison (the reference generates no groups).
func InvArbCondition(r *InvRng) map[string]any { return InvArbLeafCondition(r) }

// InvArbRiskWeights is random non-negative risk weights, each in [0, 2].
func InvArbRiskWeights(r *InvRng) RiskWeights {
	return RiskWeights{Alpha: r.Dbl(0, 2), Beta: r.Dbl(0, 2), Gamma: r.Dbl(0, 2), Delta: r.Dbl(0, 2), Epsilon: r.Dbl(0, 2), Zeta: r.Dbl(0, 2)}
}

// InvRiskDeltas are the non-negative deltas that build a pointwise-WORSE risk input.
type InvRiskDeltas struct{ DSem, DBlast, DTaint, DAge, DRev, DConf float64 }

// InvArbRiskDeltas is random deltas, each in [0, 1].
func InvArbRiskDeltas(r *InvRng) InvRiskDeltas {
	return InvRiskDeltas{DSem: r.Dbl(0, 1), DBlast: r.Dbl(0, 1), DTaint: r.Dbl(0, 1), DAge: r.Dbl(0, 1), DRev: r.Dbl(0, 1), DConf: r.Dbl(0, 1)}
}

// InvWorsenBy is a risk input that is >= base in every risk-INCREASING axis and <= in every PROTECTIVE axis, by the deltas.
func InvWorsenBy(b RiskInputs, d InvRiskDeltas) RiskInputs {
	return RiskInputs{
		SemanticDistance: invClamp01(b.SemanticDistance + d.DSem), BlastRadius: invClamp01(b.BlastRadius + d.DBlast),
		Taint: invClamp01(b.Taint + d.DTaint), Age: invClamp01(b.Age + d.DAge),
		Reversibility: invClamp01(b.Reversibility - d.DRev), Confidence: invClamp01(b.Confidence - d.DConf),
	}
}
