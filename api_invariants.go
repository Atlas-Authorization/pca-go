package pca

// InvariantsWorsen is the public form of the pca-invariants export worsen.
func InvariantsWorsen(b RiskInputs, r *InvRng) RiskInputs {
	return invWorsen(b, r)
}

// InvariantsArbResource is the public form of the pca-invariants export arbResource.
func InvariantsArbResource(r *InvRng) string {
	return invArbResource(r)
}

// InvariantsArbVerb is the public form of the pca-invariants export arbVerb.
func InvariantsArbVerb(r *InvRng) string {
	return invArbVerb(r)
}
