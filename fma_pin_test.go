package pca

import "testing"

// Go may fuse x*y+z into one rounding on arm64, ppc64 and s390x (an explicit float64() conversion forbids it). The reference rounds
// every product, so each value below is the unfused one; the fused result differs in the last digit, so a lost conversion fails on
// those architectures.
func TestProductsAreRoundedBeforeTheyAreAdded(t *testing.T) {
	// noise under load: 0.1 + 0.05*5 is 0.35 unfused and 0.35000000000000003 fused
	if got, err := WalletEtaUnderLoad(0.1, 0.05, 5); err != nil || got != 0.35 {
		t.Fatalf("WalletEtaUnderLoad(0.1, 0.05, 5) = %v, %v; want 0.35", got, err)
	}
	// 0.1 + 0.005*40 is 0.30000000000000004 unfused and 0.3 fused
	if got, err := WalletEtaUnderLoad(0.1, 0.005, 40); err != nil || got != 0.30000000000000004 {
		t.Fatalf("WalletEtaUnderLoad(0.1, 0.005, 40) = %v, %v; want 0.30000000000000004", got, err)
	}
	// the trust-budget leak: 0.9 - 0.0005*(120000/1000) is 0.8400000000000001 unfused and 0.84 fused
	b := TrustBudget{B: 0.9, Tau: 0, AsOf: 0, HasAsOf: true}.Leak(120000, 0.0005)
	if b.B != 0.8400000000000001 {
		t.Fatalf("Leak = %v, want 0.8400000000000001", b.B)
	}
}
