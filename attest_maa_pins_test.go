package pca

import "testing"

// The shipped manifest was signed by the reference: loading it replays the reference's hybrid (Ed25519 + ML-DSA-65) allowlist signature.
func TestBuiltinMaaPinsLoadAndWindow(t *testing.T) {
	p, err := LoadBuiltinMaaPins(1_795_000_000_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Vantages < 3 || len(p.MaaSigningSpkis) == 0 || len(p.MaaChainRootSpkis) == 0 || len(p.MaaChainIntermediateSpkis) == 0 || p.Version != 1 || len(p.Digest) != 43 {
		t.Fatalf("pins: %+v", p)
	}
	if _, err := LoadBuiltinMaaPins(p.ExpiresAt+1, nil); err == nil {
		t.Fatal("expired pins must be refused")
	}
	if _, err := LoadBuiltinMaaPins(1_000, nil); err == nil {
		t.Fatal("pins before their window must be refused")
	}
	if _, err := LoadBuiltinMaaPins(1_795_000_000_000, &BuiltinMaaPinsSource{Manifest: map[string]any{}, IssuerKeys: BuiltinMaaPinsIssuerKeys()}); err == nil {
		t.Fatal("a malformed manifest must be refused")
	}
}
