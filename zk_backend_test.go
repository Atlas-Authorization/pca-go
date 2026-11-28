package pca

import (
	"errors"
	"testing"
)

func TestGroth16BackendSeamFailsClosedWithoutABackend(t *testing.T) {
	prev := GetGroth16Backend()
	groth16Mu.Lock()
	groth16Current = nil
	groth16Mu.Unlock()
	defer func() {
		groth16Mu.Lock()
		groth16Current = prev
		groth16Mu.Unlock()
	}()
	if IsGroth16BackendActive() {
		t.Fatal("no backend is installed")
	}
	if ok, _, err := Groth16Verify(Groth16CurveBn254, map[string]any{}, map[string]any{}, []any{}, false); ok || !errors.Is(err, ErrGroth16BackendMissing) {
		t.Fatalf("a missing backend must be an error, never a verdict: %v %v", ok, err)
	}
	if _, err := Groth16Prove(Groth16CurveBn254, nil, nil, nil, nil); !errors.Is(err, ErrGroth16BackendMissing) {
		t.Fatalf("prove without a backend: %v", err)
	}
	if SetGroth16Backend(nil) == nil || SetGroth16Backend(&Groth16Backend{}) == nil {
		t.Fatal("a backend without Verify must be refused")
	}
	var seen string
	if err := SetGroth16Backend(&Groth16Backend{Verify: func(curve string, strict bool, vkey, proof, signals []byte) (bool, string, error) {
		seen = curve + "|" + string(vkey) + "|" + string(proof) + "|" + string(signals)
		return false, "pairing_failed", nil
	}}); err != nil {
		t.Fatal(err)
	}
	ok, reason, err := Groth16Verify(Groth16CurveBls12381, map[string]any{"curve": "bls12381"}, map[string]any{}, []any{"1"}, true)
	if ok || reason != "pairing_failed" || err != nil || seen != `bls12-381|{"curve":"bls12381"}|{}|["1"]` {
		t.Fatalf("the backend sees the JSON it is given: %v %q %v %q", ok, reason, err, seen)
	}
	if _, err := Groth16Prove(Groth16CurveBn254, nil, nil, nil, nil); !errors.Is(err, ErrGroth16BackendMissing) {
		t.Fatalf("a verify-only backend cannot prove: %v", err)
	}
}
