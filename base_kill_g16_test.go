package pca

import "testing"

// The merge key of a head cosignature: a null cosignature is refused (the reference throws reading its witness), one that
// names no witness (or is not an object) is "undefined", and an explicit null witness is a different key from that.
func TestMeshCosigWitnessKey(t *testing.T) {
	if k, err := cosigWitness(nil); err == nil || err.Error() != "AssembleMeshProof: a cosignature is null" || k != "" {
		t.Fatalf("cosigWitness(nil) = %q, %v", k, err)
	}
	for _, c := range []any{map[string]any{}, map[string]any{"sig": "s"}, "x", 5.0} {
		if k, err := cosigWitness(c); err != nil || k != "u" {
			t.Fatalf("cosigWitness(%v) = %q, %v; want \"u\"", c, k, err)
		}
	}
	if k, err := cosigWitness(map[string]any{"witness": nil}); err != nil || k != "vnull" {
		t.Fatalf("cosigWitness(null witness) = %q, %v; want \"vnull\"", k, err)
	}
	if k, err := cosigWitness(map[string]any{"witness": "w1"}); err != nil || k != `v"w1"` {
		t.Fatalf("cosigWitness(w1) = %q, %v", k, err)
	}
}
