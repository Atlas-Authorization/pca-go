package pca

import (
	"os"
	"strings"
	"testing"
)

// The shared mesh corpus (packages/pca/conformance/mesh-vectors.json): whole mesh proofs with the TypeScript verdict.
func TestMeshVectors(t *testing.T) {
	doc := load(t, "mesh-vectors.json")
	vecs, _ := doc["mesh"].([]any)
	if len(vecs) < 100 {
		t.Fatalf("expected at least 100 mesh vectors, got %d", len(vecs))
	}
	run, skipped := 0, 0
	for _, raw := range vecs {
		v := raw.(map[string]any)
		name := v["name"].(string)
		expect := v["expect"].(map[string]any)
		wantOK := expect["ok"].(bool)
		got := VerifyMeshProof(v["proof"], v["trust"])
		run++
		if got.OK != wantOK {
			t.Errorf("%s: ok = %v (reason %q), want %v (reason %q)", name, got.OK, got.Reason, wantOK, expect["reason"])
			continue
		}
		if wantOK {
			continue
		}
		wantReason, _ := expect["reason"].(string)
		if strings.HasPrefix(wantReason, "chain:") {
			if !strings.HasPrefix(got.Reason, "chain:") {
				t.Errorf("%s: reason %q, want a chain refusal (%q)", name, got.Reason, wantReason)
			}
			continue
		}
		if got.Reason != wantReason {
			t.Errorf("%s: reason %q, want %q", name, got.Reason, wantReason)
		}
		wantHop := -1
		if h, ok := expect["hop"]; ok {
			wantHop = int(num(h))
		}
		if got.Hop != wantHop {
			t.Errorf("%s: hop %d, want %d", name, got.Hop, wantHop)
		}
	}
	_ = skipped
	_ = os.Stdout
	t.Logf("%d mesh vectors", run)
}
