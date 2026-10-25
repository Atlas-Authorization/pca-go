package pca

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

// TestMapCommitLeafCapBoundary pins the exact leaf cap of IntentMapCommitPrimitive: 1<<24 leaves commit, 1<<24+1 do not.
// It kills the `len(leaves) > maxMapLeaves` -> `>=` mutant, which no smaller input can distinguish. It builds 16.7M
// normalised leaf maps (about 6-8 GB of heap) and hashes each one, so it runs only with PCA_HUGE=1 (the 4 GiB ulimit of
// the CI mutation job cannot run it; verified on the 62 GB GCP box instead).
func TestMapCommitLeafCapBoundary(t *testing.T) {
	if os.Getenv("PCA_HUGE") != "1" {
		t.Skip("set PCA_HUGE=1 (needs ~8 GB of RAM)")
	}
	salt := b64.EncodeToString(make([]byte, 32))
	leaf := map[string]any{"kind": "header", "salt": salt, "leaf": json.Number("1")}
	build := func(n int) map[string]any {
		leaves := make([]any, n)
		for i := range leaves {
			leaves[i] = leaf // one shared value: normalizeJSON copies it per element
		}
		return map[string]any{"leaves": leaves}
	}
	got := IntentMapCommitPrimitive(build(maxMapLeaves))
	if s, _ := got["map_commit"].(string); s == "" {
		t.Fatalf("exactly %d leaves must commit, got %v", maxMapLeaves, got)
	}
	runtime.GC()
	if got := IntentMapCommitPrimitive(build(maxMapLeaves + 1)); len(got) != 0 {
		t.Fatalf("%d leaves must be refused, got %v", maxMapLeaves+1, got)
	}
}
