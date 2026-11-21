package pca

import "testing"

// The leaf cap of a map commit is a DoS bound at the trust boundary: exactly maxMapLeaves commits, one more does not, and an empty
// list does not. The helper takes the count, so the boundary is decided in every CI run without 16.7M leaves.
func TestR10_MapLeafCountBoundary(t *testing.T) {
	for n, want := range map[int]bool{-1: false, 0: false, 1: true, 2: true, maxMapLeaves - 1: true, maxMapLeaves: true, maxMapLeaves + 1: false, maxMapLeaves + 2: false} {
		if got := mapLeafCountOK(n); got != want {
			t.Errorf("mapLeafCountOK(%d) = %v, want %v", n, got, want)
		}
	}
	if got := IntentMapCommitPrimitive(map[string]any{"leaves": []any{}}); len(got) != 0 {
		t.Errorf("no leaves: %v", got)
	}
}
