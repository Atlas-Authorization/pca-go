package pca

import (
	"strings"
	"testing"
	"time"
)

// Shared hard limits (all PCA verifiers): 512 KiB raw PCActn document, checked before parsing; 256 caveats per hop and
// 1024 per chain, checked on raw list sizes before any hashing or signature work.
func TestArtifactSizeCap(t *testing.T) {
	if ArtifactSizeReason != "artifact exceeds size limit (max 524288 bytes)" {
		t.Fatalf("reason: %q", ArtifactSizeReason)
	}
	pad := func(n int) string { return "{}" + strings.Repeat(" ", n-2) }
	for _, n := range []int{MaxArtifactBytes - 1, MaxArtifactBytes} {
		if _, err := ParsePCActn(pad(n)); err != nil && err.Error() == ArtifactSizeReason {
			t.Fatalf("%d bytes must reach the parser", n)
		}
	}
	start := time.Now()
	_, err := ParsePCActn("x" + pad(MaxArtifactBytes)) // garbage over the cap: the SIZE reason proves the check precedes parsing
	if err == nil || err.Error() != ArtifactSizeReason {
		t.Fatalf("limit+1: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("size rejection too slow: %v", time.Since(start))
	}
	// UTF-8 bytes, not characters: 174763 euro signs are 524289 bytes
	if _, err := ParsePCActn(strings.Repeat("€", 174763)); err == nil || err.Error() != ArtifactSizeReason {
		t.Fatalf("multi-byte limit+1: %v", err)
	}
}

func TestCaveatCaps(t *testing.T) {
	hop := func(n int) any {
		cv := make([]any, n)
		for i := range cv {
			cv[i] = map[string]any{"type": "note"}
		}
		return map[string]any{"caveats": cv}
	}
	if why, ok := VerifyChain([]any{hop(257)}, "", false); ok || why != CaveatLimitReason {
		t.Fatalf("257 per hop: %q %v", why, ok)
	}
	chain := []any{hop(205), hop(205), hop(205), hop(205), hop(205)} // 1025 in total
	if why, ok := VerifyChain(chain, "", false); ok || why != CaveatLimitReason {
		t.Fatalf("1025 per chain: %q %v", why, ok)
	}
	if caveatLimitExceeded([]any{hop(204), hop(205), hop(205), hop(205), hop(205)}) { // exactly 1024
		t.Fatal("1024 per chain must not trip the cap")
	}
	if caveatLimitExceeded([]any{hop(256)}) {
		t.Fatal("256 per hop must not trip the cap")
	}
}
