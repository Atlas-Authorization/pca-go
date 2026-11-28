package pca

import (
	"bytes"
	"testing"
)

func TestPartDPublicForms(t *testing.T) {
	// head advance: same size, different roots is equivocation; a head for another domain is refused
	a := map[string]any{"domain": "d", "size": 1.0, "root": "AAAA", "rev_size": 0.0, "rev_root": "AAAA"}
	if MeshCheckHeadAdvance(a, "nope", nil) != "malformed head" {
		t.Fatal("malformed head not refused")
	}
	if MeshCheckCosignedHead(map[string]any{}, "d", "not a trust", nil) == "" {
		t.Fatal("bad trust must be refused")
	}
	h1, err := LeafHash(map[string]any{"a": 1.0})
	h2, err2 := LeafHash(map[string]any{"a": 1.0})
	if err != nil || err2 != nil || len(h1) != 32 || !bytes.Equal(h1, h2) {
		t.Fatal("leaf hash")
	}
	d1, err := IntentStateDigest(map[string]any{"x": "y"})
	d2, _ := IntentStateDigest(map[string]any{"x": "y"})
	if err != nil || d1 == "" || d1 != d2 {
		t.Fatal("state digest")
	}
	if r1, ok := IntentFactRef(map[string]any{"k": "v"}); !ok || r1 == "" {
		t.Fatal("fact ref")
	}
	if MpcEcQ.BitLen() != 255 {
		t.Fatal("field prime")
	}
}
