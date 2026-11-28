package pca

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Consistency-proof nodes are 32-byte hashes. With oldSize 1 the old root is the starting hash, so before the fix a
// 31- or 33-byte old root (or path element) plus a crafted new root verified as consistent.
func TestLedgerConsistencyNodeLength(t *testing.T) {
	proof := func(p string) map[string]any {
		return map[string]any{"oldSize": json.Number("1"), "newSize": json.Number("2"), "path": []any{p}}
	}
	c := bytes.Repeat([]byte{7}, 32)
	for _, n := range []int{31, 32, 33} {
		bad := bytes.Repeat([]byte{9}, n)
		want := n == 32
		// the odd-length value as the old root
		if got := VerifyLedgerConsistency(b64.EncodeToString(bad), b64.EncodeToString(nodeHash(bad, c)), proof(b64.EncodeToString(c))); got != want {
			t.Errorf("old root of %d bytes: got %v, want %v", n, got, want)
		}
		// the odd-length value as the path element
		if got := VerifyLedgerConsistency(b64.EncodeToString(c), b64.EncodeToString(nodeHash(c, bad)), proof(b64.EncodeToString(bad))); got != want {
			t.Errorf("path node of %d bytes: got %v, want %v", n, got, want)
		}
	}
}
