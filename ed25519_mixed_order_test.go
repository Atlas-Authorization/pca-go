package pca

import (
	"bytes"
	"testing"

	ed "filippo.io/edwards25519"
)

// Point validation refuses a mixed-order point: B + T with T of order 2 is not in the prime-order subgroup.
func TestFrostDecodeSafePointRefusesTorsion(t *testing.T) {
	base := ed.NewGeneratorPoint().Bytes()
	t2 := append([]byte{0xec}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...) // (0, -1), order 2
	tp, err := new(ed.Point).SetBytes(t2)
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(ed.Point).Add(ed.NewGeneratorPoint(), tp).Bytes()
	ident := append([]byte{1}, make([]byte, 31)...)
	nonCanonical := append([]byte{0xee}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...) // y = p + 1
	neg := append([]byte(nil), base...)
	neg[31] |= 0x80
	for name, ok := range map[string][]byte{"B": base, "-B": neg} {
		if _, err := FrostDecodeSafePoint(ok); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, bad := range map[string][]byte{"B+T": mixed, "order 2": t2, "identity": ident, "order 4": make([]byte, 32), "non-canonical": nonCanonical} {
		if _, err := FrostDecodeSafePoint(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
		if p, err := MpcEcDecompress(bad); err == nil && MpcEcIsInSubgroup(p) {
			t.Errorf("%s accepted by the MPC subgroup test", name)
		}
	}
}
