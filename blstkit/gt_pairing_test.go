package blstkit

import (
	"testing"

	blst "github.com/supranational/blst/bindings/go"
)

// offSubgroupG1 / offSubgroupG2: canonical compressed encodings of curve points outside the prime-order subgroup (the cofactors
// are huge, so the first x that lies on the curve is one).
func offSubgroupG1(t *testing.T) []byte {
	for x := 1; x < 256; x++ {
		b := make([]byte, 48)
		b[0], b[47] = 0x80, byte(x)
		if p := new(blst.P1Affine).Uncompress(b); p != nil && !p.InG1() {
			return b
		}
	}
	t.Fatal("no off-subgroup G1 point found")
	return nil
}

func offSubgroupG2(t *testing.T) []byte {
	for x := 1; x < 256; x++ {
		b := make([]byte, 96)
		b[0], b[95] = 0x80, byte(x)
		if q := new(blst.P2Affine).Uncompress(b); q != nil && !q.InG2() {
			return b
		}
	}
	t.Fatal("no off-subgroup G2 point found")
	return nil
}

// TestGtPairingRefusesEitherBadPoint: one bad point in either slot refuses the pairing (a refusal needs only one of the two).
func TestGtPairingRefusesEitherBadPoint(t *testing.T) {
	g1, g2 := g1Bytes(abeG1), g2Bytes(bbsBP2)
	inf1 := append([]byte{0xc0}, make([]byte, 47)...)
	inf2 := append([]byte{0xc0}, make([]byte, 95)...)
	if _, ok := gtPairing([][]byte{g1}, [][]byte{g2}); !ok {
		t.Fatal("the valid pair is refused")
	}
	for name, c := range map[string]struct{ a, b []byte }{
		"infinity G1":          {inf1, g2},
		"infinity G2":          {g1, inf2},
		"outside the G1 group": {offSubgroupG1(t), g2},
		"outside the G2 group": {g1, offSubgroupG2(t)},
	} {
		if _, ok := gtPairing([][]byte{c.a}, [][]byte{c.b}); ok {
			t.Fatalf("%s: accepted", name)
		}
	}
}
