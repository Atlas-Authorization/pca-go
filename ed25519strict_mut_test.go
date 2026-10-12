package pca

// Mutation-kill tests for ed25519strict.go: curve constants, point decoding edge cases, VerifyStrict length guards.

import (
	"crypto/ed25519"
	"math/big"
	"testing"
)

func bigS(s string) *big.Int { v, _ := new(big.Int).SetString(s, 10); return v }

func TestMutEdConstants(t *testing.T) {
	d := bigS("37095705934669439343138083508754565189542113879843219016388785533085940283555")
	if edD.Cmp(d) != 0 {
		t.Fatalf("edD = %v", edD)
	}
	d2 := new(big.Int).Mod(new(big.Int).Lsh(d, 1), edP)
	if edD2.Cmp(d2) != 0 {
		t.Fatalf("edD2 = %v", edD2)
	}
	// sqrt(-1) mod p
	if edSqrtM.Cmp(bigS("19681161376707505956807079304988542015446066515923890162744021073123829784752")) != 0 {
		t.Fatalf("edSqrtM = %v", edSqrtM)
	}
}

func encY(y *big.Int, sign byte) []byte {
	b := y.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	b[31] |= sign << 7
	return b
}

func onCurve(p *edPoint) bool {
	// -x^2 + y^2 = 1 + d x^2 y^2
	x2, y2 := mm(p.X, p.X), mm(p.Y, p.Y)
	l := new(big.Int).Sub(y2, x2)
	l.Mod(l, edP)
	r := new(big.Int).Add(big.NewInt(1), mm(edD, mm(x2, y2)))
	r.Mod(r, edP)
	return l.Cmp(r) == 0 && p.X.Sign() >= 0 && p.X.Cmp(edP) < 0 && p.T.Cmp(mm(p.X, p.Y)) == 0
}

func TestMutEdDecode(t *testing.T) {
	// wrong lengths
	for _, n := range []int{0, 1, 31, 33, 64} {
		if p, ok := edDecode(make([]byte, n)); ok || p != nil {
			t.Fatalf("len %d decoded", n)
		}
	}
	// basepoint: y = 4/5, x even (sign 0); the flipped sign gives -B (x odd)
	by := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), edP))
	by.Mod(by, edP)
	bp, ok := edDecode(encY(by, 0))
	if !ok || bp.X.Bit(0) != 0 || !onCurve(bp) || bp.Y.Cmp(by) != 0 {
		t.Fatalf("basepoint: %v", ok)
	}
	nb, ok := edDecode(encY(by, 1))
	if !ok || nb.X.Bit(0) != 1 || !onCurve(nb) {
		t.Fatal("neg basepoint")
	}
	if new(big.Int).Add(bp.X, nb.X).Cmp(edP) != 0 || nb.Y.Cmp(by) != 0 {
		t.Fatal("x mismatch")
	}
	// the decoded input must not be mutated by the decode (sign bit masking works on a copy)
	enc := encY(by, 1)
	cp := append([]byte(nil), enc...)
	edDecode(enc)
	if string(enc) != string(cp) {
		t.Fatal("input mutated")
	}
	if p, ok := edDecode(enc[:32:32]); !ok || p == nil {
		t.Fatal("sign-bit encoding")
	}
	// y = 0: x = +-sqrt(-1) ; both signs valid, exactly one is odd
	for s := byte(0); s < 2; s++ {
		p, ok := edDecode(encY(big.NewInt(0), s))
		if !ok || !onCurve(p) || byte(p.X.Bit(0)) != s || p.Y.Sign() != 0 {
			t.Fatalf("y=0 sign %d: %v", s, ok)
		}
	}
	// x = 0 points: y = 1 and y = -1; sign 1 is invalid (no negative zero)
	for _, y := range []*big.Int{big.NewInt(1), new(big.Int).Sub(edP, big.NewInt(1))} {
		if p, ok := edDecode(encY(y, 0)); !ok || p.X.Sign() != 0 || !onCurve(p) {
			t.Fatalf("x=0 y=%v", y)
		}
		if p, ok := edDecode(encY(y, 1)); ok || p != nil {
			t.Fatalf("x=0 with sign bit must be rejected, y=%v", y)
		}
	}
	// non-canonical y: y = p, p+1 (low 255 bits >= p)
	for _, d := range []int64{0, 1, 18} {
		y := new(big.Int).Add(edP, big.NewInt(d))
		if p, ok := edDecode(encY(y, 0)); ok || p != nil {
			t.Fatalf("non-canonical y=p+%d accepted", d)
		}
	}
	// y = p-1 (canonical, largest) accepted
	// sweep: every y either decodes to an on-curve point or is rejected with (nil,false)
	acc, rej := 0, 0
	for yy := int64(0); yy < 200; yy++ {
		for s := byte(0); s < 2; s++ {
			p, ok := edDecode(encY(big.NewInt(yy), s))
			if ok {
				acc++
				if p == nil || !onCurve(p) || byte(p.X.Bit(0)) != s || p.Z.Cmp(big.NewInt(1)) != 0 {
					t.Fatalf("y=%d s=%d bad point", yy, s)
				}
			} else {
				rej++
				if p != nil {
					t.Fatalf("y=%d: non-nil point with ok=false", yy)
				}
			}
		}
	}
	if acc == 0 || rej == 0 {
		t.Fatalf("sweep acc=%d rej=%d", acc, rej)
	}
}

func TestMutEdMulAndStrict(t *testing.T) {
	by := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), edP))
	by.Mod(by, edP)
	bp, _ := edDecode(encY(by, 0))
	if !edIsIdentity(edMul(bp, edL)) || edIsIdentity(edMul(bp, new(big.Int).Sub(edL, big.NewInt(1)))) {
		t.Fatal("order of B")
	}
	// k*B + (L-k)*B == identity
	k := big.NewInt(123456789)
	s := edAdd(edMul(bp, k), edMul(bp, new(big.Int).Sub(edL, k)))
	if !edIsIdentity(s) {
		t.Fatal("scalar mul additivity")
	}
	if edIsIdentity(edMul(bp, big.NewInt(1))) || !edIsIdentity(edMul(bp, big.NewInt(0))) {
		t.Fatal("k=0/1")
	}
	if !edStrictPoint(encY(by, 0)) {
		t.Fatal("B strict")
	}
	if edStrictPoint(encY(big.NewInt(1), 0)) { // identity
		t.Fatal("identity strict")
	}
	if edStrictPoint(encY(new(big.Int).Sub(edP, big.NewInt(1)), 0)) { // order 2
		t.Fatal("order-2 strict")
	}
	if edStrictPoint(encY(big.NewInt(0), 0)) { // order 4
		t.Fatal("order-4 strict")
	}
}

func TestMutVerifyStrictLengths(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("m")
	sig := ed25519.Sign(priv, msg)
	if !VerifyStrict(pub, msg, sig) {
		t.Fatal("valid")
	}
	for _, n := range []int{0, 1, 10, 31, 32, 33, 63, 65, 100} {
		if VerifyStrict(pub, msg, append(append([]byte(nil), sig...), make([]byte, 80)...)[:n]) {
			t.Fatalf("sig len %d", n)
		}
		if n < 32 && VerifyStrict(pub[:n], msg, sig) {
			t.Fatalf("short pub len %d", n)
		}
		if VerifyStrict(append(append([]byte(nil), pub...), make([]byte, 80)...)[:n], msg, sig) && n != 32 {
			t.Fatalf("pub len %d", n)
		}
	}
	if VerifyStrict(pub, msg, append(append([]byte(nil), sig...), 0)) {
		t.Fatal("65-byte sig")
	}
	// S = L (non-canonical) with the genuine R must fail
	bad := append([]byte(nil), sig...)
	l := edL.FillBytes(make([]byte, 32))
	for i := 0; i < 32; i++ {
		bad[32+i] = l[31-i]
	}
	if VerifyStrict(pub, msg, bad) {
		t.Fatal("S=L")
	}
}
