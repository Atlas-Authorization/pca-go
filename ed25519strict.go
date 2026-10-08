package pca

import (
	"crypto/ed25519"
	"math/big"
)

// Strict RFC 8032 verification. Go's crypto/ed25519 does not reject small-order public keys (a forged
// (R=identity, S=0) signature verifies under an identity / order-2 key), so we additionally require A and R
// to be canonical, non-small-order, torsion-free points, and S < L.

var (
	edP     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL, _  = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	edD     *big.Int
	edD2    *big.Int
	edSqrtM *big.Int
)

func init() {
	inv := func(x *big.Int) *big.Int { return new(big.Int).Exp(x, new(big.Int).Sub(edP, big.NewInt(2)), edP) }
	edD = new(big.Int).Mul(big.NewInt(-121665), inv(big.NewInt(121666)))
	edD.Mod(edD, edP)
	edD2 = new(big.Int).Lsh(edD, 1)
	edD2.Mod(edD2, edP)
	edSqrtM = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
}

type edPoint struct{ X, Y, Z, T *big.Int }

func leInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func mm(a, b *big.Int) *big.Int { r := new(big.Int).Mul(a, b); return r.Mod(r, edP) }

// edDecode returns the point only for a canonical encoding that lies on the curve.
func edDecode(enc []byte) (*edPoint, bool) {
	if len(enc) != 32 {
		return nil, false
	}
	b := append([]byte(nil), enc...)
	sign := b[31] >> 7
	b[31] &= 0x7f
	y := leInt(b)
	if y.Cmp(edP) >= 0 {
		return nil, false
	}
	y2 := mm(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, edP)
	v := new(big.Int).Add(mm(edD, y2), big.NewInt(1))
	v.Mod(v, edP)
	v3 := mm(mm(v, v), v)
	v7 := mm(mm(v3, v3), v)
	pw := new(big.Int).Exp(mm(u, v7), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(5)), 3), edP)
	x := mm(mm(u, v3), pw)
	vx2 := mm(v, mm(x, x))
	if vx2.Cmp(u) != 0 {
		negU := new(big.Int).Sub(edP, u)
		negU.Mod(negU, edP)
		if vx2.Cmp(negU) != 0 {
			return nil, false
		}
		x = mm(x, edSqrtM)
	}
	if x.Sign() == 0 && sign == 1 {
		return nil, false
	}
	if byte(x.Bit(0)) != sign {
		x = new(big.Int).Sub(edP, x)
		x.Mod(x, edP)
	}
	return &edPoint{x, y, big.NewInt(1), mm(x, y)}, true
}

func edAdd(p, q *edPoint) *edPoint {
	sub := func(a, b *big.Int) *big.Int { r := new(big.Int).Sub(a, b); return r.Mod(r, edP) }
	add := func(a, b *big.Int) *big.Int { r := new(big.Int).Add(a, b); return r.Mod(r, edP) }
	A := mm(sub(p.Y, p.X), sub(q.Y, q.X))
	B := mm(add(p.Y, p.X), add(q.Y, q.X))
	C := mm(mm(p.T, edD2), q.T)
	D := mm(add(p.Z, p.Z), q.Z)
	E, F, G, H := sub(B, A), sub(D, C), add(D, C), add(B, A)
	return &edPoint{mm(E, F), mm(G, H), mm(F, G), mm(E, H)}
}

func edIdentity() *edPoint {
	return &edPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
}

func edIsIdentity(p *edPoint) bool { return p.X.Sign() == 0 && p.Y.Cmp(p.Z) == 0 }

func edMul(p *edPoint, k *big.Int) *edPoint {
	r := edIdentity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = edAdd(r, r)
		if k.Bit(i) == 1 {
			r = edAdd(r, p)
		}
	}
	return r
}

// edStrictPoint: canonical, on-curve, NOT small-order, NOT mixed-order (torsion-free and non-identity).
func edStrictPoint(enc []byte) bool {
	p, ok := edDecode(enc)
	if !ok || edIsIdentity(p) {
		return false
	}
	return edIsIdentity(edMul(p, edL))
}

// VerifyStrict is strict RFC 8032 Ed25519 verification. Never panics.
func VerifyStrict(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if leInt(sig[32:]).Cmp(edL) >= 0 { // non-canonical S
		return false
	}
	if !edStrictPoint(pub) || !edStrictPoint(sig[:32]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
