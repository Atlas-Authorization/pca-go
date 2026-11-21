package pca

// The prime-order group of the MPC base oblivious transfer: Ed25519 in its order-L subgroup. All group arithmetic (add, subtract,
// scalar multiplication, point decoding) runs on the vetted constant-time filippo.io/edwards25519 point, scalar and field types;
// math/big only converts public coordinates and reduces scalars. Every point received across the OT trust boundary is validated
// (on curve, non-identity, [L]P = O), and a Fiat-Shamir Schnorr proof of knowledge binds the sender's S = y*B to a known y.

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	ed "filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// MpcEcL is the prime order of the base-point subgroup; scalars live in [0, L).
var MpcEcL = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), mpcMustBig("27742317777372353535851937790883648493"))

func mpcMustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("mpc: bad constant")
	}
	return v
}

// MpcPointValidationError: a received point failed on-curve / subgroup / identity validation.
type MpcPointValidationError struct{ Msg string }

func (e *MpcPointValidationError) Error() string { return e.Msg }

func mpcPVE(msg string) error { return &MpcPointValidationError{msg} }

func mpcReverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// mpcEcScalar reduces k mod L (a negative k wraps) into a canonical edwards25519 scalar.
func mpcEcScalar(k *big.Int) *ed.Scalar {
	r := new(big.Int).Mod(k, MpcEcL)
	s, err := new(ed.Scalar).SetCanonicalBytes(mpcReverse(r.FillBytes(make([]byte, 32))))
	if err != nil {
		panic("mpc: scalar reduction failed") // unreachable: r < L
	}
	return s
}

// MpcEcBase is the standard base point B; MpcEcIdentity the neutral element.
func MpcEcBase() *ed.Point     { return ed.NewGeneratorPoint() }
func MpcEcIdentity() *ed.Point { return ed.NewIdentityPoint() }

// MpcEcMulBase is [k]B with k reduced mod L.
func MpcEcMulBase(k *big.Int) *ed.Point { return new(ed.Point).ScalarBaseMult(mpcEcScalar(k)) }

// MpcEcMul is [k]P with k reduced mod L (k = 0 gives the identity).
func MpcEcMul(k *big.Int, p *ed.Point) *ed.Point { return new(ed.Point).ScalarMult(mpcEcScalar(k), p) }

func MpcEcAdd(a, b *ed.Point) *ed.Point { return new(ed.Point).Add(a, b) }
func MpcEcSub(a, b *ed.Point) *ed.Point { return new(ed.Point).Subtract(a, b) }
func MpcEcNeg(a *ed.Point) *ed.Point    { return new(ed.Point).Negate(a) }
func MpcEcDbl(a *ed.Point) *ed.Point    { return new(ed.Point).Add(a, a) }

func MpcEcEqual(a, b *ed.Point) bool { return a.Equal(b) == 1 }

func MpcEcIsIdentity(p *ed.Point) bool { return p.Equal(ed.NewIdentityPoint()) == 1 }

func mpcFeBig(e *field.Element) *big.Int { return new(big.Int).SetBytes(mpcReverse(e.Bytes())) }

// MpcEcToAffine is the affine (x, y) of a point (the identity is (0, 1)).
func MpcEcToAffine(p *ed.Point) (x, y *big.Int) {
	X, Y, Z, _ := p.ExtendedCoordinates()
	zi := new(field.Element).Invert(Z)
	return mpcFeBig(new(field.Element).Multiply(X, zi)), mpcFeBig(new(field.Element).Multiply(Y, zi))
}

// MpcEcEncodePoint is the canonical 64-byte encoding of a point (affine x then y, little-endian), the OT key-derivation input.
func MpcEcEncodePoint(p *ed.Point) []byte {
	X, Y, Z, _ := p.ExtendedCoordinates()
	zi := new(field.Element).Invert(Z)
	out := make([]byte, 64)
	copy(out, new(field.Element).Multiply(X, zi).Bytes())
	copy(out[32:], new(field.Element).Multiply(Y, zi).Bytes())
	return out
}

// MpcEcCompress is the canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255).
func MpcEcCompress(p *ed.Point) []byte { return p.Bytes() }

// MpcEcDecompress decodes a canonical compressed encoding; a non-canonical y (>= q), a non-canonical sign or an off-curve y is refused.
func MpcEcDecompress(b []byte) (*ed.Point, error) {
	if len(b) != 32 {
		return nil, mpcPVE("decompressPoint: expected 32 bytes")
	}
	p, err := new(ed.Point).SetBytes(b)
	if err != nil {
		return nil, mpcPVE("decompressPoint: not on curve")
	}
	if !bytes.Equal(p.Bytes(), b) {
		return nil, mpcPVE("decompressPoint: non-canonical encoding")
	}
	return p, nil
}

// MpcEcFromExtended builds a point from extended coordinates (x = X/Z, y = Y/Z, T = XY/Z) mod q; an off-curve or malformed
// point (Z = 0, wrong T, off the curve) is refused.
func MpcEcFromExtended(X, Y, Z, T *big.Int) (*ed.Point, error) {
	var fe [4]*field.Element
	for i, c := range []*big.Int{X, Y, Z, T} {
		if c == nil {
			return nil, mpcPVE("not on curve")
		}
		r := new(big.Int).Mod(c, mpcEcQ)
		if i == 2 && r.Sign() == 0 {
			return nil, mpcPVE("not on curve")
		}
		e, err := new(field.Element).SetBytes(mpcReverse(r.FillBytes(make([]byte, 32))))
		if err != nil {
			return nil, mpcPVE("not on curve")
		}
		fe[i] = e
	}
	p, err := new(ed.Point).SetExtendedCoordinates(fe[0], fe[1], fe[2], fe[3])
	if err != nil {
		return nil, mpcPVE("not on curve")
	}
	return p, nil
}

// MpcEcHasPrimeOrder is the cofactor check [L]P = O (true for the identity too), as [L-1]P = -P.
func MpcEcHasPrimeOrder(p *ed.Point) bool {
	lm1 := mpcEcScalar(new(big.Int).Sub(MpcEcL, big.NewInt(1)))
	return new(ed.Point).ScalarMult(lm1, p).Equal(new(ed.Point).Negate(p)) == 1
}

// MpcEcIsInSubgroup: a valid non-identity point of the prime-order subgroup.
func MpcEcIsInSubgroup(p *ed.Point) bool { return !MpcEcIsIdentity(p) && MpcEcHasPrimeOrder(p) }

// MpcEcAssertInSubgroup refuses the identity and every small-order or mixed-order point.
func MpcEcAssertInSubgroup(p *ed.Point, label string) error {
	if p == nil {
		return mpcPVE(label + ": not on curve")
	}
	if MpcEcIsIdentity(p) {
		return mpcPVE(label + ": identity element (forbidden here)")
	}
	if !MpcEcHasPrimeOrder(p) {
		return mpcPVE(label + ": not in the prime-order subgroup (small-order/cofactor)")
	}
	return nil
}

// MpcSchnorrProof proves knowledge of y with S = y*B: commitment U = r*B and z = r + e*y.
type MpcSchnorrProof struct {
	U *ed.Point
	Z *big.Int
}

var mpcTagSchnorr = []byte("atlas-pca-mpc/schnorr-dlog")

// mpcSchnorrChallenge is e = SHA-512(tag, len(ctx), ctx, B, S, U) mod L; ctx is the session binding.
func mpcSchnorrChallenge(S, U *ed.Point, ctx []byte) *big.Int {
	h := sha512.New()
	h.Write(mpcTagSchnorr)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(ctx)))
	h.Write(n[:])
	h.Write(ctx)
	h.Write(MpcEcEncodePoint(MpcEcBase()))
	h.Write(MpcEcEncodePoint(S))
	h.Write(MpcEcEncodePoint(U))
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), MpcEcL)
}

// MpcSchnorrProve proves knowledge of y for S, bound to a non-empty session binding ctx; rnd draws the secret nonce.
func MpcSchnorrProve(y *big.Int, S *ed.Point, rnd func() *big.Int, ctx []byte) (*MpcSchnorrProof, error) {
	if len(ctx) == 0 {
		return nil, errors.New("schnorrProve: a non-empty session binding is required")
	}
	r := new(big.Int).Mod(rnd(), MpcEcL)
	if r.Sign() == 0 {
		return nil, errors.New("schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof")
	}
	U := MpcEcMulBase(r)
	e := mpcSchnorrChallenge(S, U, ctx)
	z := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(e, new(big.Int).Mod(y, MpcEcL))), MpcEcL)
	return &MpcSchnorrProof{U, z}, nil
}

// MpcSchnorrVerify checks z is in range, U is a valid subgroup point and z*B = U + e*S.
func MpcSchnorrVerify(S *ed.Point, proof *MpcSchnorrProof, ctx []byte) bool {
	if len(ctx) == 0 || proof == nil || proof.U == nil || proof.Z == nil || S == nil {
		return false
	}
	if proof.Z.Sign() < 0 || proof.Z.Cmp(MpcEcL) >= 0 {
		return false
	}
	if !MpcEcIsInSubgroup(proof.U) {
		return false
	}
	e := mpcSchnorrChallenge(S, proof.U, ctx)
	return MpcEcEqual(MpcEcMulBase(proof.Z), MpcEcAdd(proof.U, MpcEcMul(e, S)))
}

// MpcPtJ is the wire form of a point: canonical lowercase hex {x, y}.
func MpcPtJ(p *ed.Point) map[string]any {
	x, y := MpcEcToAffine(p)
	return map[string]any{"x": MpcHx(x), "y": MpcHx(y)}
}

// MpcJPt parses a wire point {x, y} (canonical hex) and validates it as a non-identity prime-order-subgroup point.
func MpcJPt(v any) (*ed.Point, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("bad point")
	}
	x, err := MpcHexBig(m["x"])
	if err != nil {
		return nil, err
	}
	y, err := MpcHexBig(m["y"])
	if err != nil {
		return nil, err
	}
	p, err := MpcEcFromExtended(x, y, big.NewInt(1), new(big.Int).Mul(x, y))
	if err != nil {
		return nil, mpcPVE("received point: not on curve")
	}
	if err := MpcEcAssertInSubgroup(p, "received point"); err != nil {
		return nil, err
	}
	return p, nil
}
