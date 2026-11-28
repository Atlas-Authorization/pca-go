package pca

// The prime-order group of the homomorphic risk accumulator: ristretto255 (RFC 9496) on the vetted
// github.com/gtank/ristretto255 element type, the Pedersen generators G and H, scalar helpers (filippo.io/edwards25519,
// constant time) and the Fiat-Shamir transcript hash (the reference @atlasauth/pca-ratchet). No group math is written here.

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	ed "filippo.io/edwards25519"
	"github.com/gtank/ristretto255"
)

// rPoint is a ristretto255 element. Points are never mutated after construction: every helper returns a fresh one.
type rPoint = *ristretto255.Element

// rScalar is a scalar mod L.
type rScalar = *ed.Scalar

var ratchetL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

var (
	rZero, rG, rH rPoint
	rPow2         [RatchetNBits]rScalar
)

func init() {
	rZero = ristretto255.NewIdentityElement()
	rG = ristretto255.NewGeneratorElement()
	h := sha512.Sum512([]byte("atlas-pca-ratchet/pedersen-generator-H/v1"))
	rH = rHashToCurve(h[:])
	for i := range rPow2 {
		rPow2[i] = rScalarOfU64(1 << uint(i))
	}
}

func rAdd(p, q rPoint) rPoint { return ristretto255.NewElement().Add(p, q) }

func rSub(p, q rPoint) rPoint { return ristretto255.NewElement().Subtract(p, q) }

// rScalarMul is k*p (constant time); k is canonical so the conversion cannot fail.
func rScalarMul(p rPoint, k rScalar) rPoint {
	gs, err := ristretto255.NewScalar().SetCanonicalBytes(k.Bytes())
	if err != nil {
		panic(err)
	}
	return ristretto255.NewElement().ScalarMult(gs, p)
}

// rEquals is ristretto equality (RFC 9496 section 4.3.3).
func rEquals(a, b rPoint) bool { return a.Equal(b) == 1 }

func leBytesToInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func intToLE32(n *big.Int) []byte {
	be := n.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return be
}

func rDecode(s []byte) (rPoint, error) {
	if len(s) != 32 {
		return nil, errors.New("ristretto255: bad length")
	}
	p, err := ristretto255.NewElement().SetCanonicalBytes(s)
	if err != nil {
		return nil, errors.New("ristretto255: invalid encoding")
	}
	return p, nil
}

func rEncode(p rPoint) []byte { return p.Bytes() }

// rHashToCurve is the RFC 9496 one-way map from 64 uniform bytes.
func rHashToCurve(b []byte) rPoint {
	p, err := ristretto255.NewElement().SetUniformBytes(b)
	if err != nil {
		panic(err)
	}
	return p
}

func rEncodePoint(p rPoint) string { return b64.EncodeToString(rEncode(p)) }

func rDecodePoint(v any) (rPoint, error) {
	s, ok := v.(string)
	raw, ok2 := DecodeB64uStrict(s, 32)
	if !ok || !ok2 {
		return nil, errors.New("decodePoint: not a canonical 32-byte base64url string")
	}
	return rDecode(raw)
}

func rEncodeScalar(k rScalar) string { return b64.EncodeToString(k.Bytes()) }

// rDecodeScalar is strict: canonical base64url, exactly 32 bytes, value < L (a reduced scalar would make every proof malleable).
func rDecodeScalar(v any) (rScalar, error) {
	s, ok := v.(string)
	raw, ok2 := DecodeB64uStrict(s, 32)
	if !ok || !ok2 {
		return nil, errors.New("decodeScalar: not a canonical 32-byte base64url string")
	}
	k, err := ed.NewScalar().SetCanonicalBytes(raw)
	if err != nil {
		return nil, errors.New("decodeScalar: non-canonical scalar (>= L)")
	}
	return k, nil
}

// rScalarOfBig is n mod L (n may be negative or wider than 256 bits). The reduction runs on math/big, so callers pass it public
// values or a caller-held blinding once at the API boundary; all arithmetic after it is on constant-time scalars.
func rScalarOfBig(n *big.Int) rScalar {
	k, err := ed.NewScalar().SetCanonicalBytes(intToLE32(new(big.Int).Mod(n, ratchetL)))
	if err != nil {
		panic(err)
	}
	return k
}

func rScalarOfU64(n uint64) rScalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return rScalarOfBig(leBytesToInt(b[:]))
}

func rBigOfScalar(k rScalar) *big.Int { return leBytesToInt(k.Bytes()) }

// rHashToScalar: a length-prefixed (4-byte big-endian) transcript, SHA-512, reduced mod L.
func rHashToScalar(parts ...[]byte) rScalar {
	h := sha512.New()
	var l [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		h.Write(l[:])
		h.Write(p)
	}
	k, err := ed.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return k
}

func rRandScalar() rScalar {
	zero := ed.NewScalar()
	for {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		k, err := ed.NewScalar().SetUniformBytes(b[:])
		if err != nil {
			panic(err)
		}
		if k.Equal(zero) == 0 {
			return k
		}
	}
}
