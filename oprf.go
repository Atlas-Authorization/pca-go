package pca

// RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 plus the PCA private-revocation and private-rate-limit layer. The group is
// the vetted ristretto255 element type (ratchet_group.go) and the scalars are constant-time filippo.io/edwards25519 scalars;
// only the RFC's protocol steps (expand_message_xmd, DLEQ proofs, finalize hashes) are written here.
//
// Native-stricter: an unknown mode, or poprf on the non-POPRF entry points, is refused (the reference silently takes the
// verifiable path).

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"unicode/utf8"

	ed "filippo.io/edwards25519"
)

const (
	oprfSuiteID   = "ristretto255-SHA512"
	oprfMaxFramed = 0xFFFF
)

var oprfModeByte = map[string]byte{"oprf": 0x00, "voprf": 0x01, "poprf": 0x02}

func oprfI2OSP2(n int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(n)) }

func oprfContext(mode string) ([]byte, error) {
	b, ok := oprfModeByte[mode]
	if !ok {
		return nil, fmt.Errorf("unknown OPRF mode %q", mode)
	}
	return append([]byte("OPRFV1-"), append([]byte{b}, []byte("-"+oprfSuiteID)...)...), nil
}

func oprfServerMode(mode string) error {
	if mode != "oprf" && mode != "voprf" {
		return fmt.Errorf("mode must be 'oprf' or 'voprf', got %q", mode)
	}
	return nil
}

func oprfFramed(b []byte, what string) error {
	if len(b) > oprfMaxFramed {
		return fmt.Errorf("%s: %d bytes exceeds the %d-byte limit (RFC 9497 2-byte length framing)", what, len(b), oprfMaxFramed)
	}
	return nil
}

// oprfMul is the reference multiply: it refuses the zero scalar.
func oprfMul(p rPoint, k rScalar) (rPoint, error) {
	if k.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("expected valid scalar: 1 <= n < group order")
	}
	return rScalarMul(p, k), nil
}

func oprfBaseMult(k rScalar) (rPoint, error) { return oprfMul(rG, k) }

func oprfIsIdentity(p rPoint) bool { return rEquals(p, rZero) }

// oprfExpandXmd is RFC 9380 expand_message_xmd with SHA-512 for the 64-byte output every suite step needs (a single block).
func oprfExpandXmd(msg, dst []byte) []byte {
	if len(dst) > 255 {
		h := sha512.Sum512(append([]byte("H2C-OVERSIZE-DST-"), dst...))
		dst = h[:]
	}
	dstPrime := append(append([]byte{}, dst...), byte(len(dst)))
	h0 := sha512.New()
	h0.Write(make([]byte, 128))
	h0.Write(msg)
	h0.Write([]byte{0, 64, 0})
	h0.Write(dstPrime)
	b0 := h0.Sum(nil)
	h1 := sha512.New()
	h1.Write(b0)
	h1.Write([]byte{1})
	h1.Write(dstPrime)
	return h1.Sum(nil)
}

func oprfHashToScalarDst(data, dst []byte) rScalar {
	k, err := ed.NewScalar().SetUniformBytes(oprfExpandXmd(data, dst))
	if err != nil {
		panic(err) // 64 bytes always
	}
	return k
}

func oprfHashToScalar(data []byte, mode string) (rScalar, error) {
	ctx, err := oprfContext(mode)
	if err != nil {
		return nil, err
	}
	return oprfHashToScalarDst(data, append([]byte("HashToScalar-"), ctx...)), nil
}

func oprfInvert(s rScalar) (rScalar, error) {
	if s.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("scalarInvert: inverse of zero")
	}
	return ed.NewScalar().Invert(s), nil
}

// OprfSerializeScalar is n mod L as 32 little-endian bytes.
func OprfSerializeScalar(n *big.Int) []byte { return rScalarOfBig(n).Bytes() }

// OprfDeserializeScalar is a canonical 32-byte little-endian scalar below the group order.
func OprfDeserializeScalar(b []byte) (*big.Int, error) {
	k, err := oprfScalar(b)
	if err != nil {
		return nil, err
	}
	return rBigOfScalar(k), nil
}

func oprfScalar(b []byte) (rScalar, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("DeserializeScalar: expected 32 bytes, got %d", len(b))
	}
	k, err := ed.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, errors.New("DeserializeScalar: non-canonical scalar (value >= group order)")
	}
	return k, nil
}

// OprfDeserializeElement decodes a canonical ristretto255 element and refuses the identity; it returns the re-serialised bytes.
func OprfDeserializeElement(b []byte) ([]byte, error) {
	p, err := oprfElement(b)
	if err != nil {
		return nil, err
	}
	return rEncode(p), nil
}

func oprfElement(b []byte) (rPoint, error) {
	p, err := rDecode(b)
	if err != nil {
		return nil, fmt.Errorf("DeserializeElement: %w", err)
	}
	if oprfIsIdentity(p) {
		return nil, errors.New("DeserializeElement: identity element is not a valid input")
	}
	return p, nil
}

func oprfHashToGroup(data []byte, mode string) (rPoint, error) {
	if err := oprfFramed(data, "HashToGroup"); err != nil {
		return nil, err
	}
	ctx, err := oprfContext(mode)
	if err != nil {
		return nil, err
	}
	return rHashToCurve(oprfExpandXmd(data, append([]byte("HashToGroup-"), ctx...))), nil
}

// OprfHashToGroup is the serialised HashToGroup element of input.
func OprfHashToGroup(input []byte, mode string) ([]byte, error) {
	p, err := oprfHashToGroup(input, mode)
	if err != nil {
		return nil, err
	}
	return rEncode(p), nil
}

// OprfDeriveKeyPair is RFC 9497 DeriveKeyPair: the secret and public key (serialised) of a 32-byte seed and info.
func OprfDeriveKeyPair(seed, info []byte, mode string) (secretKey, publicKey []byte, err error) {
	if len(seed) != 32 {
		return nil, nil, errors.New("DeriveKeyPair: seed must be exactly 32 bytes")
	}
	if err := oprfFramed(info, "DeriveKeyPair(info)"); err != nil {
		return nil, nil, err
	}
	ctx, err := oprfContext(mode)
	if err != nil {
		return nil, nil, err
	}
	dst := append([]byte("DeriveKeyPair"), ctx...)
	in := append(append(append([]byte{}, seed...), oprfI2OSP2(len(info))...), info...)
	zero := ed.NewScalar()
	for counter := 0; counter < 256; counter++ {
		sk := oprfHashToScalarDst(append(append([]byte{}, in...), byte(counter)), dst)
		if sk.Equal(zero) == 0 {
			pk, err := oprfBaseMult(sk)
			if err != nil {
				return nil, nil, err
			}
			return sk.Bytes(), rEncode(pk), nil
		}
	}
	return nil, nil, errors.New("DeriveKeyPair: failed to derive a non-zero key after 256 attempts")
}

// OprfPublicKeyFor is the serialised public key of a secret key.
func OprfPublicKeyFor(secretKey []byte) ([]byte, error) {
	sk, err := oprfScalar(secretKey)
	if err != nil {
		return nil, err
	}
	pk, err := oprfBaseMult(sk)
	if err != nil {
		return nil, err
	}
	return rEncode(pk), nil
}

// ---- DLEQ proofs (RFC 9497 section 2.2.1)

func oprfComposites(b, c, d rPoint, mode string) (rPoint, rPoint, error) {
	ctx, err := oprfContext(mode)
	if err != nil {
		return nil, nil, err
	}
	seedDst := append([]byte("Seed-"), ctx...)
	bSer := rEncode(b)
	h := sha512.New()
	h.Write(oprfI2OSP2(len(bSer)))
	h.Write(bSer)
	h.Write(oprfI2OSP2(len(seedDst)))
	h.Write(seedDst)
	seed := h.Sum(nil)
	cSer, dSer := rEncode(c), rEncode(d)
	var t []byte
	t = append(t, oprfI2OSP2(len(seed))...)
	t = append(t, seed...)
	t = append(t, oprfI2OSP2(0)...)
	t = append(t, oprfI2OSP2(len(cSer))...)
	t = append(t, cSer...)
	t = append(t, oprfI2OSP2(len(dSer))...)
	t = append(t, dSer...)
	t = append(t, "Composite"...)
	coeff, err := oprfHashToScalar(t, mode)
	if err != nil {
		return nil, nil, err
	}
	return rScalarMul(c, coeff), rScalarMul(d, coeff), nil
}

func oprfChallenge(b, m, z, t2, t3 rPoint, mode string) (rScalar, error) {
	var parts []byte
	for _, p := range []rPoint{b, m, z, t2, t3} {
		ser := rEncode(p)
		parts = append(append(parts, oprfI2OSP2(len(ser))...), ser...)
	}
	return oprfHashToScalar(append(parts, "Challenge"...), mode)
}

func oprfGenerateProof(k rScalar, a, b, c, d rPoint, mode string, fixed []byte) ([]byte, error) {
	m, _, err := oprfComposites(b, c, d, mode)
	if err != nil {
		return nil, err
	}
	z, err := oprfMul(m, k)
	if err != nil {
		return nil, err
	}
	var r rScalar
	if fixed == nil {
		r = rRandScalar()
	} else if r, err = oprfScalar(fixed); err != nil {
		return nil, err
	}
	t2, err := oprfMul(a, r)
	if err != nil {
		return nil, err
	}
	t3, err := oprfMul(m, r)
	if err != nil {
		return nil, err
	}
	cc, err := oprfChallenge(b, m, z, t2, t3, mode)
	if err != nil {
		return nil, err
	}
	s := ed.NewScalar().Subtract(r, ed.NewScalar().Multiply(cc, k))
	return append(cc.Bytes(), s.Bytes()...), nil
}

func oprfVerifyProof(a, b, c, d rPoint, proof []byte, mode string) (bool, error) {
	if len(proof) != 64 {
		return false, nil
	}
	cc, err := oprfScalar(proof[:32])
	if err != nil {
		return false, err
	}
	s, err := oprfScalar(proof[32:])
	if err != nil {
		return false, err
	}
	m, z, err := oprfComposites(b, c, d, mode)
	if err != nil {
		return false, err
	}
	t2 := rAdd(rScalarMul(a, s), rScalarMul(b, cc))
	t3 := rAdd(rScalarMul(m, s), rScalarMul(z, cc))
	expected, err := oprfChallenge(b, m, z, t2, t3, mode)
	if err != nil {
		return false, err
	}
	return expected.Equal(cc) == 1, nil
}

func oprfFinalizeHash(data, info, issued []byte, withInfo bool) []byte {
	h := sha512.New()
	h.Write(oprfI2OSP2(len(data)))
	h.Write(data)
	if withInfo {
		h.Write(oprfI2OSP2(len(info)))
		h.Write(info)
	}
	h.Write(oprfI2OSP2(len(issued)))
	h.Write(issued)
	h.Write([]byte("Finalize"))
	return h.Sum(nil)
}

// ---- OPRF / VOPRF

// OprfBlind is client step 1: the blind (client secret) and the blinded element. fixedBlind nil = a random blind.
func OprfBlind(input []byte, mode string, fixedBlind []byte) (blind, blindedElement []byte, err error) {
	if err := oprfFramed(input, "Blind(input)"); err != nil {
		return nil, nil, err
	}
	var r rScalar
	if fixedBlind == nil {
		r = rRandScalar()
	} else if r, err = oprfScalar(fixedBlind); err != nil {
		return nil, nil, err
	}
	el, err := oprfHashToGroup(input, mode)
	if err != nil {
		return nil, nil, err
	}
	if oprfIsIdentity(el) {
		return nil, nil, errors.New("Blind: input maps to identity")
	}
	bl, err := oprfMul(el, r)
	if err != nil {
		return nil, nil, err
	}
	return r.Bytes(), rEncode(bl), nil
}

// OprfBlindEvaluate is the server step: the evaluated element and, for voprf, the DLEQ proof. publicKey nil = derived;
// proofRandomness nil = random.
func OprfBlindEvaluate(secretKey, blindedElement []byte, mode string, publicKey, proofRandomness []byte) (evaluated, proof []byte, err error) {
	if err := oprfServerMode(mode); err != nil {
		return nil, nil, err
	}
	sk, err := oprfScalar(secretKey)
	if err != nil {
		return nil, nil, err
	}
	r, err := oprfElement(blindedElement)
	if err != nil {
		return nil, nil, err
	}
	ev, err := oprfMul(r, sk)
	if err != nil {
		return nil, nil, err
	}
	if mode == "oprf" {
		return rEncode(ev), nil, nil
	}
	var pk rPoint
	if publicKey == nil {
		pk, err = oprfBaseMult(sk)
	} else {
		pk, err = oprfElement(publicKey)
	}
	if err != nil {
		return nil, nil, err
	}
	proof, err = oprfGenerateProof(sk, rG, pk, r, ev, "voprf", proofRandomness)
	if err != nil {
		return nil, nil, err
	}
	return rEncode(ev), proof, nil
}

// OprfFinalize is the client's last step. For voprf the proof, public key and blinded element are required and the DLEQ proof is
// verified.
func OprfFinalize(input, blind, evaluatedElement []byte, mode string, proof, publicKey, blindedElement []byte) ([]byte, error) {
	if err := oprfFramed(input, "Finalize(input)"); err != nil {
		return nil, err
	}
	if err := oprfServerMode(mode); err != nil {
		return nil, err
	}
	r, err := oprfScalar(blind)
	if err != nil {
		return nil, err
	}
	ev, err := oprfElement(evaluatedElement)
	if err != nil {
		return nil, err
	}
	if mode == "voprf" {
		if proof == nil || publicKey == nil || blindedElement == nil {
			return nil, errors.New("Finalize(voprf): proof, publicKey and blindedElement are required")
		}
		pk, err := oprfElement(publicKey)
		if err != nil {
			return nil, err
		}
		bl, err := oprfElement(blindedElement)
		if err != nil {
			return nil, err
		}
		ok, err := oprfVerifyProof(rG, pk, bl, ev, proof, "voprf")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("Finalize(voprf): DLEQ proof verification failed")
		}
	}
	inv, err := oprfInvert(r)
	if err != nil {
		return nil, err
	}
	n, err := oprfMul(ev, inv)
	if err != nil {
		return nil, err
	}
	return oprfFinalizeHash(input, nil, rEncode(n), false), nil
}

// OprfEvaluate is the server's direct evaluation of an input (no blinding).
func OprfEvaluate(secretKey, input []byte, mode string) ([]byte, error) {
	if err := oprfFramed(input, "Evaluate(input)"); err != nil {
		return nil, err
	}
	if err := oprfServerMode(mode); err != nil {
		return nil, err
	}
	sk, err := oprfScalar(secretKey)
	if err != nil {
		return nil, err
	}
	el, err := oprfHashToGroup(input, mode)
	if err != nil {
		return nil, err
	}
	if oprfIsIdentity(el) {
		return nil, errors.New("Evaluate: input maps to identity")
	}
	p, err := oprfMul(el, sk)
	if err != nil {
		return nil, err
	}
	return oprfFinalizeHash(input, nil, rEncode(p), false), nil
}

// ---- POPRF (the public input info is bound into the evaluation)

func oprfInfoScalar(info []byte) (rScalar, error) {
	if err := oprfFramed(info, "info"); err != nil {
		return nil, err
	}
	return oprfHashToScalar(append(append([]byte("Info"), oprfI2OSP2(len(info))...), info...), "poprf")
}

// OprfBlindPoprf is the POPRF client's blind step; it also returns the tweaked key the proof is checked against.
func OprfBlindPoprf(input, info, publicKey, fixedBlind []byte) (blind, blindedElement, tweakedKey []byte, err error) {
	if err := oprfFramed(input, "Blind(input)"); err != nil {
		return nil, nil, nil, err
	}
	m, err := oprfInfoScalar(info)
	if err != nil {
		return nil, nil, nil, err
	}
	pk, err := oprfElement(publicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	bm, err := oprfBaseMult(m)
	if err != nil {
		return nil, nil, nil, err
	}
	tweaked := rAdd(bm, pk)
	if oprfIsIdentity(tweaked) {
		return nil, nil, nil, errors.New("Blind(poprf): tweaked key is identity")
	}
	blind, blindedElement, err = OprfBlind(input, "poprf", fixedBlind)
	if err != nil {
		return nil, nil, nil, err
	}
	return blind, blindedElement, rEncode(tweaked), nil
}

// OprfBlindEvaluatePoprf is the POPRF server step: the evaluated element and its DLEQ proof (proofRandomness nil = random).
func OprfBlindEvaluatePoprf(secretKey, blindedElement, info, proofRandomness []byte) (evaluated, proof []byte, err error) {
	sk, err := oprfScalar(secretKey)
	if err != nil {
		return nil, nil, err
	}
	m, err := oprfInfoScalar(info)
	if err != nil {
		return nil, nil, err
	}
	t := ed.NewScalar().Add(sk, m)
	if t.Equal(ed.NewScalar()) == 1 {
		return nil, nil, errors.New("BlindEvaluate(poprf): inverse of zero (bad info/key)")
	}
	blinded, err := oprfElement(blindedElement)
	if err != nil {
		return nil, nil, err
	}
	inv, err := oprfInvert(t)
	if err != nil {
		return nil, nil, err
	}
	ev, err := oprfMul(blinded, inv)
	if err != nil {
		return nil, nil, err
	}
	tweakedKey, err := oprfBaseMult(t)
	if err != nil {
		return nil, nil, err
	}
	proof, err = oprfGenerateProof(t, rG, tweakedKey, ev, blinded, "poprf", proofRandomness)
	if err != nil {
		return nil, nil, err
	}
	return rEncode(ev), proof, nil
}

// OprfFinalizePoprf is the POPRF client's last step; the DLEQ proof is always verified.
func OprfFinalizePoprf(input, blind, evaluatedElement, info, proof, blindedElement, tweakedKey []byte) ([]byte, error) {
	if err := oprfFramed(input, "Finalize(input)"); err != nil {
		return nil, err
	}
	if err := oprfFramed(info, "info"); err != nil {
		return nil, err
	}
	r, err := oprfScalar(blind)
	if err != nil {
		return nil, err
	}
	ev, err := oprfElement(evaluatedElement)
	if err != nil {
		return nil, err
	}
	bl, err := oprfElement(blindedElement)
	if err != nil {
		return nil, err
	}
	tk, err := oprfElement(tweakedKey)
	if err != nil {
		return nil, err
	}
	ok, err := oprfVerifyProof(rG, tk, ev, bl, proof, "poprf")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("Finalize(poprf): DLEQ proof verification failed")
	}
	inv, err := oprfInvert(r)
	if err != nil {
		return nil, err
	}
	n, err := oprfMul(ev, inv)
	if err != nil {
		return nil, err
	}
	return oprfFinalizeHash(input, info, rEncode(n), true), nil
}

// OprfEvaluatePoprf is the server's direct POPRF evaluation of an input under a public info.
func OprfEvaluatePoprf(secretKey, input, info []byte) ([]byte, error) {
	if err := oprfFramed(input, "Evaluate(input)"); err != nil {
		return nil, err
	}
	sk, err := oprfScalar(secretKey)
	if err != nil {
		return nil, err
	}
	m, err := oprfInfoScalar(info)
	if err != nil {
		return nil, err
	}
	t := ed.NewScalar().Add(sk, m)
	if t.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("Evaluate(poprf): inverse of zero (bad info/key)")
	}
	el, err := oprfHashToGroup(input, "poprf")
	if err != nil {
		return nil, err
	}
	if oprfIsIdentity(el) {
		return nil, errors.New("Evaluate(poprf): input maps to identity")
	}
	inv, err := oprfInvert(t)
	if err != nil {
		return nil, err
	}
	p, err := oprfMul(el, inv)
	if err != nil {
		return nil, err
	}
	return oprfFinalizeHash(input, info, rEncode(p), true), nil
}

// OprfToHex is the lowercase hex of bytes.
func OprfToHex(b []byte) string { return hex.EncodeToString(b) }

// OprfBytesEqual is a constant-time byte comparison (unequal lengths are unequal).
func OprfBytesEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// ---- PCA layer: private revocation

// OprfEncodeStrict is the UTF-8 of an identifier; an ill-formed string (an unpaired surrogate) is refused rather than mapped to
// U+FFFD, which would merge two different identifiers.
func oprfEncodeStrict(s, what string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("%s contains an unpaired surrogate (ill-formed UTF-16)", what)
	}
	return []byte(s), nil
}

// OprfEvaluated is a server blind-evaluation answer: the evaluated element and the DLEQ proof (nil when absent).
type OprfEvaluated struct {
	EvaluatedElement []byte
	Proof            []byte
}

// OprfBlindEvaluator is a server blind-evaluation oracle: the only thing that crosses the client to service boundary.
type OprfBlindEvaluator func(blindedElement []byte) (OprfEvaluated, error)

// OprfRevocationSet is a published private-revocation set: the lowercase-hex OPRF outputs of the revoked capability ids, the
// mode that produced them and (voprf) the service public key.
type OprfRevocationSet struct {
	Outputs   map[string]bool
	Mode      string
	PublicKey []byte
}

// OprfBuildRevocationSet precomputes the private-revocation set from the secret key and the revoked capability ids.
func OprfBuildRevocationSet(secretKey []byte, revoked []string, mode string) (*OprfRevocationSet, error) {
	if err := oprfServerMode(mode); err != nil {
		return nil, err
	}
	set := &OprfRevocationSet{Outputs: map[string]bool{}, Mode: mode}
	for _, id := range revoked {
		in, err := oprfEncodeStrict(id, "capability id")
		if err != nil {
			return nil, err
		}
		out, err := OprfEvaluate(secretKey, in, mode)
		if err != nil {
			return nil, err
		}
		set.Outputs[OprfToHex(out)] = true
	}
	if mode == "voprf" {
		pk, err := OprfPublicKeyFor(secretKey)
		if err != nil {
			return nil, err
		}
		set.PublicKey = pk
	}
	return set, nil
}

// OprfMakeRevocationEvaluator is the service's blind-evaluation oracle; it cannot recover the capability id.
func OprfMakeRevocationEvaluator(secretKey []byte, mode string) (OprfBlindEvaluator, error) {
	if err := oprfServerMode(mode); err != nil {
		return nil, err
	}
	var pk []byte
	if mode == "voprf" {
		var err error
		if pk, err = OprfPublicKeyFor(secretKey); err != nil {
			return nil, err
		}
	}
	return func(blinded []byte) (OprfEvaluated, error) {
		ev, proof, err := OprfBlindEvaluate(secretKey, blinded, mode, pk, nil)
		return OprfEvaluated{ev, proof}, err
	}, nil
}

// OprfIsRevokedPrivate is client side: is capID in the published set, learned obliviously? A voprf set verifies the service's DLEQ
// proof, so a lying service is refused rather than making every capability look non-revoked.
func OprfIsRevokedPrivate(capID string, blindEval OprfBlindEvaluator, set *OprfRevocationSet) (bool, error) {
	in, err := oprfEncodeStrict(capID, "capability id")
	if err != nil {
		return false, err
	}
	blind, blinded, err := OprfBlind(in, set.Mode, nil)
	if err != nil {
		return false, err
	}
	res, err := blindEval(blinded)
	if err != nil {
		return false, err
	}
	var out []byte
	if set.Mode == "voprf" {
		if res.Proof == nil || set.PublicKey == nil {
			return false, errors.New("isRevokedPrivate(voprf): missing DLEQ proof or service public key")
		}
		out, err = OprfFinalize(in, blind, res.EvaluatedElement, "voprf", res.Proof, set.PublicKey, blinded)
	} else {
		out, err = OprfFinalize(in, blind, res.EvaluatedElement, "oprf", nil, nil, nil)
	}
	if err != nil {
		return false, err
	}
	return set.Outputs[OprfToHex(out)], nil
}

// ---- PCA layer: private rate limiting

// OprfRateBlindEvaluator is the POPRF oracle for rate tokens: the window is the public info tag.
type OprfRateBlindEvaluator func(blindedElement []byte, window string) (OprfEvaluated, error)

// OprfRateToken is the deterministic rate token for (identifier, window): POPRF.Evaluate(sk, identifier, info = window).
func OprfRateToken(secretKey []byte, identifier, window string) ([]byte, error) {
	id, err := oprfEncodeStrict(identifier, "identifier")
	if err != nil {
		return nil, err
	}
	w, err := oprfEncodeStrict(window, "window")
	if err != nil {
		return nil, err
	}
	return OprfEvaluatePoprf(secretKey, id, w)
}

// OprfRateTokenHex is the lowercase hex of OprfRateToken: a stable, identifier-free counting key.
func OprfRateTokenHex(secretKey []byte, identifier, window string) (string, error) {
	t, err := OprfRateToken(secretKey, identifier, window)
	if err != nil {
		return "", err
	}
	return OprfToHex(t), nil
}

// OprfMakeRateEvaluator is the server's POPRF blind-evaluation oracle.
func OprfMakeRateEvaluator(secretKey []byte) OprfRateBlindEvaluator {
	return func(blinded []byte, window string) (OprfEvaluated, error) {
		w, err := oprfEncodeStrict(window, "window")
		if err != nil {
			return OprfEvaluated{}, err
		}
		ev, proof, err := OprfBlindEvaluatePoprf(secretKey, blinded, w, nil)
		return OprfEvaluated{ev, proof}, err
	}
}

// OprfPrivateRateToken obtains the rate token for (identifier, window) without revealing the identifier; it equals OprfRateToken
// for the same key. The server's DLEQ proof is verified.
func OprfPrivateRateToken(identifier, window string, blindEval OprfRateBlindEvaluator, publicKey []byte) ([]byte, error) {
	id, err := oprfEncodeStrict(identifier, "identifier")
	if err != nil {
		return nil, err
	}
	info, err := oprfEncodeStrict(window, "window")
	if err != nil {
		return nil, err
	}
	blind, blinded, tweaked, err := OprfBlindPoprf(id, info, publicKey, nil)
	if err != nil {
		return nil, err
	}
	res, err := blindEval(blinded, window)
	if err != nil {
		return nil, err
	}
	if res.Proof == nil {
		return nil, errors.New("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof")
	}
	return OprfFinalizePoprf(id, blind, res.EvaluatedElement, info, res.Proof, blinded, tweaked)
}

// OprfRateCounter counts hits per rate token with a per-window limit.
type OprfRateCounter struct {
	mu     sync.Mutex
	limit  int
	counts map[string]int
}

// NewOprfRateCounter returns a counter allowing limit hits per token (a positive integer).
func NewOprfRateCounter(limit int) (*OprfRateCounter, error) {
	if limit < 1 {
		return nil, errors.New("RateWindowCounter: limit must be a positive integer")
	}
	return &OprfRateCounter{limit: limit, counts: map[string]int{}}, nil
}

// Hit counts one use of token and reports the count and whether it is within the limit.
func (c *OprfRateCounter) Hit(token []byte) (count int, allowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := OprfToHex(token)
	c.counts[k]++
	return c.counts[k], c.counts[k] <= c.limit
}

// Count is the number of hits of token so far.
func (c *OprfRateCounter) Count(token []byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[OprfToHex(token)]
}

// Reset starts a new window.
func (c *OprfRateCounter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = map[string]int{}
}
