package blstkit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"

	blst "github.com/supranational/blst/bindings/go"
)

// BBS signatures over BLS12-381 (draft-irtf-cfrg-bbs-signatures, ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_): signatures
// and generators in G1 (48 bytes), public keys in G2 (96 bytes), scalars 32 bytes big-endian. Group arithmetic and
// hash-to-curve are blst; scalar arithmetic is math/big, which is not constant time (it touches the signing key, 1/(SK+e) and
// the prover's blinding scalars): hold long-lived issuer keys in an HSM, as with any non-hardware BBS implementation.

// BbsMaxMessages bounds the messages in one credential (a verifier derives the count from attacker-supplied proof length).
const BbsMaxMessages = 1024

const (
	bbsCiphersuite = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	bbsAPIID       = bbsCiphersuite + "H2G_HM2S_"
	bbsH2SDST      = bbsAPIID + "H2S_"
	bbsMapDST      = bbsAPIID + "MAP_MSG_TO_SCALAR_AS_HASH_"
	bbsSeedDST     = bbsAPIID + "SIG_GENERATOR_SEED_"
	bbsGenDST      = bbsAPIID + "SIG_GENERATOR_DST_"
	bbsGenSeed     = bbsAPIID + "MESSAGE_GENERATOR_SEED"
	bbsKeygenDST   = bbsAPIID + "KEYGEN_DST_"
	bbsScalarLen   = 32
	bbsPointLen    = 48
	bbsExpandLen   = 48
	// the published fixed G1 generator P1 of the ciphersuite (draft section 7.2.2)
	bbsP1Hex = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"
)

// BbsR is the order of the BBS scalar field (the BLS12-381 subgroup order r).
var BbsR, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// ---- scalars ---------------------------------------------------------------------------------------------------------

func fr(x *big.Int) *big.Int { return new(big.Int).Mod(x, BbsR) }

func frAdd(a, b *big.Int) *big.Int { return fr(new(big.Int).Add(a, b)) }
func frSub(a, b *big.Int) *big.Int { return fr(new(big.Int).Sub(a, b)) }
func frMul(a, b *big.Int) *big.Int { return fr(new(big.Int).Mul(a, b)) }

func frInv(x *big.Int) (*big.Int, error) {
	v := fr(x)
	if v.Sign() == 0 {
		return nil, errors.New("bbs: inverse of zero")
	}
	return new(big.Int).ModInverse(v, BbsR), nil
}

func i2osp(n *big.Int, l int) ([]byte, error) {
	if n.Sign() < 0 || n.BitLen() > 8*l {
		return nil, errors.New("bbs: integer out of range for I2OSP")
	}
	return n.FillBytes(make([]byte, l)), nil
}

func i2ospU(n uint64, l int) []byte {
	b, _ := i2osp(new(big.Int).SetUint64(n), l)
	return b
}

// scalarLE is the little-endian scalar encoding blst's multiplication takes.
func scalarLE(s *big.Int) []byte {
	be := fr(s).FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return be
}

// ---- expand_message_xmd (RFC 9380 5.3.1, SHA-256) --------------------------------------------------------------------

func expandXMD(msg []byte, dst string, n int) []byte {
	dstPrime := append([]byte(dst), byte(len(dst)))
	ell := (n + 31) / 32
	h := sha256.New()
	h.Write(make([]byte, 64))
	h.Write(msg)
	h.Write([]byte{byte(n >> 8), byte(n), 0})
	h.Write(dstPrime)
	b0 := h.Sum(nil)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(dstPrime)
	prev := h.Sum(nil)
	out := append([]byte(nil), prev...)
	for i := 2; i <= ell; i++ {
		x := make([]byte, 32)
		for j := range x {
			x[j] = b0[j] ^ prev[j]
		}
		h.Reset()
		h.Write(x)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// BbsHashToScalar is hash_to_scalar(msg, dst): OS2IP(expand_message_xmd(msg, dst, 48)) mod r.
func BbsHashToScalar(msg []byte, dst string) *big.Int {
	return fr(new(big.Int).SetBytes(expandXMD(msg, dst, bbsExpandLen)))
}

// BbsMapMessageToScalarAsHash maps one message octet string to one scalar.
func BbsMapMessageToScalarAsHash(message []byte) *big.Int { return BbsHashToScalar(message, bbsMapDST) }

func messagesToScalars(msgs [][]byte) []*big.Int {
	out := make([]*big.Int, len(msgs))
	for i, m := range msgs {
		out[i] = BbsMapMessageToScalarAsHash(m)
	}
	return out
}

// ---- points ----------------------------------------------------------------------------------------------------------

func isInfEncoding(b []byte) bool { return b[0]&0x40 != 0 }

func g1FromAffine(a *blst.P1Affine) *blst.P1 {
	var p blst.P1 // the zero value is the point at infinity
	p.AddAssign(a)
	return &p
}

func g2FromAffine(a *blst.P2Affine) *blst.P2 {
	var p blst.P2
	p.AddAssign(a)
	return &p
}

func g1Bytes(p *blst.P1) []byte { return p.ToAffine().Compress() }
func g2Bytes(p *blst.P2) []byte { return p.ToAffine().Compress() }

// strictG1 decodes the exact canonical compressed encoding of a prime-order G1 point (the identity included).
func strictG1(b []byte) (*blst.P1, error) {
	if !isCompressed(b, bbsPointLen) {
		return nil, errors.New("bbs: not a compressed G1 point")
	}
	a := new(blst.P1Affine).Uncompress(b)
	if a == nil || !a.InG1() || !bytes.Equal(a.Compress(), b) {
		return nil, errors.New("bbs: non-canonical or invalid G1 encoding")
	}
	return g1FromAffine(a), nil
}

func strictG2(b []byte) (*blst.P2, error) {
	if !isCompressed(b, 96) {
		return nil, errors.New("bbs: not a compressed G2 point")
	}
	a := new(blst.P2Affine).Uncompress(b)
	if a == nil || !a.InG2() || !bytes.Equal(a.Compress(), b) {
		return nil, errors.New("bbs: non-canonical or invalid G2 encoding")
	}
	return g2FromAffine(a), nil
}

func g1Add(a, b *blst.P1) *blst.P1 {
	r := *a
	r.AddAssign(b)
	return &r
}

func g1Neg(a *blst.P1) *blst.P1 {
	return new(blst.P1).Sub(a)
}

func g1Mul(p *blst.P1, s *big.Int) *blst.P1 {
	v := fr(s)
	if v.Sign() == 0 {
		return new(blst.P1)
	}
	r := *p
	return r.Mult(scalarLE(v))
}

func g2Add(a, b *blst.P2) *blst.P2 {
	r := *a
	r.AddAssign(b)
	return &r
}

func g2Mul(p *blst.P2, s *big.Int) *blst.P2 {
	v := fr(s)
	if v.Sign() == 0 {
		return new(blst.P2)
	}
	r := *p
	return r.Mult(scalarLE(v))
}

var (
	bbsP1  = mustG1(bbsP1Hex)
	bbsBP2 = blst.P2Generator()
)

func mustG1(h string) *blst.P1 {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	p, err := strictG1(b)
	if err != nil {
		panic(err)
	}
	return p
}

// pairingEq reports e(a1, a2) == e(b1, b2) over canonical non-identity points; false when any point is the identity.
func pairingEq(a1 *blst.P1, a2 *blst.P2, b1 *blst.P1, b2 *blst.P2) bool {
	l, ok1 := gtPairing([][]byte{g1Bytes(a1)}, [][]byte{g2Bytes(a2)})
	r, ok2 := gtPairing([][]byte{g1Bytes(b1)}, [][]byte{g2Bytes(b2)})
	return ok1 && ok2 && bytes.Equal(l, r)
}

// ---- generators ------------------------------------------------------------------------------------------------------

func createGenerators(count int) ([]*blst.P1, error) {
	if count < 0 {
		return nil, errors.New("bbs: generator count must be a non-negative integer")
	}
	if count > BbsMaxMessages+1 {
		return nil, fmt.Errorf("bbs: at most %d messages are supported", BbsMaxMessages)
	}
	gens := make([]*blst.P1, 0, count)
	v := expandXMD([]byte(bbsGenSeed), bbsSeedDST, bbsExpandLen)
	for i := 1; i <= count; i++ {
		v = expandXMD(append(append([]byte(nil), v...), i2ospU(uint64(i), 8)...), bbsSeedDST, bbsExpandLen)
		h := blst.HashToG1(v, []byte(bbsGenDST))
		a := new(blst.P1Affine).Uncompress(h.Compress())
		if a == nil {
			return nil, errors.New("bbs: hash to curve failed")
		}
		gens = append(gens, g1FromAffine(a))
	}
	return gens, nil
}

// BbsCreateGenerators is create_generators(count): the deterministic compressed generators (Q_1, H_1, ...).
func BbsCreateGenerators(count int) ([][]byte, error) {
	g, err := createGenerators(count)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(g))
	for i, p := range g {
		out[i] = g1Bytes(p)
	}
	return out, nil
}

// ---- serialization ---------------------------------------------------------------------------------------------------

type bbsSer struct{ buf []byte }

func (s *bbsSer) g1(p *blst.P1) { s.buf = append(s.buf, g1Bytes(p)...) }

func (s *bbsSer) scalar(v *big.Int) error {
	b, err := i2osp(v, bbsScalarLen)
	if err != nil {
		return err
	}
	s.buf = append(s.buf, b...)
	return nil
}

func (s *bbsSer) int(n int) { s.buf = append(s.buf, i2ospU(uint64(n), 8)...) }

// ---- key generation --------------------------------------------------------------------------------------------------

// BbsKeyGen derives a secret scalar from at least 32 octets of key material and optional info (draft 3.4.1).
func BbsKeyGen(keyMaterial, keyInfo []byte) (*big.Int, error) {
	if len(keyMaterial) < 32 {
		return nil, errors.New("bbs: key material must be at least 32 octets")
	}
	if len(keyInfo) > 65535 {
		return nil, errors.New("bbs: key info must be at most 65535 octets")
	}
	in := append(append(append([]byte(nil), keyMaterial...), i2ospU(uint64(len(keyInfo)), 2)...), keyInfo...)
	sk := BbsHashToScalar(in, bbsKeygenDST)
	if sk.Sign() == 0 {
		return nil, errors.New("bbs: derived SK is zero (retry with different key material)")
	}
	return sk, nil
}

// BbsSkToPk is the compressed G2 public key SK * BP2.
func BbsSkToPk(sk *big.Int) ([]byte, error) {
	if sk == nil || fr(sk).Sign() == 0 {
		return nil, errors.New("bbs: secret key is zero")
	}
	return g2Bytes(g2Mul(bbsBP2, sk)), nil
}

// BbsGenerateKeyPair draws a fresh key pair from the system CSPRNG.
func BbsGenerateKeyPair() (sk *big.Int, pk []byte, err error) {
	ikm := make([]byte, 32)
	if _, err = rand.Read(ikm); err != nil {
		return nil, nil, err
	}
	if bytes.Equal(ikm, make([]byte, 32)) {
		return nil, nil, errors.New("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key")
	}
	if sk, err = BbsKeyGen(ikm, nil); err != nil {
		return nil, nil, err
	}
	pk, err = BbsSkToPk(sk)
	return sk, pk, err
}

// ---- signature octets ------------------------------------------------------------------------------------------------

func octetsToSignature(sig []byte) (*blst.P1, *big.Int, error) {
	if len(sig) != bbsPointLen+bbsScalarLen {
		return nil, nil, errors.New("bbs: signature must be 80 octets")
	}
	A, err := strictG1(sig[:bbsPointLen])
	if err != nil {
		return nil, nil, err
	}
	if isInfEncoding(sig) {
		return nil, nil, errors.New("bbs: signature point A is the identity")
	}
	e := new(big.Int).SetBytes(sig[bbsPointLen:])
	if e.Sign() <= 0 || e.Cmp(BbsR) >= 0 {
		return nil, nil, errors.New("bbs: signature scalar e out of range")
	}
	return A, e, nil
}

func calculateDomain(pk []byte, Q1 *blst.P1, H []*blst.P1, header []byte) (*big.Int, error) {
	s := &bbsSer{}
	s.int(len(H))
	s.g1(Q1)
	for _, h := range H {
		s.g1(h)
	}
	dom := append(s.buf, bbsAPIID...)
	in := append([]byte(nil), pk...)
	in = append(in, dom...)
	in = append(in, i2ospU(uint64(len(header)), 8)...)
	in = append(in, header...)
	return BbsHashToScalar(in, bbsH2SDST), nil
}

func computeB(Q1 *blst.P1, H []*blst.P1, domain *big.Int, msgs []*big.Int) *blst.P1 {
	B := g1Add(bbsP1, g1Mul(Q1, domain))
	for i, m := range msgs {
		B = g1Add(B, g1Mul(H[i], m))
	}
	return B
}

// BbsSign produces the 80-octet BBS signature over the ordered message vector.
func BbsSign(sk *big.Int, pk, header []byte, messages [][]byte) ([]byte, error) {
	if sk == nil || fr(sk).Sign() == 0 {
		return nil, errors.New("bbs: secret key is zero")
	}
	msgs := messagesToScalars(messages)
	gens, err := createGenerators(len(msgs) + 1)
	if err != nil {
		return nil, err
	}
	Q1, H := gens[0], gens[1:]
	domain, err := calculateDomain(pk, Q1, H, header)
	if err != nil {
		return nil, err
	}
	es := &bbsSer{}
	for _, v := range append(append([]*big.Int{sk}, msgs...), domain) {
		if err := es.scalar(v); err != nil {
			return nil, err
		}
	}
	e := BbsHashToScalar(es.buf, bbsH2SDST)
	B := computeB(Q1, H, domain, msgs)
	inv, err := frInv(frAdd(sk, e))
	if err != nil {
		return nil, err
	}
	A := g1Mul(B, inv)
	eb, err := i2osp(e, bbsScalarLen)
	if err != nil {
		return nil, err
	}
	return append(g1Bytes(A), eb...), nil
}

// BbsResult is a verification outcome that says why it failed (stable reason strings).
type BbsResult struct {
	Ok     bool
	Reason string
}

func bbsFail(reason string) BbsResult { return BbsResult{Reason: reason} }

// BbsVerifyDetailed verifies a signature over exactly these messages; fails closed on any malformed input.
func BbsVerifyDetailed(pk, signature, header []byte, messages [][]byte) BbsResult {
	A, e, err := octetsToSignature(signature)
	if err != nil {
		return bbsFail("malformed-signature")
	}
	W, err := strictG2(pk)
	if err != nil || isInfEncoding(pk) {
		return bbsFail("malformed-public-key")
	}
	if len(messages) > BbsMaxMessages {
		return bbsFail("disclosed-length-mismatch")
	}
	msgs := messagesToScalars(messages)
	gens, err := createGenerators(len(msgs) + 1)
	if err != nil {
		return bbsFail("disclosed-length-mismatch")
	}
	Q1, H := gens[0], gens[1:]
	domain, _ := calculateDomain(pk, Q1, H, header)
	B := computeB(Q1, H, domain, msgs)
	// e(A, W + BP2*e) == e(B, BP2)
	if !pairingEq(A, g2Add(W, g2Mul(bbsBP2, e)), B, bbsBP2) {
		return bbsFail("pairing-mismatch")
	}
	return BbsResult{Ok: true}
}

// BbsVerify reports whether the signature covers exactly these messages.
func BbsVerify(pk, signature, header []byte, messages [][]byte) bool {
	return BbsVerifyDetailed(pk, signature, header, messages).Ok
}

// ---- challenge / proof octets ----------------------------------------------------------------------------------------

func calculateChallenge(Abar, Bbar, D, T1, T2 *blst.P1, idx []int, msgs []*big.Int, domain *big.Int, ph []byte) (*big.Int, error) {
	s := &bbsSer{}
	s.int(len(idx))
	for k := range idx {
		s.int(idx[k])
		if err := s.scalar(msgs[k]); err != nil {
			return nil, err
		}
	}
	for _, p := range []*blst.P1{Abar, Bbar, D, T1, T2} {
		s.g1(p)
	}
	if err := s.scalar(domain); err != nil {
		return nil, err
	}
	in := append(s.buf, i2ospU(uint64(len(ph)), 8)...)
	in = append(in, ph...)
	return BbsHashToScalar(in, bbsH2SDST), nil
}

type bbsProof struct {
	Abar, Bbar, D      *blst.P1
	eHat, r1Hat, r3Hat *big.Int
	mHat               []*big.Int
	c                  *big.Int
}

func readScalar(proof []byte, off int) (*big.Int, error) {
	v := new(big.Int).SetBytes(proof[off : off+bbsScalarLen])
	if v.Cmp(BbsR) >= 0 {
		return nil, errors.New("bbs: proof scalar out of range")
	}
	return v, nil
}

func octetsToProof(proof []byte) (*bbsProof, error) {
	fixed := 3*bbsPointLen + 4*bbsScalarLen
	if len(proof) < fixed || (len(proof)-fixed)%bbsScalarLen != 0 {
		return nil, errors.New("bbs: malformed proof length")
	}
	p := &bbsProof{}
	pts := []**blst.P1{&p.Abar, &p.Bbar, &p.D}
	for i, dst := range pts {
		b := proof[i*bbsPointLen : (i+1)*bbsPointLen]
		g, err := strictG1(b)
		if err != nil {
			return nil, err
		}
		if isInfEncoding(b) {
			return nil, errors.New("bbs: proof contains the identity point")
		}
		*dst = g
	}
	o := 3 * bbsPointLen
	var err error
	for _, dst := range []**big.Int{&p.eHat, &p.r1Hat, &p.r3Hat} {
		if *dst, err = readScalar(proof, o); err != nil {
			return nil, err
		}
		o += bbsScalarLen
	}
	U := (len(proof) - fixed) / bbsScalarLen
	for i := 0; i < U; i++ {
		m, err := readScalar(proof, o)
		if err != nil {
			return nil, err
		}
		p.mHat = append(p.mHat, m)
		o += bbsScalarLen
	}
	if p.c, err = readScalar(proof, o); err != nil {
		return nil, err
	}
	return p, nil
}

func proofToOctets(p *bbsProof) ([]byte, error) {
	out := append(append(g1Bytes(p.Abar), g1Bytes(p.Bbar)...), g1Bytes(p.D)...)
	sc := append([]*big.Int{p.eHat, p.r1Hat, p.r3Hat}, p.mHat...)
	sc = append(sc, p.c)
	for _, v := range sc {
		b, err := i2osp(v, bbsScalarLen)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func validateIndexes(idx []int, L int) error {
	seen := map[int]bool{}
	for _, i := range idx {
		if i < 0 || i >= L {
			return fmt.Errorf("bbs: disclosed index %d out of range [0, %d)", i, L)
		}
		if seen[i] {
			return fmt.Errorf("bbs: duplicate disclosed index %d", i)
		}
		seen[i] = true
	}
	return nil
}

func undisclosedAscending(disclosed map[int]bool, L int) []int {
	var out []int
	for i := 0; i < L; i++ {
		if !disclosed[i] {
			out = append(out, i)
		}
	}
	return out
}

// BbsProofGen is a zero-knowledge proof of knowledge of the signature disclosing the messages at disclosedIndexes. ph binds
// the proof to a context. fixedRandomScalars (5 + undisclosed scalars) pins the randomness for test vectors ONLY: reusing it
// across proofs breaks zero-knowledge and unlinkability; pass nil in production.
func BbsProofGen(pk, signature, header, ph []byte, messages [][]byte, disclosedIndexes []int, fixedRandomScalars []*big.Int) ([]byte, error) {
	A, e, err := octetsToSignature(signature)
	if err != nil {
		return nil, err
	}
	msgs := messagesToScalars(messages)
	L := len(msgs)
	if err := validateIndexes(disclosedIndexes, L); err != nil {
		return nil, err
	}
	disclosed := append([]int(nil), disclosedIndexes...)
	sort.Ints(disclosed)
	dset := map[int]bool{}
	for _, i := range disclosed {
		dset[i] = true
	}
	undisclosed := undisclosedAscending(dset, L)
	U := len(undisclosed)
	gens, err := createGenerators(L + 1)
	if err != nil {
		return nil, err
	}
	Q1, H := gens[0], gens[1:]
	domain, err := calculateDomain(pk, Q1, H, header)
	if err != nil {
		return nil, err
	}
	B := computeB(Q1, H, domain, msgs)

	rs := fixedRandomScalars
	if rs == nil {
		rs = make([]*big.Int, 5+U)
		for i := range rs {
			buf := make([]byte, bbsExpandLen)
			if _, err := rand.Read(buf); err != nil {
				return nil, err
			}
			rs[i] = fr(new(big.Int).SetBytes(buf))
		}
	}
	if len(rs) != 5+U {
		return nil, fmt.Errorf("bbs: expected %d random scalars, got %d", 5+U, len(rs))
	}
	if rs[0].Sign() == 0 || rs[1].Sign() == 0 {
		return nil, errors.New("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)")
	}
	r1, r2, eTilde, r1Tilde, r3Tilde := rs[0], rs[1], rs[2], rs[3], rs[4]
	mTilde := rs[5:]

	D := g1Mul(B, r2)
	Abar := g1Mul(A, frMul(r1, r2))
	Bbar := g1Add(g1Mul(D, r1), g1Neg(g1Mul(Abar, e)))
	T1 := g1Add(g1Mul(Abar, eTilde), g1Mul(D, r1Tilde))
	T2 := g1Mul(D, r3Tilde)
	for k, j := range undisclosed {
		T2 = g1Add(T2, g1Mul(H[j], mTilde[k]))
	}
	dmsgs := make([]*big.Int, len(disclosed))
	for k, i := range disclosed {
		dmsgs[k] = msgs[i]
	}
	c, err := calculateChallenge(Abar, Bbar, D, T1, T2, disclosed, dmsgs, domain, ph)
	if err != nil {
		return nil, err
	}
	r3, err := frInv(r2)
	if err != nil {
		return nil, err
	}
	p := &bbsProof{Abar: Abar, Bbar: Bbar, D: D, c: c,
		eHat:  frAdd(eTilde, frMul(e, c)),
		r1Hat: frSub(r1Tilde, frMul(r1, c)),
		r3Hat: frSub(r3Tilde, frMul(r3, c))}
	for k, j := range undisclosed {
		p.mHat = append(p.mHat, frAdd(mTilde[k], frMul(msgs[j], c)))
	}
	return proofToOctets(p)
}

// BbsProofVerifyDetailed verifies a proof; disclosedMessages[k] corresponds to disclosedIndexes[k].
func BbsProofVerifyDetailed(pk, proof, header, ph []byte, disclosedMessages [][]byte, disclosedIndexes []int) BbsResult {
	p, err := octetsToProof(proof)
	if err != nil {
		return bbsFail("malformed-proof")
	}
	W, err := strictG2(pk)
	if err != nil || isInfEncoding(pk) {
		return bbsFail("malformed-public-key")
	}
	if len(disclosedMessages) != len(disclosedIndexes) {
		return bbsFail("disclosed-length-mismatch")
	}
	U := len(p.mHat)
	L := len(disclosedIndexes) + U
	if L > BbsMaxMessages {
		return bbsFail("malformed-proof")
	}
	if err := validateIndexes(disclosedIndexes, L); err != nil {
		return bbsFail("invalid-disclosed-indexes")
	}
	type dm struct {
		idx int
		msg *big.Int
	}
	scal := messagesToScalars(disclosedMessages)
	disclosed := make([]dm, len(scal))
	for k := range scal {
		disclosed[k] = dm{disclosedIndexes[k], scal[k]}
	}
	sort.Slice(disclosed, func(a, b int) bool { return disclosed[a].idx < disclosed[b].idx })
	dset := map[int]bool{}
	idxs := make([]int, len(disclosed))
	msgs := make([]*big.Int, len(disclosed))
	for k, d := range disclosed {
		dset[d.idx] = true
		idxs[k], msgs[k] = d.idx, d.msg
	}
	undisclosed := undisclosedAscending(dset, L)

	gens, err := createGenerators(L + 1)
	if err != nil {
		return bbsFail("malformed-proof")
	}
	Q1, H := gens[0], gens[1:]
	domain, _ := calculateDomain(pk, Q1, H, header)

	T1 := g1Add(g1Add(g1Mul(p.Bbar, p.c), g1Mul(p.Abar, p.eHat)), g1Mul(p.D, p.r1Hat))
	Bv := g1Add(bbsP1, g1Mul(Q1, domain))
	for _, d := range disclosed {
		Bv = g1Add(Bv, g1Mul(H[d.idx], d.msg))
	}
	T2 := g1Add(g1Mul(Bv, p.c), g1Mul(p.D, p.r3Hat))
	for k, j := range undisclosed {
		T2 = g1Add(T2, g1Mul(H[j], p.mHat[k]))
	}
	cv, err := calculateChallenge(p.Abar, p.Bbar, p.D, T1, T2, idxs, msgs, domain, ph)
	if err != nil || cv.Cmp(p.c) != 0 {
		return bbsFail("challenge-mismatch")
	}
	// e(Abar, W) == e(Bbar, BP2)
	if !pairingEq(p.Abar, W, p.Bbar, bbsBP2) {
		return bbsFail("pairing-mismatch")
	}
	return BbsResult{Ok: true}
}

// BbsProofVerify reports whether the proof is valid.
func BbsProofVerify(pk, proof, header, ph []byte, disclosedMessages [][]byte, disclosedIndexes []int) bool {
	return BbsProofVerifyDetailed(pk, proof, header, ph, disclosedMessages, disclosedIndexes).Ok
}
