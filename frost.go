package pca

// FROST(Ed25519, SHA-512) threshold signing (RFC 9591): trusted-dealer key split, round-1 commit, round-2 sign, share-verified
// aggregation and the in-process quorum cosign. The aggregate is an ordinary RFC 8032 Ed25519 signature under the group key.
// Group and scalar arithmetic run on the vetted filippo.io/edwards25519 point and scalar types (constant time); only the RFC's
// protocol steps are written here. Public integers (participant identifiers, Lagrange coefficients) use math/big.

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	ed "filippo.io/edwards25519"
)

const (
	frostContext = "FROST-ED25519-SHA512-v1"
	// FrostSpentCommitmentCap bounds the one-shot nonce registry; the oldest entries are evicted first.
	FrostSpentCommitmentCap = 262144
	frostMaxSafeInt         = 9007199254740991
)

var frostSpent = struct {
	sync.Mutex
	set   map[string]struct{}
	order []string
}{set: map[string]struct{}{}}

// FrostParticipantShare is one dealer-issued share with its verifying (public) share.
type FrostParticipantShare struct {
	Identifier int64
	Share      []byte
	PublicKey  []byte
}

// FrostKeyShares is the dealer output.
type FrostKeyShares struct {
	GroupPublicKey    []byte
	ParticipantShares []FrostParticipantShare
	GroupCommitment   [][]byte
}

// FrostCommitment is a participant's public round-1 output.
type FrostCommitment struct {
	Identifier int64
	Hiding     []byte
	Binding    []byte
}

// FrostNonces are the secret round-1 nonces.
type FrostNonces struct{ Hiding, Binding []byte }

// FrostCommitResult is the round-1 output of one participant.
type FrostCommitResult struct {
	HidingNonce, BindingNonce []byte
	Commitment                FrostCommitment
}

// FrostSigShare is a participant's round-2 output.
type FrostSigShare struct {
	Identifier int64
	SigShare   []byte
}

// FrostVerificationShare binds an identifier to its verifying share.
type FrostVerificationShare struct {
	Identifier int64
	PublicKey  []byte
}

// FrostSignOpts: a nil Threshold / VerificationShare / VerificationShares means absent.
type FrostSignOpts struct {
	Threshold          *int
	VerificationShare  []byte
	VerificationShares []FrostVerificationShare
}

func frostIsID(i int64) bool { return i > 0 && i <= frostMaxSafeInt }

// FrostScalar reduces 0..64 little-endian bytes mod L (the reference bytesToScalar); more than 64 bytes is refused.
func FrostScalar(b []byte) ([]byte, error) {
	s, err := frostReduce(b)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

func frostReduce(b []byte) (*ed.Scalar, error) {
	if len(b) > 64 {
		return nil, errors.New("frost: scalar input longer than 64 bytes")
	}
	var w [64]byte
	copy(w[:], b)
	return ed.NewScalar().SetUniformBytes(w[:])
}

func frostIntScalar(i *big.Int) *ed.Scalar {
	m := new(big.Int).Mod(i, edL)
	var le [32]byte
	b := m.Bytes()
	for k := range b {
		le[len(b)-1-k] = b[k]
	}
	s, err := ed.NewScalar().SetCanonicalBytes(le[:])
	if err != nil {
		panic(err) // m < L
	}
	return s
}

func frostIDScalar(id int64) *ed.Scalar { return frostIntScalar(big.NewInt(id)) }

// FrostIsCanonicalScalar reports a 32-byte little-endian value below the group order.
func FrostIsCanonicalScalar(b []byte) bool {
	_, err := ed.NewScalar().SetCanonicalBytes(b)
	return err == nil
}

func frostH2S(m []byte) *ed.Scalar {
	d := sha512.Sum512(m)
	s, _ := ed.NewScalar().SetUniformBytes(d[:])
	return s
}

func frostTagged(tag string, m []byte) []byte {
	return append([]byte(frostContext+tag), m...)
}

// FrostHash evaluates H1..H5 of RFC 9591 section 6.1: H1/H2/H3 return a reduced 32-byte scalar, H4/H5 the 64-byte digest.
func FrostHash(which string, m []byte) ([]byte, error) {
	switch which {
	case "H1":
		return frostH2S(frostTagged("rho", m)).Bytes(), nil
	case "H2":
		return frostH2S(m).Bytes(), nil
	case "H3":
		return frostH2S(frostTagged("nonce", m)).Bytes(), nil
	case "H4":
		d := sha512.Sum512(frostTagged("msg", m))
		return d[:], nil
	case "H5":
		d := sha512.Sum512(frostTagged("com", m))
		return d[:], nil
	}
	return nil, fmt.Errorf("frost: unknown hash %q", which)
}

func frostH(which string, m []byte) []byte { b, _ := FrostHash(which, m); return b }

func frostH1(m []byte) *ed.Scalar { return frostH2S(frostTagged("rho", m)) }

// FrostDecodeSafePoint is the strict check of any point a caller can influence: 32 bytes, canonical, on the curve, not small
// order (so not the identity) and in the prime-order subgroup. Returns the canonical encoding.
func FrostDecodeSafePoint(b []byte) ([]byte, error) {
	if len(b) != 32 {
		return nil, errors.New("frost: point must be 32 bytes")
	}
	if !edStrictPoint(b) {
		return nil, errors.New("frost: point rejected (not canonical, off the curve, small order or not in the prime-order subgroup)")
	}
	return append([]byte(nil), b...), nil
}

func frostPoint(b []byte) (*ed.Point, error) {
	if _, err := FrostDecodeSafePoint(b); err != nil {
		return nil, err
	}
	return ed.NewIdentityPoint().SetBytes(b)
}

func frostBase(s *ed.Scalar) *ed.Point { return ed.NewIdentityPoint().ScalarBaseMult(s) }

func frostMul(p *ed.Point, s *ed.Scalar) *ed.Point { return ed.NewIdentityPoint().ScalarMult(s, p) }

func frostAdd(a, b *ed.Point) *ed.Point { return ed.NewIdentityPoint().Add(a, b) }

func frostValidateCommitments(lst []FrostCommitment, threshold *int) error {
	if len(lst) == 0 {
		return errors.New("frost: empty commitment list")
	}
	if threshold != nil {
		if *threshold <= 0 || int64(*threshold) > frostMaxSafeInt {
			return errors.New("frost: invalid threshold")
		}
		if len(lst) < *threshold {
			return fmt.Errorf("frost: need at least t=%d commitments (got %d)", *threshold, len(lst))
		}
	}
	seen := map[int64]bool{}
	for _, c := range lst {
		if !frostIsID(c.Identifier) {
			return errors.New("frost: participant identifier must be a positive safe integer")
		}
		if seen[c.Identifier] {
			return fmt.Errorf("frost: duplicate commitment identifier %d", c.Identifier)
		}
		seen[c.Identifier] = true
		if _, err := FrostDecodeSafePoint(c.Hiding); err != nil {
			return err
		}
		if _, err := FrostDecodeSafePoint(c.Binding); err != nil {
			return err
		}
	}
	return nil
}

func frostRand32() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// FrostTrustedDealerKeygen is the t-of-n split. secret, coefficients (t-1 of them) and identifiers are optional; missing secret
// material is drawn from crypto/rand. identifiers nil means 1..n.
func FrostTrustedDealerKeygen(t, n int, secret []byte, coefficients [][]byte, identifiers []int64) (*FrostKeyShares, error) {
	if t < 1 || t > n {
		return nil, fmt.Errorf("frostTrustedDealerKeygen: need 1 <= t <= n (got t=%d, n=%d)", t, n)
	}
	ids := identifiers
	if ids == nil {
		ids = make([]int64, n)
		for i := range ids {
			ids[i] = int64(i + 1)
		}
	}
	if len(ids) != n {
		return nil, errors.New("frostTrustedDealerKeygen: identifiers.length must equal n")
	}
	seen := map[int64]bool{}
	for _, x := range ids {
		seen[x] = true
	}
	if len(seen) != n {
		return nil, errors.New("frostTrustedDealerKeygen: identifiers must be distinct")
	}
	for _, x := range ids {
		if x <= 0 {
			return nil, errors.New("frostTrustedDealerKeygen: identifiers must be positive integers")
		}
	}
	coeffs := make([]*ed.Scalar, 0, t)
	for i := 0; i < t; i++ {
		var raw []byte
		if i == 0 {
			raw = secret
		} else if i-1 < len(coefficients) {
			raw = coefficients[i-1]
		}
		if raw == nil {
			var err error
			if raw, err = frostRand32(); err != nil {
				return nil, err
			}
		}
		s, err := frostReduce(raw)
		if err != nil {
			return nil, err
		}
		coeffs = append(coeffs, s)
	}
	out := &FrostKeyShares{}
	for _, id := range ids {
		x, acc := frostIDScalar(id), ed.NewScalar()
		for k := len(coeffs) - 1; k >= 0; k-- { // Horner on secret scalars
			acc = ed.NewScalar().MultiplyAdd(acc, x, coeffs[k])
		}
		out.ParticipantShares = append(out.ParticipantShares, FrostParticipantShare{Identifier: id, Share: acc.Bytes(), PublicKey: frostBase(acc).Bytes()})
	}
	for _, a := range coeffs {
		out.GroupCommitment = append(out.GroupCommitment, frostBase(a).Bytes())
	}
	out.GroupPublicKey = out.GroupCommitment[0]
	return out, nil
}

// FrostVerifyingShare is share*G.
func FrostVerifyingShare(share []byte) ([]byte, error) {
	s, err := frostReduce(share)
	if err != nil {
		return nil, err
	}
	return frostBase(s).Bytes(), nil
}

// FrostCommit is round 1: a fresh (hiding, binding) nonce pair and the public commitments. Nil randomness is drawn from crypto/rand.
func FrostCommit(p FrostParticipantShare, hidingRandomness, bindingRandomness []byte) (*FrostCommitResult, error) {
	var err error
	if hidingRandomness == nil {
		if hidingRandomness, err = frostRand32(); err != nil {
			return nil, err
		}
	}
	if bindingRandomness == nil {
		if bindingRandomness, err = frostRand32(); err != nil {
			return nil, err
		}
	}
	if len(hidingRandomness) != 32 || len(bindingRandomness) != 32 {
		return nil, errors.New("frostCommit: nonce randomness must be 32 bytes")
	}
	sk, err := frostReduce(p.Share)
	if err != nil {
		return nil, err
	}
	hn := frostH2S(frostTagged("nonce", append(append([]byte(nil), hidingRandomness...), sk.Bytes()...)))
	bn := frostH2S(frostTagged("nonce", append(append([]byte(nil), bindingRandomness...), sk.Bytes()...)))
	return &FrostCommitResult{
		HidingNonce: hn.Bytes(), BindingNonce: bn.Bytes(),
		Commitment: FrostCommitment{Identifier: p.Identifier, Hiding: frostBase(hn).Bytes(), Binding: frostBase(bn).Bytes()},
	}, nil
}

func frostSorted(lst []FrostCommitment) []FrostCommitment {
	c := append([]FrostCommitment(nil), lst...)
	sort.SliceStable(c, func(i, j int) bool { return c[i].Identifier < c[j].Identifier })
	return c
}

func frostBindingFactors(groupPK []byte, lst []FrostCommitment, msg []byte) map[int64]*ed.Scalar {
	var enc []byte
	for _, c := range lst {
		enc = append(enc, frostIDScalar(c.Identifier).Bytes()...)
		enc = append(enc, c.Hiding...)
		enc = append(enc, c.Binding...)
	}
	prefix := append(append(append([]byte(nil), groupPK...), frostH("H4", msg)...), frostH("H5", enc)...)
	out := map[int64]*ed.Scalar{}
	for _, c := range lst {
		out[c.Identifier] = frostH1(append(append([]byte(nil), prefix...), frostIDScalar(c.Identifier).Bytes()...))
	}
	return out
}

func frostGroupCommitment(lst []FrostCommitment, bf map[int64]*ed.Scalar) (*ed.Point, error) {
	r := ed.NewIdentityPoint()
	for _, c := range lst {
		h, err := frostPoint(c.Hiding)
		if err != nil {
			return nil, err
		}
		b, err := frostPoint(c.Binding)
		if err != nil {
			return nil, err
		}
		r = frostAdd(frostAdd(r, h), frostMul(b, bf[c.Identifier]))
	}
	return r, nil
}

// frostLambda is the Lagrange coefficient at zero (public integers only).
func frostLambda(participants []int64, i int64) (*ed.Scalar, error) {
	found := false
	for _, j := range participants {
		found = found || j == i
	}
	if !found {
		return nil, errors.New("frost: identifier not in participant list")
	}
	num, den := big.NewInt(1), big.NewInt(1)
	for _, j := range participants {
		if j != i {
			num.Mul(num, big.NewInt(j)).Mod(num, edL)
			den.Mul(den, new(big.Int).Sub(big.NewInt(j), big.NewInt(i))).Mod(den, edL)
		}
	}
	if den.Sign() == 0 {
		return nil, errors.New("frost: modular inverse of zero")
	}
	lam := num.Mul(num, new(big.Int).ModInverse(den, edL))
	lam.Mod(lam, edL)
	if lam.Sign() == 0 {
		return nil, errors.New("frost: zero Lagrange coefficient")
	}
	return frostIntScalar(lam), nil
}

func frostAllZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// FrostSign is round 2: this participant's signature share. One-shot: a nonce pair (and its public commitments) signs once, ever.
func FrostSign(identifier int64, share, groupPublicKey []byte, nonces FrostNonces, message []byte, signingCommitments []FrostCommitment, o FrostSignOpts) (*FrostSigShare, error) {
	if !frostIsID(identifier) {
		return nil, errors.New("frost: participant identifier must be a positive safe integer")
	}
	if err := frostValidateCommitments(signingCommitments, o.Threshold); err != nil {
		return nil, err
	}
	if _, err := FrostDecodeSafePoint(groupPublicKey); err != nil {
		return nil, err
	}
	if frostAllZero(nonces.Hiding) || frostAllZero(nonces.Binding) {
		return nil, errors.New("frostSign: zero/zeroized nonce")
	}
	if subtle.ConstantTimeCompare(nonces.Hiding, nonces.Binding) == 1 {
		return nil, errors.New("frostSign: hiding and binding nonce must differ")
	}
	lst := frostSorted(signingCommitments)
	var mine *FrostCommitment
	for i := range lst {
		if lst[i].Identifier == identifier {
			mine = &lst[i]
		}
	}
	if mine == nil {
		return nil, errors.New("frostSign: this identifier has no commitment in the set")
	}
	hiding, err := frostReduce(nonces.Hiding)
	if err != nil {
		return nil, err
	}
	binding, err := frostReduce(nonces.Binding)
	if err != nil {
		return nil, err
	}
	sk, err := frostReduce(share)
	if err != nil {
		return nil, err
	}
	if string(frostBase(hiding).Bytes()) != string(mine.Hiding) || string(frostBase(binding).Bytes()) != string(mine.Binding) {
		return nil, errors.New("frostSign: own commitment does not match nonces")
	}
	keys := []string{"h" + string(mine.Hiding), "b" + string(mine.Binding)}
	frostSpent.Lock()
	defer frostSpent.Unlock()
	for _, k := range keys {
		if _, used := frostSpent.set[k]; used {
			return nil, errors.New("frostSign: nonces already used (one-shot; reuse would leak the signing share)")
		}
	}
	if o.VerificationShare != nil {
		if _, err := FrostDecodeSafePoint(o.VerificationShare); err != nil {
			return nil, err
		}
		if string(frostBase(sk).Bytes()) != string(o.VerificationShare) {
			return nil, errors.New("frostSign: share does not match verification share")
		}
	}
	participants := make([]int64, len(lst))
	for i, c := range lst {
		participants[i] = c.Identifier
	}
	if o.VerificationShares != nil {
		acc := ed.NewIdentityPoint()
		for _, pid := range participants {
			var vs *FrostVerificationShare
			for i := range o.VerificationShares {
				if o.VerificationShares[i].Identifier == pid {
					vs = &o.VerificationShares[i]
					break
				}
			}
			if vs == nil {
				return nil, fmt.Errorf("frostSign: missing verification share for %d", pid)
			}
			pk, err := frostPoint(vs.PublicKey)
			if err != nil {
				return nil, err
			}
			lam, err := frostLambda(participants, pid)
			if err != nil {
				return nil, err
			}
			acc = frostAdd(acc, frostMul(pk, lam))
		}
		if string(acc.Bytes()) != string(groupPublicKey) {
			return nil, errors.New("frostSign: group public key does not match the verification shares")
		}
	}
	bf := frostBindingFactors(groupPublicKey, lst, message)
	r, err := frostGroupCommitment(lst, bf)
	if err != nil {
		return nil, err
	}
	c := frostH2S(append(append(r.Bytes(), groupPublicKey...), message...))
	lam, err := frostLambda(participants, identifier)
	if err != nil {
		return nil, err
	}
	z := ed.NewScalar().MultiplyAdd(binding, bf[identifier], hiding)
	z = ed.NewScalar().MultiplyAdd(ed.NewScalar().Multiply(lam, sk), c, z)
	for _, k := range keys {
		frostSpent.set[k] = struct{}{}
		frostSpent.order = append(frostSpent.order, k)
	}
	for len(frostSpent.order) > FrostSpentCommitmentCap {
		delete(frostSpent.set, frostSpent.order[0])
		frostSpent.order = frostSpent.order[1:]
	}
	return &FrostSigShare{Identifier: identifier, SigShare: z.Bytes()}, nil
}

// FrostVerifySigShare checks one signature share against its participant's verifying share; any malformed input is false.
func FrostVerifySigShare(identifier int64, publicKey []byte, commitment FrostCommitment, sigShare FrostSigShare, signingCommitments []FrostCommitment, groupPublicKey, message []byte) bool {
	if frostValidateCommitments(signingCommitments, nil) != nil {
		return false
	}
	lst := frostSorted(signingCommitments)
	bf := frostBindingFactors(groupPublicKey, lst, message)
	if _, ok := bf[identifier]; !ok {
		return false
	}
	r, err := frostGroupCommitment(lst, bf)
	if err != nil {
		return false
	}
	h, err := frostPoint(commitment.Hiding)
	if err != nil {
		return false
	}
	b, err := frostPoint(commitment.Binding)
	if err != nil {
		return false
	}
	commShare := frostAdd(h, frostMul(b, bf[identifier]))
	c := frostH2S(append(append(r.Bytes(), groupPublicKey...), message...))
	participants := make([]int64, len(lst))
	for i, x := range lst {
		participants[i] = x.Identifier
	}
	lam, err := frostLambda(participants, identifier)
	if err != nil {
		return false
	}
	zs, err := ed.NewScalar().SetCanonicalBytes(sigShare.SigShare)
	if err != nil {
		return false
	}
	pk, err := frostPoint(publicKey)
	if err != nil {
		return false
	}
	rhs := frostAdd(commShare, frostMul(pk, ed.NewScalar().Multiply(c, lam)))
	return frostBase(zs).Equal(rhs) == 1
}

// FrostAggregate verifies every signature share, sums them and returns the 64-byte Ed25519 signature; it fails unless that verifies.
func FrostAggregate(message []byte, signingCommitments []FrostCommitment, sigShares []FrostSigShare, groupPublicKey []byte, verificationShares []FrostVerificationShare, threshold *int) ([]byte, error) {
	if err := frostValidateCommitments(signingCommitments, threshold); err != nil {
		return nil, err
	}
	if _, err := FrostDecodeSafePoint(groupPublicKey); err != nil {
		return nil, err
	}
	lst := frostSorted(signingCommitments)
	if len(sigShares) != len(lst) {
		return nil, errors.New("frostAggregate: need exactly one signature share per commitment")
	}
	seen := map[int64]bool{}
	for _, s := range sigShares {
		in := false
		for _, c := range lst {
			in = in || c.Identifier == s.Identifier
		}
		if !in {
			return nil, errors.New("frostAggregate: share from non-signer")
		}
		if seen[s.Identifier] {
			return nil, errors.New("frostAggregate: duplicate signature share")
		}
		seen[s.Identifier] = true
	}
	if verificationShares == nil {
		return nil, errors.New("frostAggregate: verificationShares are required (every signature share is verified before aggregation)")
	}
	for _, s := range sigShares {
		var vs *FrostVerificationShare
		for i := range verificationShares {
			if verificationShares[i].Identifier == s.Identifier {
				vs = &verificationShares[i]
				break
			}
		}
		var com FrostCommitment
		for _, c := range lst {
			if c.Identifier == s.Identifier {
				com = c
			}
		}
		if vs == nil || !FrostVerifySigShare(s.Identifier, vs.PublicKey, com, s, lst, groupPublicKey, message) {
			return nil, fmt.Errorf("frostAggregate: invalid signature share from participant %d", s.Identifier)
		}
	}
	r, err := frostGroupCommitment(lst, frostBindingFactors(groupPublicKey, lst, message))
	if err != nil {
		return nil, err
	}
	z := ed.NewScalar()
	for _, s := range sigShares {
		zs, err := frostReduce(s.SigShare)
		if err != nil {
			return nil, err
		}
		z.Add(z, zs)
	}
	sig := append(r.Bytes(), z.Bytes()...)
	if !VerifyStrict(groupPublicKey, message, sig) {
		return nil, errors.New("frostAggregate: aggregate signature does not verify (a share is invalid)")
	}
	return sig, nil
}

// FrostCosign runs the whole protocol in process for a quorum of participant shares (the dealer / guardian-tier path).
func FrostCosign(groupPublicKey []byte, quorum []FrostParticipantShare, message []byte, threshold *int) ([]byte, error) {
	if len(quorum) == 0 {
		return nil, errors.New("frostCosign: empty signing quorum")
	}
	if threshold != nil && len(quorum) < *threshold {
		return nil, fmt.Errorf("frostCosign: quorum of %d is below the threshold t=%d", len(quorum), *threshold)
	}
	ids := map[int64]bool{}
	for _, p := range quorum {
		if !frostIsID(p.Identifier) {
			return nil, errors.New("frost: participant identifier must be a positive safe integer")
		}
		if ids[p.Identifier] {
			return nil, fmt.Errorf("frostCosign: duplicate participant %d in quorum", p.Identifier)
		}
		ids[p.Identifier] = true
	}
	vss := make([]FrostVerificationShare, len(quorum))
	commits := make([]*FrostCommitResult, len(quorum))
	comms := make([]FrostCommitment, len(quorum))
	for i, p := range quorum {
		vss[i] = FrostVerificationShare{Identifier: p.Identifier, PublicKey: p.PublicKey}
		c, err := FrostCommit(p, nil, nil)
		if err != nil {
			return nil, err
		}
		commits[i], comms[i] = c, c.Commitment
	}
	shares := make([]FrostSigShare, len(quorum))
	for i, p := range quorum {
		s, err := FrostSign(p.Identifier, p.Share, groupPublicKey, FrostNonces{Hiding: commits[i].HidingNonce, Binding: commits[i].BindingNonce}, message, comms,
			FrostSignOpts{Threshold: threshold, VerificationShare: p.PublicKey, VerificationShares: vss})
		if err != nil {
			return nil, err
		}
		shares[i] = *s
	}
	return FrostAggregate(message, comms, shares, groupPublicKey, vss, threshold)
}
