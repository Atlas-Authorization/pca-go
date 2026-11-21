package pca

// Trustless FROST distributed key generation (the two-round Pedersen VSS with a proof of possession): every participant contributes a
// secret polynomial, nobody holds the group secret, and the group key is the sum of the qualified participants' constant-term
// commitments. Every round-1 package and share is bound to a session id; every round-2 share is signed under the sender's constant-term
// commitment so a bad share is non-repudiable; a justified-complaint blame round and an echo-broadcast agreement round close
// equivocation. The module produces and verifies the protocol messages: the authenticated broadcast and private point-to-point links
// are the channel's (see DkgChannel). Group and scalar arithmetic run on the vetted point and scalar types.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	ed "filippo.io/edwards25519"
)

// DkgProofOfKnowledge is a Schnorr proof of knowledge of the constant term: R = k*B (base64url) and mu = k + a0*c (base64url scalar).
type DkgProofOfKnowledge struct{ R, Mu string }

// DkgRound1Package is a participant's PUBLIC round-1 broadcast: the VSS commitments and the proof of possession, bound to a session.
type DkgRound1Package struct {
	Identifier             int64
	SessionID              string
	CoefficientCommitments []string
	ProofOfKnowledge       DkgProofOfKnowledge
}

// DkgParticipantState is the RETAINED SECRET state after round 1: the polynomial. Never broadcast.
type DkgParticipantState struct {
	Identifier   int64
	T, N         int
	SessionID    []byte
	Coefficients [][]byte
	Package      DkgRound1Package
}

// DkgRound1Result is the public package and the secret state.
type DkgRound1Result struct {
	Package DkgRound1Package
	State   *DkgParticipantState
}

// DkgShareToSend is the secret share f_from(to) with the sender's non-repudiable signature (base64url R_s || s); deliver it privately.
type DkgShareToSend struct {
	From, To  int64
	SessionID string
	Share     []byte
	Sig       string
}

// DkgReceivedShare is a share received from From; an empty Sig is an unsigned share (refused by DkgVerifyShare).
type DkgReceivedShare struct {
	From      int64
	SessionID string
	Share     []byte
	Sig       string
}

// DkgSignedShare is the part of a share DkgVerifyShare needs.
type DkgSignedShare struct {
	From  int64
	Share []byte
	Sig   string
}

// DkgComplaint is a PUBLIC complaint: the accuser reveals the share it received and the accused's signature over it.
type DkgComplaint struct {
	Accused, Accuser int64
	SessionID        string
	RevealedShare    string
	ShareSig         string
}

// DkgComplaintVerdict is the adjudication of one complaint. Disqualify and AtFault are nil when absent.
type DkgComplaintVerdict struct {
	Justified  bool
	Disqualify *int64
	AtFault    *int64
	Reason     string
}

// DkgRebuttal is the accused's answer to a complaint: the share it actually signed and sent to the accuser.
type DkgRebuttal struct {
	Accused, Accuser int64
	SessionID        string
	PresentedShare   string
	ShareSig         string
}

// DkgBlameResolution names the party conclusively at fault.
type DkgBlameResolution struct {
	Guilty int64
	Reason string
}

// DkgPublicKeyPackage is the key material every finalized participant agrees on.
type DkgPublicKeyPackage struct {
	GroupPublicKey  []byte
	GroupCommitment [][]byte
	VerifyingShares []FrostVerificationShare
}

// DkgKeyPackage is the finalized per-participant key material: a drop-in for the trusted-dealer output.
type DkgKeyPackage struct {
	Identifier       int64
	SigningShare     []byte
	GroupPublicKey   []byte
	VerifyingShare   []byte
	PublicKeyPackage DkgPublicKeyPackage
}

// DkgRound1Opts fix the randomness for a deterministic run: nil Coefficients / PopNonce are drawn at random.
type DkgRound1Opts struct {
	Coefficients [][]byte
	PopNonce     []byte
}

// DkgEcho is a party's commitment over its view of the transcript.
type DkgEcho struct {
	Identifier       int64
	SessionID        string
	TranscriptDigest string
}

// DkgEchoAgreement is the outcome of the echo check; Digest is set only when Agreed.
type DkgEchoAgreement struct {
	Agreed bool
	Digest string
	Reason string
}

// DkgAgreement is the opt-in echo agreement handed to DkgFinalize. A nil Echoes skips the check.
type DkgAgreement struct {
	Echoes     []DkgEcho
	Complaints []DkgComplaint
}

var (
	dkgPopDST        = []byte("dkg-pop")
	dkgShareDST      = []byte("dkg-share")
	dkgShareNonceDST = []byte("dkg-share-nonce")
)

type dkgCommitVec struct {
	c0    *ed.Point
	bytes []byte
}

func dkgRandScalar() (*ed.Scalar, error) {
	r, err := frostNetRand()
	if err != nil {
		return nil, err
	}
	return frostReduce(r)
}

func dkgCommitVecOf(commitments []string) (dkgCommitVec, error) {
	if len(commitments) == 0 {
		return dkgCommitVec{}, errors.New("dkg: empty commitment vector")
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(commitments)))
	out := hdr
	var c0 *ed.Point
	for i, c := range commitments {
		raw, err := Unb64u(c)
		if err != nil {
			return dkgCommitVec{}, err
		}
		p, err := frostPoint(raw)
		if err != nil {
			return dkgCommitVec{}, err
		}
		if i == 0 {
			c0 = p
		}
		out = append(out, p.Bytes()...)
	}
	return dkgCommitVec{c0, out}, nil
}

func dkgCanonicalScalar(b []byte) (*ed.Scalar, error) {
	s, err := ed.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, errors.New("dkg: scalar must be 32 bytes and < the group order")
	}
	return s, nil
}

// dkgEval is f(x) = sum coeffs[j] x^j by Horner, on the scalar type.
func dkgEval(coeffs []*ed.Scalar, x *ed.Scalar) *ed.Scalar {
	acc := ed.NewScalar()
	for j := len(coeffs) - 1; j >= 0; j-- {
		acc = ed.NewScalar().MultiplyAdd(acc, x, coeffs[j])
	}
	return acc
}

// dkgVSS checks g^share == sum_k commitments[k]^(at^k).
func dkgVSS(share *ed.Scalar, commitments []string, at int64) (bool, error) {
	if len(commitments) == 0 {
		return false, nil
	}
	lhs := frostBase(share)
	rhs := ed.NewIdentityPoint()
	x := frostIntScalarSigned(at)
	xk := frostIDScalar(1)
	for _, c := range commitments {
		raw, err := Unb64u(c)
		if err != nil {
			return false, err
		}
		p, err := frostPoint(raw)
		if err != nil {
			return false, err
		}
		rhs = frostAdd(rhs, frostMul(p, xk))
		xk = ed.NewScalar().Multiply(xk, x)
	}
	return lhs.Equal(rhs) == 1, nil
}

func frostIntScalarSigned(i int64) *ed.Scalar {
	if i >= 0 {
		return frostIDScalar(i)
	}
	return ed.NewScalar().Negate(frostIDScalar(-i))
}

func dkgPopChallenge(sid []byte, id int64, cv dkgCommitVec, R *ed.Point) *ed.Scalar {
	return frostH2S(bytes.Join([][]byte{[]byte(frostContext), dkgPopDST, sid, frostIntScalarSigned(id).Bytes(), cv.bytes, R.Bytes()}, nil))
}

func dkgShareChallenge(sid []byte, from, to int64, share []byte, cv dkgCommitVec, Rs *ed.Point) *ed.Scalar {
	return frostH2S(bytes.Join([][]byte{[]byte(frostContext), dkgShareDST, sid, frostIntScalarSigned(from).Bytes(), frostIntScalarSigned(to).Bytes(), share, cv.bytes, Rs.Bytes()}, nil))
}

func dkgShareNonce(a0 *ed.Scalar, sid []byte, from, to int64, share []byte, cv dkgCommitVec) *ed.Scalar {
	return frostH2S(bytes.Join([][]byte{[]byte(frostContext), dkgShareNonceDST, a0.Bytes(), sid, frostIntScalarSigned(from).Bytes(), frostIntScalarSigned(to).Bytes(), share, cv.bytes}, nil))
}

func dkgSignShareScalar(a0 *ed.Scalar, cv dkgCommitVec, sid []byte, from, to int64, share []byte) string {
	k := dkgShareNonce(a0, sid, from, to, share, cv)
	Rs := frostBase(k)
	e := dkgShareChallenge(sid, from, to, share, cv, Rs)
	s := ed.NewScalar().MultiplyAdd(a0, e, k)
	return B64u(append(Rs.Bytes(), s.Bytes()...))
}

func dkgVerifyShareSig(sig string, sid []byte, from, to int64, share []byte, cv dkgCommitVec) bool {
	raw, err := Unb64u(sig)
	if err != nil || len(raw) != 64 {
		return false
	}
	Rs, err := frostPoint(raw[:32])
	if err != nil {
		return false
	}
	s, err := dkgCanonicalScalar(raw[32:])
	if err != nil {
		return false
	}
	e := dkgShareChallenge(sid, from, to, share, cv, Rs)
	return frostBase(s).Equal(frostAdd(Rs, frostMul(cv.c0, e))) == 1
}

func dkgVerifyShareSigAgainstPackage(sig string, sid []byte, from, to int64, share []byte, pkg DkgRound1Package) bool {
	if sig == "" || len(pkg.CoefficientCommitments) == 0 {
		return false
	}
	cv, err := dkgCommitVecOf(pkg.CoefficientCommitments)
	if err != nil {
		return false
	}
	return dkgVerifyShareSig(sig, sid, from, to, share, cv)
}

func dkgSecretCoeffs(state *DkgParticipantState) ([]*ed.Scalar, error) {
	out := make([]*ed.Scalar, len(state.Coefficients))
	for i, c := range state.Coefficients {
		s, err := frostReduce(c)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// DkgSignShare signs the share this participant sends to `to` as the sender's non-repudiable token (the signature DkgRound2 attaches).
func DkgSignShare(state *DkgParticipantState, to int64, share []byte) (string, error) {
	if share == nil {
		return "", errors.New("dkgSignShare: share must be bytes")
	}
	coeffs, err := dkgSecretCoeffs(state)
	if err != nil || len(coeffs) == 0 {
		return "", errors.New("dkgSignShare: no secret polynomial")
	}
	cv, err := dkgCommitVecOf(state.Package.CoefficientCommitments)
	if err != nil {
		return "", err
	}
	return dkgSignShareScalar(coeffs[0], cv, state.SessionID, state.Identifier, to, share), nil
}

// DkgRound1 samples a degree-(t-1) secret polynomial, commits to it and proves possession of the constant term, bound to sessionID.
func DkgRound1(identifier int64, t, n int, sessionID []byte, o DkgRound1Opts) (*DkgRound1Result, error) {
	if !frostIsID(identifier) {
		return nil, errors.New("dkgRound1: identifier must be a positive integer")
	}
	if t < 1 || n < t {
		return nil, fmt.Errorf("dkgRound1: need 1 <= t <= n (got t=%d, n=%d)", t, n)
	}
	if len(sessionID) == 0 {
		return nil, errors.New("dkgRound1: sessionId must be a non-empty byte string")
	}
	coeffs := make([]*ed.Scalar, 0, t)
	if o.Coefficients != nil {
		if len(o.Coefficients) != t {
			return nil, fmt.Errorf("dkgRound1: coefficients.length must equal t (%d)", t)
		}
		for _, c := range o.Coefficients {
			s, err := frostReduce(c)
			if err != nil {
				return nil, err
			}
			coeffs = append(coeffs, s)
		}
	} else {
		for j := 0; j < t; j++ {
			s, err := dkgRandScalar()
			if err != nil {
				return nil, err
			}
			coeffs = append(coeffs, s)
		}
	}
	coeffBytes := make([][]byte, t)
	commitments := make([]string, t)
	for j, a := range coeffs {
		coeffBytes[j] = a.Bytes()
		commitments[j] = B64u(frostBase(a).Bytes())
	}
	cv, err := dkgCommitVecOf(commitments)
	if err != nil {
		return nil, err
	}
	var k *ed.Scalar
	if o.PopNonce != nil {
		k, err = frostReduce(o.PopNonce)
	} else {
		k, err = dkgRandScalar()
	}
	if err != nil {
		return nil, err
	}
	R := frostBase(k)
	c := dkgPopChallenge(sessionID, identifier, cv, R)
	mu := ed.NewScalar().MultiplyAdd(coeffs[0], c, k)
	pkg := DkgRound1Package{Identifier: identifier, SessionID: B64u(sessionID), CoefficientCommitments: commitments,
		ProofOfKnowledge: DkgProofOfKnowledge{R: B64u(R.Bytes()), Mu: B64u(mu.Bytes())}}
	return &DkgRound1Result{Package: pkg, State: &DkgParticipantState{Identifier: identifier, T: t, N: n, SessionID: append([]byte(nil), sessionID...), Coefficients: coeffBytes, Package: pkg}}, nil
}

// DkgVerifyRound1 verifies a peer's proof of possession under the expected session and identifier. Never refuses: any deviation is false.
func DkgVerifyRound1(from int64, pkg DkgRound1Package, sessionID []byte) bool {
	if pkg.SessionID != B64u(sessionID) || len(pkg.CoefficientCommitments) == 0 {
		return false
	}
	cv, err := dkgCommitVecOf(pkg.CoefficientCommitments)
	if err != nil {
		return false
	}
	rb, err := Unb64u(pkg.ProofOfKnowledge.R)
	if err != nil {
		return false
	}
	R, err := frostPoint(rb)
	if err != nil {
		return false
	}
	mb, err := Unb64u(pkg.ProofOfKnowledge.Mu)
	if err != nil {
		return false
	}
	mu, err := dkgCanonicalScalar(mb)
	if err != nil {
		return false
	}
	c := dkgPopChallenge(sessionID, from, cv, R)
	return frostBase(mu).Equal(frostAdd(R, frostMul(cv.c0, c))) == 1
}

// DkgRound2 computes the signed secret share f_i(j) for every other participant of the packages (own package required), in package order.
func DkgRound2(state *DkgParticipantState, packages []DkgRound1Package) ([]DkgShareToSend, error) {
	seen := map[int64]bool{}
	has := false
	for _, p := range packages {
		if seen[p.Identifier] {
			return nil, errors.New("dkgRound2: duplicate identifiers in round-1 packages")
		}
		seen[p.Identifier] = true
		has = has || p.Identifier == state.Identifier
	}
	if !has {
		return nil, errors.New("dkgRound2: my own round-1 package is missing")
	}
	sid := B64u(state.SessionID)
	for _, p := range packages {
		if p.SessionID != sid {
			return nil, fmt.Errorf("dkgRound2: participant %d round-1 package is from a different session", p.Identifier)
		}
	}
	coeffs, err := dkgSecretCoeffs(state)
	if err != nil {
		return nil, err
	}
	cv, err := dkgCommitVecOf(state.Package.CoefficientCommitments)
	if err != nil {
		return nil, err
	}
	out := []DkgShareToSend{}
	for _, p := range packages {
		j := p.Identifier
		if j == state.Identifier {
			continue
		}
		share := dkgEval(coeffs, frostIntScalarSigned(j)).Bytes()
		out = append(out, DkgShareToSend{From: state.Identifier, To: j, SessionID: sid, Share: share, Sig: dkgSignShareScalar(coeffs[0], cv, state.SessionID, state.Identifier, j, share)})
	}
	return out, nil
}

// DkgVerifyShare verifies a received share: the sender's package is valid for the session, the sender's signature over exactly these
// bytes verifies under its C_0, and the Pedersen VSS check holds. Never refuses: any deviation is false.
func DkgVerifyShare(received DkgSignedShare, senderPackage DkgRound1Package, my int64, sessionID []byte) bool {
	if received.Share == nil || !DkgVerifyRound1(senderPackage.Identifier, senderPackage, sessionID) {
		return false
	}
	if !dkgVerifyShareSigAgainstPackage(received.Sig, sessionID, received.From, my, received.Share, senderPackage) {
		return false
	}
	s, err := dkgCanonicalScalar(received.Share)
	if err != nil {
		return false
	}
	ok, err := dkgVSS(s, senderPackage.CoefficientCommitments, my)
	return err == nil && ok
}

// DkgFileComplaintParams are the inputs of DkgFileComplaint; SenderCommitments is accepted for symmetry only.
type DkgFileComplaintParams struct {
	Accused, Accuser  int64
	ReceivedShare     []byte
	ShareSig          string
	SenderCommitments []string
	SessionID         []byte
}

// DkgFileComplaint builds a complaint revealing the share received and the accused's signature over it.
func DkgFileComplaint(p DkgFileComplaintParams) (DkgComplaint, error) {
	if !frostIsID(p.Accused) {
		return DkgComplaint{}, errors.New("dkgFileComplaint: accused must be a positive integer")
	}
	if !frostIsID(p.Accuser) {
		return DkgComplaint{}, errors.New("dkgFileComplaint: accuser must be a positive integer")
	}
	if p.Accused == p.Accuser {
		return DkgComplaint{}, errors.New("dkgFileComplaint: cannot file a complaint against yourself")
	}
	if p.ShareSig == "" {
		return DkgComplaint{}, errors.New("dkgFileComplaint: shareSig (the accused-signed share) is required")
	}
	if len(p.SessionID) == 0 {
		return DkgComplaint{}, errors.New("dkgFileComplaint: sessionId must be a non-empty byte string")
	}
	s, err := frostReduce(p.ReceivedShare)
	if err != nil {
		return DkgComplaint{}, err
	}
	return DkgComplaint{Accused: p.Accused, Accuser: p.Accuser, SessionID: B64u(p.SessionID), RevealedShare: B64u(s.Bytes()), ShareSig: p.ShareSig}, nil
}

func dkgFindPackage(pkgs []DkgRound1Package, id int64) (DkgRound1Package, bool) {
	for _, p := range pkgs {
		if p.Identifier == id {
			return p, true
		}
	}
	return DkgRound1Package{}, false
}

// DkgVerifyComplaint adjudicates a complaint independently from the accused's broadcast package: only a share the accused signed can
// convict. Never refuses: a malformed complaint is reported as not justified.
func DkgVerifyComplaint(c DkgComplaint, pkgs []DkgRound1Package) DkgComplaintVerdict {
	pkg, ok := dkgFindPackage(pkgs, c.Accused)
	if !ok {
		return DkgComplaintVerdict{Reason: fmt.Sprintf("accused %d has no round-1 package to adjudicate against", c.Accused)}
	}
	if pkg.SessionID != c.SessionID {
		return DkgComplaintVerdict{Reason: "complaint sessionId does not match the accused round-1 package session"}
	}
	sid, err := Unb64u(c.SessionID)
	if err != nil {
		return DkgComplaintVerdict{Reason: "malformed complaint"}
	}
	share, err := Unb64u(c.RevealedShare)
	if err != nil {
		return DkgComplaintVerdict{Reason: "malformed complaint"}
	}
	if !dkgVerifyShareSigAgainstPackage(c.ShareSig, sid, c.Accused, c.Accuser, share, pkg) {
		at := c.Accuser
		return DkgComplaintVerdict{AtFault: &at, Reason: "revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)"}
	}
	sc, err := dkgCanonicalScalar(share)
	if err != nil {
		return DkgComplaintVerdict{Reason: "malformed complaint"}
	}
	valid, err := dkgVSS(sc, pkg.CoefficientCommitments, c.Accuser)
	if err != nil {
		return DkgComplaintVerdict{Reason: "malformed complaint"}
	}
	if valid {
		at := c.Accuser
		return DkgComplaintVerdict{AtFault: &at, Reason: "accused-signed share is VALID against the accused commitments — false accusation"}
	}
	dq := c.Accused
	return DkgComplaintVerdict{Justified: true, Disqualify: &dq, Reason: "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments"}
}

// DkgRebut re-presents the share the accused actually signed and sent to the complaint's recipient.
func DkgRebut(accused int64, c DkgComplaint, state *DkgParticipantState) (DkgRebuttal, error) {
	if state.Identifier != accused {
		return DkgRebuttal{}, errors.New("dkgRebut: myRound2State is not the accused")
	}
	if c.Accused != accused {
		return DkgRebuttal{}, errors.New("dkgRebut: complaint does not name this accused")
	}
	if B64u(state.SessionID) != c.SessionID {
		return DkgRebuttal{}, errors.New("dkgRebut: complaint is scoped to a different session than my state")
	}
	coeffs, err := dkgSecretCoeffs(state)
	if err != nil {
		return DkgRebuttal{}, err
	}
	share := dkgEval(coeffs, frostIntScalarSigned(c.Accuser)).Bytes()
	sig, err := DkgSignShare(state, c.Accuser, share)
	if err != nil {
		return DkgRebuttal{}, err
	}
	return DkgRebuttal{Accused: accused, Accuser: c.Accuser, SessionID: c.SessionID, PresentedShare: B64u(share), ShareSig: sig}, nil
}

// DkgResolveBlame adjudicates a complaint, optionally with the accused's rebuttal, to a single guilty party from signatures and VSS
// alone. Never refuses: a malformed complaint is the accuser's fault.
func DkgResolveBlame(c DkgComplaint, reb *DkgRebuttal, pkgs []DkgRound1Package) DkgBlameResolution {
	malformed := DkgBlameResolution{c.Accuser, "malformed complaint — inadmissible"}
	pkg, ok := dkgFindPackage(pkgs, c.Accused)
	if !ok {
		return DkgBlameResolution{c.Accused, fmt.Sprintf("accused %d has no round-1 package to defend with", c.Accused)}
	}
	if pkg.SessionID != c.SessionID {
		return DkgBlameResolution{c.Accuser, "complaint names a session the accused did not run — inadmissible"}
	}
	sid, err := Unb64u(c.SessionID)
	if err != nil {
		return malformed
	}
	share, err := Unb64u(c.RevealedShare)
	if err != nil {
		return malformed
	}
	if dkgVerifyShareSigAgainstPackage(c.ShareSig, sid, c.Accused, c.Accuser, share, pkg) {
		sc, err := dkgCanonicalScalar(share)
		if err != nil {
			return malformed
		}
		valid, err := dkgVSS(sc, pkg.CoefficientCommitments, c.Accuser)
		if err != nil {
			return malformed
		}
		if !valid {
			return DkgBlameResolution{c.Accused, "accused non-repudiably signed a share that fails VSS"}
		}
		return DkgBlameResolution{c.Accuser, "accused-signed share is valid against its commitments — false accusation"}
	}
	if reb != nil && reb.Accused == c.Accused && reb.Accuser == c.Accuser && reb.SessionID == c.SessionID {
		rs, err := Unb64u(reb.PresentedShare)
		if err != nil {
			return malformed
		}
		good := dkgVerifyShareSigAgainstPackage(reb.ShareSig, sid, c.Accused, c.Accuser, rs, pkg)
		if good {
			sc, err := dkgCanonicalScalar(rs)
			if err != nil {
				return malformed
			}
			v, err := dkgVSS(sc, pkg.CoefficientCommitments, c.Accuser)
			if err != nil {
				return malformed
			}
			good = v
		}
		if good {
			return DkgBlameResolution{c.Accuser, "accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted"}
		}
		return DkgBlameResolution{c.Accused, "accused could not present a validly-signed, VSS-correct share on rebuttal"}
	}
	return DkgBlameResolution{c.Accuser, "complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused"}
}

// DkgQualifiedSet is the participants with a round-1 package whose proof verifies under the run's session (the plurality session of the
// packages; the first seen wins a tie) and who are not convicted by a resolved complaint. A guilty accuser removes nobody. Ascending.
func DkgQualifiedSet(participants []int64, complaints []DkgComplaint, pkgs []DkgRound1Package, rebuttals []DkgRebuttal) []int64 {
	byID := map[int64]DkgRound1Package{}
	for _, p := range pkgs {
		byID[p.Identifier] = p
	}
	var order []string
	counts := map[string]int{}
	for _, p := range pkgs {
		if _, seen := counts[p.SessionID]; !seen {
			order = append(order, p.SessionID)
		}
		counts[p.SessionID]++
	}
	runSession, best := "", -1
	for _, s := range order {
		if counts[s] > best {
			best, runSession = counts[s], s
		}
	}
	q := map[int64]bool{}
	for _, p := range participants {
		pkg, ok := byID[p]
		if !ok || pkg.SessionID != runSession {
			continue
		}
		sid, err := Unb64u(pkg.SessionID)
		if err != nil {
			continue
		}
		if DkgVerifyRound1(p, pkg, sid) {
			q[p] = true
		}
	}
	for _, c := range complaints {
		var reb *DkgRebuttal
		for i := range rebuttals {
			if r := rebuttals[i]; r.Accused == c.Accused && r.Accuser == c.Accuser && r.SessionID == c.SessionID {
				reb = &rebuttals[i]
				break
			}
		}
		if res := DkgResolveBlame(c, reb, pkgs); res.Guilty == c.Accused {
			delete(q, res.Guilty)
		}
	}
	out := []int64{}
	for id := range q {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func dkgPackageDigest(p DkgRound1Package) (string, error) {
	cc := make([]any, len(p.CoefficientCommitments))
	for i, c := range p.CoefficientCommitments {
		cc[i] = c
	}
	return HashCanonical(map[string]any{"identifier": int(p.Identifier), "sessionId": p.SessionID, "coefficientCommitments": cc,
		"proofOfKnowledge": map[string]any{"R": p.ProofOfKnowledge.R, "mu": p.ProofOfKnowledge.Mu}})
}

func dkgComplaintDigest(c DkgComplaint) (string, error) {
	return HashCanonical(map[string]any{"accused": int(c.Accused), "accuser": int(c.Accuser), "sessionId": c.SessionID, "revealedShare": c.RevealedShare, "shareSig": c.ShareSig})
}

// DkgTranscriptDigest is the canonical, order-independent digest of a transcript view: the sorted package digests, the sorted complaint
// digests, the sorted qualified set and the session id.
func DkgTranscriptDigest(pkgs []DkgRound1Package, complaints []DkgComplaint, qualified []int64, sessionID []byte) (string, error) {
	r1 := []string{}
	for _, p := range pkgs {
		d, err := dkgPackageDigest(p)
		if err != nil {
			return "", err
		}
		r1 = append(r1, d)
	}
	cs := []string{}
	for _, c := range complaints {
		d, err := dkgComplaintDigest(c)
		if err != nil {
			return "", err
		}
		cs = append(cs, d)
	}
	sort.Strings(r1)
	sort.Strings(cs)
	q := append([]int64{}, qualified...)
	sort.Slice(q, func(i, j int) bool { return q[i] < q[j] })
	r1a, csa, qa := make([]any, len(r1)), make([]any, len(cs)), make([]any, len(q))
	for i, x := range r1 {
		r1a[i] = x
	}
	for i, x := range cs {
		csa[i] = x
	}
	for i, x := range q {
		qa[i] = int(x)
	}
	return HashCanonical(map[string]any{"sessionId": B64u(sessionID), "round1": r1a, "complaints": csa, "qualified": qa})
}

// DkgMakeEcho builds this party's echo over its transcript view.
func DkgMakeEcho(identifier int64, pkgs []DkgRound1Package, complaints []DkgComplaint, qualified []int64, sessionID []byte) (DkgEcho, error) {
	d, err := DkgTranscriptDigest(pkgs, complaints, qualified, sessionID)
	if err != nil {
		return DkgEcho{}, err
	}
	return DkgEcho{Identifier: identifier, SessionID: B64u(sessionID), TranscriptDigest: d}, nil
}

// DkgCheckEchoes requires every qualified party to have contributed exactly one echo for this session, all with the same digest.
func DkgCheckEchoes(qualified []int64, echoes []DkgEcho, sessionID []byte) DkgEchoAgreement {
	sid := B64u(sessionID)
	var qorder []int64
	qSet := map[int64]bool{}
	for _, q := range qualified {
		if !qSet[q] {
			qSet[q] = true
			qorder = append(qorder, q)
		}
	}
	byID := map[int64]DkgEcho{}
	for _, e := range echoes {
		if !qSet[e.Identifier] {
			continue
		}
		if e.SessionID != sid {
			return DkgEchoAgreement{Reason: fmt.Sprintf("echo from %d is bound to a different session", e.Identifier)}
		}
		if _, dup := byID[e.Identifier]; dup {
			return DkgEchoAgreement{Reason: fmt.Sprintf("duplicate echo from qualified participant %d", e.Identifier)}
		}
		byID[e.Identifier] = e
	}
	digest, have := "", false
	for _, j := range qorder {
		e, ok := byID[j]
		if !ok {
			return DkgEchoAgreement{Reason: fmt.Sprintf("missing echo from qualified participant %d", j)}
		}
		if !have {
			digest, have = e.TranscriptDigest, true
		} else if e.TranscriptDigest != digest {
			return DkgEchoAgreement{Reason: fmt.Sprintf("qualified participant %d echoed a DIFFERENT transcript (equivocation detected)", j)}
		}
	}
	if !have {
		return DkgEchoAgreement{Reason: "no qualified echoes to agree on"}
	}
	return DkgEchoAgreement{Agreed: true, Digest: digest}
}

// DkgFinalize combines this participant's own polynomial with the shares of the qualified peers: signing share s_i, group key Y, the
// group VSS commitments and every qualified participant's verifying share. qualified nil is all participants; agreement (optional)
// runs the echo agreement round before any key is derived. Everything must name the session of myState.
func DkgFinalize(my int64, state *DkgParticipantState, received []DkgReceivedShare, all []DkgRound1Package, qualified []int64, agreement *DkgAgreement) (*DkgKeyPackage, error) {
	if state.Identifier != my {
		return nil, errors.New("dkgFinalize: myState.identifier != myIdentifier")
	}
	ids := make([]int64, len(all))
	idSet := map[int64]bool{}
	for i, p := range all {
		ids[i] = p.Identifier
		if idSet[p.Identifier] {
			return nil, errors.New("dkgFinalize: duplicate identifiers in commitments")
		}
		idSet[p.Identifier] = true
	}
	if !idSet[my] {
		return nil, errors.New("dkgFinalize: my own package is missing from allCommitments")
	}
	sid := B64u(state.SessionID)
	for _, p := range all {
		if p.SessionID != sid {
			return nil, fmt.Errorf("dkgFinalize: participant %d round-1 package is from a different session", p.Identifier)
		}
	}
	src := ids
	if qualified != nil {
		src = qualified
	}
	qset := []int64{}
	qSet := map[int64]bool{}
	for _, id := range src {
		if idSet[id] {
			qset = append(qset, id)
			qSet[id] = true
		}
	}
	if !qSet[my] {
		return nil, errors.New("dkgFinalize: myIdentifier is not in the qualified set")
	}
	if len(qSet) < state.T {
		return nil, fmt.Errorf("dkgFinalize: qualified set (%d) is smaller than the threshold t=%d", len(qSet), state.T)
	}
	t := state.T
	for _, p := range all {
		if qSet[p.Identifier] && len(p.CoefficientCommitments) != t {
			return nil, fmt.Errorf("dkgFinalize: participant %d committed to %d coefficients, expected t=%d", p.Identifier, len(p.CoefficientCommitments), t)
		}
	}
	if agreement != nil && agreement.Echoes != nil {
		qs := make([]int64, 0, len(qSet))
		for id := range qSet {
			qs = append(qs, id)
		}
		sort.Slice(qs, func(i, j int) bool { return qs[i] < qs[j] })
		check := DkgCheckEchoes(qs, agreement.Echoes, state.SessionID)
		if !check.Agreed {
			return nil, fmt.Errorf("dkgFinalize: echo-broadcast agreement failed — %s", check.Reason)
		}
		mine, err := DkgTranscriptDigest(all, agreement.Complaints, qs, state.SessionID)
		if err != nil {
			return nil, err
		}
		if check.Digest != mine {
			return nil, errors.New("dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)")
		}
	}
	recv := map[int64][]byte{}
	for _, r := range received {
		if r.From == my || !qSet[r.From] {
			continue
		}
		if r.SessionID != sid {
			return nil, fmt.Errorf("dkgFinalize: received share from %d is from a different session", r.From)
		}
		if _, dup := recv[r.From]; dup {
			return nil, fmt.Errorf("dkgFinalize: duplicate received share from %d", r.From)
		}
		recv[r.From] = r.Share
	}
	for _, j := range qset {
		if j != my {
			if _, ok := recv[j]; !ok {
				return nil, fmt.Errorf("dkgFinalize: missing received share from qualified participant %d", j)
			}
		}
	}
	coeffs, err := dkgSecretCoeffs(state)
	if err != nil {
		return nil, err
	}
	sShare := dkgEval(coeffs, frostIntScalarSigned(my))
	for _, share := range recv {
		if len(share) < 1 || len(share) > 64 {
			return nil, errors.New("ct-scalar: reduce takes 1..64 bytes")
		}
		r, err := frostReduce(share)
		if err != nil {
			return nil, err
		}
		sShare = ed.NewScalar().Add(sShare, r)
	}
	signingShare := sShare.Bytes()
	phi := make([]*ed.Point, t)
	for k := 0; k < t; k++ {
		acc := ed.NewIdentityPoint()
		for _, p := range all {
			if !qSet[p.Identifier] {
				continue
			}
			raw, err := Unb64u(p.CoefficientCommitments[k])
			if err != nil {
				return nil, err
			}
			pt, err := frostPoint(raw)
			if err != nil {
				return nil, err
			}
			acc = frostAdd(acc, pt)
		}
		phi[k] = acc
	}
	groupPK := phi[0].Bytes()
	groupCommitment := make([][]byte, t)
	for k, p := range phi {
		groupCommitment[k] = p.Bytes()
	}
	vshares := make([]FrostVerificationShare, len(qset))
	for i, j := range qset {
		acc := ed.NewIdentityPoint()
		x := frostIntScalarSigned(j)
		xk := frostIDScalar(1)
		for _, p := range phi {
			acc = frostAdd(acc, frostMul(p, xk))
			xk = ed.NewScalar().Multiply(xk, x)
		}
		vshares[i] = FrostVerificationShare{Identifier: j, PublicKey: acc.Bytes()}
	}
	verifying := frostBase(sShare)
	var mine *FrostVerificationShare
	for i := range vshares {
		if vshares[i].Identifier == my {
			mine = &vshares[i]
			break
		}
	}
	if mine == nil {
		return nil, errors.New("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)")
	}
	mp, err := frostPoint(mine.PublicKey)
	if err != nil || verifying.Equal(mp) != 1 {
		return nil, errors.New("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)")
	}
	return &DkgKeyPackage{Identifier: my, SigningShare: signingShare, GroupPublicKey: groupPK, VerifyingShare: verifying.Bytes(),
		PublicKeyPackage: DkgPublicKeyPackage{GroupPublicKey: groupPK, GroupCommitment: groupCommitment, VerifyingShares: vshares}}, nil
}

// DkgSimulateOpts shape an in-process ceremony. A nil field is absent; EquivocateEchoFor 0 is none.
type DkgSimulateOpts struct {
	Identifiers               []int64
	CoefficientsByParticipant [][][]byte
	SessionID                 []byte
	Cheaters                  []int64
	EquivocateEchoFor         int64
}

// DkgSimulation is the result of a whole in-process ceremony.
type DkgSimulation struct {
	GroupPublicKey    []byte
	ParticipantShares []FrostParticipantShare
	GroupCommitment   [][]byte
	KeyPackages       []DkgKeyPackage
	Round1Packages    []DkgRound1Package
	Qualified         []int64
	Complaints        []DkgComplaint
	Rebuttals         []DkgRebuttal
	Echoes            []DkgEcho
	SessionID         []byte
}

// FrostDkgSimulate runs the whole DKG across n participants in process and returns the shared group key and per-participant shares in
// the shape of the trusted-dealer output: a drop-in for it with no dealer. A cheater sends corrupted (but signed) shares and is
// convicted; the run finalizes over the honest qualified set.
func FrostDkgSimulate(t, n int, o DkgSimulateOpts) (*DkgSimulation, error) {
	if t < 1 || n < t {
		return nil, fmt.Errorf("frostDkgSimulate: need 1 <= t <= n (got t=%d, n=%d)", t, n)
	}
	ids := o.Identifiers
	if ids == nil {
		ids = make([]int64, n)
		for i := range ids {
			ids[i] = int64(i + 1)
		}
	}
	if len(ids) != n {
		return nil, errors.New("frostDkgSimulate: identifiers.length must equal n")
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if len(seen) != n {
		return nil, errors.New("frostDkgSimulate: identifiers must be distinct")
	}
	for _, id := range ids {
		if !frostIsID(id) {
			return nil, errors.New("frostDkgSimulate: identifiers must be positive integers")
		}
	}
	sid := o.SessionID
	if sid == nil {
		r, err := frostNetRand()
		if err != nil {
			return nil, err
		}
		sid = r
	}
	cheaters := map[int64]bool{}
	for _, c := range o.Cheaters {
		cheaters[c] = true
	}
	states := make([]*DkgParticipantState, n)
	pkgs := make([]DkgRound1Package, n)
	for i, id := range ids {
		var opts DkgRound1Opts
		if i < len(o.CoefficientsByParticipant) {
			opts.Coefficients = o.CoefficientsByParticipant[i]
		}
		r, err := DkgRound1(id, t, n, sid, opts)
		if err != nil {
			return nil, err
		}
		states[i], pkgs[i] = r.State, r.Package
	}
	for _, p := range pkgs {
		if !DkgVerifyRound1(p.Identifier, p, sid) {
			return nil, fmt.Errorf("frostDkgSimulate: PoP verification failed for participant %d", p.Identifier)
		}
	}
	inbox := map[int64][]DkgReceivedShare{}
	for _, id := range ids {
		inbox[id] = []DkgReceivedShare{}
	}
	complaints := []DkgComplaint{}
	stateByID := map[int64]*DkgParticipantState{}
	for _, st := range states {
		stateByID[st.Identifier] = st
	}
	for _, st := range states {
		outs, err := DkgRound2(st, pkgs)
		if err != nil {
			return nil, err
		}
		for _, o2 := range outs {
			share, sig := o2.Share, o2.Sig
			if cheaters[o2.From] {
				bad := append([]byte(nil), o2.Share...)
				bad[0] ^= 1
				share = bad
				s, err := DkgSignShare(st, o2.To, bad)
				if err != nil {
					return nil, err
				}
				sig = s
			}
			senderPkg, _ := dkgFindPackage(pkgs, o2.From)
			if DkgVerifyShare(DkgSignedShare{From: o2.From, Share: share, Sig: sig}, senderPkg, o2.To, sid) {
				inbox[o2.To] = append(inbox[o2.To], DkgReceivedShare{From: o2.From, SessionID: o2.SessionID, Share: share, Sig: sig})
			} else {
				c, err := DkgFileComplaint(DkgFileComplaintParams{Accused: o2.From, Accuser: o2.To, ReceivedShare: share, ShareSig: sig, SenderCommitments: senderPkg.CoefficientCommitments, SessionID: sid})
				if err != nil {
					return nil, err
				}
				complaints = append(complaints, c)
			}
		}
	}
	rebuttals := make([]DkgRebuttal, len(complaints))
	for i, c := range complaints {
		r, err := DkgRebut(c.Accused, c, stateByID[c.Accused])
		if err != nil {
			return nil, err
		}
		rebuttals[i] = r
	}
	qualified := DkgQualifiedSet(ids, complaints, pkgs, rebuttals)
	if len(qualified) < t {
		return nil, fmt.Errorf("frostDkgSimulate: only %d qualified participants (< t=%d) after the blame round", len(qualified), t)
	}
	echoes := make([]DkgEcho, len(qualified))
	for i, id := range qualified {
		view := qualified
		if id == o.EquivocateEchoFor {
			view = nil
			for _, q := range qualified {
				if q != qualified[len(qualified)-1] {
					view = append(view, q)
				}
			}
		}
		e, err := DkgMakeEcho(id, pkgs, complaints, view, sid)
		if err != nil {
			return nil, err
		}
		echoes[i] = e
	}
	inQ := map[int64]bool{}
	for _, q := range qualified {
		inQ[q] = true
	}
	var keyPackages []DkgKeyPackage
	for _, st := range states {
		if !inQ[st.Identifier] {
			continue
		}
		kp, err := DkgFinalize(st.Identifier, st, inbox[st.Identifier], pkgs, qualified, &DkgAgreement{Echoes: echoes, Complaints: complaints})
		if err != nil {
			return nil, err
		}
		keyPackages = append(keyPackages, *kp)
	}
	gpk := keyPackages[0].GroupPublicKey
	shares := make([]FrostParticipantShare, len(keyPackages))
	for i, kp := range keyPackages {
		if !bytes.Equal(kp.GroupPublicKey, gpk) {
			return nil, errors.New("frostDkgSimulate: participants disagree on the group public key")
		}
		shares[i] = FrostParticipantShare{Identifier: kp.Identifier, Share: kp.SigningShare, PublicKey: kp.VerifyingShare}
	}
	return &DkgSimulation{GroupPublicKey: gpk, ParticipantShares: shares, GroupCommitment: keyPackages[0].PublicKeyPackage.GroupCommitment, KeyPackages: keyPackages,
		Round1Packages: pkgs, Qualified: qualified, Complaints: complaints, Rebuttals: rebuttals, Echoes: echoes, SessionID: sid}, nil
}
