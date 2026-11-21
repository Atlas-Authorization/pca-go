package pca

// Post-quantum base OT from ML-KEM-768 (FIPS 203), and the hybrid base OT that folds the elliptic-curve and ML-KEM secrets into
// every transfer key. The receiver publishes a public-key pair with a known secret key for only its chosen slot, the sender
// encapsulates to both and pads each message with the shared secret. ML-KEM is the standard library's crypto/mlkem: key generation
// from a 64-byte seed (d || z) and derandomised encapsulation from a 32-byte message (crypto/mlkem/mlkemtest), so the transcripts
// are reproducible from a seeded stream. Variants: the semi-honest transfer, the commit-then-open malicious-secure transfer with a
// session id, and the random-OT form with fixed-width secrets used by the hybrid.

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/subtle"
	"errors"
	"fmt"

	ed "filippo.io/edwards25519"
)

const (
	mpcKemMsgBytes   = 32
	mpcKemSeedBytes  = 64
	mpcKemNonceBytes = 32
	// MpcKemOtSecretBytes is the width of the random-OT secrets of the malicious KEM OT.
	MpcKemOtSecretBytes = 32
)

var (
	mpcTagKemPad       = []byte("atlas-pca-mpc/kem-ot-pad")
	mpcTagKemCommit    = []byte("atlas-pca-mpc/kem-ot-commit")
	mpcTagKemSid       = []byte("atlas-pca-mpc/kem-ot-sid")
	mpcTagKemMalPad    = []byte("atlas-pca-mpc/kem-ot-mal-pad")
	mpcTagKemMalSecret = []byte("atlas-pca-mpc/kem-ot-mal-secret")
)

// MpcKemBaseOtAbort: the opened keys do not match the receiver's commitment.
type MpcKemBaseOtAbort struct{ Msg string }

func (e *MpcKemBaseOtAbort) Error() string { return e.Msg }

func mpcKemKeygen(rng MpcOtRandom) (pub []byte, sk *mlkem.DecapsulationKey768, err error) {
	sk, err = mlkem.NewDecapsulationKey768(rng.Bytes(mpcKemSeedBytes))
	if err != nil {
		return nil, nil, err
	}
	return sk.EncapsulationKey().Bytes(), sk, nil
}

// mpcKemEncaps encapsulates to pub with the 32-byte message drawn from rng, returning (ciphertext, shared secret).
func mpcKemEncaps(pub []byte, rng MpcOtRandom) (ct, ss []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(pub)
	if err != nil {
		return nil, nil, err
	}
	ss, ct, err = mlkemtest.Encapsulate768(ek, rng.Bytes(mpcKemMsgBytes))
	return ct, ss, err
}

func mpcKemEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func mpcKemXor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("kem-ot: XOR length mismatch")
	}
	return mpcOtXor(a, b), nil
}

// mpcKemExpand is SHA-256 in counter mode over tag, prefix, index, slot, counter and the shared secret.
func mpcKemExpand(tag []byte, prefix [][]byte, index int, slot int, secret []byte, n int) []byte {
	out := make([]byte, 0, n)
	for ctr := uint64(0); len(out) < n; ctr++ {
		parts := append([][]byte{tag}, prefix...)
		parts = append(parts, mpcOtU32(uint64(index)), []byte{byte(slot & 1)}, mpcOtU32(ctr), secret)
		out = append(out, mpcOtSha256(parts...)...)
	}
	return out[:n]
}

// MpcKemOtPad is a pad of n bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode.
func MpcKemOtPad(index, slot int, sharedSecret []byte, n int) ([]byte, error) {
	if n < 0 || n > 1<<20 {
		return nil, errors.New("kemOtPad: length must be an integer in [0, 1 MiB]")
	}
	return mpcKemExpand(mpcTagKemPad, nil, index, slot, sharedSecret, n), nil
}

// MpcKemBaseOtTranscript is the semi-honest transcript; every field is [i][slot].
type MpcKemBaseOtTranscript struct{ PublicKeys, Ciphertexts, Encrypted []MpcOtPair }

type MpcKemBaseOtResult struct {
	Received   [][]byte
	Transcript *MpcKemBaseOtTranscript
}

type mpcKemReceiverState struct {
	choices []int
	keys    []*mlkem.DecapsulationKey768
}

func mpcKemReceive(choices []int, rng MpcOtRandom) ([]MpcOtPair, *mpcKemReceiverState, error) {
	pks := make([]MpcOtPair, len(choices))
	st := &mpcKemReceiverState{make([]int, len(choices)), make([]*mlkem.DecapsulationKey768, len(choices))}
	for i, ch := range choices {
		c := ch & 1
		chosenPk, chosenSk, err := mpcKemKeygen(rng)
		if err != nil {
			return nil, nil, err
		}
		otherPk, _, err := mpcKemKeygen(rng)
		if err != nil {
			return nil, nil, err
		}
		if c == 0 {
			pks[i] = MpcOtPair{chosenPk, otherPk}
		} else {
			pks[i] = MpcOtPair{otherPk, chosenPk}
		}
		st.choices[i], st.keys[i] = c, chosenSk
	}
	return pks, st, nil
}

// MpcKemBaseOT is the semi-honest KEM base OT (both roles in process). A nil rng is the CSPRNG.
func MpcKemBaseOT(messages []MpcOtPair, choices []int, rng MpcOtRandom) (*MpcKemBaseOtResult, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	if len(messages) != len(choices) {
		return nil, errors.New("kemBaseOT: messages/choices length mismatch")
	}
	pks, st, err := mpcKemReceive(choices, rng)
	if err != nil {
		return nil, err
	}
	cts := make([]MpcOtPair, len(messages))
	enc := make([]MpcOtPair, len(messages))
	for i, m := range messages {
		if len(m[0]) != len(m[1]) {
			return nil, fmt.Errorf("kemBaseOtSend (index %d): the two messages must be equal length", i)
		}
		for s := 0; s < 2; s++ {
			ct, ss, err := mpcKemEncaps(pks[i][s], rng)
			if err != nil {
				return nil, err
			}
			pad, _ := MpcKemOtPad(i, s, ss, len(m[s]))
			cts[i][s] = ct
			enc[i][s], _ = mpcKemXor(m[s], pad)
		}
	}
	received := make([][]byte, len(choices))
	for i := range choices {
		c := st.choices[i]
		ss, err := st.keys[i].Decapsulate(cts[i][c])
		if err != nil {
			return nil, err
		}
		pad, _ := MpcKemOtPad(i, c, ss, len(enc[i][c]))
		received[i], _ = mpcKemXor(enc[i][c], pad)
	}
	return &MpcKemBaseOtResult{received, &MpcKemBaseOtTranscript{pks, cts, enc}}, nil
}

// MpcWithKemBaseOt is the semi-honest KEM OT as a pluggable base OT for MpcOtChannel.
func MpcWithKemBaseOt() MpcBaseOtFn {
	return func(m []MpcOtPair, c []int, r MpcOtRandom) ([][]byte, error) {
		res, err := MpcKemBaseOT(m, c, r)
		if err != nil {
			return nil, err
		}
		return res.Received, nil
	}
}

// ---- malicious-secure (commit-then-open, session id)

func mpcKemMalCommit(rn []byte, index int, pk0, pk1 []byte) []byte {
	return mpcOtSha256(mpcTagKemCommit, rn, mpcOtU32(uint64(index)), pk0, pk1)
}

func mpcKemMalSid(rn, sn []byte) []byte { return mpcOtSha256(mpcTagKemSid, rn, sn) }

func mpcKemMalPad(sid, com []byte, index, slot int, ss []byte, n int) []byte {
	return mpcKemExpand(mpcTagKemMalPad, [][]byte{sid, com}, index, slot, ss, n)
}

func mpcKemMalSecret(sid, com []byte, index, slot int, ss []byte) []byte {
	return mpcOtSha256(mpcTagKemMalSecret, sid, com, mpcOtU32(uint64(index)), []byte{byte(slot & 1)}, ss)[:MpcKemOtSecretBytes]
}

// MpcKemMalTamper holds TEST-ONLY injection points for a malicious sender or receiver (nil = honest).
type MpcKemMalTamper struct {
	TamperOpenedKeys  func([]MpcOtPair)
	TamperReceiverSid func([]byte) []byte
}

// MpcKemMalTranscript is the transcript of the malicious KEM OT; Encrypted is nil in the random-OT form.
type MpcKemMalTranscript struct {
	Rn          []byte
	Commitments [][]byte
	Sn          []byte
	PublicKeys  []MpcOtPair
	Ciphertexts []MpcOtPair
	Encrypted   []MpcOtPair
}

type MpcKemBaseOtMalResult struct {
	Received   [][]byte
	Transcript *MpcKemMalTranscript
}

// mpcKemMalSession is the receiver's committed state and the sender's view of one commit-then-open run.
type mpcKemMalSession struct {
	rn          []byte
	commitments [][]byte
	pks         []MpcOtPair
	st          *mpcKemReceiverState
	sn          []byte
	sid         []byte
	opened      []MpcOtPair
}

func mpcKemMalStart(choices []int, rng MpcOtRandom, tamper *MpcKemMalTamper) (*mpcKemMalSession, error) {
	rn := rng.Bytes(mpcKemNonceBytes)
	pks, st, err := mpcKemReceive(choices, rng)
	if err != nil {
		return nil, err
	}
	com := make([][]byte, len(choices))
	for i := range choices {
		com[i] = mpcKemMalCommit(rn, i, pks[i][0], pks[i][1])
	}
	sn := rng.Bytes(mpcKemNonceBytes)
	opened := make([]MpcOtPair, len(pks))
	copy(opened, pks)
	if tamper != nil && tamper.TamperOpenedKeys != nil {
		tamper.TamperOpenedKeys(opened)
	}
	return &mpcKemMalSession{rn, com, pks, st, sn, mpcKemMalSid(rn, sn), opened}, nil
}

// encaps checks the opened keys against the commitments and encapsulates to both slots of each index.
func (s *mpcKemMalSession) encaps(rng MpcOtRandom) (cts []MpcOtPair, coms [][]byte, sss []MpcOtPair, err error) {
	cts = make([]MpcOtPair, len(s.opened))
	coms = make([][]byte, len(s.opened))
	sss = make([]MpcOtPair, len(s.opened))
	for i, pk := range s.opened {
		com := mpcKemMalCommit(s.rn, i, pk[0], pk[1])
		if !mpcKemEqual(com, s.commitments[i]) {
			return nil, nil, nil, &MpcKemBaseOtAbort{fmt.Sprintf("kem base OT (index %d): opened public keys do not match the receiver's commitment; aborting", i)}
		}
		coms[i] = com
		for sl := 0; sl < 2; sl++ {
			if cts[i][sl], sss[i][sl], err = mpcKemEncaps(pk[sl], rng); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	return cts, coms, sss, nil
}

// MpcKemBaseOtMal is the commit-then-open malicious-secure KEM base OT (both roles in process). A nil rng is the CSPRNG.
func MpcKemBaseOtMal(messages []MpcOtPair, choices []int, rng MpcOtRandom, tamper *MpcKemMalTamper) (*MpcKemBaseOtMalResult, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	if len(messages) != len(choices) {
		return nil, errors.New("kemBaseOtMal: messages/choices length mismatch")
	}
	s, err := mpcKemMalStart(choices, rng, tamper)
	if err != nil {
		return nil, err
	}
	n := len(messages)
	if n != len(s.opened) || len(s.commitments) != n {
		return nil, errors.New("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch")
	}
	for i, m := range messages {
		if len(m[0]) != len(m[1]) {
			return nil, fmt.Errorf("kemBaseOtMalSend (index %d): the two messages must be equal length", i)
		}
	}
	cts, coms, sss, err := s.encaps(rng)
	if err != nil {
		return nil, err
	}
	enc := make([]MpcOtPair, n)
	for i, m := range messages {
		for sl := 0; sl < 2; sl++ {
			enc[i][sl], _ = mpcKemXor(m[sl], mpcKemMalPad(s.sid, coms[i], i, sl, sss[i][sl], len(m[sl])))
		}
	}
	sid := s.sid
	if tamper != nil && tamper.TamperReceiverSid != nil {
		sid = tamper.TamperReceiverSid(append([]byte(nil), sid...))
	}
	received := make([][]byte, n)
	for i := range received {
		c := s.st.choices[i]
		ss, err := s.st.keys[i].Decapsulate(cts[i][c])
		if err != nil {
			return nil, err
		}
		com := mpcKemMalCommit(s.rn, i, s.pks[i][0], s.pks[i][1])
		if received[i], err = mpcKemXor(enc[i][c], mpcKemMalPad(sid, com, i, c, ss, len(enc[i][c]))); err != nil {
			return nil, err
		}
	}
	return &MpcKemBaseOtMalResult{received, &MpcKemMalTranscript{s.rn, s.commitments, s.sn, s.opened, cts, enc}}, nil
}

// MpcWithKemBaseOtMal is the malicious-secure KEM OT as a pluggable base OT for MpcOtChannel.
func MpcWithKemBaseOtMal() MpcBaseOtFn {
	return func(m []MpcOtPair, c []int, r MpcOtRandom) ([][]byte, error) {
		res, err := MpcKemBaseOtMal(m, c, r, nil)
		if err != nil {
			return nil, err
		}
		return res.Received, nil
	}
}

// MpcKemBaseOtMalRandomResult is the random-OT form: fixed-width secrets for the hybrid base OT.
type MpcKemBaseOtMalRandomResult struct {
	SenderSecrets []MpcOtPair
	RecvSecrets   [][]byte
	Sid           []byte
	Transcript    *MpcKemMalTranscript
}

// MpcKemBaseOtMalRandom runs the commit-then-open KEM OT as a random OT (both roles in process). A nil rng is the CSPRNG.
func MpcKemBaseOtMalRandom(choices []int, rng MpcOtRandom, tamper *MpcKemMalTamper) (*MpcKemBaseOtMalRandomResult, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	s, err := mpcKemMalStart(choices, rng, tamper)
	if err != nil {
		return nil, err
	}
	cts, coms, sss, err := s.encaps(rng)
	if err != nil {
		return nil, err
	}
	n := len(choices)
	secrets := make([]MpcOtPair, n)
	for i := range secrets {
		for sl := 0; sl < 2; sl++ {
			secrets[i][sl] = mpcKemMalSecret(s.sid, coms[i], i, sl, sss[i][sl])
		}
	}
	sid := s.sid
	if tamper != nil && tamper.TamperReceiverSid != nil {
		sid = tamper.TamperReceiverSid(append([]byte(nil), sid...))
	}
	recv := make([][]byte, n)
	for i := range recv {
		c := s.st.choices[i]
		ss, err := s.st.keys[i].Decapsulate(cts[i][c])
		if err != nil {
			return nil, err
		}
		com := mpcKemMalCommit(s.rn, i, s.pks[i][0], s.pks[i][1])
		recv[i] = mpcKemMalSecret(sid, com, i, c, ss)
	}
	return &MpcKemBaseOtMalRandomResult{secrets, recv, s.sid, &MpcKemMalTranscript{s.rn, s.commitments, s.sn, s.opened, cts, nil}}, nil
}

// ---- hybrid base OT: both the EC and the ML-KEM secret fold into every transfer key

var (
	mpcTagHybridSid    = []byte("atlas-pca-mpc/hybrid-ot-sid")
	mpcTagHybridKey    = []byte("atlas-pca-mpc/hybrid-ot-transfer-key")
	mpcTagHybridCommit = []byte("atlas-pca-mpc/hybrid-ot-msg-commit")
)

// MpcHybridOtAbort: the sender's ciphertext is inconsistent with its commitment.
type MpcHybridOtAbort struct{ Msg string }

func (e *MpcHybridOtAbort) Error() string { return e.Msg }

// MpcHybridTransferKey is n bytes (at most 1 MiB) of the transfer key of one (index, slot) from both secrets.
func MpcHybridTransferKey(sid []byte, index, slot int, ssEc, ssKem []byte, n int) ([]byte, error) {
	if n < 0 || n > 1<<20 {
		return nil, errors.New("hybridTransferKey: length must be an integer in [0, 1 MiB]")
	}
	out := make([]byte, 0, n)
	for ctr := uint64(0); len(out) < n; ctr++ {
		out = append(out, mpcOtSha256(mpcTagHybridKey, sid, mpcOtU32(uint64(index)), []byte{byte(slot & 1)}, mpcOtU32(ctr), ssEc, ssKem)...)
	}
	return out[:n], nil
}

func mpcHybridCommit(sid []byte, index, slot int, msg, key []byte) []byte {
	return mpcOtSha256(mpcTagHybridCommit, sid, mpcOtU32(uint64(index)), []byte{byte(slot & 1)}, msg, key)
}

// MpcHybridBaseOtTamper holds TEST-ONLY injection points (nil = honest).
type MpcHybridBaseOtTamper struct {
	EC              *MpcBaseOtTamper
	Kem             *MpcKemMalTamper
	TamperEncrypted func([]MpcOtPair)
}

type MpcHybridBaseOtTranscript struct {
	Sid         []byte
	EcS         *ed.Point
	KemSid      []byte
	Encrypted   []MpcOtPair
	Commitments []MpcOtPair
}

type MpcHybridBaseOtResult struct {
	Received   [][]byte
	Transcript *MpcHybridBaseOtTranscript
}

// MpcHybridBaseOT runs the EC and ML-KEM random OTs side by side and transfers the messages under keys derived from both.
func MpcHybridBaseOT(messages []MpcOtPair, choices []int, rng MpcOtRandom, tamper *MpcHybridBaseOtTamper) (*MpcHybridBaseOtResult, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	if len(messages) != len(choices) {
		return nil, errors.New("hybridBaseOT: messages/choices length mismatch")
	}
	var ecT *MpcBaseOtTamper
	var kemT *MpcKemMalTamper
	if tamper != nil {
		ecT, kemT = tamper.EC, tamper.Kem
	}
	ec, err := MpcMalBaseRandomOT(choices, rng, ecT, nil)
	if err != nil {
		return nil, err
	}
	kem, err := MpcKemBaseOtMalRandom(choices, rng, kemT)
	if err != nil {
		return nil, err
	}
	sid := mpcOtSha256(mpcTagHybridSid, kem.Sid, MpcEcEncodePoint(ec.S))
	enc := make([]MpcOtPair, len(messages))
	com := make([]MpcOtPair, len(messages))
	for i, m := range messages {
		if len(m[0]) != len(m[1]) {
			return nil, fmt.Errorf("hybridSenderEncrypt (index %d): the two messages must be equal length", i)
		}
		for sl := 0; sl < 2; sl++ {
			k, _ := MpcHybridTransferKey(sid, i, sl, ec.SenderPads[i][sl], kem.SenderSecrets[i][sl], len(m[sl]))
			enc[i][sl], _ = mpcKemXor(m[sl], k)
			com[i][sl] = mpcHybridCommit(sid, i, sl, m[sl], k)
		}
	}
	if tamper != nil && tamper.TamperEncrypted != nil {
		tamper.TamperEncrypted(enc)
	}
	received := make([][]byte, len(choices))
	for i := range choices {
		c := choices[i] & 1
		key, _ := MpcHybridTransferKey(sid, i, c, ec.RecvPads[i], kem.RecvSecrets[i], len(enc[i][c]))
		m, _ := mpcKemXor(enc[i][c], key)
		if !mpcKemEqual(mpcHybridCommit(sid, i, c, m, key), com[i][c]) {
			return nil, &MpcHybridOtAbort{fmt.Sprintf("hybrid base OT (index %d): sender ciphertext inconsistent with its commitment; aborting", i)}
		}
		received[i] = m
	}
	return &MpcHybridBaseOtResult{Received: received, Transcript: &MpcHybridBaseOtTranscript{sid, ec.S, kem.Sid, enc, com}}, nil
}

// MpcWithHybridBaseOt is the hybrid base OT as a pluggable base OT for MpcOtChannel.
func MpcWithHybridBaseOt() MpcBaseOtFn {
	return func(m []MpcOtPair, c []int, r MpcOtRandom) ([][]byte, error) {
		res, err := MpcHybridBaseOT(m, c, r, nil)
		if err != nil {
			return nil, err
		}
		return res.Received, nil
	}
}
