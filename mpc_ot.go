package pca

// Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519
// subgroup: the sender proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the core
// runs as a random OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check (a deviating
// receiver is caught and the protocol aborts). Both roles run in one process; the functions take both parties' inputs and return
// the receiver's outputs plus an inspectable transcript. Randomness is the CSPRNG unless a SplitMix64 seed is given (tests only).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	ed "filippo.io/edwards25519"
)

const (
	// MpcOtKappa is the IKNP security parameter (number of base OTs / width of the selector).
	MpcOtKappa = 128
	// MpcOtSsec is the KOS statistical parameter: extra random check rows beyond kappa that mask the revealed combination.
	MpcOtSsec = 128

	mpcOtSeedBytes = MpcOtKappa / 8
)

// MpcMalOtAbort: the KOS correlation check failed, a cheating OT-extension receiver is detected.
type MpcMalOtAbort struct{ Msg string }

func (e *MpcMalOtAbort) Error() string { return e.Msg }

// MpcBaseOtAbort: a base OT aborted, a cheating sender (bad proof or inconsistent ciphertext) is detected.
type MpcBaseOtAbort struct{ Msg string }

func (e *MpcBaseOtAbort) Error() string { return e.Msg }

// MpcOtRandom is a source of scalars and seeds for OT needs.
type MpcOtRandom interface {
	// Scalar is a uniform scalar in [1, L).
	Scalar() *big.Int
	// Bytes is n random bytes.
	Bytes(n int) []byte
}

type mpcSecureOtRandom struct{}

// MpcSecureOtRandom is the crypto/rand source: scalars by rejection over 32 random bytes.
func MpcSecureOtRandom() MpcOtRandom { return mpcSecureOtRandom{} }

func (mpcSecureOtRandom) Scalar() *big.Int {
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	bound := new(big.Int).Sub(two256, new(big.Int).Mod(two256, MpcEcL))
	var b [32]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("mpc: crypto/rand failed: " + err.Error())
		}
		acc := new(big.Int).SetBytes(b[:])
		if acc.Cmp(bound) >= 0 {
			continue
		}
		if s := acc.Mod(acc, MpcEcL); s.Sign() != 0 {
			return s
		}
	}
}

func (mpcSecureOtRandom) Bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("mpc: crypto/rand failed: " + err.Error())
	}
	return b
}

type mpcStreamOtRandom struct{ next func() uint64 }

// MpcOtRandomFromSeed is the deterministic SplitMix64 stream of the low 64 bits of seed (for reproducible tests only).
func MpcOtRandomFromSeed(seed *big.Int) MpcOtRandom {
	return mpcStreamOtRandom{NewMpcFieldRng(seed).nextU64}
}

func (r mpcStreamOtRandom) Scalar() *big.Int {
	for attempt := 0; attempt < 8; attempt++ {
		acc := new(big.Int)
		for i := 0; i < 4; i++ {
			acc.Lsh(acc, 64)
			acc.Or(acc, new(big.Int).SetUint64(r.next()))
		}
		if s := acc.Mod(acc, MpcEcL); s.Sign() != 0 {
			return s
		}
	}
	panic("mpc: otRandom: entropy stream returned zero scalars repeatedly (RNG failure)")
}

func (r mpcStreamOtRandom) Bytes(n int) []byte {
	out := make([]byte, n)
	for have := 0; have < n; {
		v := r.next()
		for i := 0; i < 8 && have < n; i++ {
			out[have] = byte(v)
			have++
			v >>= 8
		}
	}
	return out
}

func mpcOtSha256(chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		h.Write(c)
	}
	return h.Sum(nil)
}

func mpcOtU32(x uint64) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(x))
	return b[:]
}

func mpcOtXor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func mpcOtConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// MpcBaseOtBinding is the session binding of one base OT: who runs it, in which session and round (indices are uint32).
type MpcBaseOtBinding struct {
	SessionID                  []byte
	SenderIndex, ReceiverIndex int64
	Round                      string
}

var (
	mpcTagBinding    = []byte("atlas-pca-mpc/base-ot-binding")
	mpcTagTranscript = []byte("atlas-pca-mpc/base-ot-transcript")
	mpcTagOtKdf      = []byte("atlas-pca-mpc/ot-kdf")
	mpcTagKos        = []byte("atlas-pca-mpc/ot-kos")
	mpcTagOtCommit   = []byte("atlas-pca-mpc/ot-msg-commit")
)

// MpcBindingBytes is the canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input).
func MpcBindingBytes(b MpcBaseOtBinding) ([]byte, error) {
	if len(b.SessionID) < 8 || len(b.SessionID) > 64 {
		return nil, errors.New("base-OT binding: sessionId must be 8..64 bytes")
	}
	if b.SenderIndex < 0 || b.SenderIndex > 0xffffffff {
		return nil, errors.New("base-OT binding: senderIndex must be a uint32")
	}
	if b.ReceiverIndex < 0 || b.ReceiverIndex > 0xffffffff {
		return nil, errors.New("base-OT binding: receiverIndex must be a uint32")
	}
	if b.SenderIndex == b.ReceiverIndex {
		return nil, errors.New("base-OT binding: sender and receiver must be different parties")
	}
	round := []byte(b.Round)
	if len(round) == 0 || len(round) > 64 {
		return nil, errors.New("base-OT binding: round label must be 1..64 bytes")
	}
	return mpcOtConcat(mpcTagBinding, mpcOtU32(uint64(len(b.SessionID))), b.SessionID, mpcOtU32(uint64(b.SenderIndex)), mpcOtU32(uint64(b.ReceiverIndex)),
		mpcOtU32(uint64(len(round))), round), nil
}

// MpcRandomBinding is a fresh binding for an in-process OT (sender 0, receiver 1): a random 16-byte session id from rng.
func MpcRandomBinding(rng MpcOtRandom, round string) MpcBaseOtBinding {
	return MpcBaseOtBinding{rng.Bytes(16), 0, 1, round}
}

// MpcBaseOtTranscriptHash hashes the whole base-OT transcript: the binding, S and every receiver point, in order.
func MpcBaseOtTranscriptHash(binding MpcBaseOtBinding, S *ed.Point, R []*ed.Point) ([]byte, error) {
	bb, err := MpcBindingBytes(binding)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{mpcTagTranscript, bb, MpcEcEncodePoint(S), mpcOtU32(uint64(len(R)))}
	for _, r := range R {
		parts = append(parts, MpcEcEncodePoint(r))
	}
	return mpcOtSha256(parts...), nil
}

// MpcBaseOtKdf is H("ot-kdf" || H(transcript) || index || R_i || P), 16 bytes.
func MpcBaseOtKdf(transcriptHash []byte, index int, Ri, p *ed.Point) []byte {
	return mpcOtSha256(mpcTagOtKdf, transcriptHash, mpcOtU32(uint64(index)), MpcEcEncodePoint(Ri), MpcEcEncodePoint(p))[:mpcOtSeedBytes]
}

// MpcKosChiWords are the KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column
// of u. colBytes, when non-nil, are the canonical column encodings already at hand (else they are derived from u).
func MpcKosChiWords(binding []byte, round int, u []*big.Int, mExt int, colBytes [][]byte) ([]uint32, error) {
	cb := (mExt + 7) / 8
	xof := sha3.NewSHAKE256()
	xof.Write(mpcTagKos)
	xof.Write(mpcOtU32(uint64(len(binding))))
	xof.Write(binding)
	xof.Write(mpcOtU32(uint64(round)))
	xof.Write(mpcOtU32(uint64(mExt)))
	xof.Write(mpcOtU32(uint64(len(u))))
	if colBytes != nil {
		for _, c := range colBytes {
			xof.Write(c)
		}
	} else {
		for _, col := range u {
			b, err := MpcOtxBigToBytes(col, cb)
			if err != nil {
				return nil, err
			}
			xof.Write(b)
		}
	}
	out := make([]byte, mExt*16)
	xof.Read(out)
	return mpcOtxLeWords(out, mExt*4), nil
}

// MpcKosChallenges are the KOS row-weights as GF(2^128) integers.
func MpcKosChallenges(binding []byte, round int, u []*big.Int, mExt int) ([]*big.Int, error) {
	w, err := MpcKosChiWords(binding, round, u, mExt, nil)
	if err != nil {
		return nil, err
	}
	chi := make([]*big.Int, mExt)
	for j := range chi {
		chi[j] = MpcOtxGfToBig(w[4*j : 4*j+4])
	}
	return chi, nil
}

// ---- base OT

// MpcOtPair is a pair of byte strings, slot 0 and slot 1.
type MpcOtPair = [2][]byte

// MpcBaseOtTamper holds TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (nil = honest).
type MpcBaseOtTamper struct {
	TamperS          func(*ed.Point) *ed.Point
	TamperProof      func(MpcSchnorrProof) MpcSchnorrProof
	TamperR          func([]*ed.Point)
	TamperCiphertext func([]MpcOtPair)
}

// MpcBaseOtTranscript is the base-OT transcript; CT and Com hold [i][slot] byte strings.
type MpcBaseOtTranscript struct {
	S     *ed.Point
	Proof MpcSchnorrProof
	R     []*ed.Point
	CT    []MpcOtPair
	Com   []MpcOtPair
}

type MpcBaseOtResult struct {
	Received   [][]byte
	Transcript *MpcBaseOtTranscript
}

// MpcBaseOtFn is a pluggable chosen-message base OT: messages[i] = {m0, m1}; it returns the receiver's recovered messages.
type MpcBaseOtFn func(messages []MpcOtPair, choices []int, rng MpcOtRandom) ([][]byte, error)

// MpcMalRandomOtResult is the output of the malicious-secure random base OT: validated points and the two pads per index.
type MpcMalRandomOtResult struct {
	S          *ed.Point
	Proof      MpcSchnorrProof
	R          []*ed.Point
	SenderPads []MpcOtPair
	RecvPads   [][]byte
}

func mpcOtCommit(i, b int, msg, pad []byte) []byte {
	return mpcOtSha256(mpcTagOtCommit, mpcOtU32(uint64(i)), []byte{byte(b & 1)}, msg, pad)
}

// MpcMalBaseRandomOT runs the random base OT with both roles in process. A nil rng is the CSPRNG; a nil binding is a fresh random one.
func MpcMalBaseRandomOT(choices []int, rng MpcOtRandom, tamper *MpcBaseOtTamper, binding *MpcBaseOtBinding) (*MpcMalRandomOtResult, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	var b MpcBaseOtBinding
	if binding != nil {
		b = *binding
	} else {
		b = MpcRandomBinding(rng, "base-ot")
	}
	setup, err := MpcMalBaseOtSenderSetup(rng, b)
	if err != nil {
		return nil, err
	}
	S, proof := setup.S, setup.Proof
	if tamper != nil && tamper.TamperS != nil {
		S = tamper.TamperS(S)
	}
	if tamper != nil && tamper.TamperProof != nil {
		proof = tamper.TamperProof(proof)
	}
	R, recvPads, err := MpcMalBaseOtReceiverRespond(S, proof, choices, rng, b)
	if err != nil {
		return nil, err
	}
	if tamper != nil && tamper.TamperR != nil {
		tamper.TamperR(R)
	}
	pads, err := MpcMalBaseOtSenderDerive(setup.Y, setup.T, R, S, b)
	if err != nil {
		return nil, err
	}
	return &MpcMalRandomOtResult{S, proof, R, pads, recvPads}, nil
}

// MpcBaseOtSenderSetup is the sender's first message and secret: y, T = y*S, S = y*B and the Schnorr proof of y.
type MpcBaseOtSenderSetup struct {
	Y     *big.Int
	T, S  *ed.Point
	Proof MpcSchnorrProof
}

func MpcMalBaseOtSenderSetup(rng MpcOtRandom, binding MpcBaseOtBinding) (*MpcBaseOtSenderSetup, error) {
	ctx, err := MpcBindingBytes(binding)
	if err != nil {
		return nil, err
	}
	y := rng.Scalar()
	S := MpcEcMulBase(y)
	T := MpcEcMul(y, S)
	proof, err := MpcSchnorrProve(y, S, rng.Scalar, ctx)
	if err != nil {
		return nil, err
	}
	return &MpcBaseOtSenderSetup{y, T, S, *proof}, nil
}

// MpcMalBaseOtReceiverRespond validates S and its proof, then answers each choice with R_i = x_i*B (+ S when the choice is 1).
func MpcMalBaseOtReceiverRespond(S *ed.Point, proof MpcSchnorrProof, choices []int, rng MpcOtRandom, binding MpcBaseOtBinding) ([]*ed.Point, [][]byte, error) {
	ctx, err := MpcBindingBytes(binding)
	if err != nil {
		return nil, nil, err
	}
	if err := MpcEcAssertInSubgroup(S, "base-OT S (received by receiver)"); err != nil {
		return nil, nil, err
	}
	if !MpcSchnorrVerify(S, &proof, ctx) {
		return nil, nil, &MpcBaseOtAbort{"base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting"}
	}
	R := make([]*ed.Point, len(choices))
	xs := make([]*big.Int, len(choices))
	for i := range choices {
		x := rng.Scalar()
		R[i] = MpcEcMulBase(x)
		if choices[i]&1 == 1 {
			R[i] = MpcEcAdd(R[i], S)
		}
		xs[i] = x
	}
	th, err := MpcBaseOtTranscriptHash(binding, S, R)
	if err != nil {
		return nil, nil, err
	}
	pads := make([][]byte, len(choices))
	for i := range choices {
		pads[i] = MpcBaseOtKdf(th, i, R[i], MpcEcMul(xs[i], S))
	}
	return R, pads, nil
}

// MpcMalBaseOtSenderDerive validates every R_i and derives the two pads of each index.
func MpcMalBaseOtSenderDerive(y *big.Int, T *ed.Point, R []*ed.Point, S *ed.Point, binding MpcBaseOtBinding) ([]MpcOtPair, error) {
	for i, r := range R {
		if err := MpcEcAssertInSubgroup(r, fmt.Sprintf("base-OT R_%d (received by sender)", i)); err != nil {
			return nil, err
		}
	}
	th, err := MpcBaseOtTranscriptHash(binding, S, R)
	if err != nil {
		return nil, err
	}
	pads := make([]MpcOtPair, len(R))
	for i, r := range R {
		yR := MpcEcMul(y, r)
		pads[i] = MpcOtPair{MpcBaseOtKdf(th, i, r, yR), MpcBaseOtKdf(th, i, r, MpcEcSub(yR, T))}
	}
	return pads, nil
}

// MpcBaseOtSenderEncrypt one-time-pads the messages under the sender pads and commits to each (message, pad).
func MpcBaseOtSenderEncrypt(messages, senderPads []MpcOtPair) (ct, com []MpcOtPair, err error) {
	if len(messages) != len(senderPads) {
		return nil, nil, errors.New("baseOT: messages/pads length mismatch")
	}
	for i, m := range messages {
		if len(m[0]) > mpcOtSeedBytes || len(m[1]) > mpcOtSeedBytes || len(m[0]) != len(m[1]) {
			return nil, nil, fmt.Errorf("baseOT: message pair %d must be equal length and at most %d bytes (pad width)", i, mpcOtSeedBytes)
		}
	}
	ct = make([]MpcOtPair, len(messages))
	com = make([]MpcOtPair, len(messages))
	for i, m := range messages {
		p0, p1 := senderPads[i][0], senderPads[i][1]
		ct[i] = MpcOtPair{mpcOtXor(m[0], p0), mpcOtXor(m[1], p1)}
		com[i] = MpcOtPair{mpcOtCommit(i, 0, m[0], p0), mpcOtCommit(i, 1, m[1], p1)}
	}
	return ct, com, nil
}

// MpcBaseOtReceiverDecrypt recovers the chosen messages, aborting on any ciphertext inconsistent with its commitment.
func MpcBaseOtReceiverDecrypt(choices []int, recvPads [][]byte, ct, com []MpcOtPair) ([][]byte, error) {
	if len(ct) != len(choices) || len(com) != len(choices) || len(recvPads) != len(choices) {
		return nil, &MpcBaseOtAbort{"base OT: ciphertext/commitment count does not match the number of choices; aborting"}
	}
	received := make([][]byte, len(choices))
	for i := range choices {
		ci := choices[i] & 1
		if len(ct[i][0]) != len(ct[i][1]) || len(ct[i][0]) > mpcOtSeedBytes || len(recvPads[i]) < len(ct[i][ci]) {
			return nil, &MpcBaseOtAbort{fmt.Sprintf("base OT (index %d): malformed ciphertext shape; aborting", i)}
		}
		m := mpcOtXor(ct[i][ci], recvPads[i][:len(ct[i][ci])])
		if subtle.ConstantTimeCompare(mpcOtCommit(i, ci, m, recvPads[i]), com[i][ci]) != 1 {
			return nil, &MpcBaseOtAbort{fmt.Sprintf("base OT (index %d): sender ciphertext inconsistent with its commitment; aborting", i)}
		}
		received[i] = m
	}
	return received, nil
}

// MpcBaseOT is a chosen-message 1-of-2 OT for len(choices) transfers, built over the random base OT.
func MpcBaseOT(messages []MpcOtPair, choices []int, rng MpcOtRandom, tamper *MpcBaseOtTamper, binding *MpcBaseOtBinding) (*MpcBaseOtResult, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	if binding == nil {
		b := MpcRandomBinding(rng, "base-ot")
		binding = &b
	}
	if len(messages) != len(choices) {
		return nil, errors.New("baseOT: messages/choices length mismatch")
	}
	ro, err := MpcMalBaseRandomOT(choices, rng, tamper, binding)
	if err != nil {
		return nil, err
	}
	ct, com, err := MpcBaseOtSenderEncrypt(messages, ro.SenderPads)
	if err != nil {
		return nil, err
	}
	if tamper != nil && tamper.TamperCiphertext != nil {
		tamper.TamperCiphertext(ct)
	}
	received, err := MpcBaseOtReceiverDecrypt(choices, ro.RecvPads, ct, com)
	if err != nil {
		return nil, err
	}
	return &MpcBaseOtResult{received, &MpcBaseOtTranscript{ro.S, ro.Proof, ro.R, ct, com}}, nil
}

// ---- OT extension (IKNP + KOS)

// MpcExtRoundMsg is the receiver's extension-round message: the u columns and the KOS values (x, t).
type MpcExtRoundMsg struct {
	U     []*big.Int
	X     *big.Int
	TComb *big.Int
}

// MpcExtPending is the receiver's per-round state between Begin and Finish.
type MpcExtPending struct {
	m          int
	choiceBits []int
	t          []uint32
	w          int
	rowOffset  int64
}

func mpcOtCheckChoices(choiceBits []int) error {
	for j, c := range choiceBits {
		if c != 0 && c != 1 {
			return fmt.Errorf("OtChannel.extend: choice bit %d must be 0 or 1", j)
		}
	}
	return nil
}

// mpcOtLimit64 converts messages to 64-bit pad width, refusing anything outside [0, 2^64).
func mpcOtMsgs64(msg []*big.Int) ([]uint64, error) {
	out := make([]uint64, len(msg))
	for j, v := range msg {
		if v == nil || v.Sign() < 0 || !v.IsUint64() {
			return nil, fmt.Errorf("OtChannel.extend: message %d must be a bigint in [0, 2^64) (the pad is 64 bits wide)", j)
		}
		out[j] = v.Uint64()
	}
	return out, nil
}

func mpcOtBig64(v []uint64) []*big.Int {
	out := make([]*big.Int, len(v))
	for i, x := range v {
		out[i] = new(big.Int).SetUint64(x)
	}
	return out
}

// MpcOtExtReceiver is the extension receiver (base-OT sender): it makes the seed pairs, then per round the u matrix and KOS values.
type MpcOtExtReceiver struct {
	rng          MpcOtRandom
	kosBinding   []byte
	seed0, seed1 [][]byte
	blk0, blk1   [MpcOtKappa]uint64
	round        int
	rowsDone     int64
	tweakDomain  []uint32
	Ready        bool
	// TamperU is TEST-ONLY: it mutates the u columns on the wire (a malicious receiver).
	TamperU func(u []*big.Int, round int)
}

func NewMpcOtExtReceiver(rng MpcOtRandom, kosBinding []byte) *MpcOtExtReceiver {
	return &MpcOtExtReceiver{rng: rng, kosBinding: kosBinding, tweakDomain: MpcOtxTweakDomain(kosBinding)}
}

// MakeSeeds are the kappa seed pairs, to be transferred by the base OT with the sender's selector as choices.
func (r *MpcOtExtReceiver) MakeSeeds() []MpcOtPair {
	messages := make([]MpcOtPair, MpcOtKappa)
	for i := range messages {
		k0 := r.rng.Bytes(mpcOtSeedBytes)
		k1 := r.rng.Bytes(mpcOtSeedBytes)
		r.seed0 = append(r.seed0, k0)
		r.seed1 = append(r.seed1, k1)
		messages[i] = MpcOtPair{k0, k1}
	}
	r.Ready = true
	return messages
}

// Begin makes one round's u columns and KOS values for the choice bits.
func (r *MpcOtExtReceiver) Begin(choiceBits []int) (*MpcExtRoundMsg, *MpcExtPending, error) {
	if !r.Ready {
		return nil, nil, errors.New("OtExtReceiver: base OT not done")
	}
	if err := mpcOtCheckChoices(choiceBits); err != nil {
		return nil, nil, err
	}
	m := len(choiceBits)
	roundIdx := r.round
	r.round++
	rowOffset := r.rowsDone
	r.rowsDone += int64(m)
	pad := MpcOtKappa + MpcOtSsec
	mExt := m + pad
	W := (mExt + 31) >> 5
	colBytes := (mExt + 7) / 8
	bvec := make([]uint32, W)
	for j := 0; j < m; j++ {
		if choiceBits[j]&1 != 0 {
			bvec[j>>5] |= 1 << uint(j&31)
		}
	}
	padBytes := r.rng.Bytes(pad)
	for p := 0; p < pad; p++ {
		if padBytes[p]&1 != 0 {
			j := m + p
			bvec[j>>5] |= 1 << uint(j&31)
		}
	}
	blocks := uint64((W + 3) / 4)
	t := make([]uint32, MpcOtCols*W)
	u := make([]*big.Int, MpcOtCols)
	ubytes := make([][]byte, MpcOtCols)
	uw := make([]uint32, W)
	for i := 0; i < MpcOtKappa; i++ {
		ti := MpcOtxPrgColumn(r.seed0[i], r.blk0[i], W)
		gi := MpcOtxPrgColumn(r.seed1[i], r.blk1[i], W)
		r.blk0[i] += blocks
		r.blk1[i] += blocks
		MpcOtxMaskTail(ti, mExt)
		MpcOtxMaskTail(gi, mExt)
		copy(t[i*W:], ti)
		for w := 0; w < W; w++ {
			uw[w] = gi[w] ^ ti[w] ^ bvec[w]
		}
		ubytes[i] = mpcOtxLeBytes(uw, W)[:colBytes]
		u[i] = MpcOtxBytesToBig(ubytes[i])
	}
	if r.TamperU != nil {
		r.TamperU(u, roundIdx)
	}
	pending := &MpcExtPending{m, append([]int(nil), choiceBits...), t, W, rowOffset}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(mExt))
	for _, c := range u {
		if c == nil || c.Sign() < 0 || c.Cmp(limit) >= 0 {
			return &MpcExtRoundMsg{u, new(big.Int), new(big.Int)}, pending, nil
		}
	}
	cols := ubytes
	if r.TamperU != nil {
		cols = nil
	}
	chi, err := MpcKosChiWords(r.kosBinding, roundIdx, u, mExt, cols)
	if err != nil {
		return nil, nil, err
	}
	x := make([]uint32, 4)
	MpcOtxAccumColumn(bvec, chi, x)
	tComb, err := MpcOtxKosCombine(t, W, chi)
	if err != nil {
		return nil, nil, err
	}
	return &MpcExtRoundMsg{u, MpcOtxGfToBig(x), MpcOtxGfToBig(tComb)}, pending, nil
}

// Finish is the receiver's output m_{c_j} for every row j, from the sender's ciphertexts.
func (r *MpcOtExtReceiver) Finish(p *MpcExtPending, y0, y1 []uint64) ([]uint64, error) {
	m := p.m
	if len(y0) != m || len(y1) != m {
		return nil, &MpcMalOtAbort{"OT extension: ciphertext count does not match the number of rows; aborting"}
	}
	rows, err := MpcOtxTransposeCols(p.t, p.w, m)
	if err != nil {
		return nil, err
	}
	h, err := MpcOtxTmmoCrh(rows, m, &MpcOtTweak{p.rowOffset, r.tweakDomain})
	if err != nil {
		return nil, err
	}
	received := make([]uint64, m)
	for j := 0; j < m; j++ {
		y := y0[j]
		if p.choiceBits[j] == 1 {
			y = y1[j]
		}
		received[j] = y ^ MpcOtxWord64(h, j)
	}
	return received, nil
}

// MpcOtExtSender is the extension sender (base-OT receiver): it holds the secret selector s and answers each round after the KOS check.
type MpcOtExtSender struct {
	rng         MpcOtRandom
	kosBinding  []byte
	s           []int
	sBits       *big.Int
	seeds       [][]byte
	blk         []uint64
	round       int
	rowsDone    int64
	tweakDomain []uint32
	Ready       bool
}

func NewMpcOtExtSender(rng MpcOtRandom, kosBinding []byte) *MpcOtExtSender {
	return &MpcOtExtSender{rng: rng, kosBinding: kosBinding, sBits: new(big.Int), tweakDomain: MpcOtxTweakDomain(kosBinding)}
}

func (s *MpcOtExtSender) MakeSelector() []int {
	s.s = make([]int, MpcOtKappa)
	for i := range s.s {
		s.s[i] = int(s.rng.Bytes(1)[0] & 1)
	}
	return append([]int(nil), s.s...)
}

func (s *MpcOtExtSender) SetSeeds(seeds [][]byte) error {
	if len(seeds) != MpcOtKappa || len(s.s) != MpcOtKappa {
		return errors.New("OtExtSender: wrong base-OT output size")
	}
	s.seeds = seeds
	s.blk = make([]uint64, MpcOtKappa)
	acc := new(big.Int)
	for i := 0; i < MpcOtKappa; i++ {
		if s.s[i] == 1 {
			acc.SetBit(acc, i, 1)
		}
	}
	s.sBits = acc
	s.Ready = true
	return nil
}

// Selector is the selector s as an integer, bit i = s[i].
func (s *MpcOtExtSender) Selector() *big.Int { return new(big.Int).Set(s.sBits) }

func (s *MpcOtExtSender) kosAbort(round int, why string) error {
	return &MpcMalOtAbort{fmt.Sprintf("KOS check (round %d): %s; a cheating OT-extension receiver was detected; aborting", round, why)}
}

// Respond runs the KOS check on the receiver's message and, when it holds, answers with the two ciphertext vectors.
func (s *MpcOtExtSender) Respond(msg *MpcExtRoundMsg, msg0, msg1 []uint64) (y0, y1 []uint64, err error) {
	if !s.Ready {
		return nil, nil, errors.New("OtExtSender: base OT not done")
	}
	m := len(msg0)
	if len(msg1) != m {
		return nil, nil, errors.New("OtChannel.extend: length mismatch")
	}
	roundIdx := s.round
	s.round++
	rowOffset := s.rowsDone
	s.rowsDone += int64(m)
	mExt := m + MpcOtKappa + MpcOtSsec
	u := msg.U
	if len(u) != MpcOtKappa {
		return nil, nil, s.kosAbort(roundIdx, "wrong number of u columns")
	}
	colLimit := new(big.Int).Lsh(big.NewInt(1), uint(mExt))
	for i := 0; i < MpcOtKappa; i++ {
		if u[i] == nil || u[i].Sign() < 0 || u[i].Cmp(colLimit) >= 0 {
			return nil, nil, s.kosAbort(roundIdx, fmt.Sprintf("malformed u column %d", i))
		}
	}
	lim128 := new(big.Int).Lsh(big.NewInt(1), 128)
	if msg.X == nil || msg.TComb == nil || msg.X.Sign() < 0 || msg.X.Cmp(lim128) >= 0 || msg.TComb.Sign() < 0 || msg.TComb.Cmp(lim128) >= 0 {
		return nil, nil, s.kosAbort(roundIdx, "malformed (x, t)")
	}
	W := (mExt + 31) >> 5
	colBytes := (mExt + 7) / 8
	blocks := uint64((W + 3) / 4)
	q := make([]uint32, MpcOtCols*W)
	ubytes := make([][]byte, MpcOtCols)
	for i := 0; i < MpcOtKappa; i++ {
		if ubytes[i], err = MpcOtxBigToBytes(u[i], colBytes); err != nil {
			return nil, nil, err
		}
		ks := MpcOtxPrgColumn(s.seeds[i], s.blk[i], W)
		s.blk[i] += blocks
		MpcOtxMaskTail(ks, mExt)
		if s.s[i] == 1 {
			ub := make([]byte, 4*W)
			copy(ub, ubytes[i])
			uw := mpcOtxLeWords(ub, W)
			for w := 0; w < W; w++ {
				ks[w] ^= uw[w]
			}
		}
		copy(q[i*W:], ks)
	}
	chi, err := MpcKosChiWords(s.kosBinding, roundIdx, u, mExt, ubytes)
	if err != nil {
		return nil, nil, err
	}
	comb, err := MpcOtxKosCombine(q, W, chi)
	if err != nil {
		return nil, nil, err
	}
	expected := new(big.Int).Xor(msg.TComb, MpcGfMul(msg.X, s.sBits))
	if MpcOtxGfToBig(comb).Cmp(expected) != 0 {
		return nil, nil, s.kosAbort(roundIdx, "correlation check FAILED")
	}
	rows, err := MpcOtxTransposeCols(q, W, m)
	if err != nil {
		return nil, nil, err
	}
	tweak := &MpcOtTweak{rowOffset, s.tweakDomain}
	h0, err := MpcOtxTmmoCrh(rows, m, tweak)
	if err != nil {
		return nil, nil, err
	}
	sw := MpcOtxGfFromBig(s.sBits)
	for j := 0; j < m; j++ {
		MpcOtxGfXorInto(rows[4*j:4*j+4], sw, 0)
	}
	h1, err := MpcOtxTmmoCrh(rows, m, tweak)
	if err != nil {
		return nil, nil, err
	}
	y0, y1 = make([]uint64, m), make([]uint64, m)
	for j := 0; j < m; j++ {
		y0[j] = msg0[j] ^ MpcOtxWord64(h0, j)
		y1[j] = msg1[j] ^ MpcOtxWord64(h1, j)
	}
	return y0, y1, nil
}

// MpcOtChannel is an in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later Extend. The
// base OT is the EC base OT unless a MpcBaseOtFn supplies another (for example a post-quantum one).
type MpcOtChannel struct {
	rng      MpcOtRandom
	baseOtFn MpcBaseOtFn
	binding  *MpcBaseOtBinding
	recv     *MpcOtExtReceiver
	send     *MpcOtExtSender
	ready    bool
	// BaseTranscript is the EC base-OT transcript of the kappa setup transfers (nil when a custom base OT is used).
	BaseTranscript *MpcBaseOtTranscript
	// TamperU is TEST-ONLY: it mutates the extension receiver's u matrix.
	TamperU func(u []*big.Int, round int)
}

// NewMpcOtChannel makes a channel. A nil rng is the CSPRNG; binding (optional) supplies the session id and party indices (its round is ignored).
func NewMpcOtChannel(rng MpcOtRandom, baseOtFn MpcBaseOtFn, binding *MpcBaseOtBinding) *MpcOtChannel {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	return &MpcOtChannel{rng: rng, baseOtFn: baseOtFn, binding: binding}
}

func (c *MpcOtChannel) setup() error {
	var base MpcBaseOtBinding
	if c.binding != nil {
		base = *c.binding
	} else {
		base = MpcRandomBinding(c.rng, "x")
	}
	kos, err := MpcBindingBytes(MpcBaseOtBinding{base.SessionID, base.SenderIndex, base.ReceiverIndex, "iknp-kos"})
	if err != nil {
		return err
	}
	r := NewMpcOtExtReceiver(c.rng, kos)
	sd := NewMpcOtExtSender(c.rng, kos)
	messages := r.MakeSeeds()
	sel := sd.MakeSelector()
	var seeds [][]byte
	if c.baseOtFn != nil {
		if seeds, err = c.baseOtFn(messages, sel, c.rng); err != nil {
			return err
		}
	} else {
		b := MpcBaseOtBinding{base.SessionID, base.SenderIndex, base.ReceiverIndex, "iknp-kappa-setup"}
		res, err := MpcBaseOT(messages, sel, c.rng, nil, &b)
		if err != nil {
			return err
		}
		seeds = res.Received
		c.BaseTranscript = res.Transcript
	}
	if err := sd.SetSeeds(seeds); err != nil {
		return err
	}
	c.recv, c.send, c.ready = r, sd, true
	return nil
}

// Selector is the sender's secret selector (running the setup on first use).
func (c *MpcOtChannel) Selector() (*big.Int, error) {
	if !c.ready {
		if err := c.setup(); err != nil {
			return nil, err
		}
	}
	return c.send.Selector(), nil
}

// MpcOtExtended is one extension's receiver output and the receiver's u matrix.
type MpcOtExtended struct{ Received, UMatrix []*big.Int }

// Extend transfers len(choiceBits) OTs: the receiver learns msg_{c_j}[j] for every row j. Messages are in [0, 2^64).
func (c *MpcOtChannel) Extend(choiceBits []int, msg0, msg1 []*big.Int) (*MpcOtExtended, error) {
	if !c.ready {
		if err := c.setup(); err != nil {
			return nil, err
		}
	}
	m := len(choiceBits)
	if len(msg0) != m || len(msg1) != m {
		return nil, errors.New("OtChannel.extend: length mismatch")
	}
	if m == 0 {
		return &MpcOtExtended{[]*big.Int{}, []*big.Int{}}, nil
	}
	if err := mpcOtCheckChoices(choiceBits); err != nil {
		return nil, err
	}
	m0, err := mpcOtMsgs64(msg0)
	if err != nil {
		return nil, err
	}
	m1, err := mpcOtMsgs64(msg1)
	if err != nil {
		return nil, err
	}
	c.recv.TamperU = c.TamperU
	msg, pending, err := c.recv.Begin(choiceBits)
	if err != nil {
		return nil, err
	}
	y0, y1, err := c.send.Respond(msg, m0, m1)
	if err != nil {
		return nil, err
	}
	got, err := c.recv.Finish(pending, y0, y1)
	if err != nil {
		return nil, err
	}
	return &MpcOtExtended{mpcOtBig64(got), msg.U}, nil
}
