package pca

// The explicit round functions of the ML-KEM base OTs and of the hybrid combiner: each party's step on its own, over the same
// primitives and in the same randomness order as the in-process simulators (MpcKemBaseOT, MpcKemBaseOtMal, MpcKemBaseOtMalRandom,
// MpcHybridBaseOT), so a transcript matches the reference byte for byte when the parties draw from one seeded stream in order.

import (
	"crypto/mlkem"
	"errors"
	"fmt"

	ed "filippo.io/edwards25519"
)

// ---- semi-honest KEM base OT

// MpcKemOtReceiverMessage is the receiver's round 1: the ordered public-key pairs the sender encapsulates under (the chosen key
// sits at the receiver's choice).
type MpcKemOtReceiverMessage struct{ PublicKeys []MpcOtPair }

// MpcKemOtReceiverState is the receiver's retained state: the choices and the chosen secret key per transfer.
type MpcKemOtReceiverState struct {
	Choices []int
	keys    []*mlkem.DecapsulationKey768
}

// MpcKemOtSenderMessage is the sender's round: the two ciphertexts and the two padded messages per transfer.
type MpcKemOtSenderMessage struct{ Ciphertexts, Encrypted []MpcOtPair }

// MpcKemBaseOtReceive is the receiver's first step of the KEM base OT.
func MpcKemBaseOtReceive(choices []int, rng MpcOtRandom) (*MpcKemOtReceiverMessage, *MpcKemOtReceiverState, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	pks, st, err := mpcKemReceive(choices, rng)
	if err != nil {
		return nil, nil, err
	}
	return &MpcKemOtReceiverMessage{pks}, &MpcKemOtReceiverState{st.choices, st.keys}, nil
}

// MpcKemBaseOtSend is the sender's step: encapsulate to both keys of every transfer and pad both messages.
func MpcKemBaseOtSend(messages []MpcOtPair, rm *MpcKemOtReceiverMessage, rng MpcOtRandom) (*MpcKemOtSenderMessage, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	if len(messages) != len(rm.PublicKeys) {
		return nil, errors.New("kemBaseOtSend: messages/publicKeys length mismatch")
	}
	cts, enc := make([]MpcOtPair, len(messages)), make([]MpcOtPair, len(messages))
	for i, m := range messages {
		if len(m[0]) != len(m[1]) {
			return nil, fmt.Errorf("kemBaseOtSend (index %d): the two messages must be equal length", i)
		}
		for s := 0; s < 2; s++ {
			ct, ss, err := mpcKemEncaps(rm.PublicKeys[i][s], rng)
			if err != nil {
				return nil, err
			}
			pad, err := MpcKemOtPad(i, s, ss, len(m[s]))
			if err != nil {
				return nil, err
			}
			cts[i][s] = ct
			if enc[i][s], err = mpcKemXor(m[s], pad); err != nil {
				return nil, err
			}
		}
	}
	return &MpcKemOtSenderMessage{cts, enc}, nil
}

// MpcKemBaseOtOpen is the receiver's last step: decapsulate only the chosen ciphertext and unmask the chosen message.
func MpcKemBaseOtOpen(state *MpcKemOtReceiverState, sm *MpcKemOtSenderMessage) ([][]byte, error) {
	n := len(state.Choices)
	if len(sm.Ciphertexts) != n || len(sm.Encrypted) != n {
		return nil, errors.New("kemBaseOtOpen: transcript/state length mismatch")
	}
	received := make([][]byte, n)
	for i := 0; i < n; i++ {
		c := state.Choices[i] & 1
		ss, err := state.keys[i].Decapsulate(sm.Ciphertexts[i][c])
		if err != nil {
			return nil, err
		}
		pad, err := MpcKemOtPad(i, c, ss, len(sm.Encrypted[i][c]))
		if err != nil {
			return nil, err
		}
		if received[i], err = mpcKemXor(sm.Encrypted[i][c], pad); err != nil {
			return nil, err
		}
	}
	return received, nil
}

// ---- committed (malicious-hardened) KEM base OT

// MpcKemMalCommitMessage is the receiver's round 1: a nonce and the commitments to the ordered public keys (not yet revealed).
type MpcKemMalCommitMessage struct {
	Rn          []byte
	Commitments [][]byte
}

// MpcKemMalOpenMessage is the receiver's round 3: the opening of the committed public keys.
type MpcKemMalOpenMessage struct{ PublicKeys []MpcOtPair }

// MpcKemMalSenderNonce is the sender's round 2: the nonce completing the session id.
type MpcKemMalSenderNonce struct{ Sn []byte }

// MpcKemMalSenderMessage is the sender's round 4: ciphertexts and (sid, com)-bound padded messages.
type MpcKemMalSenderMessage struct{ Ciphertexts, Encrypted []MpcOtPair }

// MpcKemMalReceiverState is the receiver's state across the committed flow.
type MpcKemMalReceiverState struct {
	Choices    []int
	PublicKeys []MpcOtPair
	Rn         []byte
	keys       []*mlkem.DecapsulationKey768
}

// MpcKemBaseOtMalCommit is the receiver's first step of the committed flow.
func MpcKemBaseOtMalCommit(choices []int, rng MpcOtRandom) (*MpcKemMalCommitMessage, *MpcKemMalReceiverState, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	rn := rng.Bytes(mpcKemNonceBytes)
	pks, st, err := mpcKemReceive(choices, rng)
	if err != nil {
		return nil, nil, err
	}
	com := make([][]byte, len(choices))
	for i := range choices {
		com[i] = mpcKemMalCommit(rn, i, pks[i][0], pks[i][1])
	}
	return &MpcKemMalCommitMessage{rn, com}, &MpcKemMalReceiverState{st.choices, pks, rn, st.keys}, nil
}

// MpcKemMalSessionID is the committed KEM OT's session id H(TAG || rn || sn): both parties' nonces, so neither alone fixes it.
func MpcKemMalSessionID(rn, sn []byte) []byte { return mpcKemMalSid(rn, sn) }

// MpcKemBaseOtMalSenderNonce is the sender's nonce step.
func MpcKemBaseOtMalSenderNonce(rng MpcOtRandom) *MpcKemMalSenderNonce {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	return &MpcKemMalSenderNonce{rng.Bytes(mpcKemNonceBytes)}
}

// MpcKemBaseOtMalOpen is the receiver's opening step: reveal the committed public keys.
func MpcKemBaseOtMalOpen(state *MpcKemMalReceiverState) *MpcKemMalOpenMessage {
	pks := make([]MpcOtPair, len(state.PublicKeys))
	copy(pks, state.PublicKeys)
	return &MpcKemMalOpenMessage{pks}
}

func mpcKemCheckOpening(rn []byte, i int, pk MpcOtPair, commitment []byte) ([]byte, error) {
	com := mpcKemMalCommit(rn, i, pk[0], pk[1])
	if !mpcKemEqual(com, commitment) {
		return nil, &MpcKemBaseOtAbort{fmt.Sprintf("kem base OT (index %d): opened public keys do not match the receiver's commitment; aborting", i)}
	}
	return com, nil
}

// MpcKemBaseOtMalSend is the sender's step: verify the opened keys against the commitments (a mismatch aborts with
// MpcKemBaseOtAbort), then encapsulate and pad.
func MpcKemBaseOtMalSend(messages []MpcOtPair, commit *MpcKemMalCommitMessage, nonce *MpcKemMalSenderNonce, opening *MpcKemMalOpenMessage, rng MpcOtRandom) (*MpcKemMalSenderMessage, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	pks := opening.PublicKeys
	if len(messages) != len(pks) || len(commit.Commitments) != len(pks) {
		return nil, errors.New("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch")
	}
	sid := mpcKemMalSid(commit.Rn, nonce.Sn)
	cts, enc := make([]MpcOtPair, len(pks)), make([]MpcOtPair, len(pks))
	for i, m := range messages {
		if len(m[0]) != len(m[1]) {
			return nil, fmt.Errorf("kemBaseOtMalSend (index %d): the two messages must be equal length", i)
		}
		com, err := mpcKemCheckOpening(commit.Rn, i, pks[i], commit.Commitments[i])
		if err != nil {
			return nil, err
		}
		for s := 0; s < 2; s++ {
			ct, ss, err := mpcKemEncaps(pks[i][s], rng)
			if err != nil {
				return nil, err
			}
			cts[i][s] = ct
			if enc[i][s], err = mpcKemXor(m[s], mpcKemMalPad(sid, com, i, s, ss, len(m[s]))); err != nil {
				return nil, err
			}
		}
	}
	return &MpcKemMalSenderMessage{cts, enc}, nil
}

// mpcKemRecvSid is the receiver's session id, through the test-only tamper hook when one is given.
func mpcKemRecvSid(state *MpcKemMalReceiverState, nonce *MpcKemMalSenderNonce, tamperSid func([]byte) []byte) []byte {
	sid := mpcKemMalSid(state.Rn, nonce.Sn)
	if tamperSid != nil {
		return tamperSid(append([]byte(nil), sid...))
	}
	return sid
}

// MpcKemBaseOtMalRecover is the receiver's last step of the committed flow. tamperSid is the TEST-ONLY receiver-session-id hook
// (nil = honest).
func MpcKemBaseOtMalRecover(state *MpcKemMalReceiverState, nonce *MpcKemMalSenderNonce, sm *MpcKemMalSenderMessage, tamperSid func([]byte) []byte) ([][]byte, error) {
	n := len(state.Choices)
	if len(sm.Ciphertexts) != n || len(sm.Encrypted) != n {
		return nil, errors.New("kemBaseOtMalRecover: transcript/state length mismatch")
	}
	sid := mpcKemRecvSid(state, nonce, tamperSid)
	received := make([][]byte, n)
	for i := 0; i < n; i++ {
		c := state.Choices[i] & 1
		com := mpcKemMalCommit(state.Rn, i, state.PublicKeys[i][0], state.PublicKeys[i][1])
		ss, err := state.keys[i].Decapsulate(sm.Ciphertexts[i][c])
		if err != nil {
			return nil, err
		}
		if received[i], err = mpcKemXor(sm.Encrypted[i][c], mpcKemMalPad(sid, com, i, c, ss, len(sm.Encrypted[i][c]))); err != nil {
			return nil, err
		}
	}
	return received, nil
}

// MpcKemMalRandomSenderMessage is the sender's round 4 of the random form: ciphertexts (wire) and both per-slot secrets
// (sender-local, never sent).
type MpcKemMalRandomSenderMessage struct{ Ciphertexts, SenderSecrets []MpcOtPair }

// MpcKemBaseOtMalRandomSend is the sender's step of the committed random OT.
func MpcKemBaseOtMalRandomSend(commit *MpcKemMalCommitMessage, nonce *MpcKemMalSenderNonce, opening *MpcKemMalOpenMessage, rng MpcOtRandom) (*MpcKemMalRandomSenderMessage, error) {
	if rng == nil {
		rng = MpcSecureOtRandom()
	}
	pks := opening.PublicKeys
	if len(commit.Commitments) != len(pks) {
		return nil, errors.New("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch")
	}
	sid := mpcKemMalSid(commit.Rn, nonce.Sn)
	cts, secrets := make([]MpcOtPair, len(pks)), make([]MpcOtPair, len(pks))
	for i := range pks {
		com, err := mpcKemCheckOpening(commit.Rn, i, pks[i], commit.Commitments[i])
		if err != nil {
			return nil, err
		}
		for s := 0; s < 2; s++ {
			ct, ss, err := mpcKemEncaps(pks[i][s], rng)
			if err != nil {
				return nil, err
			}
			cts[i][s] = ct
			secrets[i][s] = mpcKemMalSecret(sid, com, i, s, ss)
		}
	}
	return &MpcKemMalRandomSenderMessage{cts, secrets}, nil
}

// MpcKemBaseOtMalRandomRecover is the receiver's last step of the committed random OT: the chosen secret of every transfer.
func MpcKemBaseOtMalRandomRecover(state *MpcKemMalReceiverState, nonce *MpcKemMalSenderNonce, sm *MpcKemMalRandomSenderMessage, tamperSid func([]byte) []byte) ([][]byte, error) {
	n := len(state.Choices)
	if len(sm.Ciphertexts) != n {
		return nil, errors.New("kemBaseOtMalRandomRecover: transcript/state length mismatch")
	}
	sid := mpcKemRecvSid(state, nonce, tamperSid)
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		c := state.Choices[i] & 1
		com := mpcKemMalCommit(state.Rn, i, state.PublicKeys[i][0], state.PublicKeys[i][1])
		ss, err := state.keys[i].Decapsulate(sm.Ciphertexts[i][c])
		if err != nil {
			return nil, err
		}
		out[i] = mpcKemMalSecret(sid, com, i, c, ss)
	}
	return out, nil
}

// ---- hybrid combiner

// MpcHybridSessionID is the common session id binding both halves: H(TAG || kemSid || encode(ecS)).
func MpcHybridSessionID(kemSid []byte, ecS *ed.Point) []byte {
	return mpcOtSha256(mpcTagHybridSid, kemSid, MpcEcEncodePoint(ecS))
}

// MpcHybridSenderMessage is the hybrid sender's wire message: padded messages and per-message commitments.
type MpcHybridSenderMessage struct{ Encrypted, Commitments []MpcOtPair }

// MpcHybridSenderEncrypt takes both halves' per-slot secrets and returns the padded and committed messages.
func MpcHybridSenderEncrypt(sid []byte, messages, ecSecrets, kemSecrets []MpcOtPair) (*MpcHybridSenderMessage, error) {
	if len(messages) != len(ecSecrets) || len(messages) != len(kemSecrets) {
		return nil, errors.New("hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch")
	}
	enc, com := make([]MpcOtPair, len(messages)), make([]MpcOtPair, len(messages))
	for i, m := range messages {
		if len(m[0]) != len(m[1]) {
			return nil, fmt.Errorf("hybridSenderEncrypt (index %d): the two messages must be equal length", i)
		}
		for s := 0; s < 2; s++ {
			k, err := MpcHybridTransferKey(sid, i, s, ecSecrets[i][s], kemSecrets[i][s], len(m[s]))
			if err != nil {
				return nil, err
			}
			if enc[i][s], err = mpcKemXor(m[s], k); err != nil {
				return nil, err
			}
			com[i][s] = mpcHybridCommit(sid, i, s, m[s], k)
		}
	}
	return &MpcHybridSenderMessage{enc, com}, nil
}

// MpcHybridReceiverRecover rebuilds only the chosen transfer key, unmasks, and checks the commitment (a mismatch aborts with
// MpcHybridOtAbort).
func MpcHybridReceiverRecover(sid []byte, choices []int, sender *MpcHybridSenderMessage, ecRecv, kemRecv [][]byte) ([][]byte, error) {
	n := len(choices)
	if len(sender.Encrypted) != n || len(sender.Commitments) != n || len(ecRecv) != n || len(kemRecv) != n {
		return nil, errors.New("hybridReceiverRecover: length mismatch")
	}
	received := make([][]byte, n)
	for i, ch := range choices {
		c := ch & 1
		e := sender.Encrypted[i][c]
		key, err := MpcHybridTransferKey(sid, i, c, ecRecv[i], kemRecv[i], len(e))
		if err != nil {
			return nil, err
		}
		m, err := mpcKemXor(e, key)
		if err != nil {
			return nil, err
		}
		if !mpcKemEqual(mpcHybridCommit(sid, i, c, m, key), sender.Commitments[i][c]) {
			return nil, &MpcHybridOtAbort{fmt.Sprintf("hybrid base OT (index %d): sender ciphertext inconsistent with its commitment; aborting", i)}
		}
		received[i] = m
	}
	return received, nil
}
