package lweotkit

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// EndemicSecretBytes is the byte length of a derived random-OT shared secret (a K-PKE payload).
const EndemicSecretBytes = SymBytes

var (
	tagSid    = []byte("atlas-pca-mpc/endemic-lwe-ot-sid")
	tagHpk    = []byte("atlas-pca-mpc/endemic-lwe-ot-hpk")
	tagN      = []byte("atlas-pca-mpc/endemic-lwe-ot-N")
	tagPad    = []byte("atlas-pca-mpc/endemic-lwe-ot-pad")
	tagCommit = []byte("atlas-pca-mpc/endemic-lwe-ot-commit")
)

// ErrEndemicAbort is wrapped by every abort of the endemic base OT: malformed input, or a sender ciphertext failing its commitment.
var ErrEndemicAbort = errors.New("endemic LWE OT abort")

func abort(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrEndemicAbort}, a...)...)
}

// OtRandom is a source of random bytes for OT needs.
type OtRandom interface{ Bytes(n int) []byte }

type secureRandom struct{}

func (secureRandom) Bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("lweotkit: system randomness failed: " + err.Error())
	}
	return b
}

// SecureRandom is the CSPRNG-backed default.
func SecureRandom() OtRandom { return secureRandom{} }

// SplitMix64 is a deterministic SplitMix64 stream (reproducible tests only).
type SplitMix64 struct{ s uint64 }

// NewSplitMix64 seeds a SplitMix64 stream.
func NewSplitMix64(seed uint64) *SplitMix64 { return &SplitMix64{s: seed} }

func (r *SplitMix64) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// Bytes returns n bytes, each 64-bit draw consumed least-significant byte first.
func (r *SplitMix64) Bytes(n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		v := r.next()
		for i := 0; i < 8 && len(out) < n; i++ {
			out = append(out, byte(v))
			v >>= 8
		}
	}
	return out
}

func sha(chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		h.Write(c)
	}
	return h.Sum(nil)
}

func u32(x int) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, uint32(x)); return b }

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("lweotkit: XOR length mismatch")
	}
	o := make([]byte, len(a))
	for i := range a {
		o[i] = a[i] ^ b[i]
	}
	return o
}

// SessionID is sid = H(TAG || rn): it binds every oracle query to this receiver nonce.
func SessionID(rn []byte) []byte { return sha(tagSid, rn) }

func hpk(sid []byte, i int, other []byte) ([]byte, error) {
	in := append(append(append(append([]byte{}, tagHpk...), sid...), u32(i)...), other...)
	return HashToRing(in)
}

// Pad is the pad for a slot: SHA-256 in counter mode over TAG || sid || i || slot || ctr || payload.
func Pad(sid []byte, index, slot int, payload []byte, length int) []byte {
	out := make([]byte, 0, length)
	for ctr := 0; len(out) < length; ctr++ {
		out = append(out, sha(tagPad, sid, u32(index), []byte{byte(slot & 1)}, u32(ctr), payload)...)
	}
	return out[:length]
}

func commit(sid []byte, i, slot int, msg, pad []byte) []byte {
	return sha(tagCommit, sid, u32(i), []byte{byte(slot & 1)}, msg, pad)
}

// ReceiverMessage is the receiver's round-1 wire message.
type ReceiverMessage struct {
	Rn     []byte
	Points [][2][]byte
	Rhos   [][]byte
}

// ReceiverState is what the receiver keeps: only the chosen branch's secret key.
type ReceiverState struct {
	Choices    []int
	SecretKeys [][]byte
	Rhos       [][]byte
	Rn, Sid    []byte
}

// SenderMessage is the sender's ciphertexts plus its local pads (never sent).
type SenderMessage struct {
	Ciphertexts [][2][]byte
	SenderPads  [][2][]byte
}

// Transcript is a full chosen-message transcript, exposed for inspection and tests.
type Transcript struct {
	Rn                                  []byte
	Points                              [][2][]byte
	Rhos                                [][]byte
	Ciphertexts, Encrypted, Commitments [][2][]byte
}

// Receive is the receiver round: a real key pair per choice, a uniform vector for the other slot, and C = t_real - Hpk(sid, i, N) at the choice slot.
// The real key pair is the FIPS 203 K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
func Receive(choices []int, rng OtRandom) (*ReceiverMessage, *ReceiverState, error) {
	if rng == nil {
		rng = SecureRandom()
	}
	rn := rng.Bytes(SymBytes)
	sid := SessionID(rn)
	m := &ReceiverMessage{Rn: rn}
	st := &ReceiverState{Rn: rn, Sid: sid}
	for i, ch := range choices {
		c := ch & 1
		pk, sk, err := KPKEKeygenFips203(rng.Bytes(SymBytes))
		if err != nil {
			return nil, nil, err
		}
		nSlot, err := HashToRing(append(append(append(append([]byte{}, tagN...), sid...), u32(i)...), rng.Bytes(SymBytes)...))
		if err != nil {
			return nil, nil, err
		}
		h, err := hpk(sid, i, nSlot)
		if err != nil {
			return nil, nil, err
		}
		cPoint, err := RingSub(pk[:TVecBytes], h)
		if err != nil {
			return nil, nil, err
		}
		if c == 0 {
			m.Points = append(m.Points, [2][]byte{cPoint, nSlot})
		} else {
			m.Points = append(m.Points, [2][]byte{nSlot, cPoint})
		}
		m.Rhos = append(m.Rhos, pk[TVecBytes:])
		st.SecretKeys = append(st.SecretKeys, sk)
		st.Choices = append(st.Choices, c)
	}
	st.Rhos = m.Rhos
	return m, st, nil
}

func validate(m *ReceiverMessage) error {
	if m == nil || len(m.Rn) != SymBytes {
		return abort("malformed session nonce")
	}
	if len(m.Points) != len(m.Rhos) {
		return abort("points/rhos length mismatch")
	}
	for i := range m.Points {
		if len(m.Points[i][0]) != TVecBytes || len(m.Points[i][1]) != TVecBytes {
			return abort("malformed point pair at index %d", i)
		}
		if len(m.Rhos[i]) != PKBytes-TVecBytes {
			return abort("malformed rho at index %d", i)
		}
	}
	return nil
}

// effectiveKey is pk_b = (P_b + Hpk(sid, i, P_{1-b}) || rho).
func effectiveKey(sid []byte, i int, own, other, rho []byte) ([]byte, error) {
	h, err := hpk(sid, i, other)
	if err != nil {
		return nil, err
	}
	t, err := RingAdd(own, h)
	if err != nil {
		return nil, err
	}
	return append(t, rho...), nil
}

// SendRandom is the sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads.
// tamper (test-only, may be nil) corrupts the ciphertexts on the wire.
func SendRandom(m *ReceiverMessage, rng OtRandom, tamper func([][2][]byte)) (*SenderMessage, error) {
	if rng == nil {
		rng = SecureRandom()
	}
	if err := validate(m); err != nil {
		return nil, err
	}
	sid := SessionID(m.Rn)
	sm := &SenderMessage{}
	for i := range m.Points {
		p0, p1, rho := m.Points[i][0], m.Points[i][1], m.Rhos[i]
		pk0, err := effectiveKey(sid, i, p0, p1, rho)
		if err != nil {
			return nil, err
		}
		pk1, err := effectiveKey(sid, i, p1, p0, rho)
		if err != nil {
			return nil, err
		}
		r0, r1 := rng.Bytes(SymBytes), rng.Bytes(SymBytes)
		ct0, err := KPKEEnc(pk0, r0, rng.Bytes(SymBytes))
		if err != nil {
			return nil, err
		}
		ct1, err := KPKEEnc(pk1, r1, rng.Bytes(SymBytes))
		if err != nil {
			return nil, err
		}
		sm.Ciphertexts = append(sm.Ciphertexts, [2][]byte{ct0, ct1})
		sm.SenderPads = append(sm.SenderPads, [2][]byte{Pad(sid, i, 0, r0, EndemicSecretBytes), Pad(sid, i, 1, r1, EndemicSecretBytes)})
	}
	if tamper != nil {
		tamper(sm.Ciphertexts)
	}
	return sm, nil
}

// RecoverRandom is the receiver recovery (random-OT form): decrypt only the chosen ciphertext.
func RecoverRandom(st *ReceiverState, sm *SenderMessage) ([][]byte, error) {
	if sm == nil || len(sm.Ciphertexts) != len(st.Choices) {
		return nil, abort("ciphertext count does not match the transfer count")
	}
	for i, ct := range sm.Ciphertexts {
		if len(ct[0]) != CTBytes || len(ct[1]) != CTBytes {
			return nil, abort("malformed ciphertext pair at index %d", i)
		}
	}
	out := make([][]byte, len(st.Choices))
	for i, c := range st.Choices {
		payload, err := KPKEDec(st.SecretKeys[i], sm.Ciphertexts[i][c&1])
		if err != nil {
			return nil, err
		}
		out[i] = Pad(st.Sid, i, c&1, payload, EndemicSecretBytes)
	}
	return out, nil
}

// BaseOT is the in-process chosen-message endemic base OT: messages[i] = {m0, m1} of equal length, choices[i] in {0,1}. The sender pads and commits
// each message; the receiver recovers m_{choices[i]} and checks the commitment, aborting on any inconsistency. receiverRng and senderRng are the
// two parties' entropy (nil: the CSPRNG); tamperEncrypted (test-only, may be nil) corrupts the padded messages on the wire.
func BaseOT(messages [][2][]byte, choices []int, receiverRng, senderRng OtRandom, tamperEncrypted func([][2][]byte)) ([][]byte, *Transcript, error) {
	if len(messages) != len(choices) {
		return nil, nil, errors.New("endemicBaseOT: messages/choices length mismatch")
	}
	if senderRng == nil {
		senderRng = SecureRandom()
	}
	m, st, err := Receive(choices, receiverRng)
	if err != nil {
		return nil, nil, err
	}
	tr := &Transcript{Rn: m.Rn, Points: m.Points, Rhos: m.Rhos}
	for i, msg := range messages {
		m0, m1 := msg[0], msg[1]
		if len(m0) != len(m1) {
			return nil, nil, fmt.Errorf("endemicBaseOT (index %d): the two messages must be equal length", i)
		}
		p0, p1, rho := m.Points[i][0], m.Points[i][1], m.Rhos[i]
		r0, r1 := senderRng.Bytes(SymBytes), senderRng.Bytes(SymBytes)
		pk0, err := effectiveKey(st.Sid, i, p0, p1, rho)
		if err != nil {
			return nil, nil, err
		}
		pk1, err := effectiveKey(st.Sid, i, p1, p0, rho)
		if err != nil {
			return nil, nil, err
		}
		ct0, err := KPKEEnc(pk0, r0, senderRng.Bytes(SymBytes))
		if err != nil {
			return nil, nil, err
		}
		ct1, err := KPKEEnc(pk1, r1, senderRng.Bytes(SymBytes))
		if err != nil {
			return nil, nil, err
		}
		tr.Ciphertexts = append(tr.Ciphertexts, [2][]byte{ct0, ct1})
		pad0, pad1 := Pad(st.Sid, i, 0, r0, len(m0)), Pad(st.Sid, i, 1, r1, len(m1))
		tr.Encrypted = append(tr.Encrypted, [2][]byte{xor(m0, pad0), xor(m1, pad1)})
		tr.Commitments = append(tr.Commitments, [2][]byte{commit(st.Sid, i, 0, m0, pad0), commit(st.Sid, i, 1, m1, pad1)})
	}
	if tamperEncrypted != nil {
		tamperEncrypted(tr.Encrypted)
	}
	received := make([][]byte, len(messages))
	for i, c := range st.Choices {
		payload, err := KPKEDec(st.SecretKeys[i], tr.Ciphertexts[i][c])
		if err != nil {
			return nil, nil, err
		}
		e := tr.Encrypted[i][c]
		pad := Pad(st.Sid, i, c, payload, len(e))
		mm := xor(e, pad)
		if subtle.ConstantTimeCompare(commit(st.Sid, i, c, mm, pad), tr.Commitments[i][c]) != 1 {
			return nil, nil, abort("endemic base OT (index %d): sender ciphertext inconsistent with its commitment; aborting", i)
		}
		received[i] = mm
	}
	return received, tr, nil
}
