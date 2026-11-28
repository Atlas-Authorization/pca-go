package pca

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

func roundsMsgs(n int) []MpcOtPair {
	out := make([]MpcOtPair, n)
	for i := range out {
		out[i] = MpcOtPair{bytes.Repeat([]byte{byte(i)}, 16), bytes.Repeat([]byte{byte(0xA0 + i)}, 16)}
	}
	return out
}

func TestMpcKemRoundsAgreeWithTheSimulators(t *testing.T) {
	choices := []int{1, 0, 1, 1}
	m := roundsMsgs(4)
	r := MpcOtRandomFromSeed(big.NewInt(12345))
	rm, st, err := MpcKemBaseOtReceive(choices, r)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := MpcKemBaseOtSend(m, rm, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MpcKemBaseOtOpen(st, sm)
	if err != nil {
		t.Fatal(err)
	}
	sim, err := MpcKemBaseOT(m, choices, MpcOtRandomFromSeed(big.NewInt(12345)))
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range choices {
		if !bytes.Equal(got[i], sim.Received[i]) || !bytes.Equal(got[i], m[i][c]) {
			t.Fatalf("transfer %d differs from the simulator", i)
		}
		if !bytes.Equal(rm.PublicKeys[i][0], sim.Transcript.PublicKeys[i][0]) || !bytes.Equal(sm.Encrypted[i][1], sim.Transcript.Encrypted[i][1]) {
			t.Fatalf("transcript %d differs from the simulator", i)
		}
	}
}

func TestMpcKemCommittedRoundsAndAbort(t *testing.T) {
	choices := []int{0, 1, 1}
	m := roundsMsgs(3)
	r := MpcOtRandomFromSeed(big.NewInt(777))
	commit, st, err := MpcKemBaseOtMalCommit(choices, r)
	if err != nil {
		t.Fatal(err)
	}
	nonce := MpcKemBaseOtMalSenderNonce(r)
	opening := MpcKemBaseOtMalOpen(st)
	sm, err := MpcKemBaseOtMalSend(m, commit, nonce, opening, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MpcKemBaseOtMalRecover(st, nonce, sm, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range choices {
		if !bytes.Equal(got[i], m[i][c]) {
			t.Fatalf("transfer %d recovered the wrong message", i)
		}
	}
	bad := MpcKemBaseOtMalOpen(st)
	bad.PublicKeys[1][0], bad.PublicKeys[1][1] = bad.PublicKeys[1][1], bad.PublicKeys[1][0]
	var abort *MpcKemBaseOtAbort
	if _, err := MpcKemBaseOtMalSend(m, commit, nonce, bad, r); !errors.As(err, &abort) {
		t.Fatalf("a swapped opening must abort, got %v", err)
	}
	rs, err := MpcKemBaseOtMalRandomSend(commit, nonce, opening, r)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := MpcKemBaseOtMalRandomRecover(st, nonce, rs, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range choices {
		if !bytes.Equal(recv[i], rs.SenderSecrets[i][c]) {
			t.Fatalf("random transfer %d recovered the wrong secret", i)
		}
	}
	wrong, err := MpcKemBaseOtMalRandomRecover(st, nonce, rs, func(b []byte) []byte { b[0] ^= 1; return b })
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrong[0], rs.SenderSecrets[0][choices[0]]) {
		t.Fatal("a tampered receiver session id must change the secret")
	}
}

func TestMpcHybridRoundsRoundtripAndAbort(t *testing.T) {
	choices := []int{1, 0}
	m := roundsMsgs(2)
	sid := []byte("sid")
	ec := []MpcOtPair{{bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{9}, 32)}, {bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{10}, 32)}}
	kem := []MpcOtPair{{bytes.Repeat([]byte{20}, 32), bytes.Repeat([]byte{30}, 32)}, {bytes.Repeat([]byte{21}, 32), bytes.Repeat([]byte{31}, 32)}}
	sm, err := MpcHybridSenderEncrypt(sid, m, ec, kem)
	if err != nil {
		t.Fatal(err)
	}
	ecR, kemR := [][]byte{ec[0][1], ec[1][0]}, [][]byte{kem[0][1], kem[1][0]}
	got, err := MpcHybridReceiverRecover(sid, choices, sm, ecR, kemR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[0], m[0][1]) || !bytes.Equal(got[1], m[1][0]) {
		t.Fatal("the hybrid receiver recovered the wrong messages")
	}
	sm.Encrypted[0][1][0] ^= 1
	var abort *MpcHybridOtAbort
	if _, err := MpcHybridReceiverRecover(sid, choices, sm, ecR, kemR); !errors.As(err, &abort) {
		t.Fatalf("a tampered ciphertext must abort, got %v", err)
	}
}
