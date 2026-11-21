package pca

import (
	"encoding/json"
	"math"
	"testing"
)

// w3b: RFC 9162 walks at every (m, n) / (i, n) up to 32 (the shift loop in all verifiers), the head-consistency size gate
// (ledger.ts verifyHeadConsistency), the escalation nonce floor (escalation.ts), and String(n) (ECMAScript Number::toString).

func TestW3bConsistencyEveryTreeAllVerifiers(t *testing.T) {
	for n := 2; n <= 32; n++ {
		nr := g05Root(n)
		for m := 1; m < n; m++ {
			or, proof := g05Root(m), g05Cons(m, n)
			if !VerifyLedgerConsistency(or, nr, proof) {
				t.Fatalf("ledger refused a genuine %d -> %d proof", m, n)
			}
			if !meshConsistency(or, nr, proof) {
				t.Fatalf("mesh refused a genuine %d -> %d proof", m, n)
			}
			if !verifyConsistency(or, nr, int64(m), int64(n), proof["path"].([]any)) {
				t.Fatalf("allowlist anchor refused a genuine %d -> %d proof", m, n)
			}
		}
	}
}

func w3bPath(i int, d [][]byte) [][]byte {
	n := len(d)
	if n == 1 {
		return nil
	}
	k := g05KOf(n)
	if i < k {
		return append(w3bPath(i, d[:k]), g05MTH(d[k:]))
	}
	return append(w3bPath(i-k, d[k:]), g05MTH(d[:k]))
}

func TestW3bInclusionEveryTree(t *testing.T) {
	for n := 1; n <= 32; n++ {
		d := g05Leaves(n)
		root := g05MTH(d)
		for i := 0; i < n; i++ {
			if !VerifyRFC9162Inclusion(d[i], int64(i), int64(n), w3bPath(i, d), root) {
				t.Fatalf("refused a genuine inclusion proof of %d in %d", i, n)
			}
		}
	}
}

// The proof genuinely connects 2 -> 4; only the signed head sizes decide (ledger.ts: proof.oldSize !== older.size ||
// proof.newSize !== newer.size).
func TestW3bHeadConsistencySizeGate(t *testing.T) {
	g := g05Key(t, 0x61)
	old, c := sha([]byte("w3b-old")), sha([]byte("w3b-c"))
	or, nr := b64.EncodeToString(old), b64.EncodeToString(nodeHash(old, c))
	proof := map[string]any{"oldSize": g05N(2), "newSize": g05N(4), "path": []any{b64.EncodeToString(c)}}
	if !VerifyLedgerConsistency(or, nr, proof) {
		t.Fatal("the proof must connect the roots on its own")
	}
	older2, newer4 := g05Head(t, g, 2, or, "q"), g05Head(t, g, 4, nr, or)
	if !VerifyHeadConsistency(older2, newer4, proof, g.Public, nil) {
		t.Fatal("genuine heads refused")
	}
	if VerifyHeadConsistency(g05Head(t, g, 3, or, "q"), newer4, proof, g.Public, nil) {
		t.Fatal("proof.oldSize != older.size verified")
	}
	if VerifyHeadConsistency(older2, g05Head(t, g, 5, nr, or), proof, g.Public, nil) {
		t.Fatal("proof.newSize != newer.size verified")
	}
}

// ledger.ts: !cp.proof is a refusal at that index; so is any other non-object proof.
func TestW3bCheckpointFalsyProof(t *testing.T) {
	g := g05Key(t, 0x62)
	h3, h4 := g05Head(t, g, 3, g05Root(3), "q"), g05Head(t, g, 4, g05Root(4), g05Root(3))
	for _, proof := range []any{nil, false, "", json.Number("0")} {
		chain := []any{map[string]any{"sth": h3}, map[string]any{"sth": h4, "proof": proof}}
		if v := VerifyCheckpointChain(chain, g.Public, nil); v != (CheckpointVerdict{false, 1}) {
			t.Errorf("proof %v: %+v", proof, v)
		}
	}
}

func TestW3bEscalationNonceFloor(t *testing.T) {
	h := b64.EncodeToString(sha([]byte("w3b")))
	answer := func(nonce any) map[string]any {
		return map[string]any{"v": json.Number("1"), "kind": "pca-escalation-answer", "principal": h, "policy_digest": h, "action_digest": h,
			"history_head": h, "decision": "allow", "iat": json.Number("1"), "expires_at": json.Number("2"), "nonce": nonce, "sig": "s"}
	}
	const refused = "nonce must be canonical base64url of at least 16 bytes"
	if e := EscalationAnswerShapeError(answer(b64.EncodeToString(make([]byte, 16)))); e != "" {
		t.Fatalf("a 16-byte nonce: %q", e)
	}
	for _, nonce := range []any{b64.EncodeToString(make([]byte, 15)), "", "not base64!", json.Number("1")} {
		if e := EscalationAnswerShapeError(answer(nonce)); e != refused {
			t.Errorf("nonce %v: %q", nonce, e)
		}
	}
}

// An empty PQPK pins no PQ key: every PQ answer from that principal is refused, even one with an empty pq_pk.
func TestW3bEscalationEmptyPinRefusesPq(t *testing.T) {
	k := g05Key(t, 0x63)
	h := b64.EncodeToString(sha([]byte("w3b")))
	for _, pq := range []string{"", "QQ"} {
		a := map[string]any{"v": json.Number("1"), "kind": "pca-escalation-answer", "principal": k.Public, "policy_digest": h, "action_digest": h,
			"history_head": h, "decision": "allow", "iat": json.Number("1"), "expires_at": json.Number("2"),
			"nonce": b64.EncodeToString(make([]byte, 16)), "sig": "s", "alg": "ml-dsa-65", "pq_pk": pq, "pq_sig": "QQ"}
		bind := EscalationBinding{PolicyDigest: h, ActionDigest: h, HistoryHead: h}
		if r := VerifyEscalationAnswer(a, Ed25519Pins(k.Public), bind, 1); r.OK || r.Reason != "escalation answer signature invalid" {
			t.Errorf("pq_pk %q: %+v", pq, r)
		}
	}
}

// String(n) in the reference's reason templates, for every number a policy can carry.
func TestW3bJsNumStringIsJSString(t *testing.T) {
	for _, c := range []struct {
		f    float64
		want string
	}{{1e-7, "1e-7"}, {1.5e-7, "1.5e-7"}, {0.00001, "0.00001"}, {1234567.5, "1234567.5"}, {1e21, "1e+21"}, {1.5e21, "1.5e+21"},
		{123456789, "123456789"}, {math.Copysign(0, -1), "0"}, {-2.5, "-2.5"}} {
		if got := jsNumString(c.f); got != c.want {
			t.Errorf("jsNumString(%v) = %q, want %q", c.f, got, c.want)
		}
	}
	if got := jsAnyString(json.Number("1234567.5")); got != "1234567.5" {
		t.Errorf("jsAnyString: %q", got)
	}
}
