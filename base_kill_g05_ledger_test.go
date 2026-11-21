package pca

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
)

// g05: ledger.go guards and boundaries the corpus leaves open: RFC 9162 consistency over every (m, n) with n <= 16, each
// malformed-input guard with an input the rest of the function would otherwise accept, tree heads, witnessed heads,
// cosignatures and the k-of-n count.

func g05Key(t *testing.T, b byte) *KeyPair {
	t.Helper()
	k, err := KeyPairFromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func g05Sign(t *testing.T, k *KeyPair, domain string, body any) string {
	t.Helper()
	s, err := signBody(k, domain, body)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func g05N(i int) json.Number { return json.Number(strconv.Itoa(i)) }

// ---- an RFC 9162 tree over leaf hashes sha([i]) and its consistency proofs (section 2.1.4.1) ----

func g05KOf(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func g05MTH(d [][]byte) []byte {
	if len(d) == 1 {
		return d[0]
	}
	k := g05KOf(len(d))
	return nodeHash(g05MTH(d[:k]), g05MTH(d[k:]))
}

func g05Sub(m int, d [][]byte, b bool) [][]byte {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{g05MTH(d)}
	}
	k := g05KOf(n)
	if m <= k {
		return append(g05Sub(m, d[:k], b), g05MTH(d[k:]))
	}
	return append(g05Sub(m-k, d[k:], false), g05MTH(d[:k]))
}

func g05Leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = sha([]byte{byte(i)})
	}
	return out
}

func g05Root(n int) string { return b64.EncodeToString(g05MTH(g05Leaves(n))) }

func g05Cons(m, n int) map[string]any {
	path := []any{}
	for _, h := range g05Sub(m, g05Leaves(n), true) {
		path = append(path, b64.EncodeToString(h))
	}
	return map[string]any{"oldSize": g05N(m), "newSize": g05N(n), "path": path}
}

func TestG05LedgerConsistencyEveryTree(t *testing.T) {
	for n := 2; n <= 16; n++ {
		for m := 1; m < n; m++ {
			if !VerifyLedgerConsistency(g05Root(m), g05Root(n), g05Cons(m, n)) {
				t.Fatalf("a genuine %d -> %d consistency proof was refused", m, n)
			}
		}
		// equal sizes: an empty path between equal roots
		if !VerifyLedgerConsistency(g05Root(n), g05Root(n), map[string]any{"oldSize": g05N(n), "newSize": g05N(n), "path": []any{}}) {
			t.Fatalf("%d -> %d with equal roots was refused", n, n)
		}
	}
}

func TestG05LedgerConsistencyGuards(t *testing.T) {
	vac := func() map[string]any { return map[string]any{"oldSize": g05N(0), "newSize": g05N(3), "path": []any{}} }
	if !VerifyLedgerConsistency(EmptyTreeRoot, g05Root(3), vac()) {
		t.Fatal("0 -> 3 is vacuously consistent")
	}
	if VerifyLedgerConsistency(EmptyTreeRoot, g05N(3), vac()) {
		t.Fatal("a non-string new root verified")
	}
	if VerifyLedgerConsistency(g05N(3), g05Root(3), vac()) {
		t.Fatal("a non-string old root verified")
	}
	noOld := vac()
	delete(noOld, "oldSize")
	if VerifyLedgerConsistency(EmptyTreeRoot, g05Root(3), noOld) {
		t.Fatal("a proof without oldSize verified")
	}
	noPath := vac()
	delete(noPath, "path")
	if VerifyLedgerConsistency(EmptyTreeRoot, g05Root(3), noPath) {
		t.Fatal("a proof without a path verified")
	}
	// a power-of-two old size takes the old root as the first path element: it must decode
	if !VerifyLedgerConsistency(g05Root(2), g05Root(3), g05Cons(2, 3)) {
		t.Fatal("2 -> 3")
	}
	if VerifyLedgerConsistency("!!", g05Root(3), g05Cons(2, 3)) {
		t.Fatal("an undecodable old root verified")
	}
	// 1 -> 2: new root = H(old, path[0]). Every node must be a 32-byte hash: an empty or undecodable element is refused
	// even when the new root is H(old, <no bytes>), which is what a missing length / decode check would compute
	orB := sha([]byte("old"))
	c := sha([]byte("c"))
	or, nr, nrNil := b64.EncodeToString(orB), b64.EncodeToString(nodeHash(orB, c)), b64.EncodeToString(nodeHash(orB, nil))
	p := func(e any) map[string]any {
		return map[string]any{"oldSize": g05N(1), "newSize": g05N(2), "path": []any{e}}
	}
	if !VerifyLedgerConsistency(or, nr, p(b64.EncodeToString(c))) {
		t.Fatal("1 -> 2 with a 32-byte element")
	}
	if VerifyLedgerConsistency(or, nrNil, p("")) {
		t.Fatal("1 -> 2 with an empty element verified")
	}
	if VerifyLedgerConsistency(or, nrNil, p("!")) {
		t.Fatal("an undecodable path element verified")
	}
	if VerifyLedgerConsistency(or, nrNil, p(g05N(5))) {
		t.Fatal("a non-string path element verified")
	}
}

// ---- guardian-signed tree heads ----

func g05Head(t *testing.T, g *KeyPair, size int, root, prev string) map[string]any {
	t.Helper()
	body := map[string]any{"instance_id": "ins", "principal": "p", "size": g05N(size), "root": root, "prev_root": prev, "timestamp": g05N(1)}
	h := copyMap(body)
	h["guardian"] = g.Public
	h["sig"] = g05Sign(t, g, sthDomain, body)
	return h
}

func TestG05LedgerHeadConsistencySizesBound(t *testing.T) {
	g := g05Key(t, 0x51)
	newer := g05Head(t, g, 4, g05Root(4), g05Root(3))
	older := g05Head(t, g, 3, g05Root(3), "q")
	if !VerifyHeadConsistency(older, newer, g05Cons(3, 4), g.Public, nil) {
		t.Fatal("genuine adjacent heads refused")
	}
	// the older head claims size 2 over the size-3 root; the proof connects 3 -> 4, not the claimed sizes
	lying := g05Head(t, g, 2, g05Root(3), "q")
	if VerifyHeadConsistency(lying, newer, g05Cons(3, 4), g.Public, nil) {
		t.Fatal("a proof for other sizes than the heads' verified")
	}
}

func TestG05LedgerCheckpointChain(t *testing.T) {
	g := g05Key(t, 0x52)
	h3 := g05Head(t, g, 3, g05Root(3), "q")
	h4 := g05Head(t, g, 4, g05Root(4), g05Root(3))
	if v := VerifyCheckpointChain([]any{map[string]any{"sth": h3}}, g.Public, nil); v != (CheckpointVerdict{true, 0}) {
		t.Fatalf("single checkpoint: %+v", v)
	}
	if v := VerifyCheckpointChain([]any{map[string]any{"sth": h3}, map[string]any{"sth": h4, "proof": g05Cons(3, 4)}}, g.Public, nil); v != (CheckpointVerdict{true, 0}) {
		t.Fatalf("two checkpoints: %+v", v)
	}
	if v := VerifyCheckpointChain([]any{map[string]any{"sth": h3}, map[string]any{"sth": h4}}, g.Public, nil); v != (CheckpointVerdict{false, 1}) {
		t.Fatalf("missing proof: %+v", v)
	}
}

// ---- legacy witnessed heads ----

func g05WHead(t *testing.T, w *KeyPair, size int, root string) map[string]any {
	t.Helper()
	body := map[string]any{"principal": "p", "size": g05N(size), "root": root}
	h := copyMap(body)
	h["witness"] = w.Public
	h["sig"] = g05Sign(t, w, ledgerHeadDomain, body)
	return h
}

func TestG05LedgerEquivocationNeedsBothGenuine(t *testing.T) {
	w := g05Key(t, 0x53)
	a, b := g05WHead(t, w, 5, "r1"), g05WHead(t, w, 5, "r2")
	if !DetectEquivocation(a, b, w.Public) {
		t.Fatal("a genuine split view was not detected")
	}
	badA, badB := copyMap(a), copyMap(b)
	badA["sig"], badB["sig"] = b["sig"], a["sig"]
	if DetectEquivocation(badA, b, w.Public) {
		t.Fatal("a forged first head counted as equivocation")
	}
	if DetectEquivocation(a, badB, w.Public) {
		t.Fatal("a forged second head counted as equivocation")
	}
}

func TestG05LedgerWitnessedHeadFailClosed(t *testing.T) {
	w := g05Key(t, 0x54)
	if !VerifyWitnessedHead(g05WHead(t, w, 1, "r"), w.Public) {
		t.Fatal("genuine witnessed head refused")
	}
	// a body that cannot be canonicalized (lone surrogate) is refused, on the Ed25519 and on the PQ path
	lone := map[string]any{"witness": w.Public, "principal": "\xed\xa0\x80", "size": g05N(1), "root": "r", "sig": "AAAA"}
	if VerifyWitnessedHead(lone, w.Public) {
		t.Fatal("an uncanonicalizable body verified (ed25519)")
	}
	lonePQ := copyMap(lone)
	lonePQ["alg"], lonePQ["pq_pk"] = "ml-dsa-65", "K"
	if VerifyWitnessedHead(lonePQ, w.Public, map[string]string{w.Public: "K"}) {
		t.Fatal("an uncanonicalizable body verified (pq)")
	}
	// a head without root is refused even with a signature over the empty body
	noRoot := map[string]any{"witness": w.Public, "principal": "p", "size": g05N(1), "sig": g05Sign(t, w, ledgerHeadDomain, map[string]any(nil))}
	if VerifyWitnessedHead(noRoot, w.Public) {
		t.Fatal("a head without root verified")
	}
}

func TestG05LedgerHybridWitnessPin(t *testing.T) {
	w := g05Key(t, 0x55)
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	h, err := SignArtifact(ledgerHeadDomain, map[string]any{"principal": "p", "size": g05N(1), "root": "r"}, w, &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq})
	if err != nil {
		t.Fatal(err)
	}
	h["witness"] = w.Public
	if !VerifyWitnessedHead(h, w.Public, map[string]string{w.Public: pq.Public}) {
		t.Fatal("hybrid head under its pin refused")
	}
	if VerifyWitnessedHead(h, w.Public, map[string]string{w.Public: "other"}) {
		t.Fatal("hybrid head verified under a different pin")
	}
}

// ---- witness cosignatures ----

func g05Sth() map[string]any {
	return map[string]any{"instance_id": "ins", "principal": "p", "size": g05N(3), "root": "r", "prev_root": "q"}
}

func g05Cosig(t *testing.T, w *KeyPair, sth map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{}
	for _, k := range []string{"instance_id", "principal", "size", "root", "prev_root"} {
		body[k] = sth[k]
	}
	if e, has := sth["guardian_epoch"]; has && e != nil {
		body["guardian_epoch"] = e
	} else {
		body["guardian_epoch"] = 0
	}
	return map[string]any{"key": w.Public, "sig": g05Sign(t, w, sthWitnessDomain, body)}
}

func TestG05LedgerCosignature(t *testing.T) {
	w := g05Key(t, 0x56)
	sth := g05Sth()
	if !VerifyWitnessCosignature(sth, g05Cosig(t, w, sth), w.Public) {
		t.Fatal("genuine cosignature refused")
	}
	// guardian_epoch null binds as 0
	nullEp := g05Sth()
	nullEp["guardian_epoch"] = nil
	if !VerifyWitnessCosignature(nullEp, g05Cosig(t, w, nullEp), w.Public) {
		t.Fatal("a null guardian_epoch must bind as 0")
	}
	short := g05Sth()
	delete(short, "prev_root")
	if VerifyWitnessCosignature(short, map[string]any{"key": w.Public, "sig": "x"}, w.Public) {
		t.Fatal("a head without prev_root verified")
	}
	if VerifyWitnessCosignature(sth, map[string]any{"key": w.Public}, w.Public) {
		t.Fatal("a cosignature without sig verified")
	}
}

func TestG05LedgerCosignatureThreshold(t *testing.T) {
	w1, w2, u := g05Key(t, 0x57), g05Key(t, 0x58), g05Key(t, 0x59)
	pol := func(th int, keys ...string) map[string]any {
		ks := []any{}
		for _, k := range keys {
			ks = append(ks, k)
		}
		return map[string]any{"threshold": g05N(th), "witnessKeys": ks}
	}
	with := func(ws ...map[string]any) map[string]any {
		s := g05Sth()
		l := []any{}
		for _, w := range ws {
			l = append(l, w)
		}
		s["witnesses"] = l
		return s
	}
	base := g05Sth()
	c1, c2, cu := g05Cosig(t, w1, base), g05Cosig(t, w2, base), g05Cosig(t, u, base)
	if VerifyWitnessCosignatures("x", map[string]any{"threshold": g05N(0)}) {
		t.Fatal("a non-object head met threshold 0")
	}
	if !VerifyWitnessCosignatures(with(c1), pol(1, w1.Public)) {
		t.Fatal("1 of 1")
	}
	if !VerifyWitnessCosignatures(with(c1, c2), pol(2, w1.Public, w2.Public)) {
		t.Fatal("2 of 2")
	}
	if VerifyWitnessCosignatures(with(c1), pol(2, w1.Public, w2.Public)) {
		t.Fatal("1 cosignature met threshold 2")
	}
	if VerifyWitnessCosignatures(with(c1, c1), pol(2, w1.Public, w2.Public)) {
		t.Fatal("a duplicate cosignature counted twice")
	}
	if VerifyWitnessCosignatures(with(cu), pol(1, w1.Public)) {
		t.Fatal("an untrusted witness counted")
	}
}
