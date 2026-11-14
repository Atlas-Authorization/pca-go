package pca

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

const g11Now = int64(1_700_000_000_000)

type g11Log struct {
	priv ed25519.PrivateKey
	key  string
}

func g11NewLog() g11Log {
	seed := make([]byte, 32)
	seed[0] = 11
	priv := ed25519.NewKeyFromSeed(seed)
	return g11Log{priv: priv, key: b64.EncodeToString(priv.Public().(ed25519.PublicKey))}
}

func (l g11Log) trust() AnchorTrust {
	return AnchorTrust{LogKey: l.key, InstanceID: "ins", Principal: "p"}
}

// signed returns a signed tree head over exactly these values.
func (l g11Log) signed(inst, prin, root, prev string, size, ts int64) map[string]any {
	body, err := Canonicalize(map[string]any{"instance_id": inst, "principal": prin, "size": json.Number(anchorNum(size)),
		"root": root, "prev_root": prev, "timestamp": json.Number(anchorNum(ts))})
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(l.priv, append([]byte(sthDomain), body...))
	return map[string]any{"instance_id": inst, "principal": prin, "size": json.Number(anchorNum(size)), "root": root,
		"prev_root": prev, "timestamp": json.Number(anchorNum(ts)), "guardian": l.key, "sig": b64.EncodeToString(sig)}
}

func g11Digest(s string) string {
	d, err := HashCanonical(s)
	if err != nil {
		panic(err)
	}
	return d
}

func g11EntryMap(e AnchorEntry) map[string]any {
	return map[string]any{"issuer": e.Issuer, "version": json.Number(anchorNum(e.Version)), "digest": e.Digest}
}

func g11LeafOf(e AnchorEntry) []byte {
	c, err := anchorCommit(e)
	if err != nil {
		panic(err)
	}
	h, err := leafHash(c)
	if err != nil {
		panic(err)
	}
	return h
}

// g11Incl is the RFC 6962 audit path (leaf to root) for leaf idx.
func g11Incl(hs [][]byte, idx int) []any {
	if len(hs) == 1 {
		return []any{}
	}
	k := split(len(hs))
	if idx < k {
		return append(g11Incl(hs[:k], idx), map[string]any{"side": "R", "hash": b64.EncodeToString(build(hs[k:]))})
	}
	return append(g11Incl(hs[k:], idx-k), map[string]any{"side": "L", "hash": b64.EncodeToString(build(hs[:k]))})
}

// g11Cons is the RFC 6962 consistency proof PROOF(m, hs).
func g11Cons(m int, hs [][]byte, whole bool) [][]byte {
	n := len(hs)
	if m == n {
		if whole {
			return nil
		}
		return [][]byte{build(hs)}
	}
	k := split(n)
	if m <= k {
		return append(g11Cons(m, hs[:k], whole), build(hs[k:]))
	}
	return append(g11Cons(m-k, hs[k:], false), build(hs[:k]))
}

func g11Strs(bs [][]byte) []any {
	out := make([]any, len(bs))
	for i, b := range bs {
		out[i] = b64.EncodeToString(b)
	}
	return out
}

// g11Evidence: a log of entries, a head of that size at ts, and the inclusion proof of entries[mine].
func (l g11Log) evidence(entries []AnchorEntry, mine int, ts int64) map[string]any {
	hs := make([][]byte, len(entries))
	feed := make([]any, len(entries))
	for i, e := range entries {
		hs[i], feed[i] = g11LeafOf(e), g11EntryMap(e)
	}
	root := b64.EncodeToString(build(hs))
	return map[string]any{
		"head":    l.signed("ins", "p", root, emptyTreeRoot(), int64(len(entries)), ts),
		"entries": feed,
		"proof":   map[string]any{"index": json.Number(anchorNum(int64(mine))), "size": json.Number(anchorNum(int64(len(entries)))), "path": g11Incl(hs, mine)},
	}
}

func g11WantAnchor(t *testing.T, name string, got AnchorResult, ok bool, code string, highest int64) {
	t.Helper()
	if got.Ok != ok || got.Code != code || got.HighestAnchoredVersion != highest {
		t.Fatalf("%s: %+v want ok=%v code=%q highest=%d", name, got, ok, code, highest)
	}
}

// ---- readHead ---------------------------------------------------------------------------------------------------------

func TestG11ReadHead(t *testing.T) {
	l := g11NewLog()
	root := g11Digest("r")
	h, ok := readHead(l.signed("ins", "p", root, "prev", 5, 77), l.key)
	if !ok || h.instanceID != "ins" || h.principal != "p" || h.root != root || h.prevRoot != "prev" || h.guardian != l.key || h.size != 5 || h.timestamp != 77 {
		t.Fatalf("%+v %v", h, ok)
	}
	if _, ok := readHead("x", l.key); ok {
		t.Fatal("a non-object head")
	}
	withAlg := l.signed("ins", "p", root, "prev", 5, 77)
	withAlg["alg"] = "ml-dsa-65"
	if _, ok := readHead(withAlg, l.key); ok {
		t.Fatal("a head naming a suite")
	}
	// each field missing, the signature made over its zero value: refused because it is missing, not because of the signature
	for _, tc := range []struct {
		field string
		head  map[string]any
	}{
		{"instance_id", l.signed("", "p", root, "prev", 5, 77)},
		{"principal", l.signed("ins", "", root, "prev", 5, 77)},
		{"root", l.signed("ins", "p", "", "prev", 5, 77)},
		{"prev_root", l.signed("ins", "p", root, "", 5, 77)},
		{"size", l.signed("ins", "p", root, "prev", 0, 77)},
		{"timestamp", l.signed("ins", "p", root, "prev", 5, 0)},
	} {
		if _, ok := readHead(tc.head, l.key); !ok {
			t.Fatalf("%s: the zero-valued control must verify", tc.field)
		}
		delete(tc.head, tc.field)
		if _, ok := readHead(tc.head, l.key); ok {
			t.Errorf("a head without %s was accepted", tc.field)
		}
	}
	badSig := l.signed("ins", "p", root, "prev", 5, 77)
	badSig["sig"] = "AAAA"
	if _, ok := readHead(badSig, l.key); ok {
		t.Fatal("a short signature")
	}
	tampered := l.signed("ins", "p", root, "prev", 5, 77)
	tampered["root"] = g11Digest("other")
	if _, ok := readHead(tampered, l.key); ok {
		t.Fatal("a signature over other values")
	}
}

// ---- anchorEntryOf ----------------------------------------------------------------------------------------------------

func TestG11AnchorEntryOf(t *testing.T) {
	dig := g11Digest("d")
	mk := func(iss any, ver any, d any) map[string]any {
		return map[string]any{"issuer": iss, "version": ver, "digest": d}
	}
	one := json.Number("1")
	if e, ok := anchorEntryOf(mk("a", json.Number("7"), dig)); !ok || e != (AnchorEntry{Issuer: "a", Version: 7, Digest: dig}) {
		t.Fatalf("%+v %v", e, ok)
	}
	for name, v := range map[string]any{
		"not an object":    "x",
		"four members":     map[string]any{"issuer": "a", "version": one, "digest": dig, "x": 1},
		"issuer number":    mk(json.Number("5"), one, dig),
		"digest number":    mk("a", one, json.Number("5")),
		"version string":   mk("a", "1", dig),
		"empty issuer":     mk("", one, dig),
		"issuer 201 chars": mk(strings.Repeat("i", 201), one, dig),
		"version 0":        mk("a", json.Number("0"), dig),
		"bad digest":       mk("a", one, dig[:42]),
	} {
		if e, ok := anchorEntryOf(v); ok || e != (AnchorEntry{}) {
			t.Errorf("%s: accepted %+v", name, e)
		}
	}
	for name, v := range map[string]any{
		"issuer 200 chars": mk(strings.Repeat("i", 200), one, dig),
		"issuer 1 char":    mk("i", one, dig),
		"version 1":        mk("a", one, dig),
	} {
		if _, ok := anchorEntryOf(v); !ok {
			t.Errorf("%s: refused", name)
		}
	}
}

// ---- verifyConsistency ------------------------------------------------------------------------------------------------

func TestG11VerifyConsistencyExhaustive(t *testing.T) {
	leaves := make([][]byte, 34)
	for i := range leaves {
		leaves[i] = sha([]byte{0, byte(i)})
	}
	for n := 1; n <= 33; n++ {
		for m := 1; m <= n; m++ {
			hs := leaves[:n]
			o, r := b64.EncodeToString(build(hs[:m])), b64.EncodeToString(build(hs))
			p := g11Strs(g11Cons(m, hs, true))
			if !verifyConsistency(o, r, int64(m), int64(n), p) {
				t.Fatalf("valid proof %d->%d refused", m, n)
			}
			if m == n {
				continue
			}
			if verifyConsistency(o, b64.EncodeToString(build(leaves[:n+1])), int64(m), int64(n), p) {
				t.Fatalf("%d->%d: wrong new root accepted", m, n)
			}
			for i := range p {
				q := append([]any(nil), p...)
				q[i] = b64.EncodeToString(sha([]byte{'x', byte(i)}))
				if verifyConsistency(o, r, int64(m), int64(n), q) {
					t.Fatalf("%d->%d: tampered node %d accepted", m, n, i)
				}
			}
			if len(p) > 0 && verifyConsistency(o, r, int64(m), int64(n), p[:len(p)-1]) {
				t.Fatalf("%d->%d: truncated proof accepted", m, n)
			}
			if verifyConsistency(o, r, int64(m), int64(n), append(append([]any(nil), p...), b64.EncodeToString(leaves[0]))) {
				t.Fatalf("%d->%d: extended proof accepted", m, n)
			}
		}
	}
}

func TestG11VerifyConsistencyEdges(t *testing.T) {
	empty := emptyTreeRoot()
	x := b64.EncodeToString(sha([]byte("x")))
	y := b64.EncodeToString(sha([]byte("y")))
	l0, l1 := sha([]byte{0, 0}), sha([]byte{0, 1})
	for i, tc := range []struct {
		old, nw string
		m, n    int64
		path    []any
		want    bool
	}{
		{x, x, 2, 1, []any{}, false},        // old larger than new
		{x, x, -1, 1, []any{}, false},       // negative old size
		{empty, x, 0, 3, []any{}, true},     // from the empty tree anything follows
		{empty, x, 0, 1, []any{}, true},     // ... including size 1
		{empty, x, 0, 3, []any{x}, false},   // ... with an empty proof
		{x, y, 0, 3, []any{}, false},        // ... from the real empty root
		{empty, empty, 0, 0, []any{}, true}, // empty to empty
		{empty, x, 0, 0, []any{}, false},    // empty to a non-empty root at size 0
		{x, x, 3, 3, []any{}, true},         // same size, same root
		{x, y, 3, 3, []any{}, false},        // same size, other root
		{x, x, 3, 3, []any{x}, false},       // same size with a proof
		{x, y, 1, 2, []any{}, false},        // a proof is needed
		{x, y, 3, 4, []any{}, false},        // no nodes at all
		{x, y, 1, 2, []any{json.Number("1")}, false},
		{"!", y, 1, 2, []any{x}, false}, // an undecodable old root that is a node
		// an undecodable node is refused, never hashed as empty
		{b64.EncodeToString(l0), b64.EncodeToString(nodeHash(l0, nil)), 1, 2, []any{"!"}, false},
		{b64.EncodeToString(l0), b64.EncodeToString(nodeHash(l0, l1)), 1, 2, []any{b64.EncodeToString(l1)}, true},
	} {
		if got := verifyConsistency(tc.old, tc.nw, tc.m, tc.n, tc.path); got != tc.want {
			t.Errorf("case %d: %v want %v", i, got, tc.want)
		}
	}

	// a node past the end of a valid proof is refused even when the roots are recomputed over it
	leaves := [][]byte{sha([]byte{1}), sha([]byte{2}), sha([]byte{3}), sha([]byte{4}), sha([]byte{5})}
	p := g11Strs(g11Cons(3, leaves, true))
	extra := sha([]byte("extra"))
	o2 := b64.EncodeToString(nodeHash(extra, build(leaves[:3])))
	r2 := b64.EncodeToString(nodeHash(extra, build(leaves)))
	if verifyConsistency(o2, r2, 3, 5, append(p, b64.EncodeToString(extra))) {
		t.Fatal("a trailing node was absorbed")
	}
}

// identical leaves let a proof for a tree of 2^63-1 leaves be computed in O(log n): every subtree of size k has one root.
func TestG11VerifyConsistencyLongProof(t *testing.T) {
	leaf := sha([]byte("leaf"))
	memo := map[uint64][]byte{}
	var mth func(n uint64) []byte
	mth = func(n uint64) []byte {
		if n == 1 {
			return leaf
		}
		if h, ok := memo[n]; ok {
			return h
		}
		k := uint64(1)
		for k*2 < n {
			k *= 2
		}
		h := nodeHash(mth(k), mth(n-k))
		memo[n] = h
		return h
	}
	var sub func(m, n uint64, whole bool) []any
	sub = func(m, n uint64, whole bool) []any {
		if m == n {
			if whole {
				return nil
			}
			return []any{b64.EncodeToString(mth(n))}
		}
		k := uint64(1)
		for k*2 < n {
			k *= 2
		}
		if m <= k {
			return append(sub(m, k, whole), b64.EncodeToString(mth(n-k)))
		}
		return append(sub(m-k, n-k, false), b64.EncodeToString(mth(k)))
	}
	const n = uint64(1<<63 - 1)
	for _, m := range []uint64{3, 1<<61 + 1} {
		p := sub(m, n, true)
		if len(p) != 64 {
			t.Fatalf("proof length %d", len(p))
		}
		if !verifyConsistency(b64.EncodeToString(mth(m)), b64.EncodeToString(mth(n)), int64(m), int64(n), p) {
			t.Fatalf("the 64-node proof %d -> %d was refused", m, n)
		}
	}
}

// ---- the seams ---------------------------------------------------------------------------------------------------------

func TestG11AnchorVerdict(t *testing.T) {

	d := map[int64]string{1: "a", 2: "b"}
	g11WantAnchor(t, "ok", anchorVerdict(AnchorEntry{Version: 2, Digest: "b"}, d, 2), true, "", 2)
	g11WantAnchor(t, "rollback", anchorVerdict(AnchorEntry{Version: 1, Digest: "a"}, d, 2), false, "anchored-rollback", 0)
	g11WantAnchor(t, "other digest", anchorVerdict(AnchorEntry{Version: 2, Digest: "c"}, d, 2), false, "not-anchored", 0)
	g11WantAnchor(t, "absent version", anchorVerdict(AnchorEntry{Version: 3, Digest: "c"}, d, 2), false, "not-anchored", 0)
}

// ---- VerifyAllowlistAnchored ------------------------------------------------------------------------------------------

func TestG11AnchoredSkewAndHighest(t *testing.T) {
	l := g11NewLog()
	a1 := AnchorEntry{Issuer: "A", Version: 1, Digest: g11Digest("1")}
	neg := int64(-5)
	opts := AnchorOptions{Trust: l.trust(), NowMs: g11Now, ClockSkewMs: &neg}
	// a negative skew counts as zero
	g11WantAnchor(t, "now", VerifyAllowlistAnchored(a1, l.evidence([]AnchorEntry{a1}, 0, g11Now), opts), true, "", 1)
	g11WantAnchor(t, "now+1", VerifyAllowlistAnchored(a1, l.evidence([]AnchorEntry{a1}, 0, g11Now+1), opts), false, "stale-head", 0)

	// the highest anchored version is the maximum, not the last one seen
	a3 := AnchorEntry{Issuer: "A", Version: 3, Digest: g11Digest("3")}
	b9 := AnchorEntry{Issuer: "B", Version: 9, Digest: g11Digest("9")}
	g11WantAnchor(t, "highest", VerifyAllowlistAnchored(a3, l.evidence([]AnchorEntry{a3, b9, a1}, 0, g11Now), AnchorOptions{Trust: l.trust(), NowMs: g11Now}), true, "", 3)
}

func TestG11AnchoredCacheConsistencyFields(t *testing.T) {
	l := g11NewLog()
	a1 := AnchorEntry{Issuer: "A", Version: 1, Digest: g11Digest("1")}
	cached := l.signed("ins", "p", emptyTreeRoot(), emptyTreeRoot(), 0, g11Now-1000)
	opts := AnchorOptions{Trust: l.trust(), NowMs: g11Now, CachedHead: cached}
	run := func(c map[string]any) AnchorResult {
		ev := l.evidence([]AnchorEntry{a1}, 0, g11Now)
		ev["consistency"] = c
		return VerifyAllowlistAnchored(a1, ev, opts)
	}
	g11WantAnchor(t, "control", run(map[string]any{"oldSize": json.Number("0"), "newSize": json.Number("1"), "path": []any{}}), true, "", 1)
	g11WantAnchor(t, "no oldSize", run(map[string]any{"newSize": json.Number("1"), "path": []any{}}), false, "inconsistent-with-cache", 0)
}

func TestG11AnchoredFeedAndProofSize(t *testing.T) {
	l := g11NewLog()
	e0 := AnchorEntry{Issuer: "A", Version: 1, Digest: g11Digest("a")}
	e1 := AnchorEntry{Issuer: "B", Version: 1, Digest: g11Digest("b")}
	e2 := AnchorEntry{Issuer: "C", Version: 1, Digest: g11Digest("c")}
	opts := AnchorOptions{Trust: l.trust(), NowMs: g11Now}

	// a head that claims 3 leaves over the root of a 2-entry feed, with a proof that fits that root: the size mismatch decides
	l0, l1 := g11LeafOf(e0), g11LeafOf(e1)
	ev := map[string]any{
		"head":    l.signed("ins", "p", b64.EncodeToString(nodeHash(l0, l1)), emptyTreeRoot(), 3, g11Now),
		"entries": []any{g11EntryMap(e0), g11EntryMap(e1)},
		"proof":   map[string]any{"index": json.Number("2"), "size": json.Number("3"), "path": []any{map[string]any{"side": "L", "hash": b64.EncodeToString(l0)}}},
	}
	g11WantAnchor(t, "short feed", VerifyAllowlistAnchored(e1, ev, opts), false, "feed-mismatch", 0)

	// a proof declaring size 4 for a 3-leaf head: index 0 has the same path shape in both, the declared size decides
	ev = l.evidence([]AnchorEntry{e0, e1, e2}, 0, g11Now)
	g11WantAnchor(t, "control", VerifyAllowlistAnchored(e0, ev, opts), true, "", 1)
	ev["proof"].(map[string]any)["size"] = json.Number("4")
	g11WantAnchor(t, "proof size", VerifyAllowlistAnchored(e0, ev, opts), false, "bad-proof", 0)
}

// the feed bound is exactly anchorMaxFeed entries; identical entries keep the test-side tree O(log n)
func TestG11AnchoredFeedBound(t *testing.T) {
	l := g11NewLog()
	e := AnchorEntry{Issuer: "A", Version: 1, Digest: g11Digest("a")}
	leaf := g11LeafOf(e)
	memo := map[int][]byte{}
	var mth func(n int) []byte
	mth = func(n int) []byte {
		if n == 1 {
			return leaf
		}
		if h, ok := memo[n]; ok {
			return h
		}
		k := split(n)
		h := nodeHash(mth(k), mth(n-k))
		memo[n] = h
		return h
	}
	em := g11EntryMap(e)
	for _, tc := range []struct {
		n    int
		ok   bool
		code string
	}{{100_000, true, ""}, {100_001, false, "feed-mismatch"}} {
		// index 0: every sibling is a right subtree
		var path []any
		for n := tc.n; n > 1; n = split(n) {
			path = append([]any{map[string]any{"side": "R", "hash": b64.EncodeToString(mth(n - split(n)))}}, path...)
		}
		feed := make([]any, tc.n)
		for i := range feed {
			feed[i] = em
		}
		ev := map[string]any{
			"head":    l.signed("ins", "p", b64.EncodeToString(mth(tc.n)), emptyTreeRoot(), int64(tc.n), g11Now),
			"entries": feed,
			"proof":   map[string]any{"index": json.Number("0"), "size": json.Number(anchorNum(int64(tc.n))), "path": path},
		}
		var hi int64
		if tc.ok {
			hi = 1
		}
		g11WantAnchor(t, anchorNum(int64(tc.n)), VerifyAllowlistAnchored(e, ev, AnchorOptions{Trust: l.trust(), NowMs: g11Now}), tc.ok, tc.code, hi)
	}
}
