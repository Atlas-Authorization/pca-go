package pca

import (
	"math"
	"strings"
	"testing"
)

// g07mFx is a self-signed single-domain mesh proof: an n-hop chain, one witnessed head of the domain log holding the
// n capability digests, empty revocation sets, bindings for every non-root hop and a leaf action signed by the tip holder.
type g07mFx struct {
	proof  map[string]any
	trust  map[string]any
	head   map[string]any // the cosigned head object {head, sig, cosigs}
	leaves [][]byte
}

func g07mBuild(t *testing.T, n int) *g07mFx {
	t.Helper()
	chain, keys := mkChain(t, n, nil)
	dom, wit := newKey(t), newKey(t)
	now := int64(1_800_000_000_000)
	digests := make([]any, n)
	for i, c := range chain {
		d, err := CapHash(c.(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		digests[i] = d
	}
	hs := leafHashes(t, digests)
	emptyRev, _ := bindRevRoot(0, emptyRevTree())
	head := map[string]any{"domain": dom.id, "size": jnum(int64(n)), "root": b64.EncodeToString(rootOf(hs)),
		"rev_root": emptyRev, "rev_size": jnum(0), "timestamp": jnum(now)}
	ch := map[string]any{"head": head, "sig": signDomain(t, dom, meshHeadDomain, head),
		"cosigs": []any{map[string]any{"witness": wit.id, "sig": signDomain(t, wit, meshCosigDomain, head)}}}
	hops := make([]any, n)
	for i := range chain {
		sides, sib := treeProof(hs, i)
		ev := map[string]any{"domain": dom.id, "head": jnum(0), "inclusion": proofMap(sides, sib, i, n),
			"revocation": map[string]any{"cap": map[string]any{"size": jnum(0)}, "issuer_key": map[string]any{"size": jnum(0)}}}
		if i > 0 {
			b := map[string]any{"agent": keys[i].id, "domain": dom.id, "role": "agent"}
			ev["binding"] = map[string]any{"agent": keys[i].id, "domain": dom.id, "role": "agent", "sig": signDomain(t, dom, meshBindingDomain, b)}
		}
		hops[i] = ev
	}
	action := map[string]any{"type": "pay", "resource": "/r/1", "service_domain": dom.id, "nonce": "n1", "at": jnum(now)}
	tipHash, err := CapHash(chain[n-1].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"chain": chain, "hops": hops, "heads": []any{ch}, "rev_leaves": []any{}, "action": action,
		"action_sig": signDomain(t, keys[n], meshActionDomain, map[string]any{"action": action, "tip": tipHash})}
	trust := map[string]any{"humanPrincipal": keys[0].id, "witnesses": []any{wit.id}, "threshold": jnum(1), "now": jnum(now),
		"allowedDomains": []any{dom.id}, "rootDomain": dom.id}
	return &g07mFx{proof: proof, trust: trust, head: ch, leaves: hs}
}

func g07mJunk(n int, v func(i int) any) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = v(i)
	}
	return out
}

func g07mStrs(n int, s string) []any { return g07mJunk(n, func(int) any { return s }) }

func TestG07MeshVerifyProofVerdicts(t *testing.T) {
	ok := MeshVerdict{OK: true, Hop: -1}
	fail := func(reason string, hop int) MeshVerdict { return MeshVerdict{Reason: reason, Hop: hop} }
	emptyPin := func(int) any {
		return map[string]any{"domain": "x", "proof": map[string]any{"oldSize": jnum(0), "newSize": jnum(0), "path": []any{}}}
	}
	cases := []struct {
		name string
		n    int
		mut  func(f *g07mFx)
		want MeshVerdict
	}{
		{"valid 1 hop", 1, nil, ok},
		{"valid 2 hops", 2, nil, ok},
		{"proof not an object", 2, func(f *g07mFx) { f.proof = nil }, fail("malformed proof", -1)},
		{"256 pin proofs", 2, func(f *g07mFx) { f.proof["pin_proofs"] = g07mJunk(256, emptyPin) }, ok},
		{"257 pin proofs", 2, func(f *g07mFx) { f.proof["pin_proofs"] = g07mJunk(257, emptyPin) }, fail("malformed pin proofs", -1)},
		{"pin proofs not an array", 2, func(f *g07mFx) { f.proof["pin_proofs"] = "x" }, fail("malformed pin proofs", -1)},
		{"pin proof not an object", 2, func(f *g07mFx) { f.proof["pin_proofs"] = []any{"x"} }, fail("malformed pin proofs", -1)},
		{"pin proof without domain", 2, func(f *g07mFx) {
			f.proof["pin_proofs"] = []any{map[string]any{"proof": map[string]any{"oldSize": jnum(0), "newSize": jnum(0), "path": []any{}}}}
		}, fail("malformed pin proofs", -1)},
		{"pin proof with a bad proof", 2, func(f *g07mFx) {
			f.proof["pin_proofs"] = []any{map[string]any{"domain": "x", "proof": "bad"}}
		}, fail("malformed pin proofs", -1)},
		{"chain of 1 for 2 hops", 2, func(f *g07mFx) { f.proof["chain"] = f.proof["chain"].([]any)[:1] },
			fail("hop evidence count does not match chain length", -1)},
		{"chain of 64 (default bound)", 2, func(f *g07mFx) {
			f.proof["chain"] = g07mJunk(64, func(int) any { return map[string]any{} })
		}, fail("chain: chain too long", -1)},
		{"chain of 65 (default bound)", 2, func(f *g07mFx) {
			f.proof["chain"] = g07mJunk(65, func(int) any { return map[string]any{} })
		}, fail("chain length out of bounds", -1)},
		{"5 revocation leaves for 2 hops", 2, func(f *g07mFx) { f.proof["rev_leaves"] = g07mStrs(5, "x") },
			fail("evidence tables exceed chain size", -1)},
		{"revocation leaf not an object", 2, func(f *g07mFx) { f.proof["rev_leaves"] = []any{"x"} },
			fail("malformed revocation leaves", -1)},
		{"revocation leaf without id", 2, func(f *g07mFx) {
			f.proof["rev_leaves"] = []any{map[string]any{"proof": map[string]any{"index": jnum(0), "size": jnum(1), "path": []any{}}}}
		}, fail("malformed revocation leaves", -1)},
		{"revocation leaf with a bad proof", 2, func(f *g07mFx) {
			f.proof["rev_leaves"] = []any{map[string]any{"id": "a", "proof": "x"}}
		}, fail("malformed revocation leaves", -1)},
		{"inclusion size differs from the head", 2, func(f *g07mFx) {
			// index 2 of a size-3 tree with sibling leaf 0 hashes to the size-2 root: only the size check refuses it
			f.proof["hops"].([]any)[1].(map[string]any)["inclusion"] = map[string]any{"index": jnum(2), "size": jnum(3),
				"path": []any{map[string]any{"side": "L", "hash": b64.EncodeToString(f.leaves[0])}}}
		}, fail("hop not included in the issuing domain log", 1)},
		{"binding role not canonical", 2, func(f *g07mFx) {
			f.proof["hops"].([]any)[1].(map[string]any)["binding"].(map[string]any)["role"] = "\xed\xa0\x80"
		}, fail("malformed proof", -1)},
		{"action nonce not canonical", 2, func(f *g07mFx) {
			f.proof["action"].(map[string]any)["nonce"] = "\xed\xa0\x80"
		}, fail("malformed proof", -1)},
	}
	for _, c := range cases {
		f := g07mBuild(t, c.n)
		if c.mut != nil {
			c.mut(f)
		}
		var proof any = f.proof
		if f.proof == nil {
			proof = "x"
		}
		if got := VerifyMeshProof(proof, f.trust); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
	// a chain that fails the capability-chain policy is reported without a hop
	f := g07mBuild(t, 2)
	ch := f.proof["chain"].([]any)
	f.proof["chain"] = []any{ch[1], ch[0]}
	if got := VerifyMeshProof(f.proof, f.trust); got.OK || got.Hop != -1 || !strings.HasPrefix(got.Reason, "chain: ") {
		t.Errorf("reordered chain: %+v", got)
	}
}

func TestG07MeshRecover(t *testing.T) {
	got := func() (v MeshVerdict) {
		defer meshRecover(&v)
		panic("boom")
	}()
	if got != (MeshVerdict{Reason: "malformed proof", Hop: -1}) {
		t.Errorf("recovered verdict: %+v", got)
	}
}

func TestG07MeshCosignedHead(t *testing.T) {
	f := g07mBuild(t, 1)
	cfg, bad := meshValidTrust(f.trust)
	if bad != "" {
		t.Fatal(bad)
	}
	dom := f.head["head"].(map[string]any)["domain"].(string)
	if got := meshCheckCosignedHead(f.head, dom, cfg, nil); got != "" {
		t.Errorf("valid head: %q", got)
	}
	if got := meshCheckCosignedHead(f.head, "other", cfg, nil); got != "head is for a different domain" {
		t.Errorf("other domain: %q", got)
	}
	cos := f.head["cosigs"].([]any)
	f.head["cosigs"] = append(append([]any{}, cos...), g07mStrs(255, "junk")...)
	if got := meshCheckCosignedHead(f.head, dom, cfg, nil); got != "" {
		t.Errorf("256 cosigs: %q", got)
	}
	f.head["cosigs"] = append(append([]any{}, cos...), g07mStrs(256, "junk")...)
	if got := meshCheckCosignedHead(f.head, dom, cfg, nil); got != "malformed head" {
		t.Errorf("257 cosigs: %q", got)
	}
}

func TestG07MeshShapeHelpers(t *testing.T) {
	if mNum(math.Inf(-1)) || mNum(math.Inf(1)) || !mNum(jnum(5)) {
		t.Error("mNum infinities")
	}
	if _, ok := meshValidHead(map[string]any{"domain": "d", "rev_root": "r", "size": jnum(0), "rev_size": jnum(0), "timestamp": jnum(0)}); ok {
		t.Error("head without root accepted")
	}
	if _, ok := meshValidHead(map[string]any{"domain": "d", "root": "", "rev_root": "r", "size": jnum(0), "rev_size": jnum(0), "timestamp": jnum(0)}); !ok {
		t.Error("empty head refused")
	}
	cons := func(old, nw any, path []any) map[string]any {
		return map[string]any{"oldSize": old, "newSize": nw, "path": path}
	}
	for _, c := range []struct {
		name string
		in   any
		want bool
	}{
		{"ok", cons(jnum(0), jnum(1), []any{}), true},
		{"oldSize bad", cons("x", jnum(1), []any{}), false},
		{"newSize bad", cons(jnum(0), "x", []any{}), false},
		{"path 128", cons(jnum(0), jnum(1), g07mStrs(128, "h")), true},
		{"path 129", cons(jnum(0), jnum(1), g07mStrs(129, "h")), false},
		{"path non-string", cons(jnum(0), jnum(1), []any{jnum(5)}), false},
	} {
		if _, ok := meshValidConsistency(c.in); ok != c.want {
			t.Errorf("consistency %s: %v", c.name, ok)
		}
	}
	incl := func(path []any) map[string]any {
		return map[string]any{"index": jnum(0), "size": jnum(1), "path": path}
	}
	if _, ok := meshValidInclusion(incl(g07mStrs(128, "h"))); !ok {
		t.Error("inclusion path 128 refused")
	}
	if _, ok := meshValidInclusion(incl(g07mStrs(129, "h"))); ok {
		t.Error("inclusion path 129 accepted")
	}
	if meshExpandNM(map[string]any{"size": "x"}, nil) != nil {
		t.Error("non-integer size expanded")
	}
	if meshExpandNM(map[string]any{"size": jnum(0)}, nil) == nil {
		t.Error("size 0 refused")
	}
}

func TestG07MeshNarrows(t *testing.T) {
	type A = meshAuthority
	cases := []struct {
		name          string
		child, parent A
		want          bool
	}{
		{"no caveats", A{}, A{}, true},
		{"actions dropped", A{}, A{hasAct: true, actions: []string{"a"}}, false},
		{"actions widened", A{hasAct: true, actions: []string{"b"}}, A{hasAct: true, actions: []string{"a"}}, false},
		{"actions kept", A{hasAct: true, actions: []string{"a"}}, A{hasAct: true, actions: []string{"a"}}, true},
		{"audience dropped", A{}, A{hasAud: true, audience: []string{"d"}}, false},
		{"audience widened", A{hasAud: true, audience: []string{"e"}}, A{hasAud: true, audience: []string{"d"}}, false},
		{"amount dropped", A{}, A{hasAmount: true, maxAmount: 10}, false},
		{"amount raised", A{hasAmount: true, maxAmount: 20}, A{hasAmount: true, maxAmount: 10}, false},
		{"amount kept", A{hasAmount: true, maxAmount: 10}, A{hasAmount: true, maxAmount: 10}, true},
		{"expiry dropped", A{}, A{hasExp: true, expiresAt: 10}, false},
		{"expiry later", A{hasExp: true, expiresAt: 20}, A{hasExp: true, expiresAt: 10}, false},
		{"hops dropped", A{}, A{hasHops: true, maxHops: 3}, false},
		{"hops raised", A{hasHops: true, maxHops: 4}, A{hasHops: true, maxHops: 3}, false},
		{"hops kept", A{hasHops: true, maxHops: 3}, A{hasHops: true, maxHops: 3}, true},
	}
	for _, c := range cases {
		if got := meshNarrows(c.child, c.parent); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func g07mRevRoot1(t *testing.T, id string) string {
	t.Helper()
	h, err := leafHash(id)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := bindRevRoot(1, b64.EncodeToString(h))
	if !ok {
		t.Fatal("bind")
	}
	return r
}

func TestG07MeshLeafAndNonMembership(t *testing.T) {
	root := g07mRevRoot1(t, "x")
	pr := func(m map[string]any) map[string]any {
		out := map[string]any{"path": []any{}}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	for _, c := range []struct {
		name  string
		proof map[string]any
		want  bool
	}{
		{"valid", pr(map[string]any{"size": jnum(1), "index": jnum(0)}), true},
		{"no index", pr(map[string]any{"size": jnum(1)}), false},
		{"size differs", pr(map[string]any{"size": jnum(2), "index": jnum(0)}), false},
		{"index -1", pr(map[string]any{"size": jnum(1), "index": jnum(-1)}), false},
		{"index == size", pr(map[string]any{"size": jnum(1), "index": jnum(1)}), false},
	} {
		if got := meshLeafOK(root, 1, "x", c.proof); got != c.want {
			t.Errorf("leaf %s: got %v", c.name, got)
		}
	}
	// an undecodable sibling is refused even when the root is what an empty sibling would produce
	lx, _ := leafHash("x")
	nilSibRoot, _ := bindRevRoot(2, b64.EncodeToString(revNodeHash(lx, nil)))
	badSib := map[string]any{"size": jnum(2), "index": jnum(0), "path": []any{map[string]any{"side": "R", "hash": "bad"}}}
	if meshLeafOK(nilSibRoot, 2, "x", badSib) {
		t.Error("undecodable sibling accepted")
	}
	stepNotObject := map[string]any{"size": jnum(2), "index": jnum(0), "path": []any{"R"}}
	if meshLeafOK(nilSibRoot, 2, "x", stepNotObject) {
		t.Error("non-object step accepted")
	}
	emptyRoot, _ := bindRevRoot(0, emptyRevTree())
	if meshNonMembership(emptyRoot, map[string]any{}, "x") {
		t.Error("missing size accepted")
	}
	if !meshNonMembership(emptyRoot, map[string]any{"size": jnum(0)}, "x") {
		t.Error("empty set refused")
	}
	leaf := map[string]any{"id": "x", "proof": map[string]any{"size": jnum(1), "index": jnum(0), "path": []any{}}}
	for _, c := range []struct {
		side, id string
		want     bool
	}{{"lo", "x", false}, {"lo", "y", true}, {"hi", "x", false}, {"hi", "a", true}} {
		if got := meshNonMembership(root, map[string]any{"size": jnum(1), c.side: leaf}, c.id); got != c.want {
			t.Errorf("%s neighbour, id %s: got %v", c.side, c.id, got)
		}
	}
}

func TestG07MeshConsistency(t *testing.T) {
	h32 := func(s string) []byte { return sha([]byte(s)) }
	enc := b64.EncodeToString
	h := enc(h32("h"))
	E := emptyRevTree()
	pr := func(m map[string]any, path []any) map[string]any {
		m["path"] = path
		return m
	}
	cases := []struct {
		name     string
		old, new string
		proof    map[string]any
		want     bool
	}{
		{"same size 1", h, h, pr(map[string]any{"oldSize": jnum(1), "newSize": jnum(1)}, []any{}), true},
		{"no oldSize", E, E, pr(map[string]any{"newSize": jnum(0)}, []any{}), false},
		{"no newSize", E, E, pr(map[string]any{"oldSize": jnum(0)}, []any{}), false},
		{"negative oldSize", h, h, pr(map[string]any{"oldSize": jnum(-1), "newSize": jnum(1)}, []any{h}), false},
		{"path 129", h, h, pr(map[string]any{"oldSize": jnum(1), "newSize": jnum(2)}, g07mStrs(129, h)), false},
		{"empty to empty, wrong new root", E, h, pr(map[string]any{"oldSize": jnum(0), "newSize": jnum(0)}, []any{}), false},
		{"empty to empty", E, E, pr(map[string]any{"oldSize": jnum(0), "newSize": jnum(0)}, []any{}), true},
		{"same size 3", h, h, pr(map[string]any{"oldSize": jnum(3), "newSize": jnum(3)}, []any{}), true},
		{"same size 3 with a path", h, h, pr(map[string]any{"oldSize": jnum(3), "newSize": jnum(3)}, []any{h}), false},
		{"undecodable old root", "bad", h, pr(map[string]any{"oldSize": jnum(1), "newSize": jnum(2)}, []any{h}), false},
	}
	// 3 -> 4 with three path hashes verifies; a fourth hash after the walk ends is refused even when the roots are
	// what continuing the walk would produce.
	p := [][]byte{h32("p0"), h32("p1"), h32("p2"), h32("p3")}
	fr3, sr3 := nodeHash(p[2], p[0]), nodeHash(p[2], nodeHash(p[0], p[1]))
	fr4, sr4 := nodeHash(p[3], fr3), nodeHash(p[3], sr3)
	cases = append(cases,
		struct {
			name     string
			old, new string
			proof    map[string]any
			want     bool
		}{"3 to 4", enc(fr3), enc(sr3), pr(map[string]any{"oldSize": jnum(3), "newSize": jnum(4)}, []any{enc(p[0]), enc(p[1]), enc(p[2])}), true},
		struct {
			name     string
			old, new string
			proof    map[string]any
			want     bool
		}{"3 to 4 overlong", enc(fr4), enc(sr4), pr(map[string]any{"oldSize": jnum(3), "newSize": jnum(4)}, []any{enc(p[0]), enc(p[1]), enc(p[2]), enc(p[3])}), false},
	)
	for _, c := range cases {
		if got := meshConsistency(c.old, c.new, c.proof); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
