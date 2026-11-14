package pca

import (
	"reflect"
	"testing"
)

// R5 N5: mesh.go survivors. Reference: packages/pca/src/mesh.ts (effectiveAuthority, verifyLedgerConsistency, verifyMeshProof).

func TestR5N5MeshEffectiveMalformed(t *testing.T) {
	if _, why := meshEffective("x"); why != "malformed proof" {
		t.Errorf("caveats not an array: %q", why)
	}
	if _, why := meshEffective([]any{"x"}); why != "malformed proof" {
		t.Errorf("caveat not an object: %q", why)
	}
	if _, why := meshEffective([]any{map[string]any{"type": "scope", "actions": []any{"a"}}}); why != "" {
		t.Errorf("valid scope caveat: %q", why)
	}
}

func TestR5N5MeshIntersectDuplicates(t *testing.T) {
	// a value of the left list appears once however often the right list repeats it
	if got := meshIntersect(true, []string{"x"}, []string{"x", "x"}); !reflect.DeepEqual(got, []string{"x"}) {
		t.Errorf("intersect: %q", got)
	}
}

func TestR5N5MeshLeafHashUnhashableID(t *testing.T) {
	// an id with no canonical form has no leaf hash; a root built from an empty hash must not be accepted for it
	id := "\xed\xa0\x80"
	root, ok := bindRevRoot(1, b64.EncodeToString(nil))
	if !ok {
		t.Fatal("bind")
	}
	proof := map[string]any{"size": jnum(1), "index": jnum(0), "path": []any{}}
	if meshLeafOK(root, 1, id, proof) {
		t.Error("a leaf with no canonical id was accepted")
	}
}

func TestR5N5MeshConsistencyUndecodable(t *testing.T) {
	enc := b64.EncodeToString
	pr := func(o, n int64, path []any) map[string]any {
		return map[string]any{"oldSize": jnum(o), "newSize": jnum(n), "path": path}
	}
	h := sha([]byte("h"))
	// an undecodable old root (the old size is a power of two, so it is the first path element)
	if meshConsistency("", enc(nodeHash(nil, h)), pr(1, 2, []any{enc(h)})) {
		t.Error("undecodable old root accepted")
	}
	// an undecodable path element
	o := sha([]byte("o"))
	if meshConsistency(enc(o), enc(nodeHash(o, nil)), pr(1, 2, []any{"bad"})) {
		t.Error("undecodable path element accepted")
	}
}

// Valid RFC 9162 walks that exercise every loop of meshConsistency: 0 -> n, 1 -> 2, 2 -> 4 and 5 -> 6 (the last enters the
// inner shift loop because fn == sn is even).
func TestR5N5MeshConsistencyWalks(t *testing.T) {
	enc := b64.EncodeToString
	h := func(s string) []byte { return sha([]byte(s)) }
	pth := func(hs ...[]byte) []any {
		out := []any{}
		for _, x := range hs {
			out = append(out, enc(x))
		}
		return out
	}
	pr := func(o, n int64, path []any) map[string]any {
		return map[string]any{"oldSize": jnum(o), "newSize": jnum(n), "path": path}
	}
	if !meshConsistency(emptyRevTree(), enc(h("any")), pr(0, 5, []any{})) {
		t.Error("0 -> 5")
	}
	l0, l1 := h("l0"), h("l1")
	if !meshConsistency(enc(l0), enc(nodeHash(l0, l1)), pr(1, 2, pth(l1))) {
		t.Error("1 -> 2")
	}
	n01, n23 := h("n01"), h("n23")
	if !meshConsistency(enc(n01), enc(nodeHash(n01, n23)), pr(2, 4, pth(n23))) {
		t.Error("2 -> 4")
	}
	p0, p1, p2 := h("p0"), h("p1"), h("p2")
	if !meshConsistency(enc(nodeHash(p2, p0)), enc(nodeHash(p2, nodeHash(p0, p1))), pr(5, 6, pth(p0, p1, p2))) {
		t.Error("5 -> 6")
	}
}

func TestR5N5MeshTrustPqPins(t *testing.T) {
	run := func(v any, present bool) meshTrustCfg {
		f := g07mBuild(t, 1)
		if present {
			f.trust["pqPins"] = v
		}
		cfg, bad := meshValidTrust(f.trust)
		if bad != "" {
			t.Fatal(bad)
		}
		return cfg
	}
	cfg := run(map[string]any{"k": "v", "n": jnum(5)}, true)
	if len(cfg.pqPins) != 1 || cfg.pqPins["k"] != "v" {
		t.Errorf("pqPins: %v", cfg.pqPins)
	}
	if got := run("str", true).pqPins; got != nil {
		t.Errorf("non-object pqPins: %v", got)
	}
	if got := run(nil, false).pqPins; got != nil {
		t.Errorf("absent pqPins: %v", got)
	}
}

func TestR5N5MeshVerifyRecoversPanic(t *testing.T) {
	f := g07mBuild(t, 1)
	saved := meshChainPolicy
	defer func() { meshChainPolicy = saved }()
	meshChainPolicy = func(_ []any, _ string, _ bool, _ []string, _ map[string]string, _ map[string]any) (string, bool) {
		panic("r5 boom")
	}
	var got MeshVerdict
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic escaped VerifyMeshProof: %v", r)
			}
		}()
		got = VerifyMeshProof(f.proof, f.trust)
	}()
	if got != (MeshVerdict{Reason: "malformed proof", Hop: -1}) {
		t.Errorf("verdict: %+v", got)
	}
}
