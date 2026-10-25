package pca

// Kill tests for the Intent Layer v2 artifact plumbing (intent_artifacts.go; reference packages/pca/src/intent-artifacts.ts
// and the pinned-suite seam of pq.ts) and the LESS length rule of pq.go (pq.ts lessSigLengthOk). Each test pins one
// boundary or refusal of the reference.

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// bindSuiteFields: a PQ suite's signed body carries alg + pq_pk; pq_pk ABSENT makes the body unserialisable (refused).
func TestKillCBindSuiteFields(t *testing.T) {
	base := map[string]any{}
	if out, ok := bindSuiteFields(base, "ml-dsa-65", true, nil, false); ok || out != nil {
		t.Fatalf("pq suite without pq_pk: got %v %v, want nil false", out, ok)
	}
	// an EMPTY base (and a one-member base) must still bind: alg + pq_pk added, base members kept
	for _, b := range []map[string]any{{}, {"x": jnum(1)}} {
		out, ok := bindSuiteFields(b, "ml-dsa-65", true, "PK", true)
		if !ok || out["alg"] != "ml-dsa-65" || out["pq_pk"] != "PK" || len(out) != len(b)+2 {
			t.Fatalf("bind %v: got %v %v", b, out, ok)
		}
	}
	// ed25519 (absent or named) leaves the body untouched
	if out, ok := bindSuiteFields(map[string]any{"x": jnum(1)}, nil, false, nil, false); !ok || len(out) != 1 {
		t.Fatalf("ed25519 bind: %v %v", out, ok)
	}
}

// pinOf: an absent artifact pq_pk yields NO pin map (nil), a present one pins identity -> pq_pk.
func TestKillCPinOf(t *testing.T) {
	if p := pinOf("id", nil, false); p != nil {
		t.Fatalf("pinOf(absent) = %v, want nil", p)
	}
	if p := pinOf("id", "PK", true); len(p) != 1 || p["id"] != "PK" {
		t.Fatalf("pinOf(present) = %v", p)
	}
}

// domainMessage refuses a body strict canonicalisation refuses.
func TestKillCDomainMessage(t *testing.T) {
	if m, ok := domainMessage("d", map[string]any{"x": struct{}{}}); ok || m != nil {
		t.Fatalf("non-canonical body: got %q %v, want nil false", m, ok)
	}
	if m, ok := domainMessage("d/", map[string]any{"a": "b"}); !ok || string(m) != `d/{"a":"b"}` {
		t.Fatalf("domainMessage = %q %v", m, ok)
	}
}

// verifyPinnedSuite / verifyArtifactSig: unknown suite, a PQ suite without pq_pk, without a pin, a missing sig, a
// non-canonical body (even with a signature over the bare domain) are all refused; the pinned PQ artifact verifies.
func TestKillCPinnedSuiteRefusals(t *testing.T) {
	ed := newKey(t)
	pq := newWBPQKey(t)
	const dom = "atlas-pca/killc/v1"
	msg := []byte(dom + "{}")
	edSig := b64.EncodeToString(ed25519.Sign(ed.priv, msg))
	if !verifyPinnedSuite(nil, false, ed.id, nil, msg, edSig, nil, nil) {
		t.Fatal("ed25519 under identity must verify")
	}
	if verifyPinnedSuite("no-such-suite", true, ed.id, nil, msg, edSig, nil, nil) {
		t.Fatal("unknown suite verified")
	}
	if verifyPinnedSuite(5, true, ed.id, nil, msg, edSig, nil, nil) {
		t.Fatal("non-string alg verified")
	}

	art := signArtPQ(t, pq, dom, map[string]any{"x": jnum(1)})
	if !verifyArtifactSig(dom, art, ed.id, pq.pk) {
		t.Fatal("pinned ml-dsa-65 artifact must verify")
	}
	if verifyArtifactSig(dom, art, ed.id, nil) {
		t.Fatal("PQ artifact without a pin verified")
	}
	// PQ suite, artifact without pq_pk: refused before any pin lookup
	noPk := withoutKeys(art, "pq_pk")
	if verifyPinnedSuite("ml-dsa-65", true, ed.id, nil, []byte("m"), noPk["sig"], nil, map[string]string{ed.id: pq.pk}) {
		t.Fatal("PQ suite without pq_pk verified")
	}
	if verifyArtifactSig(dom, noPk, ed.id, pq.pk) {
		t.Fatal("PQ artifact without pq_pk verified")
	}
	// missing sig / non-string signer
	if verifyArtifactSig(dom, withoutKeys(art, "sig"), ed.id, pq.pk) {
		t.Fatal("artifact without sig verified")
	}
	edArt := signArt(t, ed, dom, map[string]any{"x": jnum(1)})
	if !verifyArtifactSig(dom, edArt, ed.id, nil) {
		t.Fatal("ed25519 artifact must verify")
	}
	if verifyArtifactSig(dom, edArt, 7, nil) {
		t.Fatal("non-string signer verified")
	}
	if verifyArtifactSig(dom, withoutKeys(edArt, "sig"), ed.id, nil) {
		t.Fatal("ed25519 artifact without sig verified")
	}
	// a body that does not canonicalise is refused, even when `sig` signs the bare (empty) message
	bad := map[string]any{"x": struct{}{}, "sig": b64.EncodeToString(ed25519.Sign(ed.priv, nil))}
	if verifyArtifactSig(dom, bad, ed.id, nil) {
		t.Fatal("non-canonical artifact verified (signature over the empty message)")
	}
	bad["sig"] = b64.EncodeToString(ed25519.Sign(ed.priv, []byte(dom)))
	if verifyArtifactSig(dom, bad, ed.id, nil) {
		t.Fatal("non-canonical artifact verified (signature over the bare domain)")
	}
}

func TestKillCClosedMembers(t *testing.T) {
	o := map[string]any{"a": jnum(1)}
	if closedMembers(o, []string{"a", "b"}) {
		t.Fatal("missing required member accepted")
	}
	if !closedMembers(o, []string{"a"}, "c") || closedMembers(map[string]any{"a": 1, "z": 2}, []string{"a"}, "c") {
		t.Fatal("closedMembers")
	}
}

func TestKillCPathSegment(t *testing.T) {
	s64 := strings.Repeat("a", 64)
	cases := map[string]bool{"a": true, "a-b_9": true, s64: true, s64 + "a": false, "": false, "__proto__": false,
		"constructor": false, "prototype": false, "a.b": false}
	for s, want := range cases {
		if got := isPathSegment(s); got != want {
			t.Errorf("isPathSegment(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestKillCResolveParamPath(t *testing.T) {
	params := map[string]any{"a": map[string]any{"b": jnum(3)}, "__proto__": jnum(1), "x": jnum(2)}
	if v, ok := resolveParamPath(params, "action.params.a.b"); !ok || v != jnum(3) {
		t.Fatalf("a.b = %v %v", v, ok)
	}
	for _, p := range []any{"x", "action.param.x", "action.params", "act", 5, "action.params.__proto__", "action.params.y",
		"action.params.x.y", "action.params.a..b", "action.params.a.b.c"} {
		if v, ok := resolveParamPath(params, p); ok || v != nil {
			t.Errorf("resolveParamPath(%v) = %v %v, want not found", p, v, ok)
		}
	}
}

func TestKillCIsParamPath(t *testing.T) {
	seg := func(n int) string { return "action.params." + strings.TrimSuffix(strings.Repeat("s.", n), ".") }
	cases := map[any]bool{seg(1): true, seg(7): true, seg(8): true, seg(9): false, "x": false, "act": false, 5: false,
		"action.params.": false, "action.params.__proto__": false, "action.params.a.constructor": false, "action.params.a b": false}
	for p, want := range cases {
		if got := isParamPath(p); got != want {
			t.Errorf("isParamPath(%v) = %v, want %v", p, got, want)
		}
	}
}

func TestKillCSetNested(t *testing.T) {
	root := map[string]any{}
	if !setNested(root, "a.b.c", "v") || !setNested(root, "a.b.d", "w") || !setNested(root, "e", "x") {
		t.Fatal("setNested on fresh paths")
	}
	got, _ := canonBytes(root)
	if string(got) != `{"a":{"b":{"c":"v","d":"w"}},"e":"x"}` {
		t.Fatalf("setNested result %s", got)
	}
	// collisions: under a leaf, onto an existing leaf, onto an existing subtree; nothing is overwritten
	if setNested(root, "e.f", "y") || setNested(root, "e", "y") || setNested(root, "a.b", "y") || setNested(root, "a.b.c", "z") {
		t.Fatal("colliding path accepted")
	}
	got, _ = canonBytes(root)
	if string(got) != `{"a":{"b":{"c":"v","d":"w"}},"e":"x"}` {
		t.Fatalf("collision changed the tree: %s", got)
	}
}

// algUnsupported / actionSchemaSuiteReason / receiptSuiteReason: only a STRING alg the dispatch does not implement.
func TestKillCSuiteReasons(t *testing.T) {
	const reg = "fn-dsa-512" // registered, not implemented by this verifier
	for _, c := range []struct {
		v    any
		want bool
	}{{"x", false}, {nil, false}, {map[string]any{}, false}, {map[string]any{"alg": "ed25519"}, false},
		{map[string]any{"alg": jnum(5)}, false}, {map[string]any{"alg": "ml-dsa-65"}, false}, {map[string]any{"alg": reg}, true},
		{map[string]any{"alg": "bogus"}, true}} {
		if got := algUnsupported(c.v, "alg"); got != c.want {
			t.Errorf("algUnsupported(%v) = %v, want %v", c.v, got, c.want)
		}
	}
	dv := map[string]any{"sig": map[string]any{"alg": "ed25519", "kid": "k"}}
	if r := actionSchemaSuiteReason(dv, []any{map[string]any{"kid": "k", "alg": "ed25519"}}); r != "" {
		t.Errorf("supported schema + key: %q", r)
	}
	if r := actionSchemaSuiteReason(dv, []any{map[string]any{"kid": "other", "alg": reg}, map[string]any{"kid": "k"}}); r != "" {
		t.Errorf("unsupported alg on ANOTHER kid: %q, want \"\"", r)
	}
	if r := actionSchemaSuiteReason(dv, []any{map[string]any{"kid": "k", "alg": reg}}); r != UnsupportedSuite {
		t.Errorf("unsupported key alg: %q", r)
	}
	if r := actionSchemaSuiteReason(map[string]any{"sig": map[string]any{"alg": reg, "kid": "k"}}, nil); r != UnsupportedSuite {
		t.Errorf("unsupported schema sig alg: %q", r)
	}
	if r := receiptSuiteReason(map[string]any{}, []any{map[string]any{"alg": reg}}); r != UnsupportedSuite {
		t.Errorf("unsupported key-set alg: %q", r)
	}
	if r := receiptSuiteReason(map[string]any{}, []any{map[string]any{"alg": "ed25519", "keys": []any{map[string]any{"alg": "ed25519"}}}}); r != "" {
		t.Errorf("supported key set: %q", r)
	}
}

// pq.ts lessSigLengthOk: 1153..1329 in steps of 16 (counted down from the maximum); LESS pk 97484 bytes.
func TestKillCLessLengths(t *testing.T) {
	if pk, sl := pqLessCat1.lens(); pk != 97484 || sl != 1329 {
		t.Fatalf("LESS lens = %d %d", pk, sl)
	}
	for n := 1100; n <= 1400; n++ {
		want := n >= 1153 && n <= 1329 && (1329-n)%16 == 0
		if got := pqLessCat1.sigLenOK(n); got != want {
			t.Errorf("LESS sigLenOK(%d) = %v, want %v", n, got, want)
		}
	}
	if pk, sl := pqNone.lens(); pk != 0 || sl != 0 {
		t.Fatalf("pqNone lens = %d %d", pk, sl)
	}
	for _, n := range []int{0, 1, 64} {
		if pqNone.sigLenOK(n) {
			t.Errorf("pqNone.sigLenOK(%d) accepted", n)
		}
	}
	if !pqMlDsa65.sigLenOK(3309) || pqMlDsa65.sigLenOK(3308) {
		t.Error("ml-dsa-65 sigLenOK")
	}
}
