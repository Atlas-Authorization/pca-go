package pca

// Mutation-kill tests: Merkle inclusion/path shape, plan leaf defaults, key helpers, number helpers, PQ glue.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestMutPathShapeMatchesIndependentTree(t *testing.T) {
	for n := 1; n <= 40; n++ {
		hs := make([][]byte, n)
		for i := range hs {
			hs[i] = sha([]byte{byte(i), byte(n)})
		}
		for idx := 0; idx < n; idx++ {
			sides, _ := treeProof(hs, idx)
			got := pathShape(idx, n)
			if fmt.Sprint(got) != fmt.Sprint(sides) {
				t.Fatalf("n=%d idx=%d got %v want %v", n, idx, got, sides)
			}
		}
	}
	if split(2) != 1 || split(3) != 2 || split(4) != 2 || split(5) != 4 || split(8) != 4 || split(9) != 8 || split(17) != 16 {
		t.Fatal("split")
	}
}

func TestMutInclusionAllTreesAndTamper(t *testing.T) {
	for n := 1; n <= 12; n++ {
		leaves := make([]any, n)
		for i := range leaves {
			leaves[i] = map[string]any{"i": i}
		}
		root, _ := MerkleRoot(leaves)
		hs := leafHashes(t, leaves)
		for idx := 0; idx < n; idx++ {
			sides, sib := treeProof(hs, idx)
			pm := proofMap(sides, sib, idx, n)
			if !VerifyInclusion(root, deepM(t, pm), leaves[idx]) {
				t.Fatalf("n=%d idx=%d valid proof rejected", n, idx)
			}
			if n > 1 && VerifyInclusion(root, deepM(t, pm), leaves[(idx+1)%n]) {
				t.Fatalf("n=%d idx=%d wrong leaf accepted", n, idx)
			}
			// wrong index/size claims with the genuine path
			for _, alt := range [][2]int{{-1, n}, {n, n}, {idx, 0}, {idx, -1}, {n + 3, n}} {
				q := deepM(t, pm)
				q["index"], q["size"] = jnum(int64(alt[0])), jnum(int64(alt[1]))
				if (alt[0] != idx || alt[1] != n) && VerifyInclusion(root, q, leaves[idx]) {
					t.Fatalf("n=%d idx=%d accepted with index=%d size=%d", n, idx, alt[0], alt[1])
				}
			}
			if len(sides) > 0 {
				q := deepM(t, pm)
				q["path"] = q["path"].([]any)[1:]
				if VerifyInclusion(root, q, leaves[idx]) {
					t.Fatal("short path")
				}
				q = deepM(t, pm)
				q["path"] = append(q["path"].([]any), q["path"].([]any)[0])
				if VerifyInclusion(root, q, leaves[idx]) {
					t.Fatal("long path")
				}
				q = deepM(t, pm)
				st := q["path"].([]any)[0].(map[string]any)
				if st["side"] == "L" {
					st["side"] = "R"
				} else {
					st["side"] = "L"
				}
				if VerifyInclusion(root, q, leaves[idx]) {
					t.Fatal("flipped side")
				}
			}
		}
	}
	// size 1 edge: index == size must be refused even though the (empty) path matches
	leaves := []any{"only"}
	root, _ := MerkleRoot(leaves)
	one := map[string]any{"index": jnum(0), "size": jnum(1), "path": []any{}}
	if !VerifyInclusion(root, one, "only") {
		t.Fatal("single leaf")
	}
	for _, alt := range []map[string]any{
		{"index": jnum(1), "size": jnum(1), "path": []any{}},
		{"index": jnum(-1), "size": jnum(1), "path": []any{}},
		{"index": jnum(0), "size": jnum(0), "path": []any{}},
		{"index": "0", "size": jnum(1), "path": []any{}},
		{"index": jnum(0), "size": "1", "path": []any{}},
		{"index": json.Number("0.5"), "size": jnum(1), "path": []any{}},
		{"index": jnum(0), "size": jnum(1)},
		{"index": jnum(0), "size": jnum(1), "path": "x"},
		{"size": jnum(1), "path": []any{}},
		{"index": jnum(0), "path": []any{}},
	} {
		if VerifyInclusion(root, alt, "only") {
			t.Fatalf("accepted %v", alt)
		}
	}
	if VerifyInclusion(root, one, "\xed\xa0\x80") {
		t.Fatal("bad leaf")
	}
	if VerifyInclusion(root, one, "other") || VerifyInclusion("AAAA", one, "only") {
		t.Fatal("wrong root/leaf")
	}
	// step shapes
	two := []any{"a", "b"}
	r2, _ := MerkleRoot(two)
	hs := leafHashes(t, two)
	sides, sib := treeProof(hs, 0)
	good := proofMap(sides, sib, 0, 2)
	if !VerifyInclusion(r2, deepM(t, good), "a") {
		t.Fatal("two-leaf")
	}
	for _, step := range []any{"x", nil, map[string]any{"side": "R"}, map[string]any{"hash": sib[0]},
		map[string]any{"side": "R", "hash": 5}, map[string]any{"side": 5, "hash": b64.EncodeToString(sib[0])},
		map[string]any{"side": "R", "hash": "AAAA"}, map[string]any{"side": "R", "hash": b64.EncodeToString(sib[0]) + "="}} {
		q := deepM(t, good)
		q["path"] = []any{step}
		if VerifyInclusion(r2, q, "a") {
			t.Fatalf("step %v accepted", step)
		}
	}
}

func TestMutSafeIntAndIsNum(t *testing.T) {
	for _, v := range []any{"1", 1, nil, 1.5, json.Number("1.0"), json.Number("1e2"), json.Number("-0"), json.Number("9007199254740992"), json.Number(""), json.Number("x")} {
		if i, ok := safeInt(v); ok || i != 0 {
			t.Fatalf("safeInt(%v) = %d %v", v, i, ok)
		}
	}
	for s, want := range map[string]int64{"0": 0, "7": 7, "-7": -7, "9007199254740991": 9007199254740991, "-9007199254740991": -9007199254740991} {
		if i, ok := safeInt(json.Number(s)); !ok || i != want {
			t.Fatalf("safeInt(%s) = %d %v", s, i, ok)
		}
	}
	for _, v := range []any{"1", nil, 1, json.Number("1e2"), json.Number("1.50"), json.Number("-0"), json.Number("x"), json.Number("0.0000001")} {
		if f, ok := isNum(v); ok || f != 0 {
			t.Fatalf("isNum(%v) = %v %v", v, f, ok)
		}
	}
	for s, want := range map[string]float64{"0": 0, "1.5": 1.5, "-2.25": -2.25, "100": 100} {
		if f, ok := isNum(json.Number(s)); !ok || f != want {
			t.Fatalf("isNum(%s) = %v %v", s, f, ok)
		}
	}
}

func TestMutPlanLeafAndDigests(t *testing.T) {
	if _, err := planLeaf(nil, map[string]any{}, "c"); err == nil {
		t.Fatal("nil node id")
	}
	empty, _ := ParamsDigest(nil)
	cond := "c"
	for name, a := range map[string]map[string]any{
		"absent":  {"verb": "v", "resource": "r"},
		"nil":     {"verb": "v", "resource": "r", "params_digest": nil, "reversibility_class": nil},
		"present": {"verb": "v", "resource": "r", "params_digest": "PD", "reversibility_class": "irreversible"},
	} {
		l, err := planLeaf("n", a, cond)
		if err != nil {
			t.Fatal(err)
		}
		wantPD, wantRC := any(empty), any(defaultRev)
		if name == "present" {
			wantPD, wantRC = "PD", "irreversible"
		}
		if l["params_digest"] != wantPD || l["reversibility_class"] != wantRC || l["node_id"] != "n" || l["verb"] != "v" || l["resource"] != "r" || l["conditions"] != cond || len(l) != 6 {
			t.Fatalf("%s: %v", name, l)
		}
	}
	// only one of the two defaults applies when the other is present
	l, _ := planLeaf("n", map[string]any{"params_digest": "PD"}, "c")
	if l["params_digest"] != "PD" || l["reversibility_class"] != defaultRev {
		t.Fatalf("%v", l)
	}
	l, _ = planLeaf("n", map[string]any{"reversibility_class": "x"}, "c")
	if l["params_digest"] != empty || l["reversibility_class"] != "x" {
		t.Fatalf("%v", l)
	}
	p := map[string]any{"a": jnum(1)}
	d, _ := ParamsDigest(p)
	h, _ := HashCanonical(p)
	if d != h || d == empty {
		t.Fatal("ParamsDigest must hash the params")
	}
	if e2, _ := HashCanonical(map[string]any{}); e2 != empty {
		t.Fatal("empty params digest")
	}
	cd, _ := conditionsDigest(nil, nil)
	want, _ := HashCanonical(map[string]any{"pre": nil, "post": nil})
	if cd != want {
		t.Fatal("conditionsDigest")
	}
}

func TestMutVerifyB64u(t *testing.T) {
	k := newKey(t)
	msg := []byte("hello")
	sig := b64.EncodeToString(ed25519.Sign(k.priv, msg))
	if !verifyB64u(k.id, msg, sig) {
		t.Fatal("valid")
	}
	for _, c := range [][2]string{{"x", sig}, {k.id, "x"}, {k.id[:20], sig}, {k.id, sig[:20]}, {"", ""}, {k.id + "A", sig}, {k.id, sig + "A"}} {
		if verifyB64u(c[0], msg, c[1]) {
			t.Fatalf("accepted %q %q", c[0], c[1])
		}
	}
	if verifyB64u(k.id, []byte("other"), sig) {
		t.Fatal("wrong message")
	}
}

func TestMutThresholdAndParse(t *testing.T) {
	f := newFx(t)
	m, err := ThresholdMessage(f.norm())
	if err != nil || string(m[:len(sigDomain)]) != sigDomain || len(m) != len(sigDomain)+32 {
		t.Fatalf("message shape: %v", err)
	}
	// the threshold block is not signed over, sig is stripped
	q := f.norm()
	q["threshold"] = map[string]any{"shares": []any{}}
	q["sig"] = "different"
	m2, _ := ThresholdMessage(q)
	if string(m) != string(m2) {
		t.Fatal("threshold/sig must be unsigned")
	}
	q["aud"] = "other"
	m3, _ := ThresholdMessage(q)
	if string(m) == string(m3) {
		t.Fatal("aud must be signed")
	}
	q = f.norm()
	q["pq_sig"] = "x"
	if m4, _ := ThresholdMessage(q); string(m4) != string(m) {
		t.Fatal("pq_sig is unsigned")
	}
	q = f.norm()
	q["alg"], q["pq_pk"] = "ed25519", "x"
	if m5, _ := ThresholdMessage(q); string(m5) == string(m) {
		t.Fatal("alg/pq_pk are signed")
	}
	bad := f.norm()
	sub(bad, "action")["verb"] = "\xed\xa0\x80"
	if m6, err := ThresholdMessage(bad); err == nil || m6 != nil {
		t.Fatal("ThresholdMessage must fail on a lone surrogate")
	}
	if p, err := ParsePCActn("x"); err == nil || p != nil {
		t.Fatal("ParsePCActn garbage")
	}
	if p, err := ParsePCActn("[]"); err == nil || p != nil || err.Error() != "PCActn is not an object" {
		t.Fatalf("ParsePCActn array: %v", err)
	}
	if p, err := ParsePCActn(`{"a":1}`); err != nil || p["a"] != json.Number("1") {
		t.Fatal("ParsePCActn object")
	}
	if _, err := ParseJSON([]byte("[]")); err == nil || err.Error() != "strict JSON: top level is not an object" {
		t.Fatalf("ParseJSON: %v", err)
	}
	if _, err := ParseJSON([]byte("{")); err == nil {
		t.Fatal("ParseJSON err")
	}
}

func TestMutFromContext(t *testing.T) {
	if v, p, ok := FromContext(context.Background()); ok || v != nil || p != nil {
		t.Fatal("empty ctx")
	}
	ctx := context.WithValue(context.Background(), ctxKey{}, (*contextValue)(nil))
	if v, p, ok := FromContext(ctx); ok || v != nil || p != nil {
		t.Fatal("typed-nil value must report absent (and not panic)")
	}
	ctx = context.WithValue(context.Background(), ctxKey{}, "not a contextValue")
	if _, _, ok := FromContext(ctx); ok {
		t.Fatal("wrong type")
	}
	vd := &Verdict{Allow: true}
	pm := map[string]any{"a": 1}
	ctx = context.WithValue(context.Background(), ctxKey{}, &contextValue{verdict: vd, pcactn: pm})
	if v, p, ok := FromContext(ctx); !ok || v != vd || p["a"] != 1 {
		t.Fatal("present")
	}
}

func TestMutResolveSigAlg(t *testing.T) {
	if s, ok := resolveSigAlg(nil, false); !ok || s.alg != "ed25519" || !s.hasEd25519 || s.hasMlDsa || s.needsPqPk || s.needsPqSig || s.sigBytes != 64 {
		t.Fatal("default")
	}
	if s, ok := resolveSigAlg("ml-dsa-65", true); !ok || s.hasEd25519 || !s.hasMlDsa || !s.needsPqPk || s.needsPqSig || s.sigBytes != 3309 {
		t.Fatal("ml-dsa")
	}
	if s, ok := resolveSigAlg("hybrid-ed25519-ml-dsa-65", true); !ok || !s.hasEd25519 || !s.hasMlDsa || !s.needsPqPk || !s.needsPqSig || s.sigBytes != 64 {
		t.Fatal("hybrid")
	}
	for _, a := range []any{5, nil, "nope", "", "ML-DSA-65", "ed448"} {
		if s, ok := resolveSigAlg(a, true); ok || s.alg != "" {
			t.Fatalf("%v resolved", a)
		}
	}
}

func TestMutValidateSignatureWire(t *testing.T) {
	sig64, sig3309 := b64.EncodeToString(make([]byte, 64)), b64.EncodeToString(make([]byte, 3309))
	pk := b64.EncodeToString(make([]byte, 1952))
	for _, c := range []struct {
		p    map[string]any
		want string
	}{
		{map[string]any{"sig": sig64}, ""},
		{map[string]any{"alg": 5, "sig": sig64}, "'alg' must be a string"},
		{map[string]any{"alg": nil, "sig": sig64}, "'alg' must be a string"},
		{map[string]any{"alg": "x", "sig": sig64}, "unknown signature alg 'x'"},
		{map[string]any{"alg": "ml-dsa-65", "sig": sig3309, "pq_pk": pk}, ""},
		{map[string]any{"alg": "ml-dsa-65", "sig": sig64, "pq_pk": pk}, "'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'"},
		{map[string]any{"alg": "ml-dsa-65", "sig": sig3309}, "'pq_pk' is not canonical base64url (1952 bytes)"},
		{map[string]any{"alg": "ml-dsa-65", "sig": sig3309, "pq_pk": pk, "pq_sig": sig3309}, "'pq_sig' must be absent for alg 'ml-dsa-65'"},
		{map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "sig": sig64, "pq_pk": pk, "pq_sig": sig3309}, ""},
		{map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "sig": sig64, "pq_pk": pk}, "'pq_sig' is not canonical base64url (3309 bytes)"},
		{map[string]any{"sig": sig64, "pq_pk": pk}, "'pq_pk' must be absent for alg 'ed25519'"},
		{map[string]any{"sig": sig64, "pq_sig": sig3309}, "'pq_sig' must be absent for alg 'ed25519'"},
		{map[string]any{"sig": sig64, "pq_pk": nil}, "'pq_pk' must be absent for alg 'ed25519'"},
	} {
		if got := validateSignatureWire(c.p); got != c.want {
			t.Fatalf("%v: %q want %q", c.p, got, c.want)
		}
	}
}

func TestMutMlDsa(t *testing.T) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("pq message")
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	pkb, _ := pk.MarshalBinary()
	if !mlDsa65VerifyRaw(pkb, msg, sig) {
		t.Fatal("valid raw")
	}
	short := func(b []byte, n int) []byte { return b[:len(b)-n] }
	long := func(b []byte) []byte { return append(append([]byte(nil), b...), 0) }
	for name, c := range map[string][3][]byte{
		"short pk": {short(pkb, 1), msg, sig}, "long pk": {long(pkb), msg, sig},
		"short sig": {pkb, msg, short(sig, 1)}, "long sig": {pkb, msg, long(sig)},
		"both short": {short(pkb, 1), msg, short(sig, 1)}, "nil": {nil, msg, nil}, "wrong msg": {pkb, []byte("x"), sig},
	} {
		if mlDsa65VerifyRaw(c[0], c[1], c[2]) {
			t.Fatalf("%s accepted", name)
		}
	}
	e, s := b64.EncodeToString(pkb), b64.EncodeToString(sig)
	if !mlDsa65VerifyB64u(callerVouchedPqKey(e), msg, s) {
		t.Fatal("valid b64u")
	}
	for name, c := range map[string][2]any{
		"pk nonstring": {5, s}, "sig nonstring": {e, 5}, "pk nil": {nil, s}, "sig nil": {e, nil},
		"pk bad b64": {"!!", s}, "sig bad b64": {e, "!!"}, "pk short": {e[:100], s}, "sig short": {e, s[:100]},
		"pk wrong len but canonical": {b64.EncodeToString(pkb[:1951]), s},
	} {
		if mlDsa65VerifyB64u(callerVouchedPqKey(c[0]), msg, c[1]) {
			t.Fatalf("%s accepted", name)
		}
	}
	// verifyLeafSuite dispatch
	ed := newKey(t)
	edSig := b64.EncodeToString(ed25519.Sign(ed.priv, msg))
	if !verifyLeafSuite(nil, false, ed.id, callerVouchedPqKey(nil), msg, edSig, nil) || !verifyLeafSuite("ed25519", true, ed.id, callerVouchedPqKey(nil), msg, edSig, nil) {
		t.Fatal("ed25519 leaf")
	}
	if !verifyLeafSuite("ml-dsa-65", true, "", callerVouchedPqKey(e), msg, s, nil) {
		t.Fatal("ml-dsa leaf")
	}
	// ml-dsa-65 sig verified under the holder (wrong) must not pass for ed25519
	if verifyLeafSuite("ml-dsa-65", true, ed.id, callerVouchedPqKey(nil), msg, s, nil) || verifyLeafSuite("ml-dsa-65", true, "", callerVouchedPqKey(e), msg, edSig, nil) {
		t.Fatal("cross-suite")
	}
	if verifyLeafSuite("nope", true, ed.id, callerVouchedPqKey(nil), msg, edSig, nil) || verifyLeafSuite(5, true, ed.id, callerVouchedPqKey(nil), msg, edSig, nil) {
		t.Fatal("unknown alg")
	}
	if verifyLeafSuite(nil, false, ed.id, callerVouchedPqKey(nil), msg, 5, nil) || verifyLeafSuite(nil, false, ed.id, callerVouchedPqKey(nil), msg, nil, nil) ||
		verifyLeafSuite("ml-dsa-65", true, "", callerVouchedPqKey(e), msg, 5, nil) || verifyLeafSuite("hybrid-ed25519-ml-dsa-65", true, ed.id, callerVouchedPqKey(e), msg, 5, s) {
		t.Fatal("non-string sig")
	}
	h := "hybrid-ed25519-ml-dsa-65"
	if !verifyLeafSuite(h, true, ed.id, callerVouchedPqKey(e), msg, edSig, s) {
		t.Fatal("hybrid valid")
	}
	if verifyLeafSuite(h, true, ed.id, callerVouchedPqKey(e), msg, edSig, 5) || verifyLeafSuite(h, true, ed.id, callerVouchedPqKey(e), msg, edSig, nil) {
		t.Fatal("hybrid pq_sig non-string")
	}
	if verifyLeafSuite(h, true, ed.id, callerVouchedPqKey(e), msg, edSig, edSig) || verifyLeafSuite(h, true, ed.id, callerVouchedPqKey(e), msg, s, s) ||
		verifyLeafSuite(h, true, newKey(t).id, callerVouchedPqKey(e), msg, edSig, s) || verifyLeafSuite(h, true, ed.id, callerVouchedPqKey(5), msg, edSig, s) {
		t.Fatal("hybrid needs both components")
	}
}
