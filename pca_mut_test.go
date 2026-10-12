package pca

// Mutation-kill tests for pca.go: strict base64url, canonicalization limits/escapes, Merkle, wire caps.

import (
	"encoding/json"
	"strings"
	"testing"
)

func nested(n int, obj bool) any {
	var v any = []any{}
	if obj {
		v = map[string]any{}
	}
	for i := 1; i < n; i++ {
		if obj {
			v = map[string]any{"a": v}
		} else {
			v = []any{v}
		}
	}
	return v
}

func TestMutDecodeB64uWantLen(t *testing.T) {
	if b, ok := DecodeB64uStrict("", 0); !ok || len(b) != 0 {
		t.Fatal("empty with want 0")
	}
	if _, ok := DecodeB64uStrict("YQ", 0); ok {
		t.Fatal("want 0 but 1 byte")
	}
	if _, ok := DecodeB64uStrict("YQ", 1); !ok {
		t.Fatal("want 1")
	}
	if _, ok := DecodeB64uStrict("YQ", 2); ok {
		t.Fatal("want 2")
	}
	if _, ok := DecodeB64uStrict("YQ", -1); !ok {
		t.Fatal("any length")
	}
	if _, ok := DecodeB64uStrict("Y", -1); ok {
		t.Fatal("len%4==1")
	}
	if _, ok := DecodeB64uStrict("YR", -1); ok { // non-zero trailing bits
		t.Fatal("trailing bits")
	}
	for _, s := range []string{"Y\nQ", "YQ==", "Y+Q", "Y/Q", "Y Q", "YQ\n", "\rYQ"} {
		if _, ok := DecodeB64uStrict(s, -1); ok {
			t.Fatalf("%q accepted", s)
		}
	}
	// b64uOK: non-string never ok, even where an empty string would be
	for _, n := range []int{-1, 0, 32} {
		for _, v := range []any{nil, 5, json.Number("1"), []any{}} {
			if b64uOK(v, n) {
				t.Fatalf("b64uOK(%v,%d)", v, n)
			}
		}
	}
	if !b64uOK("", 0) || !b64uOK("", -1) || b64uOK("", 32) {
		t.Fatal("empty string handling")
	}
}

func TestMutCanonicalizeEscapes(t *testing.T) {
	got, err := Canonicalize("a\b\f\n\r\t\"\\\x01\x1fz")
	want := `"a\b\f\n\r\t\"\\\u0001\u001fz"`
	if err != nil || got != want {
		t.Fatalf("%q %v", got, err)
	}
	for _, c := range []struct {
		in   any
		want string
	}{
		{nil, "null"}, {true, "true"}, {false, "false"}, {json.Number("12"), "12"}, {5, "5"}, {-5, "-5"}, {0, "0"},
		{9007199254740991, "9007199254740991"}, {-9007199254740991, "-9007199254740991"},
		{[]any{1, "a", nil}, `[1,"a",null]`},
		{map[string]any{"b": 1, "a": 2, "": 3}, `{"":3,"a":2,"b":1}`},
	} {
		got, err := Canonicalize(c.in)
		if err != nil || got != c.want {
			t.Fatalf("%v: %q %v", c.in, got, err)
		}
	}
	for _, in := range []any{9007199254740992, -9007199254740992, json.Number("1.0"), 1.5, struct{}{},
		"\xed\xa0\x80", map[string]any{"\xed\xa0\x80": 1}, []any{"\xed\xa0\x80"}, map[string]any{"k": "\xed\xa0\x80"}} {
		if s, err := Canonicalize(in); err == nil || s != "" {
			t.Fatalf("%v should fail, got %q", in, s)
		}
	}
	if _, err := HashCanonical("\xed\xa0\x80"); err == nil {
		t.Fatal("HashCanonical error")
	}
	if h, err := HashCanonical(nil); err != nil || h == "" {
		t.Fatal("HashCanonical ok")
	}
}

func TestMutCanonicalizeDepth(t *testing.T) {
	for _, obj := range []bool{false, true} {
		if _, err := Canonicalize(nested(32, obj)); err != nil {
			t.Fatalf("depth %d obj=%v: %v", 32, obj, err)
		}
		if _, err := Canonicalize(nested(33, obj)); err == nil {
			t.Fatalf("depth %d obj=%v accepted", 33, obj)
		}
	}
	// a deep value inside an object / array position still counts from the real nesting depth
	if _, err := Canonicalize(map[string]any{"x": nested(32, false)}); err == nil {
		t.Fatal("nesting under a key must add depth")
	}
	if _, err := Canonicalize([]any{nested(32, true)}); err == nil {
		t.Fatal("nesting under an array must add depth")
	}
	if _, err := Canonicalize(map[string]any{"x": nested(31, false)}); err != nil {
		t.Fatal("depth exactly 32 under a key")
	}
}

func TestMutMerkle(t *testing.T) {
	if r, err := MerkleRoot(nil); err == nil || r != "" {
		t.Fatal("empty leaf set")
	}
	lh, _ := leafHash("a")
	r1, err := MerkleRoot([]any{"a"})
	if err != nil || r1 != b64.EncodeToString(lh) {
		t.Fatalf("single leaf: %q %v", r1, err)
	}
	if _, err := MerkleRoot([]any{"a", "\xed\xa0\x80"}); err == nil {
		t.Fatal("bad leaf")
	}
	if _, err := leafHash("\xed\xa0\x80"); err == nil {
		t.Fatal("leafHash err")
	}
	// nodeHash = sha256(0x01 || l || r)
	l, r := make([]byte, 32), make([]byte, 32)
	r[0] = 7
	if string(nodeHash(l, r)) != string(sha(append(append([]byte{1}, l...), r...))) {
		t.Fatal("nodeHash")
	}
	if len(nodeHash(nil, nil)) != 32 || string(nodeHash(nil, nil)) != string(sha([]byte{1})) {
		t.Fatal("nodeHash empty")
	}
}

func TestMutInclusionBadSibling(t *testing.T) {
	leaf := "x"
	h, _ := leafHash(leaf)
	// root computed with an EMPTY sibling; the proof carries an undecodable sibling hash
	root := b64.EncodeToString(nodeHash(h, nil))
	proof := map[string]any{"index": json.Number("0"), "size": json.Number("2"),
		"path": []any{map[string]any{"side": "R", "hash": "!!"}}}
	if VerifyInclusion(root, proof, leaf) {
		t.Fatal("undecodable sibling accepted")
	}
	// the same with a wrong-length (but decodable) sibling
	proof["path"] = []any{map[string]any{"side": "R", "hash": "AAAA"}}
	if VerifyInclusion(b64.EncodeToString(nodeHash(h, []byte{0, 0, 0})), proof, leaf) {
		t.Fatal("short sibling accepted")
	}
	// and a good two-leaf proof, both sides
	h2, _ := leafHash("y")
	rt, _ := MerkleRoot([]any{"x", "y"})
	for i, side := range []string{"R", "L"} {
		sib, lf := h2, "x"
		if side == "L" {
			sib, lf = h, "y"
		}
		p := map[string]any{"index": json.Number(string(rune('0' + i))), "size": json.Number("2"),
			"path": []any{map[string]any{"side": side, "hash": b64.EncodeToString(sib)}}}
		if !VerifyInclusion(rt, p, lf) {
			t.Fatalf("good proof side %s", side)
		}
	}
}

func baseWire(t *testing.T) map[string]any {
	t.Helper()
	p, _, _, _ := loadValidVector(t)
	b, _ := json.Marshal(p)
	q, err := ParsePCActn(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestMutWireAudNonceCaps(t *testing.T) {
	p := baseWire(t)
	if r := ValidateWireV2(p); r != "" {
		t.Fatalf("base: %s", r)
	}
	for n, ok := range map[int]bool{1: true, 256: true, 257: false} {
		p["aud"] = strings.Repeat("a", n)
		if r := ValidateWireV2(p); (r == "") != ok {
			t.Fatalf("aud len %d: %q", n, r)
		}
	}
	p["aud"] = ""
	if ValidateWireV2(p) != "'aud' must be a non-empty string" {
		t.Fatal("empty aud")
	}
	p["aud"] = "rs"
	for n, ok := range map[int]bool{0: false, 1: true, 128: true, 129: false} {
		p["nonce"] = strings.Repeat("n", n)
		if r := ValidateWireV2(p); (r == "") != ok {
			t.Fatalf("nonce len %d: %q", n, r)
		}
	}
	p["nonce"] = 5
	if ValidateWireV2(p) != "'nonce' must be a non-empty string" {
		t.Fatal("non-string nonce")
	}
}
