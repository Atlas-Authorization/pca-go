package pca

import (
	"bytes"
	"strings"
	"testing"
)

// g08: kills for actions.go (def validation bounds, normalization order, pack proofs), policyclasses.go and
// provenance_gate.go (RFC 9162 inclusion bounds, the recover scope).

// g08Seg128 is a 128-byte verb-shaped name (4 segments); tail extends the last segment.
func g08Seg128(tail int) string {
	return strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + "." + strings.Repeat("c", 32) + "." + strings.Repeat("d", 29+tail)
}

func TestK05KillG08DefBounds(t *testing.T) {
	if n := len(g08Seg128(0)); n != 128 {
		t.Fatalf("fixture length %d", n)
	}
	const titleErr = "title must be a non-empty string up to 120 bytes"
	const verbErr = "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)"
	def := func(kv ...any) map[string]any {
		return g08With(map[string]any{"v": 1, "kind": "pca-action-def", "verb": "a.b"}, kv...)
	}
	g08Eq(t, "verb 128", validateDef(def("verb", g08Seg128(0))), titleErr)
	g08Eq(t, "verb 129", validateDef(def("verb", g08Seg128(1))), verbErr)
	g08Eq(t, "alias 128", validateDef(def("aliases", []any{g08Seg128(0)})), titleErr)
	g08Eq(t, "alias 129", validateDef(def("aliases", []any{g08Seg128(1)})), "aliases must be distinct verb-shaped names other than the verb")
	// resource.type: 128 bytes accepted (the next refusal is params), 129 refused.
	rt128 := strings.Repeat("r", 32) + "." + strings.Repeat("s", 32) + "." + strings.Repeat("t", 32) + "." + strings.Repeat("u", 29)
	res := func(rt string) map[string]any {
		return def("title", "t", "effects", []any{"read"}, "resource", map[string]any{"type": rt, "id": "*", "scope": "one"})
	}
	g08Eq(t, "rt 128", validateDef(res(rt128)), "params must be an object")
	g08Eq(t, "rt 129", validateDef(res(rt128+"u")), "resource.type is malformed")
	// the strict-JSON profile starts at depth 0: a scalar under 32 arrays is fine, under 33 it is too deep.
	nest := func(n int) any {
		var v any = 0
		for i := 0; i < n; i++ {
			v = []any{v}
		}
		return v
	}
	g08Eq(t, "depth 32", validateDef(nest(32)), "def must be an object")
	g08Eq(t, "depth 33", validateDef(nest(33)), "not strict JSON: nesting deeper than 32")
}

func TestK05KillG08DefRecoverSeam(t *testing.T) {
	validateDefHook = func(any) { panic("g08 boom") }
	defer func() { validateDefHook = nil }()
	g08Eq(t, "panic", validateDef(map[string]any{}), "malformed def: g08 boom")
}

func TestK05KillG08IDPatternLen(t *testing.T) {
	const lm = "resource.id.len must be [min, max] in 1..128"
	for _, c := range []struct {
		ln   []any
		want string
	}{
		{[]any{1, 1}, ""}, {[]any{1, 128}, ""}, {[]any{0, 5}, lm}, {[]any{1.5, 5}, lm}, {[]any{129, 5}, lm}, {[]any{200, 5}, lm},
		{[]any{1, 0}, lm}, {[]any{1, 1.5}, lm}, {[]any{1, 129}, lm}, {[]any{5, 4}, "resource.id.len: min > max"},
	} {
		got := idPatternError(map[string]any{"prefix": "", "class": "digits", "len": c.ln})
		g08Eq(t, "len", got, c.want)
	}
}

func TestK05KillG08ActionHelpers(t *testing.T) {
	if got, found := unknownMember(map[string]any{"zz": 1, "aa": 1, "mm": 1, "kind": 1}, []string{"kind"}); !found || got != "aa" {
		t.Errorf("unknownMember = %q, want aa", got)
	}
	if got, found := unknownMember(map[string]any{"kind": 1}, []string{"kind"}); found || got != "" {
		t.Errorf("unknownMember none = %q", got)
	}
	if revRank["reversible"] != 0 || revRank["rate_limited"] != 1 || revRank["irreversible"] != 2 || len(revRank) != 3 {
		t.Errorf("revRank %v", revRank)
	}
	if sensitivityRank["free"] != 0 || sensitivityRank["material"] != 1 || sensitivityRank["critical"] != 2 || len(sensitivityRank) != 3 {
		t.Errorf("sensitivityRank %v", sensitivityRank)
	}
	// maxSens keeps the first argument on a tie (an unknown class ranks with free).
	for _, c := range [][3]string{{"bogus", "free", "bogus"}, {"free", "bogus", "free"}, {"free", "critical", "critical"}, {"critical", "material", "critical"}} {
		if got := maxSens(c[0], c[1]); got != c[2] {
			t.Errorf("maxSens(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestK05KillG08NormalizeDef(t *testing.T) {
	se := func(tg, k string) any { return map[string]any{"target": tg, "kind": k} }
	d := map[string]any{"kind": "pca-action-def", "verb": "a.b", "title": "t", "effects": []any{"read"},
		"resource": map[string]any{"type": "t", "id": "*", "scope": "one"}, "params": map[string]any{},
		"side_effects": []any{se("b", "create"), se("a", "update"), se("a", "create")}}
	out := normalizeDef(d)
	var got []string
	for _, e := range out["side_effects"].([]any) {
		m := e.(map[string]any)
		got = append(got, m["target"].(string)+"/"+m["kind"].(string))
	}
	if strings.Join(got, ",") != "a/create,a/update,b/create" {
		t.Errorf("side_effects order %v", got)
	}
	if ppm := out["blast"].(map[string]any)["ppm"].(int); ppm != 50000 {
		t.Errorf("scope one ppm %d", ppm)
	}
	// an unknown scope has no radius: the ppm stays 0.
	d["resource"] = map[string]any{"type": "t", "id": "*", "scope": "bogus"}
	if ppm := normalizeDef(d)["blast"].(map[string]any)["ppm"].(int); ppm != 0 {
		t.Errorf("unknown scope ppm %d", ppm)
	}
}

func TestK05KillG08PackProof(t *testing.T) {
	if _, err := packProof([]string{"x", "x"}, "x"); err == nil || err.Error() != "duplicate_def: a pack lists a def digest twice" {
		t.Errorf("dup: %v", err)
	}
	if _, err := packProof([]string{"a"}, "z"); err == nil || err.Error() != "not_in_pack: the digest is not in the pack" {
		t.Errorf("above all: %v", err)
	}
	lone := "\xed\xa0\x80"
	_, want := leafHash(packLeaf(lone))
	if want == nil {
		t.Fatal("a lone surrogate leaf must not canonicalize")
	}
	if p, err := packProof([]string{lone}, lone); err == nil || err.Error() != want.Error() || p != nil {
		t.Errorf("leaf hash error: %v %v", p, err)
	}
	p, err := packProof([]string{"a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if path, ok := p["path"].([]any); !ok || path == nil || len(path) != 0 {
		t.Errorf("single-leaf path %#v", p["path"])
	}
}

func TestK05KillG08PolicyClasses(t *testing.T) {
	if policyClassIndex("nope") != -1 || policyClassIndex("constitution") != 0 || policyClassIndex("user") != 4 {
		t.Error("policyClassIndex")
	}
	entry := func(c, digest string) any {
		return map[string]any{"class": c, "revision": 0, "digest": digest, "decision": "allow"}
	}
	six := []any{entry("org", "d"), entry("org", "d"), entry("org", "d"), entry("org", "d"), entry("org", "d"), entry("org", "d")}
	g08Eq(t, "six", ClassVerdictsError(six), "more than 5 policy classes")
	g08Eq(t, "digest 128", ClassVerdictsError([]any{entry("org", strings.Repeat("d", 128))}), "")
	g08Eq(t, "digest 129", ClassVerdictsError([]any{entry("org", strings.Repeat("d", 129))}), "policy_classes[0].digest invalid")
}

func TestK05KillG08RFC9162Bounds(t *testing.T) {
	leaf := RFC9162LeafHash([]byte("g08"))
	p1 := bytes.Repeat([]byte{0x11}, 32)
	if !VerifyRFC9162Inclusion(leaf, 0, 2, [][]byte{p1}, rfc9162Node(leaf, p1)) {
		t.Fatal("control proof refused")
	}
	// the largest safe size: index 0 needs 53 right siblings.
	var proof [][]byte
	r := leaf
	for i := 0; i < 53; i++ {
		p := bytes.Repeat([]byte{byte(i + 1)}, 32)
		proof = append(proof, p)
		r = rfc9162Node(r, p)
	}
	if !VerifyRFC9162Inclusion(leaf, 0, int64(maxSafeInt), proof, r) {
		t.Error("size 2^53-1 refused")
	}
	// a 31-byte leaf hash is refused even when the proof would compute the root.
	short := leaf[:31]
	if VerifyRFC9162Inclusion(short, 0, 2, [][]byte{p1}, rfc9162Node(short, p1)) {
		t.Error("31-byte leaf accepted")
	}
	if VerifyRFC9162Inclusion(short, 0, 1, nil, short) {
		t.Error("31-byte leaf/root accepted")
	}
	// a proof longer than the tree is high is refused.
	if VerifyRFC9162Inclusion(leaf, 0, 1, [][]byte{p1}, rfc9162Node(p1, leaf)) {
		t.Error("extra proof element accepted")
	}
}

func TestK05KillG08ProvenanceRecoverSeam(t *testing.T) {
	in := map[string]any{"policy": nil}
	if r := ProvenanceGate(in); r.Code != "malformed_policy" {
		t.Fatalf("baseline %q", r.Code)
	}
	provenanceGateHook = func(any) { panic("g08 boom") }
	defer func() { provenanceGateHook = nil }()
	if r := ProvenanceGate(in); r.OK || r.Code != "malformed_facts" {
		t.Errorf("panic: %+v", r)
	}
}
