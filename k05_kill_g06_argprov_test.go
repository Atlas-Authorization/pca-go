package pca

// k05 mutation kills (group g06): argument provenance (arg_provenance.go): label joins, token characters, leaf limits, the
// recorder's refusals and clock floor, and the decision's fail-closed catch. Self-contained.

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestK05G06ProvJoinAndWordUnits(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"trusted", "first_party", "first_party"},
		{"first_party", "trusted", "first_party"},
		{"web", "agent", "agent"},
		{"agent", "web", "agent"},
		{"tool", "web", "web"},
		{"trusted", "x", "trusted"}, // equal ranks keep the left label
	} {
		if got := provJoin(c.a, c.b); got != c.want {
			t.Fatalf("provJoin(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
	for _, c := range []struct {
		u    uint16
		want bool
	}{{'0', true}, {'9', true}, {'A', true}, {'Z', true}, {'a', true}, {'z', true}, {'_', true}, {0x80, true}, {0x7f, false}, {'/', false}, {':', false}, {'@', false}, {'[', false}, {'`', false}, {'{', false}} {
		if got := provWordUnit(c.u); got != c.want {
			t.Fatalf("provWordUnit(%#x) = %v", c.u, got)
		}
	}
}

func TestK05G06IsReadOnlyActionTraits(t *testing.T) {
	read := []any{"read"}
	for _, c := range []struct {
		a    map[string]any
		want bool
	}{
		{map[string]any{"effects": read}, true},
		{map[string]any{"effects": read, "traits": nil}, true},
		{map[string]any{"effects": read, "traits": "x"}, false},
		{map[string]any{"effects": read, "traits": []any{"pca.pii_access"}}, true},
		{map[string]any{"effects": read, "traits": []any{"pca.write"}}, false},
	} {
		if got := IsReadOnlyAction(c.a); got != c.want {
			t.Fatalf("%v: %v", c.a, got)
		}
	}
}

func g06nest(k int) any {
	var v any = "x"
	for i := 0; i < k; i++ {
		v = []any{v}
	}
	return v
}

func TestK05G06ProvLeavesLimits(t *testing.T) {
	if l, ok := ProvLeaves(g06nest(32)); !ok || len(l) != 1 || l[0] != "x" {
		t.Fatalf("depth 32: %v %v", l, ok)
	}
	if l, ok := ProvLeaves(g06nest(33)); ok || l != nil {
		t.Fatalf("depth 33: %v %v", l, ok)
	}
	keys := func(n int) map[string]any {
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("k%05d", i)] = []any{}
		}
		return m
	}
	if l, ok := ProvLeaves(keys(MaxProvLeaves)); !ok || len(l) != MaxProvLeaves {
		t.Fatalf("%d leaves: %d %v", MaxProvLeaves, len(l), ok)
	}
	if _, ok := ProvLeaves(keys(MaxProvLeaves + 1)); ok {
		t.Fatalf("%d leaves accepted", MaxProvLeaves+1)
	}
}

func TestK05G06ProvParamsDepth(t *testing.T) {
	op := func(k int) Operation {
		return Operation{Verb: "v", Resource: "r", Params: map[string]any{"a": g06nest(k)}}
	}
	// 31 nested lists: JSON for the params reader (depth from 1), too deep for the canonical digest
	if _, err := ProvActionDigest(op(31)); err == nil || err.Error() != "canonicalize: nesting too deep" {
		t.Fatalf("31: %v", err)
	}
	if _, err := ProvActionDigest(op(32)); err == nil || err.Error() != "provenance: the operation params are not JSON" {
		t.Fatalf("32: %v", err)
	}
	for _, c := range []struct {
		k    int
		want string
	}{{31, "canonicalize: nesting too deep"}, {32, "provenance: the operation params are not JSON"}} {
		r := g06rec(t, ProvenanceRecorderOptions{})
		if b, err := PrincipalDirectProvenance(r, op(c.k)); err == nil || err.Error() != c.want || b != nil || len(r.Receipts()) != 0 {
			t.Fatalf("direct %d: %v %v, %d receipts", c.k, b, err, len(r.Receipts()))
		}
	}
}

func TestK05G06ProvClipSurrogateBoundaries(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	for _, c := range []struct{ in, want string }{
		{a(199) + "\U00010000" + a(200), a(199)}, // the cut lands on low surrogate DC00: back off one unit
		{a(199) + "\U000103FF" + a(200), a(199)}, // low surrogate DFFF
		{a(200) + "\uE000" + a(200), a(200)},     // U+E000 is no surrogate: no back-off
	} {
		if got, err := provClip(c.in); err != nil || got != c.want {
			t.Fatalf("provClip: %d units, want %d (%v)", len(utf16Units(got)), len(utf16Units(c.want)), err)
		}
	}
}

func TestK05G06ProvBundleSession(t *testing.T) {
	one := map[string]any{"receipts": []any{map[string]any{"session": "s0"}}}
	two := map[string]any{"receipts": []any{map[string]any{"session": "s0"}, map[string]any{"session": "s1"}}}
	if provBundleSession(one) != "s0" || provBundleSession(two) != "s0" || provBundleSession(map[string]any{}) != "" {
		t.Fatal("provBundleSession reads the first receipt's session")
	}
}

func g06rec(t *testing.T, o ProvenanceRecorderOptions) *ProvenanceRecorder {
	t.Helper()
	if o.Mediator == "" {
		o.Mediator = "m"
	}
	if o.Kid == "" {
		o.Kid = "k"
	}
	r, err := NewProvenanceRecorder(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestK05G06ProvRecorderOptions(t *testing.T) {
	if _, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: strings.Repeat("m", 256), Kid: "k"}); err != nil {
		t.Fatalf("mediator of 256 bytes: %v", err)
	}
	if _, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: strings.Repeat("m", 257), Kid: "k"}); err == nil {
		t.Fatal("mediator of 257 bytes accepted")
	}
	if _, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: "m", Kid: "k", Suite: &SuiteOpts{}}); err != nil {
		t.Fatalf("explicit ed25519 suite: %v", err)
	}
	if _, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: "m", Kid: "k", Suite: &SuiteOpts{Alg: "x"}}); err == nil ||
		err.Error() != "NewProvenanceRecorder: x needs a post-quantum key pair" {
		t.Fatalf("suite without a post-quantum key: %v", err)
	}
	r1, r2 := g06rec(t, ProvenanceRecorderOptions{}), g06rec(t, ProvenanceRecorderOptions{})
	if r1.Session == r2.Session || r1.Pin.PK == r2.Pin.PK {
		t.Fatal("two recorders share a random session or key")
	}
}

func TestK05G06ProvRecorderClockFloor(t *testing.T) {
	r := g06rec(t, ProvenanceRecorderOptions{Now: func() int64 { return -5 }})
	rc, err := r.Principal("hi")
	if err != nil {
		t.Fatal(err)
	}
	if f := jsF(rc["issued_at"]); f != 0 {
		t.Fatalf("issued_at %v, want 0", rc["issued_at"])
	}
}

func TestK05G06ProvRecorderRefusals(t *testing.T) {
	const lone = "\xed\xa0\x80" // a lone surrogate (WTF-8): outside the strict canonical profile
	const loneErr = "canonicalize: lone surrogate in string"
	r := g06rec(t, ProvenanceRecorderOptions{})
	if rc, err := r.Tool("t", lone); err == nil || err.Error() != loneErr || rc != nil {
		t.Fatalf("lone-surrogate content: %v %v", rc, err)
	}
	if rc, err := r.Tool(lone, "c"); err == nil || err.Error() != loneErr || rc != nil {
		t.Fatalf("lone-surrogate source: %v %v", rc, err)
	}
	if b, err := r.ForAction(Operation{Verb: "v", Resource: "r", Params: map[string]any{"x": math.NaN()}}); err == nil ||
		err.Error() != "provenance: the operation params are not JSON" || b != nil {
		t.Fatalf("NaN params: %v %v", b, err)
	}
	if b, err := PrincipalDirectProvenance(r, Operation{Verb: lone, Resource: "r", Params: map[string]any{}}); err == nil || err.Error() != loneErr || b != nil {
		t.Fatalf("lone-surrogate verb: %v %v", b, err)
	}
	if n := len(r.Receipts()); n != 0 {
		t.Fatalf("%d receipts recorded by refused calls", n)
	}

	// a previous receipt outside the strict profile: nothing more is appended
	const notCanon = "provenance: the previous receipt is not canonical"
	bad := map[string]any{"x": lone}
	c := g06rec(t, ProvenanceRecorderOptions{})
	c.chain = []map[string]any{bad}
	if rc, err := c.Tool("t", "c"); err == nil || err.Error() != notCanon || rc != nil {
		t.Fatalf("segment after a bad receipt: %v %v", rc, err)
	}
	op := Operation{Verb: "v", Resource: "r", Params: map[string]any{}}
	if b, err := c.ForAction(op); err == nil || err.Error() != notCanon || b != nil {
		t.Fatalf("action after a bad receipt: %v %v", b, err)
	}
	// a full session whose last receipt is bad: the principal segment's refusal comes first
	full := g06rec(t, ProvenanceRecorderOptions{})
	for i := 0; i < MaxProvReceipts; i++ {
		full.chain = append(full.chain, bad)
	}
	if b, err := PrincipalDirectProvenance(full, op); err == nil || err.Error() != notCanon || b != nil {
		t.Fatalf("direct provenance after a bad receipt: %v %v", b, err)
	}
}

func TestK05G06DecideArgProvenanceObservations(t *testing.T) {
	in := func(source string) map[string]any {
		return map[string]any{"operation": map[string]any{"verb": "v", "resource": "r", "params": map[string]any{}}, "mediators": []any{},
			"observed": []any{map[string]any{"origin": "tool", "source": source}}}
	}
	const bad = "observations must be a list of {origin, source}"
	if d := DecideArgProvenance(in(strings.Repeat("s", 256))); d.Outcome != "escalate" || d.Reason == bad {
		t.Fatalf("source of 256 bytes: %+v", d)
	}
	if d := DecideArgProvenance(in(strings.Repeat("s", 257))); d.Outcome != "deny" || d.Code != "malformed_config" || d.Reason != bad {
		t.Fatalf("source of 257 bytes: %+v", d)
	}
}

func TestK05G06DecideArgProvenanceRecovers(t *testing.T) {
	old := provNormalizeInput
	provNormalizeInput = func(any) any { panic("boom") }
	t.Cleanup(func() { provNormalizeInput = old })
	d := DecideArgProvenance(map[string]any{})
	if d.Outcome != "deny" || d.Code != "malformed_config" || d.Reason != "evaluation error (fail closed): boom" {
		t.Fatalf("%+v", d)
	}
}
