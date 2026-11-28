package pca

import (
	"strings"
	"testing"
)

// The compact mesh proof's layout on unusual evidence, as the TypeScript reference (mesh.ts assembleMeshProof) builds it:
// entries dedupe by canonical JSON (member order does not matter; a non-canonical number such as 3.0 is refused, fail closed), absent members stay absent (a present null is kept), JS-falsy bracketing leaves and
// bindings are dropped, and head cosignatures must be an array.

func mpAssemble(t *testing.T, hops ...string) (map[string]any, error) {
	t.Helper()
	k := sreKey(t, sreDoc(t), "agent")
	return AssembleMeshProof([]map[string]any{{"id": "c0"}}, sreObjs(sreJSON(t, "["+strings.Join(hops, ",")+"]")),
		map[string]any{"verb": "read"}, k, nil)
}

func mpWant(t *testing.T, name string, p map[string]any, err error, member, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if g, w := sreCanon(t, p[member]), sreCanon(t, sreJSON(t, want)); g != w {
		t.Errorf("%s %s\n got  %s\n want %s", name, member, g, w)
	}
}

func TestMeshProofDedupesByCanonicalJSON(t *testing.T) {
	p, err := mpAssemble(t,
		`{"domain":"d","head":{"head":{"a":1,"b":3},"sig":"s","cosigs":[{"witness":"w1"}]},"inclusion":{},`+
			`"revocation":{"cap":{"size":2,"lo":{"id":"x","n":3},"hi":0},"issuer_key":{"size":2,"lo":"","hi":false}},"binding":false}`,
		`{"domain":"d","head":{"head":{"b":3,"a":1},"sig":"s","cosigs":[{"witness":"w2"}]},"inclusion":{},`+
			`"revocation":{"cap":{"size":2},"issuer_key":{"size":2,"hi":{"n":3,"id":"x"}}},"binding":{"k":1}}`)
	mpWant(t, "dedupe", p, err, "heads", `[{"head":{"a":1,"b":3},"sig":"s","cosigs":[{"witness":"w1"},{"witness":"w2"}]}]`)
	mpWant(t, "dedupe", p, err, "rev_leaves", `[{"id":"x","n":3}]`)
	mpWant(t, "dedupe", p, err, "hops", `[`+
		`{"domain":"d","head":0,"inclusion":{},"revocation":{"cap":{"size":2,"lo":0},"issuer_key":{"size":2}}},`+
		`{"domain":"d","head":0,"inclusion":{},"revocation":{"cap":{"size":2},"issuer_key":{"size":2,"hi":0}},"binding":{"k":1}}]`)
}

func TestMeshProofAbsentMembersStayAbsent(t *testing.T) {
	p, err := mpAssemble(t, `{"head":{"cosigs":[]},"revocation":{"cap":{},"issuer_key":{"size":1}}}`)
	mpWant(t, "absent", p, err, "heads", `[{"cosigs":[]}]`)
	mpWant(t, "absent", p, err, "hops", `[{"head":0,"revocation":{"cap":{},"issuer_key":{"size":1}}}]`)
	// a present null is the reference's null, kept as is
	p, err = mpAssemble(t, `{"domain":null,"inclusion":null,"head":{"head":null,"sig":null,"cosigs":[]},"revocation":{"cap":{"size":null},"issuer_key":{}}}`)
	mpWant(t, "null", p, err, "heads", `[{"head":null,"sig":null,"cosigs":[]}]`)
	mpWant(t, "null", p, err, "hops", `[{"domain":null,"head":0,"inclusion":null,"revocation":{"cap":{"size":null},"issuer_key":{}}}]`)
}

func TestMeshProofRefusesCosigsThatAreNotAnArray(t *testing.T) {
	hop := func(head string) string {
		return `{"domain":"d","head":{"head":1,"sig":"s"` + head + `},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}`
	}
	for _, c := range []struct {
		name string
		hops []string
	}{
		{"absent", []string{hop("")}},
		{"null", []string{hop(`,"cosigs":null`)}},
		{"string", []string{hop(`,"cosigs":"ab"`)}}, // the reference spreads a string into its characters; refused here
		{"object", []string{hop(`,"cosigs":{}`)}},
		{"absent on a merge", []string{hop(`,"cosigs":[]`), hop("")}},
	} {
		p, err := mpAssemble(t, c.hops...)
		sreErr(t, c.name, err, "AssembleMeshProof: head cosigs must be an array")
		if p != nil {
			t.Errorf("%s: %v", c.name, p)
		}
	}
}
