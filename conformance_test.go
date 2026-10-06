package pca

import (
	"os"
	"testing"
)

const dir = "conformance/"

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(dir + name)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestVectors(t *testing.T) {
	doc := load(t, "vectors.json")
	vs := doc["vectors"].([]any)
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	for _, x := range vs {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			got, err := VerifyPCActnCore(v["pcactn"].(map[string]any), v["grant"].(map[string]any))
			if err != nil {
				t.Fatal(err)
			}
			exp := v["expect"].(map[string]any)
			if got.Allow != exp["allow"].(bool) {
				t.Errorf("allow = %v, want %v (%s)", got.Allow, exp["allow"], got.Reason)
			}
			for k, w := range exp["checks"].(map[string]any) {
				if got.Checks[k] != w.(bool) {
					t.Errorf("check %s = %v, want %v", k, got.Checks[k], w)
				}
			}
		})
	}
}

func TestPrimitives(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	for _, x := range prim["canonical"].([]any) {
		c := x.(map[string]any)
		s, err := Canonicalize(c["value"])
		if err != nil || s != c["expect"].(string) {
			t.Errorf("canonical mismatch: %q vs %q (%v)", s, c["expect"], err)
		}
		h, _ := HashCanonical(c["value"])
		if h != c["hash"].(string) {
			t.Errorf("hash mismatch for %s", s)
		}
	}
	for _, x := range prim["merkle"].([]any) {
		m := x.(map[string]any)
		leaves := m["leaves"].([]any)
		root, err := MerkleRoot(leaves)
		if err != nil || root != m["root"].(string) {
			t.Errorf("merkle root mismatch: %s vs %s", root, m["root"])
		}
		for i, p := range m["proofs"].([]any) {
			if !VerifyInclusion(root, p.(map[string]any), leaves[i]) {
				t.Errorf("proof %d does not verify", i)
			}
		}
	}
	e, _ := ParamsDigest(nil)
	if e != prim["params_digest_empty"].(string) {
		t.Error("empty params digest mismatch")
	}
}
