package pca

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// Replays packages/pca/conformance/provenance-vectors.json: build provenance gates (track K9).
func loadProvenance(t *testing.T) map[string]any {
	t.Helper()
	for _, p := range []string{"conformance/provenance-vectors.json", dir + "provenance-vectors.json"} {
		if b, err := os.ReadFile(p); err == nil {
			v, err := ParseJSONLenient(b)
			if err != nil {
				t.Fatal(err)
			}
			return v.(map[string]any)["primitives"].(map[string]any)
		}
	}
	t.Fatal("provenance-vectors.json is missing")
	return nil
}

func unhexT(t *testing.T, s any) []byte {
	b, err := hex.DecodeString(s.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProvenanceVectors(t *testing.T) {
	doc := loadProvenance(t)
	for k, want := range map[string]int{"merkle_inclusion": 44, "gate": 45, "model_path": 7} {
		if n := len(doc[k].([]any)); n < want {
			t.Fatalf("%s: %d vectors, want >= %d", k, n, want)
		}
	}
	for _, x := range doc["merkle_inclusion"].([]any) {
		e := x.(map[string]any)
		i := e["input"].(map[string]any)
		var proof [][]byte
		for _, h := range i["proof_hex"].([]any) {
			proof = append(proof, unhexT(t, h))
		}
		ok := VerifyRFC9162Inclusion(RFC9162LeafHash(unhexT(t, i["leaf_hex"])), num(i["index"]), num(i["size"]), proof, unhexT(t, i["root_hex"]))
		if ok != e["expect"].(map[string]any)["ok"] {
			t.Errorf("merkle %v: got %v", e["name"], ok)
		}
	}
	for _, x := range doc["gate"].([]any) {
		e := x.(map[string]any)
		g := ProvenanceGate(e["input"])
		got := map[string]any{"ok": g.OK}
		if g.OK {
			got["level"], got["claims"] = g.Level, g.Claims
		} else {
			got["code"] = g.Code
		}
		if want := provPlain(e["expect"]); !reflect.DeepEqual(got, want) {
			t.Errorf("gate %v:\n got %v\nwant %v", e["name"], got, want)
		}
	}
	for _, x := range doc["model_path"].([]any) {
		e := x.(map[string]any)
		if got := isModelDerivedPath(e["input"].(map[string]any)["path"].(string), nil); got != e["expect"].(map[string]any)["model"] {
			t.Errorf("model_path %v: got %v", e["name"], got)
		}
	}
}

// provPlain turns json.Number into int64 so a vector compares exactly with ProvenanceGate's claims.
func provPlain(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, x := range t {
			m[k] = provPlain(x)
		}
		return m
	case json.Number:
		return num(t)
	}
	return v
}

func TestProvenanceCaveatAndTotality(t *testing.T) {
	c := ProvenanceCaveat(ProvenanceCaveatOptions{Issuer: "ci", MinLevel: 3, SourceRepo: "https://github.com/acme/tool"})
	if e := NeedsDischargeError(c); e != "" {
		t.Fatal(e)
	}
	req := c["require"].([]any)
	if c["issuer_class"] != "artifact" || c["id"] != "provenance" || c["bind"] != "action" || c["ttl_ms"] != int64(300_000) || len(req) != 3 ||
		req[2].(map[string]any)["claim"] != "runtime_bound" {
		t.Fatalf("caveat %v", c)
	}
	for _, bad := range []any{nil, 1, "x", []any{}, map[string]any{"facts": map[string]any{}, "policy": map[string]any{}}} {
		if ProvenanceGate(bad).OK {
			t.Errorf("%v passed", bad)
		}
	}
	if VerifyRFC9162Inclusion(nil, 1<<60, 1, nil, nil) {
		t.Error("malformed inclusion passed")
	}
}
