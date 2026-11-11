package pca

import (
	"os"
	"strings"
	"testing"
)

// The shared mesh corpus (packages/pca/conformance/mesh-vectors.json): whole mesh proofs with the TypeScript verdict.
func TestMeshVectors(t *testing.T) {
	doc := load(t, "mesh-vectors.json")
	vecs, _ := doc["mesh"].([]any)
	if len(vecs) < 100 {
		t.Fatalf("expected at least 100 mesh vectors, got %d", len(vecs))
	}
	run, skipped := 0, 0
	for _, raw := range vecs {
		v := raw.(map[string]any)
		name := v["name"].(string)
		expect := v["expect"].(map[string]any)
		wantOK := expect["ok"].(bool)
		got := VerifyMeshProof(v["proof"], v["trust"])
		run++
		if got.OK != wantOK {
			t.Errorf("%s: ok = %v (reason %q), want %v (reason %q)", name, got.OK, got.Reason, wantOK, expect["reason"])
			continue
		}
		if wantOK {
			continue
		}
		wantReason, _ := expect["reason"].(string)
		if strings.HasPrefix(wantReason, "chain:") {
			if !strings.HasPrefix(got.Reason, "chain:") {
				t.Errorf("%s: reason %q, want a chain refusal (%q)", name, got.Reason, wantReason)
			}
			continue
		}
		if got.Reason != wantReason {
			t.Errorf("%s: reason %q, want %q", name, got.Reason, wantReason)
		}
		wantHop := -1
		if h, ok := expect["hop"]; ok {
			wantHop = int(num(h))
		}
		if got.Hop != wantHop {
			t.Errorf("%s: hop %d, want %d", name, got.Hop, wantHop)
		}
	}
	_ = skipped
	_ = os.Stdout
	t.Logf("%d mesh vectors", run)
}

// a head pinned at size 0 (root "") advances: "" is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused.
func TestMeshEmptyHeadAdvances(t *testing.T) {
	v, err := ParseJSONLenient([]byte(`{"e":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":0,"root":"","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"n":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":3,"root":"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"ok":{"oldSize":0,"newSize":3,"path":[]},"path":{"oldSize":0,"newSize":3,"path":["CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow"]},"old1":{"oldSize":1,"newSize":3,"path":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	j := normalizeJSON(v).(map[string]any)
	for _, c := range []struct {
		proof any
		want  string
	}{{j["ok"], ""}, {nil, "consistency proof required for a larger head"}, {j["path"], "head is not consistent with the previous head (fork or rewrite)"}, {j["old1"], "consistency proof required for a larger head"}} {
		if got := meshCheckHeadAdvance(j["e"], j["n"], c.proof); got != c.want {
			t.Errorf("proof %v: got %q, want %q", c.proof, got, c.want)
		}
	}
}
