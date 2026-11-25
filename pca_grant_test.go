package pca

import "testing"

// Replays packages/pca/conformance/pca-grant-vectors.json: the pca_grant authorization-details type.
func TestPcaGrantVectors(t *testing.T) {
	doc := load(t, "pca-grant-vectors.json")
	if num(doc["format"]) != 1 {
		t.Fatal("not a format-1 pca_grant vector file")
	}
	for _, x := range doc["digest"].([]any) {
		v := x.(map[string]any)
		var ids []string
		for _, i := range v["ids"].([]any) {
			ids = append(ids, i.(string))
		}
		if got, err := PcaGrantChainDigest(ids); err != nil || got != v["digest"] {
			t.Errorf("digest %v = %q, want %v", ids, got, v["digest"])
		}
	}
	for _, x := range doc["detail"].([]any) {
		v := x.(map[string]any)
		t.Run("detail/"+v["name"].(string), func(t *testing.T) {
			code, ok := ValidatePcaGrantDetail(v["input"])
			exp := v["expect"].(map[string]any)
			if ok != exp["ok"].(bool) || (!ok && code != exp["code"]) {
				t.Errorf("got ok=%v code=%q, want %v", ok, code, exp)
			}
		})
	}
	for _, x := range doc["array"].([]any) {
		v := x.(map[string]any)
		t.Run("array/"+v["name"].(string), func(t *testing.T) {
			list, code := ParsePcaGrantDetails(v["input"])
			exp := v["expect"].(map[string]any)
			ok := code == ""
			if ok != exp["ok"].(bool) {
				t.Fatalf("ok=%v code=%q, want %v", ok, code, exp)
			}
			if ok && int64(len(list)) != num(exp["count"]) {
				t.Errorf("count %d, want %v", len(list), exp["count"])
			}
			if !ok && code != exp["code"] {
				t.Errorf("code %q, want %v", code, exp["code"])
			}
		})
	}
	for _, x := range doc["presentation"].([]any) {
		v := x.(map[string]any)
		t.Run("presentation/"+v["name"].(string), func(t *testing.T) {
			var details []map[string]any
			for _, d := range v["details"].([]any) {
				details = append(details, d.(map[string]any))
			}
			p := v["presented"].(map[string]any)
			var ids []string
			for _, i := range p["chain_ids"].([]any) {
				ids = append(ids, i.(string))
			}
			idx, code := CheckPcaGrantPresentation(details, p["resource"].(string), ids, p["proof_verified"].(bool))
			exp := v["expect"].(map[string]any)
			if exp["allow"].(bool) {
				if code != "" || int64(idx) != num(exp["index"]) {
					t.Errorf("got idx=%d code=%q, want allow index %v", idx, code, exp["index"])
				}
			} else if code != exp["code"] {
				t.Errorf("code %q, want %v", code, exp["code"])
			}
		})
	}
}
