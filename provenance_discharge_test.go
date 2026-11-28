package pca

import "testing"

func TestProvenanceDischargeBodyAndLowerMedian(t *testing.T) {
	req := map[string]any{"caveat_id": "provenance", "issuer": "ci", "cap_hash": "h", "bind": "action", "ttl_ms": jsNumber(1000), "action_digest": "ad"}
	gate := ProvenanceGateResult{OK: true, Level: 3, Claims: map[string]any{"slsa_level": int64(3)}}
	d, err := ProvenanceDischargeBody(req, gate, 5000, 1000, "n")
	if err != nil || d.CaveatID != "provenance" || d.NotAfter != 6000 || d.ActionDigest != "ad" || d.Claims["slsa_level"] != int64(3) {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := ProvenanceDischargeBody(req, gate, 5000, 1001, "n"); err == nil {
		t.Fatal("ttl above the caveat's was accepted")
	}
	if _, err := ProvenanceDischargeBody(req, ProvenanceGateResult{Code: "no_facts"}, 1, 1, "n"); err == nil {
		t.Fatal("a refused gate produced a discharge")
	}
	if m, _ := LowerMedian([]float64{4, 1, 3, 2}); m != 2 {
		t.Fatalf("median %v", m)
	}
	if m, _ := LowerMedian([]float64{9}); m != 9 {
		t.Fatal("single")
	}
	if _, err := LowerMedian(nil); err == nil {
		t.Fatal("empty")
	}
}
