package pca

import "testing"

// g07asRep builds a report from (name, entry) pairs in order.
func g07asRep(names []string, entries []CheckAssurance) AssuranceReport {
	var r AssuranceReport
	for i, n := range names {
		r.Set(n, entries[i])
	}
	return r
}

func TestG07AssuranceZkRanks(t *testing.T) {
	zk := func(level, req string) string {
		return UnmetAssurance(g07asRep([]string{"zk_compliance"}, []CheckAssurance{{Outcome: "pass", Level: level}}), AssuranceRequirement{Zk: req})
	}
	cases := []struct{ level, req, want string }{
		{"stark", "proof", ""},
		{"zkvm", "proof", ""},
		{"stark", "snark", "assurance: zk compliance (snark) required but the evidence is stark"},
		{"zkvm", "snark", "assurance: zk compliance (snark) required but the evidence is zkvm"},
		{"attested_vm", "proof", "assurance: zk compliance (proof) required but the evidence is attested_vm"},
		{"attested_vm_hw", "proof", "assurance: zk compliance (proof) required but the evidence is attested_vm_hw"},
		{"attested_vm_hw", "attested_vm", ""},
		{"", "attested_vm", "assurance: zk compliance (attested_vm) required but the evidence is unknown"},
		{"groth16", "snark", ""},
	}
	for _, c := range cases {
		if got := zk(c.level, c.req); got != c.want {
			t.Errorf("%s vs %s: got %q, want %q", c.level, c.req, got, c.want)
		}
	}
}

func TestG07AssuranceEmptyReasons(t *testing.T) {
	r := g07asRep([]string{"bond"}, []CheckAssurance{{Outcome: "unsupported"}})
	if got, want := UnmetAssurance(r, AssuranceRequirement{}), "assurance: unsupported: bond (not implemented); a high-assurance policy never accepts it"; got != want {
		t.Errorf("got %q", got)
	}
	r = g07asRep([]string{"attestation"}, []CheckAssurance{{Outcome: "pass", Degraded: true}})
	if got, want := UnmetAssurance(r, AssuranceRequirement{}), "assurance: attestation rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it"; got != want {
		t.Errorf("got %q", got)
	}
	r = g07asRep([]string{"attestation"}, []CheckAssurance{{Outcome: "pass"}})
	if got, want := UnmetAssurance(r, AssuranceRequirement{Attestation: "hardware"}), "assurance: hardware attestation required but the evidence is unknown"; got != want {
		t.Errorf("got %q", got)
	}
}

func TestG07AssuranceAwaitingAuditOutsideThreshold(t *testing.T) {
	req := AssuranceRequirement{Threshold: []string{"frost"}}
	thr := CheckAssurance{Outcome: "pass", Level: "frost", AwaitingAudit: true}
	if got := UnmetAssurance(g07asRep([]string{"threshold"}, []CheckAssurance{thr}), req); got != "" {
		t.Errorf("listed threshold scheme refused: %q", got)
	}
	r := g07asRep([]string{"threshold", "attestation"}, []CheckAssurance{thr, {Outcome: "pass", Level: "frost", AwaitingAudit: true}})
	if got, want := UnmetAssurance(r, req), "assurance: attestation rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it"; got != want {
		t.Errorf("got %q", got)
	}
}

func TestG07MultiRootLevelEdges(t *testing.T) {
	hw := WithAssuranceLabel("h", AssuranceLabel{Level: "hardware"})
	sw := WithAssuranceLabel("s", AssuranceLabel{Level: "software"})
	if got := MultiRootLevel([]AttestationRoot{{Verifier: hw, Required: true}}, 0); got != "hardware" {
		t.Errorf("threshold 0: %q", got)
	}
	if got := MultiRootLevel([]AttestationRoot{{Verifier: "plain", Required: true}, {Verifier: sw, Required: true}}, 2); got != "unknown" {
		t.Errorf("unknown+software: %q", got)
	}
	if got := MultiRootLevel([]AttestationRoot{{Verifier: sw, Required: true}}, 1); got != "software" {
		t.Errorf("software: %q", got)
	}
	if got := weakestLevel([]string{"pq"}); got != "pq" {
		t.Errorf("weakestLevel pq: %q", got)
	}
}

func TestG07BuildAssuranceReportEdges(t *testing.T) {
	r := BuildAssuranceReport(AssuranceSources{
		Checks:         []NamedStatus{{"cap_chain", "pass"}},
		PCActn:         map[string]any{"cap_chain": []any{map[string]any{}}},
		AllowUnboundPq: true,
	})
	if e, _ := r.Get("cap_chain"); e.Level != "ed25519" {
		t.Errorf("ed25519 chain with AllowUnboundPq: %q", e.Level)
	}
	r = BuildAssuranceReport(AssuranceSources{
		Checks: []NamedStatus{{"attestation", "pass"}},
		Hooks:  AssuranceHooks{Attestation: WithAssuranceLabel("a", AssuranceLabel{Vendor: "v", Ceremony: "multi-party"})},
	})
	if e, _ := r.Get("attestation"); e.Level != "unknown" || e.Vendor != "v" || e.Ceremony != "" {
		t.Errorf("attestation entry: %+v", e)
	}
}
