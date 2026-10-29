package pca

import "testing"

// Assurance labels (T8, B7): replays assurance-vectors.json (signature_level, report, requirement, multi_root), then the
// Authorize wiring. A missing vector file fails the test.

func labelFromJSON(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string: // "unlabelled": a hook with no label
		return struct{}{}
	case map[string]any:
		l := AssuranceLabel{}
		l.Level, _ = t["level"].(string)
		l.Vendor, _ = t["vendor"].(string)
		l.AwaitingAudit, _ = t["awaiting_audit"].(bool)
		l.Ceremony, _ = t["ceremony"].(string)
		return WithAssuranceLabel(struct{}{}, l)
	}
	return nil
}

func TestAssuranceSignatureLevelVectors(t *testing.T) {
	rs := grows(t, load(t, "assurance-vectors.json"), "signature_level")
	if len(rs) != 14 {
		t.Fatalf("rows %d", len(rs))
	}
	for _, v := range rs {
		if got := SignatureLevel(v["alg"]); got != v["level"] {
			t.Errorf("%v: %s want %v", v["alg"], got, v["level"])
		}
	}
}

func TestAssuranceReportVectors(t *testing.T) {
	rs := grows(t, load(t, "assurance-vectors.json"), "report")
	if len(rs) != 37 {
		t.Fatalf("rows %d", len(rs))
	}
	for _, v := range rs {
		src := AssuranceSources{}
		checks := v["checks"].(map[string]any)
		for _, name := range jsKeys(checks) {
			src.Checks = append(src.Checks, NamedStatus{Name: name, Status: checks[name].(string)})
		}
		src.PCActn, _ = v["pcactn"].(map[string]any)
		if h, ok := v["hooks"].(map[string]any); ok {
			src.Hooks = AssuranceHooks{Attestation: labelFromJSON(h["attestation"]), Zk: labelFromJSON(h["zk"]),
				Threshold: labelFromJSON(h["threshold"]), Revocation: labelFromJSON(h["revocation"])}
		}
		src.AttestationHook = labelFromJSON(v["attestation_hook"])
		src.ThresholdT = fptr(v["threshold_t"])
		src.AllowUnboundPq, _ = v["allow_unbound_pq"].(bool)
		if d, ok := v["degraded"].(map[string]any); ok {
			src.Degraded = map[string]string{}
			for k, x := range d {
				src.Degraded[k], _ = x.(string)
			}
		}
		got := canonOf(t, BuildAssuranceReport(src).ToMap())
		if want := canonOf(t, v["report"]); got != want {
			t.Errorf("%s:\n got %s\nwant %s", v["name"], got, want)
		}
	}
}

func requirementOf(v map[string]any) AssuranceRequirement {
	r := AssuranceRequirement{}
	r.Attestation, _ = v["attestation"].(string)
	r.Zk, _ = v["zk"].(string)
	r.Signature, _ = v["signature"].(string)
	r.AllowAwaitingAudit, _ = v["allowAwaitingAudit"].(bool)
	if p, _ := v["allowPreview"].(bool); p { // deprecated input alias
		r.AllowAwaitingAudit = true
	}
	if arr, ok := v["threshold"].([]any); ok {
		r.Threshold = []string{}
		for _, x := range arr {
			r.Threshold = append(r.Threshold, x.(string))
		}
	}
	return r
}

func TestAssuranceRequirementVectors(t *testing.T) {
	rs := grows(t, load(t, "assurance-vectors.json"), "requirement")
	if len(rs) != 47 {
		t.Fatalf("rows %d", len(rs))
	}
	for _, v := range rs {
		got := UnmetAssurance(AssuranceReportFromMap(v["report"].(map[string]any)), requirementOf(v["require"].(map[string]any)))
		want, _ := v["unmet"].(string)
		if got != want {
			t.Errorf("%s:\n got %q\nwant %q", v["name"], got, want)
		}
	}
}

func TestAssuranceMultiRootVectors(t *testing.T) {
	rs := grows(t, load(t, "assurance-vectors.json"), "multi_root")
	if len(rs) != 10 {
		t.Fatalf("rows %d", len(rs))
	}
	for _, v := range rs {
		var roots []AttestationRoot
		for _, r := range v["roots"].([]any) {
			rm := r.(map[string]any)
			req, _ := rm["required"].(bool)
			roots = append(roots, AttestationRoot{Verifier: labelFromJSON(map[string]any{"level": rm["level"]}), Required: req})
		}
		if got := MultiRootLevel(roots, int(num(v["threshold"]))); got != v["level"] {
			t.Errorf("%s: %s want %v", v["name"], got, v["level"])
		}
	}
}

// A label comes from the verifier's configuration: an unlabelled hook, a hook of another level, and presented evidence
// can never meet a requirement.
func TestAssuranceLabelsNeverFromEvidence(t *testing.T) {
	hw := WithAssuranceLabel(struct{}{}, AssuranceLabel{Level: "hardware", Vendor: "v"})
	rep := BuildAssuranceReport(AssuranceSources{Checks: []NamedStatus{{"attestation", "pass"}}, Hooks: AssuranceHooks{Attestation: hw}})
	if why := UnmetAssurance(rep, AssuranceRequirement{Attestation: "hardware"}); why != "" {
		t.Fatalf("labelled hardware must meet hardware: %s", why)
	}
	if why := UnmetAssurance(rep, AssuranceRequirement{Attestation: "multi_root"}); why == "" {
		t.Fatal("hardware must not meet multi_root")
	}
	rep = BuildAssuranceReport(AssuranceSources{Checks: []NamedStatus{{"attestation", "pass"}}, Hooks: AssuranceHooks{Attestation: struct{}{}}})
	if why := UnmetAssurance(rep, AssuranceRequirement{Attestation: "software"}); why != "assurance: software attestation required but the evidence is unknown" {
		t.Fatalf("unlabelled: %q", why)
	}
	if why := UnmetAssurance(AssuranceReport{}, AssuranceRequirement{Attestation: "software"}); why != "assurance: software attestation required but there is no attestation evidence" {
		t.Fatalf("absent: %q", why)
	}
	if why := UnmetAssurance(AssuranceReport{}, AssuranceRequirement{Attestation: "bogus"}); why == "" {
		t.Fatal("an unknown required level can never be met")
	}
}

// ---- Authorize wiring

func TestAuthorizeAssuranceGate(t *testing.T) {
	in, pcactn, _ := planAuthorizeFixture(t) // the first fixture: Ed25519 signatures, single step
	store := NewMemoryStateStore()
	in.StateStore = store

	denied := in
	denied.RequireAssurance = &AssuranceRequirement{Signature: "pq"}
	r := Authorize(pcactn, denied)
	if r.Allow || r.Checks["assurance"] != "fail" || r.Reason != "assurance: post-quantum signatures required but leaf_signature is ed25519" {
		t.Fatalf("an Ed25519 proof must not meet a PQ requirement: %+v", r)
	}
	if got, _ := r.Assurance.Get("leaf_signature"); got.Level != "ed25519" || len(got.Suites) != 1 || got.Suites[0] != "ed25519" {
		t.Fatalf("the result carries the report: %+v", got)
	}
	// the denial must not have consumed the replay counter: the same proof still passes without the requirement
	ok := Authorize(pcactn, in)
	if !ok.Allow {
		t.Fatalf("a refused assurance must leave the replay state untouched: %+v", ok)
	}
	if lp, _ := ok.Assurance.Get("cap_chain"); lp.Outcome != "pass" || lp.Level != "ed25519" {
		t.Fatalf("the capability chain is reported as cap_chain: %+v", ok.Assurance.ToMap())
	}
	// a requirement the evidence meets does not change the decision
	met := in
	met.StateStore = NewMemoryStateStore()
	met.RequireAssurance = &AssuranceRequirement{}
	if r := Authorize(pcactn, met); !r.Allow {
		t.Fatalf("an empty requirement must allow: %+v", r)
	}
	// no attestation check ran: a hardware requirement is unmet, never silently met
	hwReq := in
	hwReq.StateStore = NewMemoryStateStore()
	hwReq.RequireAssurance = &AssuranceRequirement{Attestation: "hardware"}
	if r := Authorize(pcactn, hwReq); r.Allow || r.Reason != "assurance: hardware attestation required but there is no attestation evidence" {
		t.Fatalf("%+v", r)
	}
}
