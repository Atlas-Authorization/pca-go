package pca

import (
	"encoding/json"
	"strings"
	"testing"
)

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

// An unknown requirement value is refused with a deterministic reason, before any evidence lookup (fail closed).
func TestUnmetAssuranceUnknownValuesFailClosed(t *testing.T) {
	cases := []struct {
		req  AssuranceRequirement
		want string
	}{
		{AssuranceRequirement{Attestation: "tpm"}, `assurance: unknown attestation requirement "tpm" (fail closed)`},
		{AssuranceRequirement{Attestation: "unknown"}, `assurance: unknown attestation requirement "unknown" (fail closed)`},
		{AssuranceRequirement{Zk: "groth16"}, `assurance: unknown zk requirement "groth16" (fail closed)`},
		{AssuranceRequirement{Signature: "PQ"}, `assurance: unknown signature requirement "PQ" (fail closed)`},
		{AssuranceRequirement{Threshold: []string{"multisig", "bls"}}, `assurance: unknown threshold requirement ["multisig","bls"] (fail closed)`},
		{AssuranceRequirement{Zk: "bogus", Attestation: "hardware"}, `assurance: unknown zk requirement "bogus" (fail closed)`},
	}
	for _, c := range cases {
		if got := UnmetAssurance(AssuranceReport{}, c.req); got != c.want {
			t.Errorf("%+v: got %q want %q", c.req, got, c.want)
		}
	}
	for _, a := range []string{"software", "hardware", "multi_root"} {
		if got := UnmetAssurance(AssuranceReport{}, AssuranceRequirement{Attestation: a}); strings.Contains(got, "unknown") && strings.Contains(got, "fail closed") {
			t.Errorf("known attestation %s refused as unknown: %q", a, got)
		}
	}
}

// A requirement read from JSON refuses an empty, null or unknown value and an unknown key; it never means "not required".
func TestAssuranceRequirementUnmarshalFailsClosed(t *testing.T) {
	cases := map[string]string{
		`{"zk":""}`:                        `assurance: unknown zk requirement "" (fail closed)`,
		`{"attestation":""}`:               `assurance: unknown attestation requirement "" (fail closed)`,
		`{"signature":""}`:                 `assurance: unknown signature requirement "" (fail closed)`,
		`{"signature":null}`:               `assurance: unknown signature requirement null (fail closed)`,
		`{"signature":"PQ"}`:               `assurance: unknown signature requirement "PQ" (fail closed)`,
		`{"zk":"groth16"}`:                 `assurance: unknown zk requirement "groth16" (fail closed)`,
		`{"threshold":"multisig"}`:         `assurance: unknown threshold requirement "multisig" (fail closed)`,
		`{"threshold":null}`:               `assurance: unknown threshold requirement null (fail closed)`,
		`{"threshold":["multisig","bls"]}`: `assurance: unknown threshold requirement ["multisig","bls"] (fail closed)`,
		`{"atestation":"hardware"}`:        `assurance: unknown requirement atestation (fail closed)`,
	}
	for in, want := range cases {
		var r AssuranceRequirement
		if err := json.Unmarshal([]byte(in), &r); err != nil {
			t.Fatal(err)
		}
		if got := UnmetAssurance(AssuranceReport{}, r); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
	var ok AssuranceRequirement
	_ = json.Unmarshal([]byte(`{"attestation":"software","signature":"pq","threshold":["multisig"],"allowAwaitingAudit":"yes"}`), &ok)
	if ok.invalid != "" || ok.Attestation != "software" || ok.Signature != "pq" || ok.AllowAwaitingAudit {
		t.Errorf("known values must parse unchanged: %+v", ok)
	}
}

// Every refusal path of UnmarshalJSON: a non-object, the first problem wins (unknown key before bad value, then attestation,
// zk, signature, threshold), non-string values, a number json.Unmarshal cannot hold, and no HTML escaping in the text.
func TestAssuranceRequirementUnmarshalDetails(t *testing.T) {
	cases := map[string]string{
		`"hardware"`:                          `assurance: unknown assurance requirement(s): invalid (fail closed)`,
		`[1]`:                                 `assurance: unknown assurance requirement(s): invalid (fail closed)`,
		`{"b":1,"a":2}`:                       `assurance: unknown requirement a (fail closed)`,
		`{"zk":"x","bad":1}`:                  `assurance: unknown requirement bad (fail closed)`,
		`{"signature":"y","zk":"x"}`:          `assurance: unknown zk requirement "x" (fail closed)`,
		`{"attestation":"a","zk":"x"}`:        `assurance: unknown attestation requirement "a" (fail closed)`,
		`{"threshold":["bls"],"signature":1}`: `assurance: unknown signature requirement 1 (fail closed)`,
		`{"attestation":"a","threshold":1}`:   `assurance: unknown attestation requirement "a" (fail closed)`,
		`{"zk":1e400}`:                        `assurance: unknown zk requirement null (fail closed)`, // JS: JSON.stringify(Infinity) is "null"
		`{"zk":"<&>"}`:                        `assurance: unknown zk requirement "<&>" (fail closed)`,
		`{"threshold":[1]}`:                   `assurance: unknown threshold requirement [1] (fail closed)`,
	}
	for in, want := range cases {
		var r AssuranceRequirement
		if err := json.Unmarshal([]byte(in), &r); err != nil {
			t.Fatal(err)
		}
		if got := UnmetAssurance(AssuranceReport{}, r); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
	for in, want := range map[string]bool{`{"allowAwaitingAudit":true}`: true, `{"allowPreview":true}`: true, `{"allowPreview":false}`: false,
		`{"allowAwaitingAudit":false,"allowPreview":true}`: true, `{"allowAwaitingAudit":1}`: false} {
		var r AssuranceRequirement
		if err := json.Unmarshal([]byte(in), &r); err != nil || r.invalid != "" || r.AllowAwaitingAudit != want {
			t.Errorf("%s: %+v %v", in, r, err)
		}
	}
	var r AssuranceRequirement
	if err := json.Unmarshal([]byte(`{"attestation":"multi_root","zk":"snark","signature":"pq","threshold":["multisig","frost","frost_dkg","mpc"]}`), &r); err != nil ||
		r.invalid != "" || r.Attestation != "multi_root" || r.Zk != "snark" || r.Signature != "pq" || len(r.Threshold) != 4 {
		t.Errorf("known values must parse unchanged: %+v %v", r, err)
	}
	for _, s := range []string{"multisig", "frost", "frost_dkg", "mpc"} {
		if got := UnmetAssurance(AssuranceReport{}, AssuranceRequirement{Threshold: []string{s}}); strings.Contains(got, "fail closed") {
			t.Errorf("known scheme %s refused: %q", s, got)
		}
	}
	if got := UnmetAssurance(AssuranceReport{}, AssuranceRequirement{}); got != "" {
		t.Errorf("an unset requirement is met: %q", got)
	}
}
