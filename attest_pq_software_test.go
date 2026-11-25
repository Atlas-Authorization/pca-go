package pca

import (
	"strings"
	"testing"
)

func TestPqSoftwareRootRoundTrip(t *testing.T) {
	pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", fill(32, 9))
	if err != nil {
		t.Fatal(err)
	}
	att, err := CreatePqSoftwareAttestor("ml-dsa-65", pq, nil)
	if err != nil {
		t.Fatal(err)
	}
	exp := ExpectedAttestationBinding{HolderPub: "h", GrantRef: "g", Epoch: 3, Nonce: attTestNonce}
	st, err := att.Attest(PqAttestationClaims{Measurement: "aa", WeightsDigest: "w", ModelID: "m", Operator: "op", HolderPub: "h", GrantRef: "g", Epoch: 3, Nonce: attTestNonce})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(o PqSoftwareVerifierOptions) *PqSoftwareVerifier {
		o.ResolveEvidence = func(_, _ map[string]any) map[string]any { return st }
		v, err := CreatePqSoftwareVerifier(o)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := PqSoftwareVerifierOptions{TrustedPqPublicKeys: []string{att.PqPublicKey}, Policy: PqSoftwarePolicy{Measurements: []string{"aa"}}}
	r := mk(base).VerifyHardware(nil, nil, 0, exp)
	if !r.OK || !r.Bound || r.Measured["weights_measured"] != false || r.HostAsserted["suite"] != "ml-dsa-65" {
		t.Fatalf("good statement: %+v", r)
	}
	if v := mk(base); v.Assurance().Vendor != "pq-software" {
		t.Fatal("label")
	}
	bad := map[string]PqSoftwareVerifierOptions{
		"PQ attestor key is not trusted": {TrustedPqPublicKeys: []string{"other"}, Policy: base.Policy},
		"measurement not in policy":      {TrustedPqPublicKeys: base.TrustedPqPublicKeys, Policy: PqSoftwarePolicy{Measurements: []string{"bb"}}},
		"hybrid required":                {TrustedPqPublicKeys: base.TrustedPqPublicKeys, Policy: base.Policy, RequireHybrid: true},
		"not in the allowed-suites list": {TrustedPqPublicKeys: base.TrustedPqPublicKeys, Policy: base.Policy, AllowedSuites: []string{"ml-dsa-87"}},
		"measured weights digest not in": {TrustedPqPublicKeys: base.TrustedPqPublicKeys, Policy: PqSoftwarePolicy{Measurements: []string{"aa"}, WeightsMeasurements: []string{"x"}}},
	}
	for want, o := range bad {
		if r := mk(o).VerifyHardware(nil, nil, 0, exp); r.OK || !strings.Contains(r.Reason, want) {
			t.Fatalf("%q: %+v", want, r)
		}
	}
	other := exp
	other.Nonce = "fedcba9876543210fedcba9876543210"
	if r := mk(base).VerifyHardware(nil, nil, 0, other); r.OK || !strings.Contains(r.Reason, "binding mismatch") {
		t.Fatalf("binding: %+v", r)
	}
	if _, err := CreatePqSoftwareVerifier(PqSoftwareVerifierOptions{TrustedPqPublicKeys: []string{"k"}}); err == nil {
		t.Fatal("empty measurements must be refused")
	}
	if _, err := CreatePqSoftwareAttestor("ed25519", nil, nil); err == nil {
		t.Fatal("classical suite must be refused")
	}
}
