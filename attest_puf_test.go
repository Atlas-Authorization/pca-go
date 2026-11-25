package pca

import (
	"strings"
	"testing"
)

func pufTestRandom(n int) ([]byte, error) { return fill(n, 0x5a), nil }

func TestPufFuzzyExtractorCorrectsNoiseWithinBound(t *testing.T) {
	enrolled := NewSimulatedPuf("dev", fill(16, 1), 160, nil)
	bits, _ := enrolled.Response([]byte("c"))
	key, helper, err := FuzzyEnroll(bits, FuzzyExtractorParams{Rep: 5, MessageBits: 32}, pufTestRandom)
	if err != nil || len(key) != PufKeyBytes || RepetitionCorrectionBound(5) != 2 {
		t.Fatalf("enroll: %v", err)
	}
	noisy := NewSimulatedPuf("dev", fill(16, 1), 160, []int{0, 1, 7})
	nb, _ := noisy.Response([]byte("c"))
	again, err := FuzzyReproduce(nb, helper)
	if err != nil || string(again) != string(key) {
		t.Fatalf("two flips in one codeword and one in another must be corrected: %v", err)
	}
	tooNoisy := NewSimulatedPuf("dev", fill(16, 1), 160, []int{0, 1, 2})
	tb, _ := tooNoisy.Response([]byte("c"))
	if k, err := FuzzyReproduce(tb, helper); err == nil && string(k) == string(key) {
		t.Fatal("three flips in one codeword exceed the bound")
	}
	if _, _, err := FuzzyEnroll(bits, FuzzyExtractorParams{Rep: 4, MessageBits: 40}, pufTestRandom); err == nil {
		t.Fatal("an even rep must be refused")
	}
	if _, err := FuzzyReproduce(bits[:10], helper); err == nil {
		t.Fatal("a short response must be refused")
	}
}

func TestPufRootEnrollAttestVerify(t *testing.T) {
	for _, alg := range []string{"ed25519", "ml-dsa-65"} {
		dev := NewSimulatedPuf("dev-1", fill(16, 3), 160, []int{4})
		enr, err := EnrollPuf(NewSimulatedPuf("dev-1", fill(16, 3), 160, nil), []byte("challenge"), EnrollPufOptions{FuzzyExtractorParams: FuzzyExtractorParams{Rep: 5, MessageBits: 32}, Alg: alg, RandomBytes: pufTestRandom})
		if err != nil {
			t.Fatal(err)
		}
		att, err := CreatePufAttestor(dev, *enr)
		if err != nil {
			t.Fatal(err)
		}
		exp := ExpectedAttestationBinding{HolderPub: "h", GrantRef: "g", Epoch: 1, Nonce: attTestNonce}
		st, err := att.Attest(PufClaims{Measurement: "m1", HolderPub: "h", GrantRef: "g", Epoch: 1, Nonce: attTestNonce})
		if err != nil {
			t.Fatal(err)
		}
		reg := NewPufEnrollmentRegistry(*enr)
		mk := func(o PufVerifierOptions) *PufVerifier {
			o.ResolveEvidence = func(_, _ map[string]any) map[string]any { return st }
			o.ResolveEnrollment = func(id string, _, _ map[string]any) (PufEnrollment, bool) { return reg.Lookup(id) }
			v, err := CreatePufVerifier(o)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		pol := PufPolicy{Measurements: []string{"m1"}}
		if r := mk(PufVerifierOptions{Policy: pol}).VerifyHardware(nil, nil, 0, exp); !r.OK || !r.Bound || r.HostAsserted["provider_id"] != "dev-1" {
			t.Fatalf("%s: good statement: %+v", alg, r)
		}
		// a cloned device (other seed) re-derives a different key: the statement does not verify under the enrolled key
		clone, _ := CreatePufAttestor(NewSimulatedPuf("dev-1", fill(16, 9), 160, nil), *enr)
		if cs, err := clone.Attest(PufClaims{Measurement: "m1", HolderPub: "h", GrantRef: "g", Epoch: 1, Nonce: attTestNonce}); err == nil {
			v := mk(PufVerifierOptions{Policy: pol})
			v.o.ResolveEvidence = func(_, _ map[string]any) map[string]any { return cs }
			if r := v.VerifyHardware(nil, nil, 0, exp); r.OK {
				t.Fatalf("%s: a clone must not verify", alg)
			}
		}
		reg.Revoke("dev-1")
		if r := mk(PufVerifierOptions{Policy: pol}).VerifyHardware(nil, nil, 0, exp); r.OK || !strings.Contains(r.Reason, "no PUF enrollment") {
			t.Fatalf("%s: revoked: %+v", alg, r)
		}
		reg = NewPufEnrollmentRegistry(*enr)
		if alg == "ed25519" {
			if r := mk(PufVerifierOptions{Policy: pol, RequirePq: true}).VerifyHardware(nil, nil, 0, exp); r.OK || !strings.Contains(r.Reason, "PQ required") {
				t.Fatalf("classical suite under RequirePq: %+v", r)
			}
		}
		if r := mk(PufVerifierOptions{Policy: PufPolicy{Measurements: []string{"other"}}}).VerifyHardware(nil, nil, 0, exp); r.OK || !strings.Contains(r.Reason, "measurement not in policy") {
			t.Fatalf("measurement: %+v", r)
		}
		tampered := *enr
		tampered.Helper.Salt = b64.EncodeToString(fill(32, 1))
		reg = NewPufEnrollmentRegistry(tampered)
		if r := mk(PufVerifierOptions{Policy: pol}).VerifyHardware(nil, nil, 0, exp); r.OK || !strings.Contains(r.Reason, "helper commitment mismatch") {
			t.Fatalf("tampered helper: %+v", r)
		}
	}
}

func TestPufTpmEkProviderFailsClosed(t *testing.T) {
	zero, one := 0, 1
	mk := func(res TpmCommandResult) *TpmEkPufProvider {
		p, err := NewTpmEkPufProvider(TpmEkPufOptions{ID: "tpm", Length: 64, Run: func(string, []string) *TpmCommandResult { return &res }})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if bits, err := mk(TpmCommandResult{Status: &zero, Stdout: fill(100, 7)}).Response([]byte("c")); err != nil || len(bits) != 64 {
		t.Fatalf("good EK: %v", err)
	}
	for name, res := range map[string]TpmCommandResult{"short": {Status: &zero, Stdout: fill(10, 7)}, "status": {Status: &one}, "spawn": {Error: "tpm2_readpublic: not found"}} {
		if _, err := mk(res).Response([]byte("c")); err == nil {
			t.Fatalf("%s must fail closed", name)
		}
	}
	if _, err := NewTpmEkPufProvider(TpmEkPufOptions{ID: "", Length: 1}); err == nil {
		t.Fatal("empty id")
	}
}
