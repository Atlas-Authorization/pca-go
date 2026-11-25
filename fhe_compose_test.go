package pca

import (
	"bytes"
	"errors"
	"testing"
)

func TestFheComposeWithFakeBackend(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	_, signer, _ := fheKey(secret)
	actn := map[string]any{
		"risk_claim": map[string]any{"inputs": map[string]any{"semanticDistance": jsNumber(0.1), "reversibility": jsNumber(0.5), "blastRadius": jsNumber(0.2),
			"taint": jsNumber(0), "confidence": jsNumber(1), "age": jsNumber(0)}},
		"action": map[string]any{"params_digest": "d"}, "aud": "a", "counter": jsNumber(1),
	}
	policy := map[string]any{"scale": jsNumber(1000), "weights": []any{}}
	var sawScaled []int64
	enc := func(pk string, scaled []int64) (string, error) { sawScaled = scaled; return "ct-" + pk, nil }
	signed, err := FheEncryptedRiskClaim(actn, "pk", policy, secret, "ctx", enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(sawScaled) != 6 || signed["signer"] != signer || signed["context"] != "ctx" {
		t.Fatalf("claim: %v %v", sawScaled, signed)
	}
	binding, _ := FheBindingFromPCActn(actn)
	exp := FheClaimExpectations{TrustedSigners: []string{signer}, Context: "ctx", Binding: binding, Policy: policy, Nonces: FheMemoryNonceGuard(10)}
	called := 0
	eval := func(encInputs string, p map[string]any) (map[string]any, error) {
		called++
		if encInputs != "ct-pk" {
			t.Fatal("wrong ciphertext")
		}
		return map[string]any{"encRiskRaw": "r", "encSlack": "s"}, nil
	}
	r := FheEvalSignedRiskClaim(signed, exp, eval)
	if r["ok"] != true || called != 1 || r["claimDigest"] == nil {
		t.Fatalf("eval: %v", r)
	}
	if r := FheEvalSignedRiskClaim(signed, exp, eval); r["ok"] != false || called != 1 {
		t.Fatal("replay reached the backend")
	}
	exp.Nonces = FheMemoryNonceGuard(10)
	bad := func(string, map[string]any) (map[string]any, error) { return nil, errors.New("boom") }
	if r := FheEvalSignedRiskClaim(signed, exp, bad); r["ok"] != false || r["reason"] != "evaluation failed: boom" {
		t.Fatalf("backend failure: %v", r)
	}
	if _, err := FheEncryptedRiskClaim(actn, "pk", nil, secret, "ctx", enc); err == nil {
		t.Fatal("nil policy accepted")
	}
}
