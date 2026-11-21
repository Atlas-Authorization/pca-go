package pca

import (
	"crypto/rand"
	"errors"
	"math"
)

// The two compositions of the encrypted-risk-claim flow that need a BFV backend. The backend is passed as functions so this module
// stays free of cgo: the sealkit module's EncryptRiskInputs and EvalRiskGate (closed over the evaluation keys) are the real ones.

// FheEncryptFunc encrypts the quantized risk inputs under a public key (sealkit.EncryptRiskInputs).
type FheEncryptFunc func(publicKey string, inputsScaled []int64) (string, error)

// FheEvalFunc evaluates the gate blind over the ciphertext under the policy and returns {encRiskRaw, encSlack} (sealkit.EvalRiskGate
// with the evaluation keys closed over).
type FheEvalFunc func(encInputs string, policy map[string]any) (map[string]any, error)

// FheEncryptedRiskClaim is the agent / encryptor side: read the PCActn's risk inputs, quantize, encrypt under the public key, bind
// the ciphertext to the action and SIGN it. The plaintext inputs never leave this call.
func FheEncryptedRiskClaim(actn map[string]any, publicKey string, policy map[string]any, signerSecretKey []byte, context string, encrypt FheEncryptFunc) (map[string]any, error) {
	if policy == nil {
		return nil, errors.New("policy must be an object")
	}
	if encrypt == nil {
		return nil, errors.New("an FHE encrypt backend is required")
	}
	inputs, err := FheRiskInputsFromPCActn(actn)
	if err != nil {
		return nil, err
	}
	scale := float64(1000) // the default scale
	if s, ok := jsNum(policy["scale"]); ok {
		scale = s
	}
	q, err := FheQuantizeRiskInputs(inputs, scale)
	if err != nil {
		return nil, err
	}
	scaled := make([]int64, len(q))
	for i, v := range q {
		if v != math.Trunc(v) || math.Abs(v) > 9007199254740991 {
			return nil, errors.New("quantized risk inputs must be safe integers")
		}
		scaled[i] = int64(v)
	}
	encInputs, err := encrypt(publicKey, scaled)
	if err != nil {
		return nil, err
	}
	binding, err := FheBindingFromPCActn(actn)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, fheNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return FheSignRiskClaim(map[string]any{"binding": binding, "encInputs": encInputs, "policy": policy}, signerSecretKey, context, nonce)
}

// FheEvalSignedRiskClaim is the evaluator side: verify the signed claim, then run the gate. The ciphertext is not handed to the
// backend unless the signature, signer, context, binding, policy and nonce all check out. The result is {ok: true, gate,
// claimDigest} or {ok: false, reason}.
func FheEvalSignedRiskClaim(signed any, exp FheClaimExpectations, eval FheEvalFunc) map[string]any {
	chk := FheVerifySignedRiskClaim(signed, exp)
	if chk["ok"] != true {
		return chk
	}
	fail := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	if eval == nil {
		return fail("evaluation failed: no FHE evaluation backend")
	}
	claim := chk["claim"].(map[string]any)
	policy, _ := claim["policy"].(map[string]any)
	enc, _ := claim["encInputs"].(string)
	var gate map[string]any
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("unknown error")
			}
		}()
		gate, err = eval(enc, policy)
	}()
	if err != nil {
		return fail("evaluation failed: " + err.Error())
	}
	return map[string]any{"ok": true, "gate": gate, "claimDigest": chk["digest"]}
}
