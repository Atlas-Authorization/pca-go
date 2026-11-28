package pca

import (
	"crypto/sha256"
	"math"
	"strings"
	"testing"
)

// Replay of the post-quantum software attestation root against the reference (ref-attest-pq-software), every case: statement
// minting under the ML-DSA suites and their hybrids, the attestor's construction refusals and the verifier over a constant evidence
// seam (including the SLH-DSA statements, which are verify-only inputs). A reference throw requires a refusal.

// pqBytes reads key material that is bytes, {"$bytes"} or (after seed resolution) a base64url string.
func pqBytes(v any) ([]byte, bool) {
	if b, ok := qvBytes(v); ok {
		return b, true
	}
	if s, ok := v.(string); ok {
		return DecodeB64uStrict(s, -1)
	}
	return nil, false
}

func pqKeysOf(spec map[string]any) (alg string, pq *PqKeyPair, ed *KeyPair, err error) {
	alg = "ed25519"
	if a, ok := spec["alg"].(string); ok {
		alg = a
	}
	if seed, ok := pqBytes(spec["seed"]); ok {
		fam := ""
		switch {
		case strings.Contains(alg, "ml-dsa-87"):
			fam = "ML-DSA-87"
		case strings.Contains(alg, "ml-dsa-65"):
			fam = "ML-DSA-65"
		}
		// the case that hands an ML-DSA-65 key to an ML-DSA-87 suite names the 65 seed: the key material stays of the 65 family
		if label := sha256.Sum256([]byte("atlas-pca-conformance/pq-software/ml-dsa-65/pq")); alg == "ml-dsa-87" && string(seed) == string(label[:]) {
			fam = "ML-DSA-65"
		}
		if fam != "" {
			if pq, err = GeneratePqKeyPairFromSeed(fam, seed); err != nil {
				return
			}
		}
	}
	if secret, ok := pqBytes(spec["edSecret"]); ok {
		ed, err = KeyPairFromSeed(secret)
	}
	return
}

func TestPqSoftwareAttestationMatchesTheReference(t *testing.T) {
	attestor := func(v any) (*PqSoftwareAttestor, error) {
		alg, pq, ed, err := pqKeysOf(vecObj(v))
		if err != nil {
			return nil, err
		}
		return CreatePqSoftwareAttestor(alg, pq, ed)
	}
	keysOut := func(a *PqSoftwareAttestor) map[string]any {
		out := map[string]any{"pqPublicKey": a.PqPublicKey}
		if a.Ed25519PublicKey != "" {
			out["ed25519PublicKey"] = a.Ed25519PublicKey
		}
		return out
	}
	verifierOpts := func(cfg map[string]any, st map[string]any) PqSoftwareVerifierOptions {
		pol := vecObj(cfg["policy"])
		o := PqSoftwareVerifierOptions{TrustedPqPublicKeys: attStrings(cfg["trustedPqPublicKeys"]), TrustedEd25519PublicKeys: attStrings(cfg["trustedEd25519PublicKeys"]),
			RequireHybrid: cfg["requireHybrid"] == true, Policy: PqSoftwarePolicy{Measurements: attStrings(pol["measurements"]), WeightsMeasurements: attStrings(pol["weightsMeasurements"])}}
		if b, ok := cfg["requirePq"].(bool); ok {
			o.RequirePq = &b
		}
		if _, present := cfg["allowedSuites"]; present { // a value that is no array allows nothing
			o.AllowedSuites = append([]string{}, attStrings(cfg["allowedSuites"])...)
		}
		if cfg["noEvidenceSeam"] != true {
			o.ResolveEvidence = func(_, _ map[string]any) map[string]any { return st }
		}
		return o
	}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) { return map[string]any{"PQ_ATTEST_DOMAIN": PqAttestDomain}, nil },
		"buildAttestor": func(a []any) (any, error) {
			at, err := attestor(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return keysOut(at), nil
		},
		"attest": func(a []any) (any, error) {
			at, err := attestor(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			cm := vecObj(scDecode(vecArg(a, 1)))
			c := PqAttestationClaims{Measurement: rsStr(cm["measurement"]), WeightsDigest: rsStr(cm["weights_digest"]), SystemPromptDigest: rsStr(cm["system_prompt_digest"]),
				ToolManifestDigest: rsStr(cm["tool_manifest_digest"]), ModelID: rsStr(cm["model_id"]), Operator: rsStr(cm["operator"]), HolderPub: rsStr(cm["holder_pub"]),
				GrantRef: rsStr(cm["grant_ref"]), Nonce: rsStr(cm["nonce"]), Epoch: math.NaN()}
			if f, ok := jsNum(cm["epoch"]); ok {
				c.Epoch = f
			}
			for _, k := range []string{"weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator"} {
				if s, isStr := cm[k].(string); isStr && s == "" {
					c.KeepEmpty = append(c.KeepEmpty, k)
				}
			}
			st, err := at.Attest(c)
			if err != nil {
				return nil, err
			}
			out := keysOut(at)
			out["statement"] = st
			return out, nil
		},
		"buildVerifier": func(a []any) (any, error) {
			_, err := CreatePqSoftwareVerifier(verifierOpts(vecObj(vecArg(a, 0)), nil))
			if err != nil {
				return nil, err
			}
			return map[string]any{"built": true}, nil
		},
		"verifyPq": func(a []any) (any, error) {
			sc := vecObj(scDecode(vecArg(a, 0)))
			v, err := CreatePqSoftwareVerifier(verifierOpts(vecObj(sc["config"]), vecObj(sc["evidence"])))
			if err != nil {
				return nil, err
			}
			in := vecObj(sc["input"])
			var exp ExpectedAttestationBinding
			if in["expected"] != nil {
				exp = attExpected(in["expected"])
			}
			now, _ := jsNum(in["nowMs"])
			return v.VerifyHardware(map[string]any{}, map[string]any{}, int64(now), exp).Wire(), nil
		},
	}
	replayAll(t, "ref-attest-pq-software.json.gz", 137, vecSeeded(fns), nil, map[string]bool{"buildAttestor": true, "buildVerifier": true})
}
