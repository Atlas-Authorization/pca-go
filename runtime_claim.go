package pca

// Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class.
// Valid only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
// verifiedEvidence), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
// "none". Total.

const runtimeClaimDomain = "atlas-pca/runtime-class-claim/v1\x00"

var runtimeClasses = map[string]bool{"none": true, "os_confined": true, "egress_default_deny": true, "wasi_no_ambient": true}
var runtimeClaimKeys = map[string]bool{"v": true, "class": true, "passport_digest": true, "evidence_digest": true, "iat": true, "exp": true, "attestor": true, "sig": true}

func rcContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// VerifiedRuntimeClass returns the class the claim proves, or "none".
func VerifiedRuntimeClass(v any, pinnedAttestors []string, passportDigest string, verifiedEvidence []string, now any) string {
	c, ok := v.(map[string]any)
	if !ok || len(c) != len(runtimeClaimKeys) {
		return "none"
	}
	for k := range c {
		if !runtimeClaimKeys[k] {
			return "none"
		}
	}
	if f, ok := jsNum(c["v"]); !ok || f != 1 {
		return "none"
	}
	class, _ := c["class"].(string)
	if !runtimeClasses[class] {
		return "none"
	}
	if !k3Str(c["attestor"], 128) || !k3Str(c["passport_digest"], 128) || !k3Str(c["evidence_digest"], 128) || !k3Int(c["iat"]) || !k3Int(c["exp"]) || !k3Int(now) {
		return "none"
	}
	attestor := c["attestor"].(string)
	if !contains(pinnedAttestors, attestor) || c["passport_digest"].(string) != passportDigest || !contains(verifiedEvidence, c["evidence_digest"].(string)) {
		return "none"
	}
	iat, _ := jsNum(c["iat"])
	exp, _ := jsNum(c["exp"])
	n, _ := jsNum(now)
	if !(iat <= n && n < exp) {
		return "none"
	}
	body := map[string]any{}
	for k, x := range c {
		if k != "sig" {
			body[k] = x
		}
	}
	if extSigned(attestor, runtimeClaimDomain, body, c["sig"]) {
		return class
	}
	return "none"
}
