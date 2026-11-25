package pca

// EAT evidence for blueprint admission and the running-image digest the artifact attestation verifier joins to Sigstore build
// provenance. EatAdmissionEvidence turns an EAT into admission evidence for one instance key: signature, issuer, freshness and
// RATS appraisal must all pass and cnf.jkt must be the RFC 7638 thumbprint of THE INSTANCE KEY, so evidence for one instance
// cannot admit another.

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
)

var eatTierRank = map[string]int{"rejected": 0, "contraindicated": 0, "warning": 1, "affirming": 2, "affirming-hw-rooted": 3}

// EatEd25519Jkt is the RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url.
func EatEd25519Jkt(holderPubB64u any) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + jsAnyString(holderPubB64u) + `"}`
	h := sha256.Sum256([]byte(canonical))
	return B64u(h[:])
}

// EatAdmissionEvidence is admission evidence for o["instanceKey"] (unpadded base64url Ed25519 public key) from an EAT. o carries the
// options of EatVerifyFreshAttested (nonce, policy, now, ...) plus minTier (affirming by default, so degraded warning evidence does
// not admit). Anything unverifiable is {ok: false}. The identity returned is the measured identity the verifier established. A
// minTier other than affirming or affirming-hw-rooted is refused before verification.
func EatAdmissionEvidence(eat any, key *JOSEKey, o map[string]any) (res map[string]any) {
	fail := func(bound bool, reason string) map[string]any {
		return map[string]any{"ok": false, "bound": bound, "reason": reason}
	}
	defer func() {
		if r := recover(); r != nil {
			msg, _ := r.(string)
			if e, ok := r.(error); ok {
				msg = e.Error()
			}
			res = fail(false, eatJSErrorName(msg))
		}
	}()
	minTier := "affirming"
	if mt, present := o["minTier"]; present {
		s, ok := mt.(string)
		if !ok || (s != "affirming" && s != "affirming-hw-rooted") {
			return fail(false, "invalid minTier")
		}
		minTier = s
	}
	rest := make(map[string]any, len(o)+1)
	for k, v := range o {
		if k != "instanceKey" && k != "minTier" {
			rest[k] = v
		}
	}
	rest["channelBinding"] = map[string]any{"jkt": EatEd25519Jkt(o["instanceKey"])}
	v, err := EatVerifyFreshAttested(eat, key, rest)
	if err != nil {
		return fail(false, eatJSErrorName(err.Error()))
	}
	tier, hasTier := v["tier"].(string)
	if v["ok"] != true || !hasTier {
		reason := "EAT rejected"
		if rs, ok := v["reasons"].([]any); ok && len(rs) > 0 {
			reason = jsAnyString(rs[len(rs)-1])
		}
		return fail(false, reason)
	}
	if r, known := eatTierRank[tier]; !known || r < eatTierRank[minTier] {
		return fail(true, "appraisal tier "+tier+" is below the minimum")
	}
	// a pass checked cnf.jkt against the instance key, so it is bound
	m, hasM := eatGet(v["claims"], "measured")
	if !hasM || m == nil {
		return map[string]any{"ok": true, "bound": true}
	}
	id := map[string]any{}
	for _, k := range []string{"runtime_measurement", "model_id", "weights_digest", "operator"} {
		if x, present := eatGet(m, k); present {
			id[k] = x
		}
	}
	return map[string]any{"ok": true, "bound": true, "identity": id}
}

var (
	eatSha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	eatSha512HexRe = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// EatRuntimeDigestFromEat is the running image's digest from an ACCEPTED EAT verdict: exactly one measurements entry labelled slot
// (default image), lowercase hex of the algorithm's length (alg sha256, the default: 64, else 128). Nil when the verdict is not ok,
// the slot is missing or repeated, or the value is malformed (no case folding).
func EatRuntimeDigestFromEat(verdict any, slot, alg string) (map[string]any, error) {
	v, ok := verdict.(map[string]any)
	if !ok || v["ok"] != true || !eatTruthy(v["claims"]) {
		return nil, nil
	}
	if slot == "" {
		slot = "image"
	}
	if alg == "" {
		alg = "sha256"
	}
	// `(measurements ?? []).filter(...)`: only an array filters, any other present value throws
	var ms []any
	if mv := eatMember(v["claims"], "measurements"); mv != nil {
		l, isList := mv.([]any)
		if !isList {
			return nil, errors.New("(verdict.claims.measurements ?? []).filter is not a function")
		}
		ms = l
	}
	var hits []any
	for _, m := range ms {
		if m == nil {
			return nil, errors.New("Cannot read properties of null (reading 'type')")
		}
		if t, isS := eatMember(m, "type").(string); isS && t == slot {
			hits = append(hits, m)
		}
	}
	if len(hits) != 1 {
		return nil, nil
	}
	val, isS := eatMember(hits[0], "value").(string)
	re := eatSha512HexRe
	if alg == "sha256" {
		re = eatSha256HexRe
	}
	if !isS || !re.MatchString(val) {
		return nil, nil
	}
	return map[string]any{"alg": alg, "digest": val}, nil
}

// eatJSErrorName is the `e.name` the reference reports for a failure with this message: the engine's type errors are TypeError.
func eatJSErrorName(msg string) string {
	for _, p := range []string{"Cannot read properties of", "Cannot destructure", "is not a function", "is not iterable"} {
		if strings.Contains(msg, p) {
			return "TypeError"
		}
	}
	return "Error"
}
