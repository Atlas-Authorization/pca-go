package pca

import (
	"math"
	"slices"
)

// The passport verifier over decoded values, with the reference's member and number semantics and its reason details: the verdict
// is {ok: true, passport, iss, sub, exp, hardware_verified} or {ok: false, reason, detail?}. VerifyPassport (passport.go) answers the
// same question for typed options and returns only the reason code.

// PassportValueHooks are the two verifier callbacks of VerifyPassportValue. A nil Revocation is "no revocation source"
// (revocation_unavailable); Revocation reports whether the passport {id, iss, sub} is revoked (only the value true counts as
// revoked) and an error is revocation_unavailable. A nil Attest is no hardware verifier; Attest returns the vendor verifier's
// result object {ok, bound, reason?, measured?} for the evidence document and the binding it must carry.
type PassportValueHooks struct {
	Revocation func(id, iss, sub string) (any, error)
	Attest     func(doc map[string]any, binding PassportBinding) (map[string]any, error)
}

func passportBad(reason string, detail ...string) map[string]any {
	m := map[string]any{"ok": false, "reason": reason}
	if len(detail) > 0 {
		m["detail"] = detail[0]
	}
	return m
}

// VerifyPassportValue verifies a signed passport (a decoded value) against the options {trustedIssuers, now, clockSkewMs?, subject?,
// maxEvidenceAgeMs?, pqPins?}. Order: shape, version, suite, field types, the signed times, the pinned issuer, the signature, the
// content-addressed id, the time window, the subject, revocation, then hardware evidence. It never panics. The option that accepts
// an unpinned post-quantum key is not read.
func VerifyPassportValue(sp any, o map[string]any, h PassportValueHooks) (verdict map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			verdict = passportBad("malformed", "error")
		}
	}()
	s, ok := sp.(map[string]any)
	if !ok || s["typ"] != "atlas-pca/passport" || s["passport"] == nil {
		return passportBad("malformed")
	}
	if !jsStrictEq(s["ver"], jsNumber(1)) {
		return passportBad("unsupported_version", jsMemberString(s, "ver"))
	}
	alg, algPresent := s["alg"]
	if algPresent && !IsKnownSigAlg(alg) {
		return passportBad("unsupported_suite", jsValueString(alg))
	}
	p, _ := s["passport"].(map[string]any)
	iss, ok1 := passportStr(s["iss"])
	sub, ok2 := passportStr(s["sub"])
	_, ok3 := passportStr(s["sig"])
	id, ok4 := passportStr(p["id"])
	_, ok5 := passportStr(p["model_id"])
	_, ok6 := passportStr(p["operator"])
	hw, ok7 := p["hardware_rooted"].(bool)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return passportBad("malformed")
	}
	nbf, a := jsNum(s["nbf"])
	exp, b := jsNum(s["exp"])
	now, c := jsNum(o["now"])
	if !(a && b && c && jsIsSafeInteger(s["nbf"]) && jsIsSafeInteger(s["exp"]) && jsIsSafeInteger(s["iat"]) && jsIsSafeInteger(o["now"])) || exp <= nbf {
		return passportBad("malformed", "times")
	}
	issuers, isList := o["trustedIssuers"].([]any)
	if !isList || !slices.ContainsFunc(issuers, func(x any) bool { return jsStrictEq(x, iss) }) {
		return passportBad("unknown_issuer")
	}
	canon, err := Canonicalize(withoutKeys(s, "sig", "pq_sig"))
	if err != nil {
		return passportBad("malformed", err.Error())
	}
	var pins map[string]string
	if pm, isMap := o["pqPins"].(map[string]any); isMap {
		pins = map[string]string{}
		for k, v := range pm {
			pins[k], _ = v.(string)
		}
	}
	if !verifyPinnedSuite(alg, algPresent, iss, s["pq_pk"], append([]byte(passportSigDomain), canon...), s["sig"], s["pq_sig"], pins) {
		return passportBad("bad_signature")
	}
	fp, err := PassportFingerprint(p)
	if err != nil {
		return passportBad("malformed", err.Error())
	}
	if fp != id {
		return passportBad("id_mismatch")
	}
	skew := 0.0
	if v, has := o["clockSkewMs"]; has && v != nil {
		skew = jsToNumber(v)
	}
	skew = math.Min(math.Max(skew, 0), float64(passportMaxSkew)) // a NaN stays NaN: no ordering below holds
	if !(finite(skew) && now+skew >= nbf) {
		return passportBad("not_yet_valid")
	}
	if !(finite(skew) && now-skew < exp) {
		return passportBad("expired")
	}
	if want, has := o["subject"]; has && !jsStrictEq(want, sub) {
		return passportBad("subject_mismatch")
	}
	if h.Revocation == nil {
		return passportBad("revocation_unavailable", "no revocation source")
	}
	revoked, err := h.Revocation(id, iss, sub)
	if err != nil {
		return passportBad("revocation_unavailable")
	}
	if revoked == true {
		return passportBad("revoked")
	}
	if hw {
		ev, _ := s["evidence"].(map[string]any)
		doc, _ := ev["document"].(map[string]any)
		nonce, nok := passportStr(doc["nonce"])
		if !nok {
			return passportBad("hardware_evidence_missing")
		}
		if !jsIsSafeInteger(ev["at"]) {
			return passportBad("hardware_evidence_missing", "evidence.at")
		}
		at, _ := jsNum(ev["at"])
		maxAge := float64(passportDefaultEvidence)
		if v, has := o["maxEvidenceAgeMs"]; has && v != nil {
			maxAge = jsF(v)
		}
		if !finite(maxAge) || maxAge < 0 || !(now-at <= maxAge) || !(at-now <= skew) {
			return passportBad("hardware_evidence_stale")
		}
		if h.Attest == nil {
			return passportBad("hardware_verifier_missing")
		}
		r, err := h.Attest(doc, PassportEvidenceBinding(id, sub, nonce))
		if err != nil {
			return passportBad("hardware_attestation_failed", err.Error())
		}
		if r == nil || r["ok"] != true || r["bound"] != true {
			reason, has := r["reason"].(string)
			if has {
				return passportBad("hardware_attestation_failed", reason)
			}
			return passportBad("hardware_attestation_failed")
		}
		m, _ := r["measured"].(map[string]any)
		if !passportMeasuredMatches(p, m) {
			return passportBad("hardware_identity_mismatch")
		}
	}
	return map[string]any{"ok": true, "passport": p, "iss": iss, "sub": sub, "exp": s["exp"], "hardware_verified": hw}
}

// passportMeasuredMatches: the hardware-measured identity equals the claims (model and operator always; the optional digests and the
// runtime measurement when the passport has them; measured weights when it claims them). A missing measured identity never matches.
func passportMeasuredMatches(p, m map[string]any) bool {
	if m == nil || !jsStrictEq(m["model_id"], p["model_id"]) || !jsStrictEq(m["operator"], p["operator"]) {
		return false
	}
	for _, k := range []string{"weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"} {
		if want, has := p[k]; has {
			if got, hasGot := m[k]; !hasGot || !jsStrictEq(got, want) {
				return false
			}
		}
	}
	return !(p["weights_measured"] == true && m["weights_measured"] != true)
}
