package pca

// Signed agent passport verification (wire level), the native counterpart of verifyPassport in @atlasauth/pca.
// Same reason codes and check order; the reason text is not part of the contract. Every signature suite this verifier
// implements for PCActns (SupportedSuites) is accepted, the post-quantum ones only under a PQ key pinned for the issuer
// (PQPins); a suite it does not implement is refused with unsupported_suite.
// Hardware evidence: the age rule, the binding handed to the verifier and the identity comparison are enforced here. The
// verifier is the integrator's Attest, or, when none is given, the built-in vendor verifier of DefaultHardware (AMD SEV-SNP,
// Intel TDX, Azure MAA, Google Confidential Space, NVIDIA GPU: see VerifierFromConfig); an integrator Attest always wins.
// With neither, a hardware_rooted passport that passes every other check is refused with hardware_verifier_missing
// (fail closed, never a software pass).

import "slices"

const (
	passportSigDomain       = "atlas-pca/passport-sig/v1\x00"
	passportDefaultEvidence = int64(24 * 3600_000)
	passportMaxSkew         = int64(60_000)
)

// PassportOptions configures VerifyPassport.
type PassportOptions struct {
	TrustedIssuers   []string
	NowMs            int64
	ClockSkewMs      *int64
	MaxEvidenceAgeMs *int64
	// Subject, when non-nil, must equal the passport's sub.
	Subject *string
	// PQPins maps an issuer key to the PQ public key pinned for it (required for every non-Ed25519 suite).
	PQPins map[string]string
	// Attest verifies hardware evidence (a vendor verifier). nil means none is configured (DefaultHardware is then used).
	Attest func(doc map[string]any, expected PassportBinding) (PassportAttestation, error)
	// DefaultHardware is the built-in vendor verifier used when Attest is nil. nil means none.
	DefaultHardware *DefaultHardware
	// Revoked reports whether the passport is revoked; nil means no revocation source (revocation_unavailable).
	Revoked func(id, iss, sub string) (bool, error)
}

// PassportBinding is what the quote's bound value must equal: holder = the subject key, grant = "passport:<id>", epoch 0.
type PassportBinding struct {
	HolderPub string
	GrantRef  string
	Epoch     int64
	Nonce     string
}

// PassportAttestation is a hardware verifier's answer. Measured holds model_id, operator, weights_digest,
// weights_measured, runtime_measurement, system_prompt_digest and tool_manifest_digest as the hardware measured them.
type PassportAttestation struct {
	OK, Bound bool
	Measured  map[string]any
}

func passportStr(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && s != ""
}

// VerifyPassport returns "" when the passport verifies, else the reason code.
func VerifyPassport(sp any, o PassportOptions) string {
	s, ok := sp.(map[string]any)
	if !ok {
		return "malformed"
	}
	p, pok := s["passport"].(map[string]any)
	if typ, _ := s["typ"].(string); typ != "atlas-pca/passport" || !pok {
		return "malformed"
	}
	if ver, ok := safeInt(s["ver"]); !ok || ver != 1 {
		return "unsupported_version"
	}
	alg, algPresent := s["alg"]
	if algPresent && !suiteSupported(alg, true) {
		return "unsupported_suite"
	}
	iss, ok1 := passportStr(s["iss"])
	sub, ok2 := passportStr(s["sub"])
	_, ok3 := passportStr(s["sig"])
	id, ok4 := passportStr(p["id"])
	_, ok5 := passportStr(p["model_id"])
	_, ok6 := passportStr(p["operator"])
	hw, ok7 := p["hardware_rooted"].(bool)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return "malformed"
	}
	nbf, a := safeInt(s["nbf"])
	exp, b := safeInt(s["exp"])
	_, c := safeInt(s["iat"])
	if !(a && b && c) || exp <= nbf || o.NowMs > maxSafeInt || o.NowMs < -maxSafeInt {
		return "malformed"
	}
	if !slices.Contains(o.TrustedIssuers, iss) {
		return "unknown_issuer"
	}
	body := make(map[string]any, len(s))
	for k, v := range s {
		if k != "sig" && k != "pq_sig" {
			body[k] = v
		}
	}
	canon, err := Canonicalize(body)
	if err != nil {
		return "malformed"
	}
	if !verifyPinnedSuite(alg, algPresent, iss, s["pq_pk"], append([]byte(passportSigDomain), canon...), s["sig"], s["pq_sig"], o.PQPins) {
		return "bad_signature"
	}
	fp := map[string]any{"d": "atlas-pca/passport/v1", "operator": p["operator"], "hardware_rooted": hw}
	for _, k := range []string{"model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"} {
		if v, present := p[k]; present {
			fp[k] = v
		} else {
			fp[k] = nil
		}
	}
	if want, err := HashCanonical(fp); err != nil || want != id {
		return "id_mismatch"
	}
	skew := int64(0)
	if o.ClockSkewMs != nil {
		skew = min(max(*o.ClockSkewMs, 0), passportMaxSkew)
	}
	if o.NowMs+skew < nbf {
		return "not_yet_valid"
	}
	if o.NowMs-skew >= exp {
		return "expired"
	}
	if o.Subject != nil && *o.Subject != sub {
		return "subject_mismatch"
	}
	if o.Revoked == nil {
		return "revocation_unavailable"
	}
	if r, err := o.Revoked(id, iss, sub); err != nil {
		return "revocation_unavailable"
	} else if r {
		return "revoked"
	}
	if hw {
		ev, _ := s["evidence"].(map[string]any)
		doc, dok := ev["document"].(map[string]any)
		if _, nok := passportStr(doc["nonce"]); !dok || !nok {
			return "hardware_evidence_missing"
		}
		at, atok := safeInt(ev["at"])
		if !atok {
			return "hardware_evidence_missing"
		}
		maxAge := passportDefaultEvidence
		if o.MaxEvidenceAgeMs != nil {
			maxAge = *o.MaxEvidenceAgeMs
		}
		if maxAge < 0 || o.NowMs-at > maxAge || at-o.NowMs > skew {
			return "hardware_evidence_stale"
		}
		attest := o.Attest
		if attest == nil && o.DefaultHardware != nil && o.DefaultHardware.Verifier != nil {
			attest = o.DefaultHardware.attest(o.NowMs)
		}
		if attest == nil {
			return "hardware_verifier_missing"
		}
		nonce, _ := doc["nonce"].(string)
		r, err := attest(doc, PassportBinding{HolderPub: sub, GrantRef: "passport:" + id, Epoch: 0, Nonce: nonce})
		if err != nil || !r.OK || !r.Bound {
			return "hardware_attestation_failed"
		}
		if !passportIdentityMatches(p, r.Measured) {
			return "hardware_identity_mismatch"
		}
	}
	return ""
}

// passportIdentityMatches: the hardware-measured identity equals the claims (model and operator always; the optional digests
// and the runtime measurement when the passport states them; measured weights when it claims them).
func passportIdentityMatches(p, m map[string]any) bool {
	if m == nil {
		return false
	}
	eq := func(k string) bool {
		a, aok := p[k].(string)
		b, bok := m[k].(string)
		return aok && bok && a == b
	}
	if !eq("model_id") || !eq("operator") {
		return false
	}
	for _, k := range []string{"weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"} {
		if _, present := p[k]; present && !eq(k) {
			return false
		}
	}
	if p["weights_measured"] == true && m["weights_measured"] != true {
		return false
	}
	return true
}
