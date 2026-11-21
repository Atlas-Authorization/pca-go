package pca

// The AMD SEV-SNP hardware root composed into the EAT verdict: verify the report signature and the VCEK to ASK to ARK chain under
// a pinned ARK (delegated to the SEV-SNP verifier of attest_amd.go), then project the verified report into EAT evidence and a
// measured identity.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"strings"
)

// EatMilanArkSpkiSha384 is the SPKI SHA-384 (lowercase hex) of the AMD Milan ARK.
const EatMilanArkSpkiSha384 = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e"

// EatKnownAmdArkSpkiSha384 returns the pinned ARK SPKI SHA-384 (hex) of each AMD family: milan, genoa, turin.
func EatKnownAmdArkSpkiSha384() map[string]string {
	out := make(map[string]string, len(amdARKSpkiSHA384))
	for k, v := range amdARKSpkiSHA384 {
		out[k] = v
	}
	return out
}

// eatCertToDer reads a certificate given as DER bytes or as exactly one PEM block.
func eatCertToDer(in any) ([]byte, error) {
	switch t := in.(type) {
	case []byte:
		return t, nil
	case string:
		blocks := pemCertBlocks(t)
		if len(blocks) != 1 {
			return nil, errors.New("expected exactly one PEM certificate, found " + jsNumberString(float64(len(blocks))))
		}
		b, _ := pem.Decode([]byte(blocks[0]))
		if b == nil {
			return nil, errors.New("PEM certificate is malformed")
		}
		return b.Bytes, nil
	}
	return nil, errors.New("a certificate is DER bytes or a PEM string")
}

func eatDerToPem(der []byte) string {
	b := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	for len(b) > 0 {
		n := min(64, len(b))
		sb.WriteString(b[:n] + "\n")
		b = b[n:]
	}
	return "-----BEGIN CERTIFICATE-----\n" + sb.String() + "-----END CERTIFICATE-----\n"
}

// EatVerifyAmdAttestation composes the AMD SEV-SNP hardware root of trust into one verdict: the per-family ARK pin, an exact
// ASK-then-ARK bundle, validity against the verifier clock nowMs, the report signature and the VCEK binding. It fails closed on
// any failure and never panics. opts: vcek, ask, ark (DER bytes or one PEM string each), exactly one of family (milan | genoa |
// turin) and trustAnchorArkSpkiSha384 (the root is never inferred from the evidence), nowMs, clockSkewMs, allowDebug (insecure
// opt-in), expectedMeasurement (hex). The result is {ok, hardwareRoot, report, evidence, measured} or {ok false, reason, hardwareRoot}.
func EatVerifyAmdAttestation(rawReport []byte, opts map[string]any) map[string]any {
	return eatVerifyAmd(rawReport, opts)
}

// eatVerifyAmd is EatVerifyAmdAttestation over a report that may not be bytes: the pin and the certificates are checked first, then the
// report is parsed, as the reference does.
func eatVerifyAmd(rawAny any, opts map[string]any) (res map[string]any) {
	root := EatAmdHardwareRootLabel
	fail := func(reason string) map[string]any {
		return map[string]any{"ok": false, "reason": reason, "hardwareRoot": root}
	}
	defer func() {
		if r := recover(); r != nil {
			res = fail("AMD attestation verification error (fail closed): " + jsAnyString(r))
		}
	}()
	_, hasFamily := opts["family"]
	_, hasPin := opts["trustAnchorArkSpkiSha384"]
	if hasFamily == hasPin {
		return fail("exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)")
	}
	var pin string
	if hasFamily {
		fam, _ := opts["family"].(string)
		p, ok := amdARKSpkiSHA384[fam]
		if !ok {
			return fail("unknown AMD family " + jsAnyString(opts["family"]) + " (expected milan | genoa | turin)")
		}
		pin = p
	} else {
		pin, _ = opts["trustAnchorArkSpkiSha384"].(string)
	}
	vcek, err := eatCertToDer(opts["vcek"])
	var askPem string
	if err == nil {
		var ask, ark []byte
		if ask, err = eatCertToDer(opts["ask"]); err == nil {
			if ark, err = eatCertToDer(opts["ark"]); err == nil {
				askPem = eatDerToPem(ask) + eatDerToPem(ark)
			}
		}
	}
	if err != nil {
		return fail("certificate parse failed: " + err.Error())
	}
	rawReport, isBytes := rawAny.([]byte)
	if !isBytes { // a report that is not bytes never reaches the parser's length check
		return fail("report parse failed: parseSevSnpReport: expected Uint8Array")
	}
	var ms []string
	if m, ok := opts["expectedMeasurement"].(string); ok && m != "" {
		ms = []string{strings.ToLower(m)}
	}
	v := &amdVerifier{pin: pin, policy: snpPolicy{measurements: ms, allowDebug: opts["allowDebug"] == true, requireEcdsaP384: true}, skew: opts["clockSkewMs"]}
	f, ok := eatFinite(opts["nowMs"])
	if !ok { // the verifier's clock is required: every certificate's validity window is checked against it, never against a default
		return fail("cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check")
	}
	nowMs := int64(f)
	reason, rep := v.verifyReport(rawReport, vcek, askPem, nowMs, nil)
	if rep == nil {
		if reason == "" {
			reason = "AMD SEV-SNP verification failed"
		}
		return fail(reason)
	}
	version := uint32(0)
	if len(rawReport) >= 4 {
		version = binary.LittleEndian.Uint32(rawReport)
	}
	ev := eatEvidenceOf(version, rep)
	return map[string]any{"ok": true, "hardwareRoot": root, "report": ev, "evidence": ev, "measured": eatMeasuredOf(rep)}
}

// eatOr is v unless it is nil or the empty string.
func eatOr(v any, dflt string) any {
	if s, ok := v.(string); v == nil || (ok && s == "") {
		return dflt
	}
	return v
}

// eatVerifyAmdOption verifies the amd evidence of EatVerifyFreshAttested: the launch measurement defaults to the EAT's own
// claimed one, and the verifier clock is the call's now.
func eatVerifyAmdOption(claims any, amd any, now float64) map[string]any {
	m, _ := amd.(map[string]any)
	o := map[string]any{"vcek": m["vcek"], "ask": m["ask"], "ark": m["ark"], "nowMs": jsNumber(now)}
	for _, k := range []string{"family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug"} {
		if v, present := m[k]; present {
			o[k] = v
		}
	}
	expected := m["expectedMeasurement"]
	if expected == nil {
		if lm, ok, err := eatLaunchMeasurement(claims); err == nil && ok {
			expected = lm
		}
	}
	if expected != nil {
		o["expectedMeasurement"] = expected
	}
	return eatVerifyAmd(m["rawReport"], o)
}
