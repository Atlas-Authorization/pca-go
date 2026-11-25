package pca

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Replay of the safety certificate against the reference (ref-safety-certificate), every case: the bound and its statement, the
// checks validator, the signed message, issuing under ed25519, ml-dsa-65 and the hybrid (keys from seed labels; ML-DSA signing is
// deterministic, so certificates compare byte for byte), verification with every reason, the canonical text, the decoder and the
// compliance row. A reference throw requires a refusal.
//
// The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) is NOT ported: the two corpus cases
// that the reference accepts only through it are asserted REFUSED here, with the count asserted.

// scDecode resolves the corpus non-finite number form {"$num": "NaN" | "Infinity" | "-Infinity"} to a float64, deeply.
func scDecode(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["$num"].(string); ok && len(t) == 1 {
			switch s {
			case "NaN":
				return math.NaN()
			case "Infinity":
				return math.Inf(1)
			case "-Infinity":
				return math.Inf(-1)
			}
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = scDecode(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = scDecode(x)
		}
		return a
	}
	return v
}

// scNumOut is a number as the corpus writes it: a non-finite one in the {"$num"} form.
func scNumOut(f float64) any {
	switch {
	case math.IsNaN(f):
		return map[string]any{"$num": "NaN"}
	case math.IsInf(f, 1):
		return map[string]any{"$num": "Infinity"}
	case math.IsInf(f, -1):
		return map[string]any{"$num": "-Infinity"}
	}
	return jsNumber(f)
}

func scOpts(v any) SafetyVerifyOptions {
	var o SafetyVerifyOptions
	m, _ := v.(map[string]any)
	if g, ok := m["guardian"].(string); ok {
		o.Guardian = &g
	}
	if l, ok := m["requireChecks"].([]any); ok {
		o.RequireChecks = []string{}
		for _, x := range l {
			s, _ := x.(string)
			o.RequireChecks = append(o.RequireChecks, s)
		}
	}
	if _, ok := m["maxAgeMs"]; ok {
		f := jsF(m["maxAgeMs"])
		o.MaxAgeMs = &f
	}
	if _, ok := m["now"]; ok {
		f := jsF(m["now"])
		o.Now = &f
	}
	if p, ok := m["pqPins"].(map[string]any); ok {
		o.PqPins = map[string]string{}
		for k, x := range p {
			o.PqPins[k], _ = x.(string)
		}
	}
	return o
}

func scVerdict(v SafetyCertificateVerdict) map[string]any {
	m := map[string]any{"ok": v.OK}
	if v.Reason != "" {
		m["reason"] = v.Reason
	}
	if v.HasBound {
		m["recomputedBound"] = scNumOut(v.RecomputedBound)
	}
	return m
}

func TestSafetyCertificateMatchesTheReference(t *testing.T) {
	unboundRefused := 0
	seededIn := func(a []any) []any { return scDecode(vecResolveSeeds(a)).([]any) }
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"MAX_SAFETY_CHECKS": jsNumber(MaxSafetyChecks), "SAFETY_CERT_DOMAIN": SafetyCertDomain, "SAFETY_CERT_SCOPE": SafetyCertScope, "SAFETY_CERT_VERSION": jsNumber(SafetyCertVersion)}, nil
		},
		"safetyCertificateBound": func(a []any) (any, error) {
			p, _ := scDecode(vecArg(a, 0)).(map[string]any)
			return scNumOut(SafetyCertificateBound(jsF(p["bMax"]), jsF(p["kappa"]))), nil
		},
		"safetyCertificateStatement": func(a []any) (any, error) {
			return SafetyCertificateStatement(jsF(scDecode(vecArg(a, 0)))), nil
		},
		"validateSafetyChecks": func(a []any) (any, error) {
			if r := ValidateSafetyChecks(vecArg(a, 0)); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"safetyCertificateMessage": func(a []any) (any, error) {
			c, ok := scDecode(vecArg(a, 0)).(map[string]any)
			if !ok {
				return nil, errors.New("not a certificate object")
			}
			b, err := SafetyCertificateMessage(c)
			if err != nil {
				return nil, err
			}
			return vecBytesOut(b), nil
		},
		"issueSafetyCertificate": func(a []any) (any, error) {
			a = seededIn(a)
			o, _ := a[0].(map[string]any)
			secret, ok := qvBytes(o["guardianSecret"])
			if !ok {
				return nil, errors.New("guardianSecret is bytes")
			}
			key, err := KeyPairFromSeed(secret)
			if err != nil {
				return nil, err
			}
			var suite *SuiteOpts
			if sm, ok := o["suite"].(map[string]any); ok {
				alg, _ := sm["alg"].(string)
				suite = &SuiteOpts{Alg: alg}
				if seedB, ok := qvBytes(sm["pqSeed"]); ok {
					family := "ML-DSA-65"
					if suite.Alg == "ml-dsa-87" {
						family = "ML-DSA-87"
					}
					if suite.Pq, err = GeneratePqKeyPairFromSeed(family, seedB); err != nil {
						return nil, err
					}
				}
			}
			var grantRef, instance any
			if s, ok := o["grantRef"]; ok {
				grantRef = s
			}
			if s, ok := o["instance"]; ok {
				instance = s
			}
			checks, hasChecks := o["checks"]
			var issued any
			if v, ok := o["issuedAt"]; ok && v != nil {
				issued = v
			}
			return issueSafetyCertificateValue(o["policy"], key, grantRef, instance, checks, hasChecks, issued, suite)
		},
		"verifySafetyCertificate": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			opts := scOpts(vecArg(a, 1))
			v := VerifySafetyCertificate(vecArg(a, 0), opts)
			if m, _ := vecArg(a, 1).(map[string]any); m["allowUnboundPq"] == true {
				// the unpinned-key option is not ported: the certificate must be refused, and only for the signature
				if v.OK || v.Reason != "guardian signature does not verify" {
					return nil, errors.New("an unpinned post-quantum key was accepted: " + v.Reason)
				}
				unboundRefused++
				return map[string]any{"unboundRefused": true}, nil
			}
			return scVerdict(v), nil
		},
		"encodeSafetyCertificate": func(a []any) (any, error) { return EncodeSafetyCertificate(scDecode(vecArg(a, 0))) },
		"decodeSafetyCertificate": func(a []any) (any, error) {
			s, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, nil
			}
			if m := DecodeSafetyCertificate(s); m != nil {
				return m, nil
			}
			return nil, nil
		},
		"safetyCertificateForCompliance": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			if m := SafetyCertificateForCompliance(vecArg(a, 0), scOpts(vecArg(a, 1))); m != nil {
				return m, nil
			}
			return nil, nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"verifySafetyCertificate": func(want, got any) bool {
			if g := vecObj(got); g["unboundRefused"] == true {
				return vecObj(want)["ok"] == true // accepted by the reference only through the legacy option
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-safety-certificate.json.gz", 262, fns, cmp, map[string]bool{"issueSafetyCertificate": true})
	if unboundRefused != 2 {
		t.Fatalf("%d unpinned-key cases were refused, 2 are expected", unboundRefused)
	}
}

// TestSafetyCertificateTypedAPI issues a certificate through the typed entry point and drives the verifier over it.
func TestSafetyCertificateTypedAPI(t *testing.T) {
	enc, _ := vecSeedValue(map[string]any{"$seed": "t/guardian"})
	key, err := KeyPairFromSeedB64u(enc)
	if err != nil {
		t.Fatal(err)
	}
	policy := RiskPolicy{Weights: RiskWeights{Alpha: 0.25, Beta: 0.2, Gamma: 0.2, Delta: 0.2, Epsilon: 0.1, Zeta: 0.05}, Theta1: 0.25, Theta2: 0.6, Kappa: 2, Lambda: 0.0005, Rho: 0.5, BMax: 5}
	// a native unit fixture (not replayed against the corpus): any fixed instant works.
	at := 1800000000000.0
	cert, err := IssueSafetyCertificate(SafetyCertificateIssue{Policy: policy, GuardianSecret: key, IssuedAt: &at, Checks: []SafetyCheck{
		{ID: "lint", Status: "passed", Evidence: SafetyCheckEvidence{Kind: "sha256", Ref: strings.Repeat("a", 64)}, At: 1799999999000},
		{ID: "tests", Status: "failed", Evidence: SafetyCheckEvidence{Kind: "url", Ref: "https://example.com/report"}, At: 1799999999500},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if v := VerifySafetyCertificate(cert, SafetyVerifyOptions{}); !v.OK || v.RecomputedBound != 2.5 {
		t.Fatalf("verdict %+v", v)
	}
	g := key.Public
	if v := VerifySafetyCertificate(cert, SafetyVerifyOptions{Guardian: &g, RequireChecks: []string{"lint"}}); !v.OK {
		t.Fatalf("pinned and required: %+v", v)
	}
	if v := VerifySafetyCertificate(cert, SafetyVerifyOptions{RequireChecks: []string{"tests"}}); v.OK || v.Reason != "required check 'tests' is failed" {
		t.Fatalf("a failed required check: %+v", v)
	}
	if SafetyCertificateForCompliance(cert, SafetyVerifyOptions{}) == nil {
		t.Fatal("no compliance row for a verified certificate")
	}
	text, err := EncodeSafetyCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	back := DecodeSafetyCertificate(text)
	if back == nil || !VerifySafetyCertificate(back, SafetyVerifyOptions{}).OK {
		t.Fatal("the decoded certificate does not verify")
	}
	back["bound"] = jsNumber(99)
	if v := VerifySafetyCertificate(back, SafetyVerifyOptions{}); v.OK || !strings.HasPrefix(v.Reason, "stated bound") {
		t.Fatalf("a tampered bound: %+v", v)
	}
}
