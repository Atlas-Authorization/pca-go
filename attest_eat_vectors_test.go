package pca

// Replays the reference corpus for the EAT layer: constants, channel binding, buildEAT (EdDSA tokens byte for byte), verifyEAT,
// freshness, channel binding, appraisal, the tolerant SEV-SNP parse and the fresh-attested pipeline. Signing seeds are labels
// ({"$seed": label}); the key is sha256("atlas-pca-conformance/" + label). Not ported (skipped): the AMD delegation, the
// artifact discharge (that one replays in the sigstore module).

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func eatTestSeed(spec map[string]any) []byte {
	if m, ok := spec["seed"].(map[string]any); ok {
		if label, ok := m["$seed"].(string); ok {
			d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			return d[:]
		}
	}
	return nil
}

func eatTestVerifyKey(v any) (*JOSEKey, error) {
	spec, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("verify key spec is not an object")
	}
	if spec["alg"] == "ES256" {
		return ImportPublicJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": spec["x"], "y": spec["y"]})
	}
	return ImportPublicJWK(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": spec["pub"]})
}

func eatTestSkip(why string) (any, error) { return nil, vecSkip(why) }

func TestEatVectors(t *testing.T) {
	// the artifact discharge needs the Sigstore module, which replays it
	inSigstoreModule := func([]any) (any, error) { return eatTestSkip("replayed in the sigstore module") }
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"EAT_TYP": EatTyp, "DEFAULT_EAT_ALG": EatDefaultAlg, "DEFAULT_MAX_AGE_MS": jsNumber(EatDefaultMaxAgeMs),
				"CHANNEL_BINDING_DOMAIN": EatChannelBindingDomain, "AMD_SEV_SNP_SIGNED_REGION_END": jsNumber(EatAmdSevSnpSignedRegion),
				"AMD_SEV_SNP_HARDWARE_ROOT_LABEL": EatAmdHardwareRootLabel, "KNOWN_REPORT_VERSIONS": EatKnownReportVersions,
				"KNOWN_AMD_ARK_SPKI_SHA384": amdARKSpkiSHA384, "AMD_MILAN_ARK_SPKI_SHA384": EatMilanArkSpkiSha384,
				"PQCOSIGN_DOMAIN": EatPqCosignDomain, "DEFAULT_PQ_COSIGN_SUITE": EatDefaultPqCosignSuite, "PQ_COSIGN_SUITES": EatPqCosignSuites}, nil
		},
		"deriveChannelCnf": func(a []any) (any, error) {
			id, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, errors.New("channelId is required")
			}
			thumb, _ := vecArg(a, 1).(string)
			return EatDeriveChannelCnf(id, thumb)
		},
		"bindChannel": func(a []any) (any, error) {
			id, ok1 := vecArg(a, 1).(string)
			n, ok2 := vecArg(a, 2).(string)
			if !ok1 || !ok2 {
				return nil, errors.New("channelId and nonce are required")
			}
			return EatBindChannel(vecArg(a, 0), id, n)
		},
		"buildEAT": func(a []any) (any, error) {
			args := vecObj(vecArg(a, 0))
			spec := vecObj(args["key"])
			if spec == nil || spec["alg"] != "EdDSA" || eatTestSeed(spec) == nil {
				return eatTestSkip("ES256 signing is randomized (verify-only inputs)")
			}
			rest := map[string]any{}
			for k, v := range args {
				if k != "key" {
					rest[k] = v
				}
			}
			return EatBuild(rest, eatTestSeed(spec))
		},
		"verifyEAT": func(a []any) (any, error) {
			k, err := eatTestVerifyKey(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return EatVerify(vecArg(a, 0), k, vecObj(vecArg(a, 2)))
		},
		"verifyFreshness": func(a []any) (any, error) {
			return EatVerifyFreshness(vecArg(a, 0), eatOracleClock(vecObj(vecArg(a, 1))))
		},
		"verifyChannelBinding": func(a []any) (any, error) {
			return EatVerifyChannelBinding(vecArg(a, 0), vecObj(vecArg(a, 1)))
		},
		"appraise": func(a []any) (any, error) {
			for i := 0; i < 4 && i < len(a); i++ {
				if a[i] == nil {
					return nil, errors.New("explicit null argument is dereferenced")
				}
			}
			rv, en, ex := any(map[string]any{}), any(map[string]any{}), any(map[string]any{})
			if len(a) > 1 {
				rv = a[1]
			}
			if len(a) > 2 {
				en = a[2]
			}
			if len(a) > 3 {
				ex = a[3]
			}
			// the reference before 3d8698b79 read a null / boolean / array minTcb as 0 (or threw), and a non-RFC 9711 dbgstat as
			// "disabled": the native refuses both (fail closed)
			if v, present := eatGet(rv, "minTcb"); present {
				switch v.(type) {
				case nil, bool, []any:
					return eatTestSkip("minTcb that is not a TCB version (hardened after the corpus was produced)")
				}
			}
			if d, present := eatGet(vecArg(a, 0), "dbgstat"); present && eatMember(rv, "requireDebugDisabled") == true {
				if s, ok := d.(string); !ok || !eatInStrings(eatDbgstatValues, s) {
					return eatTestSkip("non-RFC 9711 dbgstat (hardened after the corpus was produced)")
				}
			}
			return EatAppraise(a[0], rv, en, ex)
		},
		"parseReportTolerant": func(a []any) (any, error) {
			if m, ok := vecArg(a, 0).(map[string]any); ok {
				if _, has := m["$bytes"]; has {
					return EatParseReportTolerant(vcBytes(m)), nil
				}
			}
			return map[string]any{"ok": false, "version": jsNumber(0), "known": false, "degraded": true,
				"notes": []any{"input is not a Uint8Array"}, "hasReport": false}, nil
		},
		"verifyFreshAttestedEAT": func(a []any) (any, error) {
			opts := eatTestAmdOpts(vecObj(vecArg(a, 1)))
			k, err := eatTestVerifyKey(opts["verifyKey"])
			if err != nil {
				return map[string]any{"ok": false, "reasons": []any{"EAT signature/claims invalid: " + err.Error()}}, nil
			}
			return EatVerifyFreshAttested(vecArg(a, 0), k, opts)
		},
		"verifyAmdAttestation": eatTestVerifyAmd,
		"canonicalVerdictBytes": func(a []any) (any, error) {
			b, err := EatCanonicalVerdictBytes(vecArg(a, 0), vecArg(a, 1))
			return vcBytesOut(b), err
		},
		"verdictFromAppraisal": func(a []any) (any, error) { return EatVerdictFromAppraisal(vecArg(a, 0), vecArg(a, 1)), nil },
		"coSignAttestation":    eatTestCoSign,
		"verifyCoSignedAttestation": func(a []any) (any, error) {
			return EatVerifyCoSignedAttestation(vecArg(a, 0), eatOracleClock(vecObj(vecArg(a, 1)))), nil
		},
		"isPqCoSignSuite":        func(a []any) (any, error) { return EatIsPqCoSignSuite(vecArg(a, 0)), nil },
		"ed25519Jkt":             func(a []any) (any, error) { return EatEd25519Jkt(vecArg(a, 0)), nil },
		"eatAdmissionEvidence":   eatTestAdmission,
		"runtimeDigestFromEat":   eatTestRuntimeDigest,
		"issueArtifactDischarge": inSigstoreModule,
	}
	cmp := map[string]func(want, got any) bool{"verifyFreshAttestedEAT": eatTestStricter, "eatAdmissionEvidence": eatTestStricter}
	replayVectorsCmp(t, "ref-attest-eat.json.gz", fns, cmp)
	replaySecretGen(t, "ref-attest-eat.json.gz", func(t *testing.T, p string) { replayVectorsCmp(t, p, fns, cmp) })
}

// eatOracleClock gives a call whose `now` option is ABSENT, or is a string (the reference reads a non-number as "use the clock"; the
// corpus names those cases "uses clock"), the clock the reference oracle ran under. A number, a non-finite one included ({"$num"} in the
// corpus), is never replaced: a NaN or infinite clock is a refusal case that must reach the native as it is.
func eatOracleClock(opts map[string]any) map[string]any {
	if v, has := opts["now"]; has {
		if _, isStr := v.(string); !isStr {
			return opts
		}
	}
	out := make(map[string]any, len(opts)+1)
	for k, v := range opts {
		out[k] = v
	}
	out["now"] = jsNumber(vecOracleNow())
	return out
}
