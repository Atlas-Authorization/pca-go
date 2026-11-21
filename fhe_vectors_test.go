package pca

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// Signing seeds are labels ({"$seed": label} = sha256("atlas-pca-conformance/" + label)); a bare string is a base64url key (the
// wrong-length key cases).
func fheSeedArg(v any) []byte {
	if l, ok := vecObj(v)["$seed"].(string); ok {
		h := sha256.Sum256([]byte("atlas-pca-conformance/" + l))
		return h[:]
	}
	s, _ := v.(string)
	b, _ := b64.DecodeString(s)
	return b
}

func fheScale(a []any, i int) float64 {
	if i < len(a) {
		return jsF(a[i])
	}
	return FheDefaultScale
}

func fheStrs(v any) []string {
	var out []string
	for _, x := range vecArgList(v) {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func fheGuard(exp map[string]any) FheNonceGuard {
	used := map[string]bool{}
	for _, k := range fheStrs(exp["used"]) {
		used[k] = true
	}
	max := int(jsF(exp["max"]))
	return func(k string) bool {
		if used[k] || len(used) >= max {
			return false
		}
		used[k] = true
		return true
	}
}

func fheNums(v []float64, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return FheNumbers(v), nil
}

func TestFheMatchesReference(t *testing.T) {
	replayVectors(t, "ref-fhe.json.gz", map[string]vecFn{
		"transformedInputs": func(a []any) (any, error) { return fheNums(FheTransformedInputs(vecArg(a, 0))) },
		"quantizeRiskInputs": func(a []any) (any, error) {
			return fheNums(FheQuantizeRiskInputs(vecArg(a, 0), fheScale(a, 1)))
		},
		"weightVector": func(a []any) (any, error) { return fheNums(FheWeightVector(vecArg(a, 0))) },
		"fheRiskPolicy": func(a []any) (any, error) {
			return FheRiskPolicy(vecArg(a, 0), vecArg(a, 1), fheScale(a, 2))
		},
		"plaintextVerdict": func(a []any) (any, error) { return FhePlaintextVerdict(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) },
		"fromActn": func(a []any) (any, error) {
			in, err := FheRiskInputsFromPCActn(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return fheNums(FheTransformedInputs(in))
		},
		"binding": func(a []any) (any, error) { return FheBindingFromPCActn(vecArg(a, 0)) },
		"sign": func(a []any) (any, error) {
			return FheSignRiskClaim(vecObj(vecArg(a, 0)), fheSeedArg(vecArg(a, 1)), vecStrOf(vecArg(a, 2)), vcBytes(vecArg(a, 3)))
		},
		"claimDigest": func(a []any) (any, error) { return FheSignedClaimDigest(vecArg(a, 0)) },
		"verifyClaim": func(a []any) (any, error) {
			exp := vecObj(vecArg(a, 1))
			return FheVerifySignedRiskClaim(vecArg(a, 0), FheClaimExpectations{
				TrustedSigners: fheStrs(exp["trustedSigners"]), Context: vecStr(exp, "context"),
				Binding: exp["binding"], Policy: exp["policy"], Nonces: fheGuard(exp),
			}), nil
		},
		"attest": func(a []any) (any, error) {
			gate := vecObj(vecArg(a, 2))
			admit, _ := vecArg(a, 3).(bool)
			return FheAttestVerdict(fheSeedArg(vecArg(a, 0)), vecArg(a, 1), gate, admit)
		},
		"verifyAttest": func(a []any) (any, error) {
			exp := vecObj(vecArg(a, 1))
			var gate map[string]any
			if g, ok := exp["gate"].(map[string]any); ok {
				gate = g
			}
			return FheVerifyVerdictAttestation(vecArg(a, 0), fheStrs(exp["trustedHolders"]), vecStr(exp, "claimDigest"), gate), nil
		},
		"nonceGuard": func(a []any) (any, error) {
			g := FheMemoryNonceGuard(int(jsF(vecArg(a, 0))))
			var out []any
			for _, k := range fheStrs(vecArg(a, 1)) {
				out = append(out, g(k))
			}
			return out, nil
		},
	})
}

func vecStrOf(v any) string { s, _ := v.(string); return s }

// A claim signed with the wrong key length is refused, never signed.
func TestFheSignRefusesBadKey(t *testing.T) {
	_, err := FheSignRiskClaim(map[string]any{}, make([]byte, 31), "ctx", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	if err == nil || !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("want a key-length refusal, got %v", err)
	}
}
