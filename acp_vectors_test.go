package pca

// Replay of the reference corpus for the ACP delegated payment tokens, x402 v1 / v2 and the Stripe Shared Payment Granted Tokens.
// The signing key in the corpus is replaced by its seed label ("$seed"); it is re-derived here (SHA-256 of
// "atlas-pca-conformance/<label>"). Stores, verifiers and settle steps are built from the specs the corpus names.
// Where the reference output depends on the member order of a caller-supplied object (a token's paymentMethod, a header's JSON) the
// decoded value is compared and a token must additionally verify under the signer's key (a Go map keeps no insertion order).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
)

type acpTestStore struct {
	claim func(jti string, exp float64) (bool, error)
}

func (s *acpTestStore) Claim(jti string, exp float64) (bool, error) { return s.claim(jti, exp) }

// acpSpecStore is the single-use store a spec names; any other value is passed through as is (and is not a store).
func acpSpecStore(spec any) any {
	s, ok := spec.(string)
	if !ok {
		return spec
	}
	switch s {
	case "once":
		seen := map[string]bool{}
		return &acpTestStore{claim: func(j string, _ float64) (bool, error) {
			if seen[j] {
				return false, nil
			}
			seen[j] = true
			return true, nil
		}}
	case "always":
		return &acpTestStore{claim: func(string, float64) (bool, error) { return true, nil }}
	case "never", "truthy": // a truthy non-boolean is not `=== true`
		return &acpTestStore{claim: func(string, float64) (bool, error) { return false, nil }}
	case "throw":
		return &acpTestStore{claim: func(string, float64) (bool, error) { return false, errors.New("store down") }}
	}
	return spec
}

func acpSeedSigner() ed25519.PrivateKey {
	d := sha256.Sum256([]byte("atlas-pca-conformance/acp/signer"))
	return ed25519.NewKeyFromSeed(d[:])
}

// seedLabelOnly is the label of a lone {"$seed": label} value (a key member the corpus keeps as a seed label), else "" and false.
func seedLabelOnly(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return "", false
	}
	l, ok := m["$seed"].(string)
	return l, ok
}

// acpSeedKeys rewrites every {"$seed": label, ...} member into the private JWK member d derived from the label, and a member whose
// value is a lone {"$seed": label} into the base64url of that derived seed.
func acpSeedKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if label, ok := seedLabelOnly(x); ok {
				d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
				out[k] = base64.RawURLEncoding.EncodeToString(d[:])
				continue
			}
			out[k] = acpSeedKeys(x)
		}
		if label, ok := out["$seed"].(string); ok {
			d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			delete(out, "$seed")
			out["d"] = base64.RawURLEncoding.EncodeToString(d[:])
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = acpSeedKeys(x)
		}
		return out
	}
	return v
}

var acpTestReason = regexp.MustCompile(`(?s)^(token signature did not verify|bound proof failed to verify): .*$`)

func acpNormRes(r map[string]any) map[string]any {
	out := make(map[string]any, len(r))
	for k, v := range r {
		out[k] = v
	}
	if s, ok := out["reason"].(string); ok {
		out["reason"] = acpTestReason.ReplaceAllString(s, "$1")
	}
	if pr, ok := out["pcaResult"].(map[string]any); ok {
		out["pcaResult"] = map[string]any{"allow": pr["allow"]}
	}
	return out
}

func acpWithStore(op map[string]any) map[string]any {
	o2 := make(map[string]any, len(op))
	for k, v := range op {
		o2[k] = v
	}
	if sp, has := op["singleUse"]; has {
		o2["singleUse"] = acpSpecStore(sp)
	}
	return o2
}

func acpTimes(a []any) int {
	if f, ok := jsNum(vecArg(a, 2)); ok {
		return int(f)
	}
	return 1
}

func acpRepeat(times int, run func() (map[string]any, error)) (any, error) {
	rs := make([]any, 0, times)
	for i := 0; i < times; i++ {
		r, err := run()
		if err != nil {
			return nil, err
		}
		rs = append(rs, acpNormRes(r))
	}
	if times == 1 {
		return rs[0], nil
	}
	return rs, nil
}

func acpObjArg(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("options are not an object")
	}
	return m, nil
}

func acpStrList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func acpFloats(v any) []float64 {
	l, _ := v.([]any)
	out := make([]float64, 0, len(l))
	for _, x := range l {
		f, _ := jsNum(x)
		out = append(out, f)
	}
	return out
}

func acpStrs(l []string) any { return acpStringsAny(l) }

// acpHdrEq compares two header values by their decoded JSON.
func acpHdrEq(a, b string) bool {
	da, e1 := base64.StdEncoding.DecodeString(a)
	db, e2 := base64.StdEncoding.DecodeString(b)
	if e1 != nil || e2 != nil {
		return false
	}
	va, e3 := ParseJSONLenient(da)
	vb, e4 := ParseJSONLenient(db)
	return e3 == nil && e4 == nil && baseCanon(normalizeJSON(va)) == baseCanon(normalizeJSON(vb))
}

// acpLooseEq is value equality where a string that is a base64 JSON header compares by its decoded value.
func acpLooseEq(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, x := range w {
			y, has := g[k]
			if !has || !acpLooseEq(x, y) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !acpLooseEq(w[i], g[i]) {
				return false
			}
		}
		return true
	case string:
		g, ok := got.(string)
		return ok && (w == g || acpHdrEq(w, g))
	}
	return baseCanon(want) == baseCanon(got)
}

// acpTokenEq: identical, or the same header and claims (member order aside) and a signature that verifies under the signer's key.
func acpTokenEq(want, got any) bool {
	w, ok1 := want.(string)
	g, ok2 := got.(string)
	if !ok1 || !ok2 {
		return false
	}
	if w == g {
		return true
	}
	wp, gp := strings.Split(w, "."), strings.Split(g, ".")
	if len(wp) != 3 || len(gp) != 3 {
		return false
	}
	for i := 0; i < 2; i++ {
		a, e1 := ParseJSONLenient(nodeB64(wp[i]))
		b, e2 := ParseJSONLenient(nodeB64(gp[i]))
		if e1 != nil || e2 != nil || baseCanon(normalizeJSON(a)) != baseCanon(normalizeJSON(b)) {
			return false
		}
	}
	return ed25519.Verify(acpSeedSigner().Public().(ed25519.PublicKey), []byte(gp[0]+"."+gp[1]), nodeB64(gp[2]))
}

func acpTestFns() map[string]vecFn {
	verifyToken := func(a []any) (any, error) {
		a = acpSeedKeys(a).([]any)
		op, err := acpObjArg(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		o2 := acpWithStore(op)
		return acpRepeat(acpTimes(a), func() (map[string]any, error) { return AcpVerifyDelegatedPaymentToken(vecArg(a, 0), o2) })
	}
	return map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"v": AcpDelegatedTokenVersion, "t": AcpDelegatedTokenType, "s": AcpSpendCapType, "m": AcpMerchantAllowType,
				"c": AcpMerchantCategoryType, "h": AcpHumanPresentType, "x1": AcpX402Version1, "x2": AcpX402Version2, "sup": AcpX402SupportedVersions,
				"pr": AcpX402PaymentRequiredHeader, "ps": AcpX402PaymentSignatureHeader, "pe": AcpX402PaymentResponseHeader,
				"st": AcpX402HTTPStatus, "spt": AcpStripeSptObject}, nil
		},
		"spendCapCaveat": func(a []any) (any, error) {
			f, _ := jsNum(vecArg(a, 0))
			if len(a) > 1 {
				c, _ := a[1].(string)
				return AcpSpendCapCaveat(f, &c), nil
			}
			return AcpSpendCapCaveat(f, nil), nil
		},
		"merchantAllowCaveat":    func(a []any) (any, error) { return AcpMerchantAllowCaveat(acpStrList(vecArg(a, 0))), nil },
		"merchantCategoryCaveat": func(a []any) (any, error) { return AcpMerchantCategoryCaveat(acpStrList(vecArg(a, 0))), nil },
		"humanPresentCaveat": func(a []any) (any, error) {
			if len(a) == 0 {
				return AcpHumanPresentCaveat(true), nil
			}
			b, _ := a[0].(bool)
			return AcpHumanPresentCaveat(b), nil
		},
		"extractPaymentAuthority": func(a []any) (any, error) { return AcpExtractPaymentAuthority(vecArg(a, 0)) },
		"checkPaymentAuthority":   func(a []any) (any, error) { return AcpCheckPaymentAuthority(vecArg(a, 0), vecArg(a, 1)) },
		"mintDelegatedPaymentToken": func(a []any) (any, error) {
			a = acpSeedKeys(a).([]any)
			op, err := acpObjArg(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return AcpMintDelegatedPaymentToken(vecArg(a, 0), op)
		},
		"verifyDelegatedPaymentToken": verifyToken,
		"x402Challenge":               func(a []any) (any, error) { return AcpX402Challenge(vecArg(a, 0), vecArg(a, 1)) },
		"x402ChallengeV2":             func(a []any) (any, error) { return AcpX402ChallengeV2(vecArg(a, 0), vecArg(a, 1)) },
		"x402Settle": func(a []any) (any, error) {
			vspec := vecArg(a, 1)
			verify := func(any) (map[string]any, error) {
				if s, ok := vspec.(string); ok && s == "throw" {
					return nil, errors.New("verify down")
				}
				m, _ := vspec.(map[string]any)
				return m, nil
			}
			var settle AcpX402Settler
			switch vecArg(a, 2) {
			case "echo":
				settle = func(p, c any) (any, error) {
					r := map[string]any{}
					if j := acpGet(c, "jti"); j != acpU {
						r["jti"] = j
					}
					if t := acpGet(p, "token"); t != acpU {
						r["token"] = t
					}
					return r, nil
				}
			case "value":
				settle = func(any, any) (any, error) { return "receipt-1", nil }
			case "throw":
				settle = func(any, any) (any, error) { return nil, errors.New("settle down") }
			case "undef":
				settle = func(any, any) (any, error) { return nil, nil }
			}
			return AcpX402Settle(vecArg(a, 0), verify, settle)
		},
		"acpX402Verifier": func(a []any) (any, error) {
			a = acpSeedKeys(a).([]any)
			op, err := acpObjArg(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			fn := AcpX402Verifier(acpWithStore(op))
			return acpRepeat(acpTimes(a), func() (map[string]any, error) { return fn(vecArg(a, 0)) })
		},
		"toAcpAllowance":              func(a []any) (any, error) { return AcpToAllowance(vecArg(a, 0)) },
		"resourceInfoProblems":        func(a []any) (any, error) { return AcpResourceInfoProblems(vecArg(a, 0)), nil },
		"requirementV2Problems":       func(a []any) (any, error) { return AcpRequirementV2Problems(vecArg(a, 0)), nil },
		"paymentRequiredV2Problems":   func(a []any) (any, error) { return AcpPaymentRequiredV2Problems(vecArg(a, 0)), nil },
		"paymentPayloadV2Problems":    func(a []any) (any, error) { return AcpPaymentPayloadV2Problems(vecArg(a, 0)), nil },
		"settlementResponseProblems":  func(a []any) (any, error) { return AcpSettlementResponseProblems(vecArg(a, 0)), nil },
		"stripeSptProblems":           func(a []any) (any, error) { return AcpStripeSptProblems(vecArg(a, 0)), nil },
		"encodePaymentRequiredHeader": func(a []any) (any, error) { return AcpEncodePaymentRequiredHeader(vecArg(a, 0)) },
		"decodePaymentRequiredHeader": func(a []any) (any, error) { return AcpDecodePaymentRequiredHeader(vecArg(a, 0)) },
		"encodePaymentSignatureHeader": func(a []any) (any, error) {
			return AcpEncodePaymentSignatureHeader(vecArg(a, 0))
		},
		"decodePaymentSignatureHeader": func(a []any) (any, error) {
			return AcpDecodePaymentSignatureHeader(vecArg(a, 0))
		},
		"encodePaymentResponseHeader": func(a []any) (any, error) { return AcpEncodePaymentResponseHeader(vecArg(a, 0)) },
		"decodePaymentResponseHeader": func(a []any) (any, error) { return AcpDecodePaymentResponseHeader(vecArg(a, 0)) },
		"x402Negotiate": func(a []any) (any, error) {
			if vecArg(a, 0) == nil {
				return nil, errors.New("Cannot read properties of null (reading 'length')") // the reference reads offered.length
			}
			var supported []float64
			if len(a) > 1 {
				supported = acpFloats(a[1])
			}
			v, ok := AcpX402Negotiate(acpFloats(a[0]), supported)
			if !ok {
				return nil, nil
			}
			return v, nil
		},
		"x402AcceptedMatches":  func(a []any) (any, error) { return AcpX402AcceptedMatches(vecArg(a, 0), vecArg(a, 1)) },
		"normalizeX402Payload": func(a []any) (any, error) { return AcpNormalizeX402Payload(vecArg(a, 0)), nil },
		"readPaymentSignature": func(a []any) (any, error) {
			r := AcpReadPaymentSignature(vecArg(a, 0))
			if s, _ := r["reason"].(string); strings.HasSuffix(s, "is given more than once") {
				return nil, vecSkip("JS object member order picks the first of several case-variant header names; a Go map has none, so the ambiguity is refused")
			}
			return r, nil
		},
		"x402SettlementResponse":      func(a []any) (any, error) { return AcpX402SettlementResponse(vecArg(a, 0), vecArg(a, 1)) },
		"x402PaymentSignatureHeaders": func(a []any) (any, error) { return AcpX402PaymentSignatureHeaders(vecArg(a, 0)) },
		"parseStripeSpt":              func(a []any) (any, error) { return AcpParseStripeSpt(vecArg(a, 0)) },
		"stripeSptUsable":             func(a []any) (any, error) { return AcpStripeSptUsable(vecArg(a, 0), vecArg(a, 1)) },
		"stripeUsageLimitsFor":        func(a []any) (any, error) { return AcpStripeUsageLimitsFor(vecArg(a, 0)) },
		"stripeSptWithinClaims":       func(a []any) (any, error) { return AcpStripeSptWithinClaims(vecArg(a, 0), vecArg(a, 1)) },
	}
}

func TestAcpReferenceVectors(t *testing.T) {
	loose := func(w, g any) bool { return acpLooseEq(w, g) }
	replayVectorsCmp(t, "ref-acp.json.gz", acpTestFns(), map[string]func(want, got any) bool{
		"mintDelegatedPaymentToken":    acpTokenEq,
		"encodePaymentRequiredHeader":  loose,
		"encodePaymentSignatureHeader": loose,
		"encodePaymentResponseHeader":  loose,
		"x402ChallengeV2":              loose,
		"x402SettlementResponse":       loose,
		"x402PaymentSignatureHeaders":  loose,
	})
}

// A real grant and a real signed PCActn: the full core re-verification runs to an allow (the audience tri-state included).
func TestAcpReferenceVectorsRealGrant(t *testing.T) {
	replayVectors(t, "ref-acp-java-extra.json.gz", map[string]vecFn{"verifyDelegatedPaymentToken": acpTestFns()["verifyDelegatedPaymentToken"]})
}
