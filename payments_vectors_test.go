package pca

// Replays the payments reference corpus: mandate build, charge decision (the reference's recorded policy decision is fed back
// through the injected decider, so the native assembly, refusals, exact money arithmetic and budget threading are compared case
// by case), charge PCActn, Shared Payment Token limits, spend rails, the Stripe Issuing adapter and agent network tokens.
// Secrets cross as {"$seed": label} (the test re-derives the 32-byte Ed25519 seed); bytes as {"$bytes": base64url}.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
)

func payRevive(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = payRevive(e)
		}
		return out
	case map[string]any:
		if len(x) == 1 {
			if b := baseBytes(x); b != nil { // {"$bytes": b64url} or {"$bytes": {"$seed": label}}
				return b
			}
			if s, ok := x["$seed"].(string); ok {
				d := sha256.Sum256([]byte("atlas-pca-conformance/" + s))
				return d[:]
			}
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = payRevive(e)
		}
		return out
	}
	return v
}

// payNoTauBudgetRefusal is a DELIBERATE, pinned divergence: the native is stricter than the reference on a trust budget without a finite
// tau. The reference reads the missing or non-finite tau as a depleted budget (B 0, a step-up, the guardian share released for the
// human recharge); the native refuses the budget as not a trust budget, fails closed at the maximum risk and releases nothing. Both
// refuse the charge. The comparison accepts the native result only when the reference's own budget has no finite tau, the reference
// refused, and the native result is exactly that fail-closed refusal.
func payNoTauBudgetRefusal(budget func(want map[string]any) map[string]any) func(want, got any) bool {
	return func(want, got any) bool {
		if baseCanon(want) == baseCanon(got) {
			return true
		}
		w, g := vecObj(want), vecObj(got)
		if w == nil || g == nil {
			return false
		}
		wd, gd := vecObj(w["decision"]), vecObj(g["decision"])
		if wd == nil || gd == nil || wd["admit"] != false || gd["admit"] != false {
			return false
		}
		b := budget(w)
		if b == nil {
			return false
		}
		if t, has := b["tau"]; has {
			if m := vecObj(t); m == nil || m["$num"] == nil {
				if f, ok := jsNum(t); ok && finite(f) {
					return false // a finite tau: no divergence is allowed
				}
			}
		}
		r, _ := jsNum(gd["r"])
		return r == 1 && gd["releaseGuardianShare"] == false &&
			fmt.Sprint(gd["reasons"]) == "[policy evaluation error (fail closed): budget is not a trust budget]"
	}
}

var payNegZeroRefusal = regexp.MustCompile(`^strict JSON: negative zero is not allowed \(at offset \d+\)$`)

// payHasNegativeZero reports whether a decoded value holds a number written -0.
func payHasNegativeZero(v any) bool {
	switch x := v.(type) {
	case json.Number:
		return x == "-0"
	case []any:
		for _, e := range x {
			if payHasNegativeZero(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if payHasNegativeZero(e) {
				return true
			}
		}
	}
	return false
}

func payArgs(f func(a []any) (any, error)) vecFn {
	return func(a []any) (any, error) { return f(payRevive(a).([]any)) }
}

func payMember(m map[string]any, k string) any {
	if v, has := m[k]; has {
		return v
	}
	return payU
}

func payNullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestPaymentsVectors(t *testing.T) {
	m := func(v any) map[string]any { x, _ := v.(map[string]any); return x }
	replayVectors(t, "ref-payments.json.gz", map[string]vecFn{
		"buildPaymentMandate": payArgs(func(a []any) (any, error) {
			res, err := BuildPaymentMandate(vecArg(a, 0))
			if err != nil && payHasNegativeZero(vecArg(a, 0)) && payNegZeroRefusal.MatchString(err.Error()) {
				// DELIBERATE: the native is stricter than the reference here. The reference reads a -0 as 0; the native's strict profile
				// refuses a negative zero in a mandate, because -0 and 0 are one number with two spellings. Only this exact refusal is
				// pinned (its text is matched above); every other refusal, and every accepted mandate, is compared with the reference.
				return nil, vecSkip("negative zero in a mandate: native refusal pinned (stricter than the reference on purpose)")
			}
			return res, err
		}),
		"mandatePredicates":   payArgs(func(a []any) (any, error) { return MandatePredicates(vecArg(a, 0)) }),
		"mandateCaveats":      payArgs(func(a []any) (any, error) { return MandateCaveats(vecArg(a, 0)) }),
		"mandateRiskPolicy":   payArgs(func(a []any) (any, error) { return MandateRiskPolicy(vecArg(a, 0), vecArg(a, 1)) }),
		"autoSpendBound":      payArgs(func(a []any) (any, error) { return AutoSpendBound(vecArg(a, 0)) }),
		"isMinorUnits":        payArgs(func(a []any) (any, error) { return IsMinorUnits(vecArg(a, 0)), nil }),
		"isPlainId":           payArgs(func(a []any) (any, error) { return IsPlainID(vecArg(a, 0)), nil }),
		"chargeActionContext": payArgs(func(a []any) (any, error) { return ChargeActionContext(vecArg(a, 0), vecArg(a, 1)) }),
		"chargeParams":        payArgs(func(a []any) (any, error) { return ChargeParams(vecArg(a, 0), vecArg(a, 1)) }),
		"chargePlanNode": payArgs(func(a []any) (any, error) {
			id, _ := vecArg(a, 2).(string)
			return ChargePlanNode(vecArg(a, 0), vecArg(a, 1), id)
		}),
		"chargeDecideInput": payArgs(func(a []any) (any, error) {
			return ChargeDecideInput(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3))
		}),
		"authorizeCharge": payArgs(func(a []any) (any, error) {
			rec := m(vecArg(a, 3))
			return AuthorizeCharge(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), func(map[string]any) (map[string]any, error) { return rec, nil })
		}),
		"chargeToPCActn":           payArgs(func(a []any) (any, error) { return ChargeToPCActn(vecArg(a, 0), vecArg(a, 1), m(vecArg(a, 2))) }),
		"settleCharge":             payArgs(func(a []any) (any, error) { return SettleCharge(vecArg(a, 0), vecArg(a, 1)) }),
		"applyHumanCosign":         payArgs(func(a []any) (any, error) { return ApplyHumanCosign(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) }),
		"sharedPaymentTokenLimits": payArgs(func(a []any) (any, error) { return SharedPaymentTokenLimits(vecArg(a, 0), vecArg(a, 1)) }),
		"railLimits":               payArgs(func(a []any) (any, error) { return RailLimits(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) }),
		"categoriesFromTraits": payArgs(func(a []any) (any, error) {
			l, _ := vecArg(a, 0).([]any)
			return CategoriesFromTraits(l), nil
		}),
		"reconcileSettlement": payArgs(func(a []any) (any, error) { return ReconcileSettlement(vecArg(a, 0), vecArg(a, 1)) }),
		"verifyStripeSignature": payArgs(func(a []any) (any, error) {
			rb, _ := vecArg(a, 0).(string)
			tol := float64(StripeWebhookToleranceSec)
			if tl := vecArg(a, 4); tl != nil {
				tol = jsF(tl)
			}
			return VerifyStripeSignature(rb, vecArg(a, 1), vecArg(a, 2), jsF(vecArg(a, 3)), tol), nil
		}),
		"signStripePayload": payArgs(func(a []any) (any, error) {
			rb, _ := vecArg(a, 0).(string)
			sc, _ := vecArg(a, 1).(string)
			return SignStripePayload(rb, sc, vecArg(a, 2)), nil
		}),
		"stripeCardParams": payArgs(func(a []any) (any, error) {
			return StripeCardParams(m(vecArg(a, 0)), m(vecArg(a, 1)), vecArg(a, 2), m(vecArg(a, 3)))
		}),
		"stripeAuthorizationFromEvent": payArgs(func(a []any) (any, error) { return StripeAuthorizationFromEvent(vecArg(a, 0)), nil }),
		"stripeIssuingWebhook": payArgs(func(a []any) (any, error) {
			rb, _ := vecArg(a, 0).(string)
			sc, _ := vecArg(a, 2).(string)
			now := jsF(vecArg(a, 3))
			approved := vecArg(a, 4) == true
			h := NewStripeIssuingWebhook(StripeWebhookOptions{Secret: sc, NowSec: func() float64 { return now },
				Authorize: func(map[string]any) RailVerdict { return RailVerdict{Approved: approved} }})
			return h(rb, vecArg(a, 1)), nil
		}),
		"stripeSettlementFromTransaction": payArgs(func(a []any) (any, error) { return StripeSettlementFromTransaction(vecArg(a, 0)), nil }),
		"tokenRefError":                   payArgs(func(a []any) (any, error) { return payNullIfEmpty(TokenRefError(vecArg(a, 0))), nil }),
		"looksLikePan": payArgs(func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			return LooksLikePan(s), nil
		}),
		"bindNetworkToken": payArgs(func(a []any) (any, error) {
			o := m(vecArg(a, 0))
			sec, _ := o["holderSecret"].([]byte)
			pub, _ := o["holderPublic"].([]byte)
			return BindNetworkToken(BindNetworkTokenOptions{Provider: payMember(o, "provider"), TokenRef: payMember(o, "tokenRef"), Grant: payMember(o, "grant"),
				IssuerNonce: payMember(o, "issuerNonce"), HolderSecret: sec, HolderPublic: pub})
		}),
		"verifyNetworkTokenBinding": payArgs(func(a []any) (any, error) {
			return payNullIfEmpty(CheckNetworkTokenBinding(vecArg(a, 0), vecArg(a, 1))), nil
		}),
		"bindingMessage": payArgs(func(a []any) (any, error) {
			b, err := NetworkTokenBindingMessage(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(b)}, nil
		}),
		"controlsFromLimits": payArgs(func(a []any) (any, error) { return ControlsFromLimits(m(vecArg(a, 0)), vecArg(a, 1)) }),
		"settlementMetadata": payArgs(func(a []any) (any, error) {
			d, _ := vecArg(a, 1).(string)
			return SettlementMetadata(m(vecArg(a, 0)), d), nil
		}),
		"reconcileNetworkSettlement": payArgs(func(a []any) (any, error) { return ReconcileNetworkSettlement(vecArg(a, 0), vecArg(a, 1)) }),
		"chargeWithNetworkToken": payArgs(func(a []any) (any, error) {
			return ChargeWithNetworkToken(m(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2), m(vecArg(a, 3)))
		}),
	})
}

func TestRailAuthorizerDeclinesEverythingButAuto(t *testing.T) {
	auth, err := NewRailAuthorizer(RailAuthorizerOptions{Instruments: func(string) (*InstrumentBinding, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	mid := "m"
	if v := auth(&RailAuthorization{ID: "a1", InstrumentID: "c", Amount: jsNumber(5), Currency: "USD", MerchantID: &mid}); v.Approved || v.Reasons[0] != "instrument_unknown" {
		t.Fatalf("unknown instrument: %+v", v)
	}
	if v := auth(nil); v.Approved || v.Reasons[0] != "malformed_authorization" {
		t.Fatalf("nil authorization: %+v", v)
	}
	if v := auth(&RailAuthorization{ID: "a1", InstrumentID: "c", Amount: jsNumber(0), Currency: "USD", MerchantID: &mid}); v.Approved || v.Reasons[0] != "amount_not_positive_minor_units" {
		t.Fatalf("zero amount: %+v", v)
	}
	if v := auth(&RailAuthorization{ID: "a1", InstrumentID: "c", Amount: jsNumber(5), Currency: "USD"}); v.Approved || v.Reasons[0] != "merchant_unknown" {
		t.Fatalf("no merchant: %+v", v)
	}
}

// TestPaymentsCoreVectors replays the built-in policy engine path (authorizeChargeCore: no injected decider) and the bonded
// claim over a charge PCActn.
func TestPaymentsCoreVectors(t *testing.T) {
	replayVectorsCmp(t, "ref-payments-java-extra.json.gz", map[string]vecFn{
		"authorizeChargeCore": payArgs(func(a []any) (any, error) {
			return AuthorizeCharge(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), nil)
		}),
		"openChargeBond": payArgs(func(a []any) (any, error) {
			pc, _ := vecArg(a, 0).(map[string]any)
			o, _ := vecArg(a, 1).(map[string]any)
			opts := OpenOptimisticOptions{}
			opts.BondRef, _ = o["bondRef"].(string)
			if f, ok := jsNum(o["claimedR"]); ok {
				opts.ClaimedR = f
			}
			opt := func(k string) *float64 {
				if v, has := o[k]; has && v != nil {
					if f, ok := jsNum(v); ok {
						return &f
					}
				}
				return nil
			}
			opts.ChallengeWindowMs, opts.IssuedAt, opts.ServerNow = opt("challengeWindowMs"), opt("issuedAt"), opt("serverNow")
			seed, _ := vecArg(a, 2).(string)
			if sb, ok := vecArg(a, 2).([]byte); ok { // a seed label revives to its 32 bytes
				seed = base64.RawURLEncoding.EncodeToString(sb)
			}
			kp, err := KeyPairFromSeedB64u(seed)
			if err != nil {
				return nil, err
			}
			return OpenChargeBond(pc, opts, kp)
		}),
	}, map[string]func(want, got any) bool{"authorizeChargeCore": payNoTauBudgetRefusal(func(w map[string]any) map[string]any { return vecObj(w["budgetBefore"]) })})
}
