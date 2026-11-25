package pca

// Payments for PCA (the reference @atlasauth/pca-payments): a payment mandate as a Root Intent Grant, the charge decision, the
// charge PCActn, Shared Payment Token limits and spend rails (card limits, settlement reconciliation). Values are the reference's
// JSON shapes (camelCase members, map[string]any with json.Number numbers) and inputs follow JavaScript semantics where the
// reference does (absent vs null members, truthiness, coercing comparisons), so a hostile mandate or charge is refused or priced
// exactly as the reference does. The policy decision defaults to the native Policy VM (NativeChargeDecider); a ChargeDecider may be injected.
// The Stripe Issuing adapter is in payments_stripe.go, agent network tokens in payments_network.go.

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ChargeReversibilityClass = "reversible"
	ChargeVerb               = "charge"
	AmountNotMinorUnits      = "amount_not_integer_minor_units"
	MerchantInvalid          = "merchant_invalid"
)

// MandateGrantError codes: verified_grant_required | mandate_grant_mismatch | mandate_terms_mismatch (a *CodedError).
func mandateGrantError(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// ---- JS-semantics helpers (absent member = payU) ------------------------------------------------------------------------

type payUndef struct{}

var payU any = payUndef{}

func payIsU(v any) bool { _, ok := v.(payUndef); return ok }

func payNullish(v any) bool { return v == nil || payIsU(v) }

// payGet is `o.k`: a TypeError for null / undefined, undefined for a missing member or a primitive / array receiver.
func payGet(o any, k string) (any, error) {
	if payNullish(o) {
		what := "null"
		if payIsU(o) {
			what = "undefined"
		}
		return nil, fmt.Errorf("Cannot read properties of %s (reading '%s')", what, k)
	}
	if m, ok := o.(map[string]any); ok {
		if v, has := m[k]; has {
			return v, nil
		}
	}
	return payU, nil
}

// payOpt is `o?.k`.
func payOpt(o any, k string) any {
	if payNullish(o) {
		return payU
	}
	v, _ := payGet(o, k)
	return v
}

// payMust chains member reads: payMust(o, "a", "b") is `o.a.b`.
func payMust(o any, ks ...string) (any, error) {
	var err error
	for _, k := range ks {
		if o, err = payGet(o, k); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func payFinite(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func payTruthy(v any) bool { return !payIsU(v) && jsTruthy(v) }

func payToNumber(v any) float64 {
	if payIsU(v) {
		return math.NaN()
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	if _, ok := v.(map[string]any); ok {
		return math.NaN()
	}
	return jsToNumber(v)
}

func payToStr(v any) string {
	if payIsU(v) {
		return "undefined"
	}
	return jsValueString(v)
}

// payNum is the JSON value of a computed number (a non-finite one stays float64, which canonicalization refuses as JS does).
func payNum(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return f
	}
	return jsNumber(f)
}

func payMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Min(a, b)
}

func payMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Max(a, b)
}

// payRound is Math.round (half up).
func payRound(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return x
	}
	r := math.Floor(x)
	if x-r >= 0.5 {
		return r + 1
	}
	return r
}

// payGT is the JS `>`: two strings compare by UTF-16 code units, anything else numerically after ToNumber.
func payGT(a, b any) bool {
	sa, oka := a.(string)
	sb, okb := b.(string)
	if oka && okb {
		return compareUnits(utf16Units(sa), utf16Units(sb)) > 0
	}
	return payToNumber(a) > payToNumber(b)
}

func payStrictEq(a, b any) bool {
	if payIsU(a) || payIsU(b) {
		return payIsU(a) && payIsU(b)
	}
	return jsStrictEq(a, b)
}

// payLength is `v.length` (a TypeError for null / undefined; NaN when there is none).
func payLength(v any) (float64, error) {
	switch x := v.(type) {
	case nil, payUndef:
		return 0, errors.New("Cannot read properties of undefined (reading 'length')")
	case string:
		return float64(jsLen(x)), nil
	case []any:
		return float64(len(x)), nil
	case map[string]any:
		if l, has := x["length"]; has {
			return payToNumber(l), nil
		}
	}
	return math.NaN(), nil
}

// paySpreadList is `[...v]` (a string spreads into its code points).
func paySpreadList(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return append([]any{}, x...), nil
	case string:
		out := []any{}
		for i := 0; i < len(x); { // spread iterates code points; a lone surrogate (3 WTF-8 bytes) is one element
			if x[i] == 0xED && i+2 < len(x) && x[i+1] >= 0xA0 && x[i+1] <= 0xBF {
				out = append(out, x[i:i+3])
				i += 3
				continue
			}
			r, n := utf8.DecodeRuneInString(x[i:])
			out = append(out, string(r))
			i += n
		}
		return out, nil
	}
	return nil, errors.New("object is not iterable")
}

// paySpreadObj is `{...v}`.
func paySpreadObj(v any) map[string]any {
	out := map[string]any{}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			out[k] = e
		}
	case []any:
		for i, e := range x {
			out[fmt.Sprint(i)] = e
		}
	case string:
		for i, u := range utf16Units(x) {
			out[fmt.Sprint(i)] = string(rune(u))
		}
	}
	return out
}

// payHash is hashCanonical; undefined has no encoding.
func payHash(v any) (string, error) {
	if payIsU(v) {
		return "", errors.New("canonicalize: unsupported type undefined")
	}
	return HashCanonical(v)
}

func paySet(m map[string]any, k string, v any) {
	if !payIsU(v) {
		m[k] = v
	}
}

func payNowMs() float64 { return float64(time.Now().UnixMilli()) }

// ---- mandate ------------------------------------------------------------------------------------------------------------

var payStarOrControl = regexp.MustCompile("[*\x00-\x1f\x7f]")

// IsPlainID: a merchant id that cannot act as a resource pattern (a non-empty string without `*` or control characters).
func IsPlainID(x any) bool {
	s, ok := x.(string)
	return ok && s != "" && !payStarOrControl.MatchString(s)
}

// IsMinorUnits: a non-negative safe integer that is not -0 (amounts are integer minor units: cents, not dollars).
func IsMinorUnits(x any) bool { return jsIsNonNeg(x) }

func payValidate(p any) error {
	g := func(k string) any { v, _ := payGet(p, k); return v }
	if _, err := payGet(p, "strictMinorUnits"); err != nil {
		return err
	}
	// -0 is a number the strict canonicalizer refuses: refuse it here too instead of signing it.
	for _, k := range []string{"perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign", "periodMs", "maxTransactionsPerPeriod", "periodStart", "now"} {
		if f, ok := jsNum(g(k)); ok && f == 0 && math.Signbit(f) {
			return fmt.Errorf("buildPaymentMandate: %s must not be negative zero", k)
		}
	}
	if s := g("strictMinorUnits"); !(s == false) {
		rep := g("replenishPerCosign")
		if payNullish(rep) {
			rep = jsNumber(0)
		}
		for _, kv := range [][2]any{{"perTransactionCap", g("perTransactionCap")}, {"autoApproveThreshold", g("autoApproveThreshold")}, {"cumulativeCap", g("cumulativeCap")}, {"replenishPerCosign", rep}} {
			if !jsIsSafeInteger(kv[1]) {
				return fmt.Errorf("buildPaymentMandate: %s must be a safe integer in minor units (strictMinorUnits)", kv[0])
			}
		}
	}
	ms, ok := g("merchants").([]any)
	if !ok || len(ms) == 0 {
		return errors.New("buildPaymentMandate: at least one allowlisted merchant is required")
	}
	for _, m := range ms {
		if s, ok := m.(string); !ok || s == "" {
			return errors.New("buildPaymentMandate: merchant ids must be non-empty strings")
		}
	}
	for _, m := range ms {
		if !IsPlainID(m) {
			return errors.New("buildPaymentMandate: merchant ids must not contain `*` or control characters")
		}
	}
	if c, ok := g("currency").(string); !ok || c == "" {
		return errors.New("buildPaymentMandate: currency is required")
	}
	x, y, cap := g("perTransactionCap"), g("autoApproveThreshold"), g("cumulativeCap")
	xf, yf, cf := jsF(x), jsF(y), jsF(cap)
	if !payFinite(x) || !(xf > 0) {
		return errors.New("buildPaymentMandate: perTransactionCap (X) must be a finite number > 0")
	}
	if !payFinite(y) || yf < 0 || yf > xf {
		return errors.New("buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X")
	}
	if !payFinite(cap) || cf < xf {
		return errors.New("buildPaymentMandate: cumulativeCap must be a finite number ≥ perTransactionCap (X)")
	}
	if pm := g("periodMs"); !payIsU(pm) && (!payFinite(pm) || !(jsF(pm) > 0)) {
		return errors.New("buildPaymentMandate: periodMs must be a finite number > 0 when given")
	}
	if mx := g("maxTransactionsPerPeriod"); !payIsU(mx) && (!payFinite(mx) || jsF(mx) != math.Trunc(jsF(mx)) || !(jsF(mx) > 0)) {
		return errors.New("buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given")
	}
	if rep := g("replenishPerCosign"); !payIsU(rep) && (!payFinite(rep) || jsF(rep) < 0) {
		return errors.New("buildPaymentMandate: replenishPerCosign must be a finite number ≥ 0 when given")
	}
	return nil
}

func payCond(field, op string, value any) map[string]any {
	c := map[string]any{"field": field, "op": op}
	paySet(c, "value", value)
	return c
}

// MandatePredicates: one allowlist predicate per merchant, each carrying the hard ceiling X, the currency, a non-negative amount
// and (when the mandate constrains them) the categories.
func MandatePredicates(terms any) ([]any, error) {
	mv, err := payGet(terms, "merchants")
	if err != nil {
		return nil, err
	}
	merchants, ok := mv.([]any)
	if !ok {
		return nil, errors.New("terms.merchants.map is not a function")
	}
	out := make([]any, 0, len(merchants))
	for _, m := range merchants {
		x, _ := payGet(terms, "perTransactionCap")
		cur, _ := payGet(terms, "currency")
		conds := []any{payCond("action.params.amount", "lte", x), payCond("action.params.currency", "eq", cur), payCond("action.params.amount", "gte", jsNumber(0))}
		cats, _ := payGet(terms, "categories")
		n, err := payLength(cats)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			conds = append(conds, payCond("action.params.category", "in", cats))
		}
		out = append(out, map[string]any{"verb": ChargeVerb, "resource": "merchant:" + payToStr(m), "where": conds})
	}
	return out, nil
}

// MandateCaveats: the period window, the velocity cap and the bonded / refundable reversibility floor.
func MandateCaveats(terms any) ([]any, error) {
	ps, err := payGet(terms, "periodStart")
	if err != nil {
		return nil, err
	}
	pe, _ := payGet(terms, "periodEnd")
	mx, _ := payGet(terms, "maxTransactionsPerPeriod")
	cv := []any{}
	if payToNumber(ps) > 0 {
		cv = append(cv, map[string]any{"type": "not_before", "at": ps})
	}
	if !payIsU(pe) {
		cv = append(cv, map[string]any{"type": "expires", "at": pe})
	}
	if !payIsU(mx) && !payIsU(pe) {
		per := payMax(1, payRound((payToNumber(pe)-payToNumber(ps))/1000))
		cv = append(cv, map[string]any{"type": "rate", "max": mx, "per_secs": payNum(per)})
	}
	return append(cv, map[string]any{"type": "reversibility_max", "class": ChargeReversibilityClass}), nil
}

// MandateRiskPolicy makes "spend = risk" exact: only the blast radius weighs, theta1 = theta2 = Y/X, kappa = X, lambda = 0,
// rho = replenishPerCosign, bMax = cumulativeCap.
func MandateRiskPolicy(terms any, replenishPerCosign any) (map[string]any, error) {
	a, err := payGet(terms, "autoApproveThreshold")
	if err != nil {
		return nil, err
	}
	x, _ := payGet(terms, "perTransactionCap")
	cap, _ := payGet(terms, "cumulativeCap")
	th := payNum(payToNumber(a) / payToNumber(x))
	p := map[string]any{
		"weights": map[string]any{"alpha": jsNumber(0), "beta": jsNumber(0), "gamma": jsNumber(1), "delta": jsNumber(0), "epsilon": jsNumber(0), "zeta": jsNumber(0)},
		"theta1":  th, "theta2": th, "lambda": jsNumber(0),
	}
	paySet(p, "kappa", x)
	paySet(p, "rho", replenishPerCosign)
	paySet(p, "bMax", cap)
	return p, nil
}

// AutoSpendBound: the most an agent can spend autonomously between two human co-signs, safetyBound(policy) * kappa.
func AutoSpendBound(mandate any) (any, error) {
	p, err := payGet(mandate, "policy")
	if err != nil {
		return nil, err
	}
	kv, err := payGet(p, "kappa")
	if err != nil {
		return nil, err
	}
	bv, _ := payGet(p, "bMax")
	kappa := payToNumber(kv)
	bound := 0.0
	if kappa > 0 {
		bound = payMax(0, payToNumber(bv)) / kappa
	}
	return payNum(bound * kappa), nil
}

// BuildPaymentMandate encodes the params as a PCA Root Intent Grant envelope plus the initial trust budget. params.principalSecret
// is the principal's 32-byte Ed25519 seed ([]byte); principalPublic must be its public key.
func BuildPaymentMandate(params any) (map[string]any, error) {
	if err := payValidate(params); err != nil {
		return nil, err
	}
	g := func(k string) any { v, _ := payGet(params, k); return v }
	now := g("now")
	if !payFinite(now) {
		now = jsNumber(payNowMs())
	}
	periodStart := g("periodStart")
	if !payFinite(periodStart) {
		periodStart = now
	}
	cats := []any{}
	if c := g("categories"); payTruthy(c) {
		var err error
		if cats, err = paySpreadList(c); err != nil {
			return nil, err
		}
	}
	merchants := append([]any{}, g("merchants").([]any)...)
	terms := map[string]any{"merchants": merchants, "categories": cats, "currency": g("currency"), "perTransactionCap": g("perTransactionCap"),
		"autoApproveThreshold": g("autoApproveThreshold"), "cumulativeCap": g("cumulativeCap"), "periodStart": periodStart}
	if pm := g("periodMs"); !payIsU(pm) {
		terms["periodEnd"] = payNum(jsF(periodStart) + jsF(pm))
	}
	if mx := g("maxTransactionsPerPeriod"); !payIsU(mx) {
		terms["maxTransactionsPerPeriod"] = mx
	}
	rep := g("replenishPerCosign")
	if payNullish(rep) {
		rep = terms["cumulativeCap"]
	}
	policy, err := MandateRiskPolicy(terms, rep)
	if err != nil {
		return nil, err
	}
	goal := g("goal")
	if payNullish(goal) {
		names := make([]string, len(merchants))
		for i, m := range merchants {
			names[i] = m.(string)
		}
		goal = fmt.Sprintf("spend ≤ %s %s autonomously / ≤ %s with co-sign, ≤ %s cumulative, at [%s]", payToStr(terms["autoApproveThreshold"]),
			terms["currency"].(string), payToStr(terms["perTransactionCap"]), payToStr(terms["cumulativeCap"]), strings.Join(names, ", "))
	}
	goalS, ok := goal.(string)
	if !ok {
		return nil, errors.New("buildPaymentMandate: goal must be a string")
	}
	seed, ok := g("principalSecret").([]byte)
	if !ok {
		return nil, errors.New("buildPaymentMandate: principalSecret must be a 32-byte Ed25519 seed")
	}
	principal, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	if pub, _ := g("principalPublic").(string); pub != principal.Public {
		return nil, errors.New("buildPaymentMandate: principalPublic is not the public key of principalSecret")
	}
	holder, ok := g("agentPublic").(string)
	if !ok {
		return nil, errors.New("buildPaymentMandate: agentPublic must be a base64url public key")
	}
	salt := ""
	if s := g("goalSalt"); !payIsU(s) {
		if salt, ok = s.(string); !ok || salt == "" {
			return nil, errors.New("buildPaymentMandate: goalSalt must be a non-empty string")
		}
	}
	preds, err := MandatePredicates(terms)
	if err != nil {
		return nil, err
	}
	cvs, err := MandateCaveats(terms)
	if err != nil {
		return nil, err
	}
	minted, err := MintGrant(principal, holder, map[string]any{"predicates": preds, "caveats": cvs, "agent_binding": map[string]any{}, "risk_policy": policy}, goalS, salt, "", nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"grant": minted.Grant, "policy": policy, "budget": map[string]any{"B": terms["cumulativeCap"], "tau": now, "asOf": now},
		"terms": terms, "goalCommit": minted.GoalCommit, "goalSalt": minted.GoalSalt}, nil
}

// ---- charge decision ----------------------------------------------------------------------------------------------------

// ChargeDecider is the PCA policy decision (`decide`) over a charge's decide input; it returns the policy decision object
// ({admit, releaseGuardianShare, r, requiredThreshold, budget, reasons, ...}).
type ChargeDecider func(input map[string]any) (map[string]any, error)

func payChargeParams(mandate, charge any) (map[string]any, error) {
	amount, err := payGet(charge, "amount")
	if err != nil {
		return nil, err
	}
	cur, _ := payGet(charge, "currency")
	if payIsU(cur) { // only an ABSENT currency defaults to the mandate's: null is carried as is and fails the currency predicate
		if cur, err = payMust(mandate, "terms", "currency"); err != nil {
			return nil, err
		}
	}
	p := map[string]any{}
	paySet(p, "amount", amount)
	paySet(p, "currency", cur)
	cat, _ := payGet(charge, "category")
	paySet(p, "category", cat)
	return p, nil
}

// ChargeParams: the charge params committed in both the plan node and the PCActn action.
func ChargeParams(mandate, charge any) (map[string]any, error) {
	return payChargeParams(mandate, charge)
}

// ChargeActionContext: the action a charge denotes (the verb / resource / params the predicates and risk read).
func ChargeActionContext(mandate, charge any) (map[string]any, error) {
	merchant, err := payGet(charge, "merchant")
	if err != nil {
		return nil, err
	}
	params, err := payChargeParams(mandate, charge)
	if err != nil {
		return nil, err
	}
	return map[string]any{"action": map[string]any{"verb": ChargeVerb, "resource": "merchant:" + payToStr(merchant), "params": params,
		"reversibility_class": ChargeReversibilityClass}}, nil
}

// payBind binds a mandate to the grant the caller VERIFIED: the mandate's grant must be that grant and the terms / policy must be
// exactly the ones signed into its envelope. The budget is clamped to the signed bMax.
func payBind(mandate, verifiedGrant any) (map[string]any, error) {
	switch verifiedGrant.(type) {
	case map[string]any, []any:
	default:
		return nil, mandateGrantError("verified_grant_required", "a verified (or stored) grant is required; the mandate's own grant is never the authority")
	}
	switch mandate.(type) {
	case map[string]any, []any:
	default:
		return nil, mandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant")
	}
	mg, _ := payGet(mandate, "grant")
	h1, err := payHash(mg)
	if err != nil {
		return nil, err
	}
	h2, err := payHash(verifiedGrant)
	if err != nil {
		return nil, err
	}
	if h1 != h2 {
		return nil, mandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant")
	}
	env := ReadEnvelope(verifiedGrant)
	terms, _ := payGet(mandate, "terms")
	policy, _ := payGet(mandate, "policy")
	mismatch := mandateGrantError("mandate_terms_mismatch", "the mandate terms / policy are not the ones signed into the verified grant")
	if env == nil || !payTruthy(terms) || !payTruthy(policy) {
		return nil, mismatch
	}
	same := func(a any, b any) (bool, error) {
		x, err := payHash(a)
		if err != nil {
			return false, err
		}
		y, err := payHash(b)
		return err == nil && x == y, err
	}
	preds, err := MandatePredicates(terms)
	if err != nil {
		return nil, err
	}
	if ok, err := same(env["predicates"], preds); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, mismatch
	}
	cvs, err := MandateCaveats(terms)
	if err != nil {
		return nil, err
	}
	if ok, err := same(env["caveats"], cvs); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, mismatch
	}
	if ok, err := same(env["risk_policy"], policy); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, mismatch
	}
	bMax := jsF(env["risk_policy"].(map[string]any)["bMax"])
	budget := payOpt(mandate, "budget")
	b := payOpt(budget, "B")
	B := 0.0
	if payFinite(b) {
		B = payMax(0, payMin(jsF(b), bMax))
	}
	out := paySpreadObj(mandate)
	out["grant"] = verifiedGrant
	nb := paySpreadObj(budget)
	nb["B"] = payNum(B)
	out["budget"] = nb
	return out, nil
}

// ChargeDecideInput assembles the decide input for a charge: risk collapses to the normalised amount (spend = risk). A mandate
// whose grant, terms or policy differ from verifiedGrant is refused (a *CodedError with a MandateGrantError code).
func ChargeDecideInput(mandate0, charge, now, verifiedGrant any) (map[string]any, error) {
	mandate, err := payBind(mandate0, verifiedGrant)
	if err != nil {
		return nil, err
	}
	xv, err := payMust(mandate, "terms", "perTransactionCap")
	if err != nil {
		return nil, err
	}
	av, err := payGet(charge, "amount")
	if err != nil {
		return nil, err
	}
	amount := math.Inf(1)
	if payFinite(av) {
		amount = jsF(av)
	}
	x := payToNumber(xv)
	blast := 1.0
	if x > 0 {
		blast = amount / x
	}
	action, err := ChargeActionContext(mandate, charge)
	if err != nil {
		return nil, err
	}
	ctx := map[string]any{"reversibilityClass": ChargeReversibilityClass}
	rt, _ := payGet(charge, "recentChargeTimes")
	paySet(ctx, "recentActionTimes", rt)
	in := map[string]any{"grant": verifiedGrant, "action": action,
		"risk":   map[string]any{"semanticDistance": jsNumber(0), "reversibility": jsNumber(1), "blastRadius": payNum(blast), "taint": jsNumber(0), "confidence": jsNumber(1), "age": jsNumber(0)},
		"budget": mandate["budget"], "caveatContext": ctx}
	paySet(in, "now", now)
	return in, nil
}

// AuthorizeCharge runs a charge through the PCA decision (decide) against the grant you VERIFIED (or loaded from your own store).
// Pure: reads the mandate budget (clamped to the signed bMax) and returns the next one in budgetAfter. outcome: auto (t=1, the
// agent may charge alone), step_up (a human co-sign is needed) or deny. A fractional, negative or unsafe amount and a merchant
// that is not a plain id are refused whatever the policy says.
func AuthorizeCharge(mandate0, charge, verifiedGrant any, decide ChargeDecider) (map[string]any, error) {
	mandate, err := payBind(mandate0, verifiedGrant)
	if err != nil {
		return nil, err
	}
	nv, err := payGet(charge, "now")
	if err != nil {
		return nil, err
	}
	now := nv
	if !payFinite(nv) {
		now = jsNumber(payNowMs())
	}
	input, err := ChargeDecideInput(mandate, charge, now, verifiedGrant)
	if err != nil {
		return nil, err
	}
	if decide == nil {
		decide = NativeChargeDecider // the reference's default is its built-in policy engine
	}
	raw, err := decide(input)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("authorizeCharge: the decider returned no decision")
	}
	amount, _ := payGet(charge, "amount")
	merchant, _ := payGet(charge, "merchant")
	refusal := ""
	if !IsMinorUnits(amount) {
		refusal = AmountNotMinorUnits
	} else if !IsPlainID(merchant) {
		refusal = MerchantInvalid
	}
	decision := raw
	if refusal != "" {
		rs, ok := raw["reasons"].([]any)
		if !ok {
			return nil, errors.New("raw.reasons is not iterable")
		}
		decision = paySpreadObj(raw)
		decision["admit"], decision["releaseGuardianShare"] = false, false
		decision["reasons"] = append([]any{refusal}, rs...)
		decision["budget"] = mandate["budget"]
	}
	outcome := "step_up"
	if !payTruthy(payOpt(decision, "releaseGuardianShare")) {
		outcome = "deny"
	} else if payTruthy(payOpt(decision, "admit")) {
		outcome = "auto"
	}
	policy, _ := mandate["policy"].(map[string]any)
	terms, _ := mandate["terms"].(map[string]any)
	budget := mandate["budget"].(map[string]any)
	exact := outcome == "auto" && IsMinorUnits(amount) && payStrictEq(payOpt(policy, "kappa"), payOpt(terms, "perTransactionCap")) && jsIsSafeInteger(budget["B"])
	var cost any = jsNumber(0)
	if outcome == "auto" {
		if exact {
			cost = amount
		} else {
			cost = payNum(RiskCost(jsF(payOpt(decision, "r")), jsF(payOpt(policy, "kappa"))))
		}
	}
	t, err := payMust(decision, "requiredThreshold", "t")
	if err != nil {
		return nil, err
	}
	after := payOpt(decision, "budget")
	if exact {
		nb := paySpreadObj(after)
		nb["B"] = payNum(jsF(budget["B"]) - jsF(amount))
		after = nb
	}
	out := map[string]any{"outcome": outcome, "t": t, "r": payOpt(decision, "r"), "requiredThreshold": payOpt(decision, "requiredThreshold"), "cost": cost,
		"budgetBefore": budget, "budgetAfter": after, "reasons": payOpt(decision, "reasons"), "decision": decision}
	for k, v := range out {
		if payIsU(v) {
			delete(out, k)
		}
	}
	return out, nil
}

// SettleCharge advances the mandate's budget after a decision (functional: a new mandate).
func SettleCharge(mandate, decision any) (map[string]any, error) {
	after, err := payGet(decision, "budgetAfter")
	if err != nil {
		return nil, err
	}
	out := paySpreadObj(mandate)
	if payIsU(after) {
		delete(out, "budget")
	} else {
		out["budget"] = after
	}
	return out, nil
}

func payNz(x any) float64 {
	if payFinite(x) && jsF(x) > 0 {
		return jsF(x)
	}
	return 0
}

// ApplyHumanCosign restores autonomous budget by rho (or fully to bMax when opts.full is truthy): the only way the budget goes up.
// opts is a JSON object (a nil opts is refused, as the reference refuses null).
func ApplyHumanCosign(mandate, now, opts any) (map[string]any, error) {
	fv, err := payGet(opts, "full")
	if err != nil {
		return nil, err
	}
	policy, err := payGet(mandate, "policy")
	if err != nil {
		return nil, err
	}
	bMax, err := payGet(policy, "bMax")
	if err != nil {
		return nil, err
	}
	var B float64
	if payTruthy(fv) {
		B = payNz(bMax)
	} else {
		bud, _ := payGet(mandate, "budget")
		bb, err := payGet(bud, "B")
		if err != nil {
			return nil, err
		}
		rho, _ := payGet(policy, "rho")
		var total float64
		switch bb.(type) {
		case string, map[string]any, []any: // b.B + nz(rho) concatenates (ToPrimitive is a string); Math.min then reads it as a number
			total = jsStringToNumber(payToStr(bb) + jsValueString(jsNumber(payNz(rho))))
		default:
			total = payToNumber(bb) + payNz(rho)
		}
		B = payMin(payNz(bMax), total)
	}
	budget := map[string]any{"B": payNum(B)}
	paySet(budget, "tau", now)
	paySet(budget, "asOf", now)
	out := paySpreadObj(mandate)
	out["budget"] = budget
	return out, nil
}

// ---- the charge as a proof-carrying action ------------------------------------------------------------------------------

// ChargePlanNode: the committed plan node for a charge; params_digest pins the charge params so the leaf reconciles with the PCActn.
func ChargePlanNode(mandate, charge any, id string) (map[string]any, error) {
	merchant, err := payGet(charge, "merchant")
	if err != nil {
		return nil, err
	}
	params, err := payChargeParams(mandate, charge)
	if err != nil {
		return nil, err
	}
	d, err := ParamsDigest(params)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "verb": ChargeVerb, "resource": "merchant:" + payToStr(merchant), "reversibility_class": ChargeReversibilityClass, "params_digest": d}, nil
}

// ChargeToPCActn builds the signed PCActn for a charge: {pcactn, node}. opts: signerSecret (the leaf holder's 32-byte Ed25519 seed,
// []byte), aud, counter, optional chain (default [mandate.grant]), nodeId (default charge:<merchant>:<counter>) and now (iat, ms).
func ChargeToPCActn(mandate, charge any, opts map[string]any) (map[string]any, error) {
	amount, err := payGet(charge, "amount")
	if err != nil {
		return nil, err
	}
	if !IsMinorUnits(amount) {
		return nil, errors.New("chargeToPCActn: amount must be a non-negative integer in minor units")
	}
	merchant, _ := payGet(charge, "merchant")
	nodeID, has := opts["nodeId"]
	if !has || nodeID == nil {
		nodeID = "charge:" + payToStr(merchant) + ":" + jsMemberString(opts, "counter")
	}
	nid, ok := nodeID.(string)
	if !ok {
		return nil, errors.New("chargeToPCActn: nodeId must be a string")
	}
	node, err := ChargePlanNode(mandate, charge, nid)
	if err != nil {
		return nil, err
	}
	xv, err := payMust(mandate, "terms", "perTransactionCap")
	if err != nil {
		return nil, err
	}
	x := payToNumber(xv)
	r := 1.0
	if x > 0 {
		r = jsF(amount) / x
	}
	r = riskClamp01(r)
	params, err := payChargeParams(mandate, charge)
	if err != nil {
		return nil, err
	}
	var chain []map[string]any
	if cv, has := opts["chain"]; has && cv != nil {
		cl, ok := cv.([]any)
		if !ok || len(cl) == 0 {
			return nil, errors.New("chargeToPCActn: chain must be a non-empty capability list")
		}
		for _, c := range cl {
			cm, ok := c.(map[string]any)
			if !ok {
				return nil, errors.New("chargeToPCActn: chain must hold capabilities")
			}
			chain = append(chain, cm)
		}
	} else {
		g, _ := payGet(mandate, "grant")
		gm, ok := g.(map[string]any)
		if !ok {
			return nil, errors.New("chargeToPCActn: the mandate carries no grant")
		}
		chain = []map[string]any{gm}
	}
	seed, ok := opts["signerSecret"].([]byte)
	if !ok {
		return nil, errors.New("chargeToPCActn: signerSecret must be a 32-byte Ed25519 seed")
	}
	signer, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	aud, _ := opts["aud"].(string)
	counter, ok := jsNum(opts["counter"])
	if !ok || counter != math.Trunc(counter) {
		return nil, errors.New("chargeToPCActn: counter must be an integer")
	}
	var iat int64
	if nw, has := opts["now"]; has && nw != nil {
		f, ok := jsNum(nw)
		if !ok || f != math.Trunc(f) {
			return nil, errors.New("chargeToPCActn: now must be an epoch-ms integer")
		}
		iat = int64(f)
	}
	inputs := paySpreadObj(params)
	inputs["blastRadius"] = payNum(r)
	pcactn, err := BuildPCActn(PCActnInput{Grant: chain[0], Chain: chain, Plan: []map[string]any{node}, NodeID: nid, Params: params, Counter: int64(counter),
		Signer: signer, Aud: aud, Iat: iat, Extra: map[string]any{"risk_claim": map[string]any{"r": payNum(r), "inputs": inputs}}})
	if err != nil {
		return nil, err
	}
	return map[string]any{"pcactn": pcactn, "node": node}, nil
}

// ---- Shared Payment Token limits, spend rails ---------------------------------------------------------------------------

// SharedPaymentTokenLimits: the usage_limits of a Stripe Shared Payment Token that fits what the mandate lets an agent spend
// WITHOUT a co-sign (at most the auto-approve threshold and the remaining autonomous budget, lowercase currency, expiring with the
// mandate period). Refused when no autonomous capacity is left or the period has ended at now.
func SharedPaymentTokenLimits(mandate, now any) (map[string]any, error) {
	if !payFinite(now) {
		return nil, errors.New("sharedPaymentTokenLimits: now must be an epoch-ms time")
	}
	t, err := payGet(mandate, "terms")
	if err != nil {
		return nil, err
	}
	bv, err := payMust(mandate, "budget", "B")
	if err != nil {
		return nil, err
	}
	budget := math.Floor(payToNumber(bv))
	aat, err := payGet(t, "autoApproveThreshold")
	if err != nil {
		return nil, err
	}
	mx := payMin(payToNumber(aat), budget)
	if !jsIsSafeInteger(payNum(mx)) || mx <= 0 {
		return nil, errors.New("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed")
	}
	pe, _ := payGet(t, "periodEnd")
	if !payIsU(pe) {
		if f, ok := jsNum(pe); !ok || !finite(f) { // an infinite end would serialize as a null expiry
			return nil, errors.New("sharedPaymentTokenLimits: periodEnd must be an epoch-ms time")
		}
	}
	if !payIsU(pe) && !(finite(jsF(now)) && jsF(now) < payToNumber(pe)) {
		return nil, errors.New("sharedPaymentTokenLimits: the mandate period has ended")
	}
	cur, _ := payGet(t, "currency")
	cs, ok := cur.(string)
	if !ok {
		return nil, errors.New("t.currency.toLowerCase is not a function")
	}
	out := map[string]any{"currency": strings.ToLower(cs), "max_amount": payNum(mx)}
	if !payIsU(pe) {
		out["expires_at"] = payNum(math.Floor(payToNumber(pe) / 1000))
	}
	return out, nil
}

var mccTraitRe = regexp.MustCompile(`^mcc\.c([0-9]{4})$`)

// CategoriesFromTraits: an action-kit trait mcc.c5734 says the verb may spend in MCC 5734 (traits only narrow). Sorted, unique.
func CategoriesFromTraits(traits []any) []any {
	set := map[string]bool{}
	for _, t := range traits {
		if m := mccTraitRe.FindStringSubmatch(payToStr(t)); m != nil {
			set[m[1]] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out) // four ASCII digits: byte order is code-unit order
	res := make([]any, len(out))
	for i, s := range out {
		res[i] = s
	}
	return res
}

// paySortJS is Array.prototype.sort() with no comparator: by String(x) in UTF-16 code-unit order, undefined last.
func paySortJS(xs []any) {
	sort.SliceStable(xs, func(i, j int) bool {
		return compareUnits(utf16Units(payToStr(xs[i])), utf16Units(payToStr(xs[j]))) < 0
	})
}

func payIncludes(xs []any, v any) bool {
	for _, x := range xs {
		if payStrictEq(x, v) {
			return true
		}
	}
	return false
}

// RailLimits: the limits an instrument (virtual card) for this mandate may carry. Amounts come from SharedPaymentTokenLimits;
// categories are the mandate's allowlist narrowed by the action's confirmed mcc.* traits (an empty intersection is refused, and no
// category control at all is refused unless opts.allowAnyCategory is true). opts is a JSON object (nil is refused).
func RailLimits(mandate, now, opts any) (map[string]any, error) {
	spt, err := SharedPaymentTokenLimits(mandate, now)
	if err != nil {
		return nil, err
	}
	bv, _ := payMust(mandate, "budget", "B")
	total := payNum(math.Floor(payToNumber(bv)))
	t, _ := payGet(mandate, "terms")
	cv, err := payGet(t, "categories")
	if err != nil {
		return nil, err
	}
	fromMandate, err := paySpreadList(cv)
	if err != nil {
		return nil, err
	}
	tv, err := payGet(opts, "actionTraits")
	if err != nil {
		return nil, err
	}
	var traits []any
	if !payNullish(tv) {
		if traits, err = paySpreadList(tv); err != nil {
			return nil, err
		}
	}
	fromTraits := CategoriesFromTraits(traits)
	var cats []any
	if len(fromMandate) > 0 && len(fromTraits) > 0 {
		cats = []any{}
		for _, c := range fromMandate {
			if payIncludes(fromTraits, c) {
				cats = append(cats, c)
			}
		}
		paySortJS(cats)
		if len(cats) == 0 {
			return nil, errors.New("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent")
		}
	} else {
		cats = fromMandate
		if len(cats) == 0 {
			cats = fromTraits
		}
		paySortJS(cats)
	}
	if aac, _ := payGet(opts, "allowAnyCategory"); len(cats) == 0 && aac != true {
		return nil, errors.New("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category")
	}
	cur, _ := payGet(t, "currency")
	ms, _ := payGet(t, "merchants")
	merchants, err := paySpreadList(ms)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"currency": strings.ToUpper(cur.(string)), "perAuthorizationMax": spt["max_amount"], "totalMax": total, "categories": cats, "merchants": merchants}
	if e, has := spt["expires_at"]; has {
		out["expiresAt"] = payNum(jsF(e) * 1000)
	}
	return out, nil
}

// ReconcileSettlement compares what settled with what PCA approved: {ok: true} only on an exact fit; anything else (excess, other
// merchant or currency, a second capture) is {ok: false, reasons, action: "freeze_grant"}, a tighten-only event.
func ReconcileSettlement(approved, s any) (map[string]any, error) {
	g := func(o any, k string) (any, error) { return payGet(o, k) }
	reasons := []any{}
	sid, err := g(s, "authorizationId")
	if err != nil {
		return nil, err
	}
	aid, err := g(approved, "id")
	if err != nil {
		return nil, err
	}
	if !payStrictEq(sid, aid) {
		reasons = append(reasons, "authorization_id_mismatch")
	}
	sa, _ := g(s, "amount")
	aa, _ := g(approved, "amount")
	if payGT(sa, aa) {
		reasons = append(reasons, "settled_more_than_approved")
	}
	sc, _ := g(s, "currency")
	ac, _ := g(approved, "currency")
	scs, ok1 := sc.(string)
	acs, ok2 := ac.(string)
	if !ok1 || !ok2 {
		return nil, errors.New("currency.toUpperCase is not a function")
	}
	if strings.ToUpper(scs) != strings.ToUpper(acs) {
		reasons = append(reasons, "currency_mismatch")
	}
	sm, _ := g(s, "merchantId")
	am, _ := g(approved, "merchantId")
	if !payStrictEq(sm, am) {
		reasons = append(reasons, "merchant_mismatch")
	}
	if c, _ := g(s, "captures"); payGT(c, jsNumber(1)) {
		reasons = append(reasons, "second_capture")
	}
	if len(reasons) == 0 {
		return map[string]any{"ok": true}, nil
	}
	return map[string]any{"ok": false, "reasons": reasons, "action": "freeze_grant"}, nil
}
