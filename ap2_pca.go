package pca

// Binding AP2 mandates to a PCA grant and to the PCA proof of each action. AP2 decides what a mandate may say; PCA decides whether the
// agent may act. The two are tied together by a namespaced x_pca claim INSIDE the mandate object (so it is covered by the issuer's /
// agent's signature and by the next hop's sd_hash):
//
//	open mandate   x_pca = { v, grant, terms }    the PCA grant (principal-signed, Ed25519) and the terms it was minted from
//	closed payment x_pca = { v, charge, pcactn }  the PCActn (agent-signed, Ed25519) that authorises exactly this charge
//
// The PCActn's signed nonce commits to the AP2 side: the transaction id, payee, amount, instrument, the open mandate's sd_hash and
// the thumbprint of the agent's AP2 key.

import (
	"math"
)

// ap2MinorTerm is a PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused.
func ap2MinorTerm(v any, name string) (float64, error) {
	f, ok := jsNum(v)
	if !ok || !jsIsSafeInteger(v) || f < 0 || ap2IsNegZero(f) {
		return 0, ap2Fail("PCA term %s must be a non-negative integer in minor units, got %s", name, ap2Str(v))
	}
	return f, nil
}

// ap2ToJSON is JSON.parse(JSON.stringify(v)): a deep copy as the wire carries it.
func ap2ToJSON(v any) (any, error) {
	if ap2IsU(v) {
		return nil, ap2Fail("\"undefined\" is not valid JSON")
	}
	s, err := ap2Stringify(v)
	if err != nil {
		return nil, err
	}
	x, _, _, err := ap2ParseText(s)
	return x, err
}

// Ap2PcaOpenClaim is the x_pca claim of an open mandate: the principal-signed grant and the terms it was minted from. mandate is the
// PCA payment mandate ({grant, terms, ...}).
func Ap2PcaOpenClaim(mandate any) (map[string]any, error) {
	grant, err := ap2ToJSON(ap2Get(mandate, "grant"))
	if err != nil {
		return nil, err
	}
	terms, err := ap2ToJSON(ap2Get(mandate, "terms"))
	if err != nil {
		return nil, err
	}
	return ap2Map("v", ap2Num(Ap2PcaBindingVersion), "grant", grant, "terms", terms), nil
}

// Ap2BudgetMax is the value of AP2 payment.budget.max for a PCA cap in integer minor units. The official AP2 SDK reads it as
// int(max * 100) whatever the currency, while the schema calls it an amount, so two readers exist: the SDK (hundredths) and a
// major-unit reader (max * 10^exponent). The value emitted never lets EITHER read more than the cap: exponent 0..2 is cap / 100,
// exponent 3 or more is cap / 10^exponent. The double is nudged up by at most a few ulps when cap / divisor falls just under the exact
// decimal, so that the SDK's int(max * 100) is exact (0.29 * 100 is 28.999999999999996 in floating point).
func Ap2BudgetMax(capMinor any, currency any) (float64, error) {
	cp, err := ap2MinorTerm(capMinor, "cumulativeCap")
	if err != nil {
		return 0, err
	}
	e, err := Ap2CurrencyExponent(currency)
	if err != nil {
		return 0, err
	}
	sdkTarget := cp
	if e > 2 {
		sdkTarget = math.Floor(cp / ap2Pow10[e-2])
	}
	d := cp / ap2Pow10[max(e, 2)]
	for i := 0; i < 8 && d > 0 && math.Trunc(float64(d*100)) < sdkTarget; i++ {
		d = math.Nextafter(d, math.Inf(1))
	}
	if math.Trunc(float64(d*100)) != sdkTarget || ap2Round(float64(d*ap2Pow10[e])) > cp {
		return 0, ap2Fail("cumulativeCap %s %s has no exact AP2 budget.max representation", jsNumberString(cp), ap2Str(currency))
	}
	return d, nil
}

// Ap2BudgetReads is what the two readers of an AP2 budget.max read, in minor units of currency: the SDK (int(max * 100)) and a
// major-unit reader.
func Ap2BudgetReads(maxV any, currency any) (sdk, major float64, err error) {
	e, err := Ap2CurrencyExponent(currency)
	if err != nil {
		return 0, 0, err
	}
	f, ok := jsNum(maxV)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, 0, ap2Fail("budget.max must be a finite non-negative number, got %s", ap2Str(maxV))
	}
	return math.Trunc(float64(f * 100)), ap2Round(float64(f * ap2Pow10[e])), nil
}

// Ap2RiskRatio is amount / cap, clamped to [0, 1] and rounded UP to 12 decimals. PCA's canonical encoding refuses numbers with more
// than 15 significant digits (so 100/300 cannot be signed as-is); rounding up can only raise the risk the threshold policy sees.
func Ap2RiskRatio(amount, cap float64) float64 {
	r := 1.0
	if cap > 0 {
		r = amount / cap
	}
	return math.Min(1, math.Max(0, math.Ceil(float64(r*1e12)-1e-6)/1e12))
}

// Ap2PcaBindingNonce is the value the PCActn's signed nonce must equal for these AP2 facts (transactionId, payeeId, amount, currency,
// instrumentId, openHash, agentJkt).
func Ap2PcaBindingNonce(facts map[string]any) (string, error) {
	h, err := HashCanonical(ap2New().set("v", ap2Num(Ap2PcaBindingVersion)).spread(facts).done())
	if err != nil {
		return "", err
	}
	return "ap2:" + h, nil
}

func ap2MerchantsFor(terms any, merchants any) ([]any, error) {
	ids, ok := ap2Get(terms, "merchants").([]any)
	if !ok {
		return nil, ap2Fail("Cannot read properties of %s (reading 'map')", ap2Str(ap2Get(terms, "merchants")))
	}
	list, _ := merchants.([]any)
	out := make([]any, len(ids))
	for i, id := range ids {
		var found any
		for _, m := range list {
			if ap2StrictEq(ap2Get(m, "id"), id) {
				found = m
				break
			}
		}
		if found == nil {
			return nil, ap2Fail("no merchant descriptor supplied for PCA merchant %s", ap2Str(id))
		}
		out[i] = found
	}
	return out, nil
}

// Ap2PaymentConstraintsFromTerms is the AP2 open payment constraints a set of PCA terms denotes. PCA terms are INTEGER MINOR UNITS of
// the mandate currency; budget.max is derived exactly by Ap2BudgetMax; no currency is refused for its exponent.
func Ap2PaymentConstraintsFromTerms(terms any, merchants any, checkoutReference string) ([]any, error) {
	cur := ap2Get(terms, "currency")
	perTx, err := ap2MinorTerm(ap2Get(terms, "perTransactionCap"), "perTransactionCap")
	if err != nil {
		return nil, err
	}
	budgetMax, err := Ap2BudgetMax(ap2Get(terms, "cumulativeCap"), cur)
	if err != nil {
		return nil, err
	}
	allowed, err := ap2MerchantsFor(terms, merchants)
	if err != nil {
		return nil, err
	}
	rec := ap2New().set("type", "payment.agent_recurrence").set("frequency", "ON_DEMAND")
	if mt := ap2Get(terms, "maxTransactionsPerPeriod"); !ap2IsU(mt) {
		rec.set("max_occurrences", mt)
	}
	return []any{
		ap2Map("type", "payment.amount_range", "currency", cur, "min", ap2Num(0), "max", ap2Num(perTx)),
		ap2Map("type", "payment.allowed_payees", "allowed", allowed),
		ap2Map("type", "payment.reference", "conditional_transaction_id", checkoutReference),
		ap2Map("type", "payment.budget", "currency", cur, "max", ap2Num(budgetMax)),
		rec.done(),
	}, nil
}

// Ap2FromTermsOptions are the issuance parameters of an open mandate minted from PCA terms.
type Ap2FromTermsOptions struct {
	Issuer   Ap2Issuer
	AgentJwk any
	// Merchants are the descriptors for every merchant id in the PCA terms (AP2 needs a name; PCA only holds the id).
	Merchants []any
	// Iat is epoch seconds; Exp the expiry (epoch seconds, must not exceed the PCA period end; nil = the period end, required then).
	Iat  float64
	Exp  *float64
	Salt func() string
}

func ap2OpenExpiry(terms any, o Ap2FromTermsOptions) (float64, error) {
	pe := ap2Get(terms, "periodEnd")
	hasPE := !ap2IsU(pe)
	periodEnd := math.NaN()
	if hasPE {
		periodEnd = math.Floor(ap2N(pe) / 1000)
	}
	var exp float64
	switch {
	case o.Exp != nil:
		exp = *o.Exp
	case hasPE:
		exp = periodEnd
	default:
		return 0, ap2Fail("exp is required when the PCA terms have no period end")
	}
	if hasPE && !(finite(exp) && exp <= periodEnd) {
		return 0, ap2Fail("exp must not exceed the PCA period end")
	}
	return exp, nil
}

func (o Ap2FromTermsOptions) common(exp float64, pca any) Ap2OpenMandateCommon {
	return Ap2OpenMandateCommon{Issuer: o.Issuer, AgentJwk: o.AgentJwk, Iat: o.Iat, Exp: exp, Pca: pca, Salt: o.Salt}
}

// Ap2OpenPaymentMandateFromPca issues the open payment mandate for a PCA mandate (grant + terms), chained to checkoutReference.
func Ap2OpenPaymentMandateFromPca(mandate any, o Ap2FromTermsOptions, checkoutReference string) (string, error) {
	terms := ap2Get(mandate, "terms")
	exp, err := ap2OpenExpiry(terms, o)
	if err != nil {
		return "", err
	}
	pca, err := Ap2PcaOpenClaim(mandate)
	if err != nil {
		return "", err
	}
	constraints, err := Ap2PaymentConstraintsFromTerms(terms, o.Merchants, checkoutReference)
	if err != nil {
		return "", err
	}
	return Ap2IssueOpenPaymentMandate(Ap2OpenPaymentMandateInput{Ap2OpenMandateCommon: o.common(exp, pca), Constraints: constraints})
}

// Ap2OpenCheckoutMandateFromPca issues the open checkout mandate for a PCA mandate: the acceptable line items and the merchant
// allowlist.
func Ap2OpenCheckoutMandateFromPca(mandate any, o Ap2FromTermsOptions, lineItems any) (string, error) {
	terms := ap2Get(mandate, "terms")
	exp, err := ap2OpenExpiry(terms, o)
	if err != nil {
		return "", err
	}
	pca, err := Ap2PcaOpenClaim(mandate)
	if err != nil {
		return "", err
	}
	allowed, err := ap2MerchantsFor(terms, o.Merchants)
	if err != nil {
		return "", err
	}
	constraints := []any{ap2Map("type", "checkout.line_items", "items", lineItems), ap2Map("type", "checkout.allowed_merchants", "allowed", allowed)}
	return Ap2IssueOpenCheckoutMandate(Ap2OpenCheckoutMandateInput{Ap2OpenMandateCommon: o.common(exp, pca), Constraints: constraints})
}

// Ap2PcaPaymentBindingInput is everything Ap2BuildPcaPaymentBinding needs.
type Ap2PcaPaymentBindingInput struct {
	// Mandate is the PCA mandate (grant + terms + budget) the agent holds.
	Mandate map[string]any
	// Open is the open payment mandate token the closed mandate will be chained to.
	Open     string
	AgentJwk any
	// AgentSecret is the agent's Ed25519 seed (the PCA grant's holder); it signs the PCActn.
	AgentSecret []byte
	// Audience is the PCA audience (the resource server / Atlas instance id this action is for).
	Audience      string
	Counter       int64
	TransactionID string
	Payee         map[string]any
	// Amount is {amount (integer minor units), currency}.
	Amount       map[string]any
	InstrumentID string
	// Category is the optional charge category; Now the PCActn iat in epoch ms (nil = the clock).
	Category *string
	Now      *float64
	// Cosign, for a charge that needs a human co-sign (PCA step-up), returns the threshold shares over the built PCActn.
	Cosign func(pcactn map[string]any) any
}

// Ap2BuildPcaPaymentBinding builds the x_pca claim of a closed payment mandate: a PCActn authorising exactly this charge.
func Ap2BuildPcaPaymentBinding(i Ap2PcaPaymentBindingInput) (map[string]any, error) {
	major, err := ap2MinorTerm(ap2Get(i.Amount, "amount"), "amount") // the charge amount is integer minor units, as in the mandate
	if err != nil {
		return nil, err
	}
	payeeID, ok := ap2Get(i.Payee, "id").(string)
	if !ok {
		return nil, ap2Fail("payee.id is required")
	}
	cur := ap2Get(i.Amount, "currency")
	charge := ap2New().set("merchant", payeeID).set("amount", ap2Num(major)).set("currency", cur)
	claimCharge := ap2New().set("amount", ap2Num(major)).set("currency", cur)
	if i.Category != nil {
		charge.set("category", *i.Category)
		claimCharge.set("category", *i.Category)
	}
	chargeMap := charge.done()
	hop, err := Ap2ParseSdJwtHop(i.Open)
	if err != nil {
		return nil, err
	}
	openHash, err := Ap2SdHashOf(hop, "")
	if err != nil {
		return nil, err
	}
	jkt, err := Ap2JwkThumbprint(i.AgentJwk)
	if err != nil {
		return nil, err
	}
	facts := ap2Map("transactionId", i.TransactionID, "payeeId", payeeID, "amount", ap2Num(major), "currency", cur, "instrumentId", i.InstrumentID,
		"openHash", openHash, "agentJkt", jkt)
	terms := ap2Get(i.Mandate, "terms")
	risk := Ap2RiskRatio(major, ap2N(ap2Get(terms, "perTransactionCap")))
	nodeID := "ap2:" + i.TransactionID
	node, err := ChargePlanNode(i.Mandate, chargeMap, nodeID)
	if err != nil {
		return nil, err
	}
	params, err := ChargeParams(i.Mandate, chargeMap)
	if err != nil {
		return nil, err
	}
	nonce, err := Ap2PcaBindingNonce(facts)
	if err != nil {
		return nil, err
	}
	signer, err := KeyPairFromSeed(i.AgentSecret)
	if err != nil {
		return nil, err
	}
	grant, ok := i.Mandate["grant"].(map[string]any)
	if !ok {
		return nil, ap2Fail("the mandate carries no grant")
	}
	inputs := map[string]any{}
	for k, v := range params {
		inputs[k] = v
	}
	inputs["blastRadius"] = ap2Num(risk)
	var iat int64
	if i.Now != nil {
		iat = int64(*i.Now)
	}
	built, err := BuildPCActn(PCActnInput{Grant: grant, Chain: []map[string]any{grant}, Plan: []map[string]any{node}, NodeID: nodeID, Params: params,
		Counter: i.Counter, Signer: signer, Aud: i.Audience, Iat: iat,
		Extra: map[string]any{"nonce": nonce, "risk_claim": map[string]any{"r": ap2Num(risk), "inputs": inputs}}})
	if err != nil {
		return nil, err
	}
	pcactn := built
	if i.Cosign != nil {
		pcactn = map[string]any{}
		for k, v := range built {
			pcactn[k] = v
		}
		pcactn["threshold"] = i.Cosign(built)
	}
	wire, err := ap2ToJSON(pcactn)
	if err != nil {
		return nil, err
	}
	return ap2Map("v", ap2Num(Ap2PcaBindingVersion), "charge", claimCharge.done(), "pcactn", wire), nil
}
