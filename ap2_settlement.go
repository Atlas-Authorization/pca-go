package pca

// Settlement backends: the rails PCA's governance feeds. STRUCTURAL ONLY, no network. A backend turns a payment mandate that has
// ALREADY been verified into the rail's wire shape. Amounts are the mandate's integer minor units; nothing here accepts a decimal.

import (
	"encoding/base64"
	"math"
	"math/big"
	"strings"
)

// Ap2ToAtomicUnits converts integer minor units to an integer string of atomic units. It scales by 10^(decimals - exponent) with
// big integers, so no float is involved; when the asset has fewer decimals than the currency the division must be exact, else the
// amount is refused. amount is {amount, currency}.
func Ap2ToAtomicUnits(amount any, decimals any) (string, error) {
	df, isNum := jsNum(decimals)
	if !isNum || df != math.Trunc(df) || math.IsInf(df, 0) || df < 0 || df > 18 {
		return "", ap2Fail("x402: decimals must be an integer in 0..18, got %s", ap2Str(decimals))
	}
	amt := ap2Get(amount, "amount")
	af, _ := jsNum(amt)
	if !jsIsSafeInteger(amt) || af < 0 || ap2IsNegZero(af) {
		return "", ap2Fail("x402: amount %s cannot be expressed in atomic units with %s decimals", ap2Str(amt), jsNumberString(df))
	}
	exp, err := Ap2CurrencyExponent(ap2Get(amount, "currency"))
	if err != nil {
		return "", err
	}
	dec := int(df)
	minor := new(big.Int).SetInt64(int64(af))
	ten := big.NewInt(10)
	if dec >= exp {
		return new(big.Int).Mul(minor, new(big.Int).Exp(ten, big.NewInt(int64(dec-exp)), nil)).String(), nil
	}
	div := new(big.Int).Exp(ten, big.NewInt(int64(exp-dec)), nil)
	q, r := new(big.Int).QuoRem(minor, div, new(big.Int))
	if r.Sign() != 0 {
		return "", ap2Fail("x402: amount %s cannot be expressed in atomic units with %s decimals", ap2Str(amt), jsNumberString(df))
	}
	return q.String(), nil
}

// ap2Or is `ctx?.k ?? def`.
func ap2Or(ctx map[string]any, k string, def any) any {
	if v, ok := ctx[k]; ok && v != nil {
		return v
	}
	return def
}

// Ap2X402Settlement builds the Coinbase x402 adapter's payload: the HTTP 402 Payment Required challenge (accepts) plus the X-PAYMENT
// request header (standard base64 of the JSON payment payload). The payload is a placeholder envelope, not a signed authorization.
// ctx (nil = none) may carry network, decimals (default 6), resourceUrl, payTo, asset and maxTimeoutSeconds (default 60).
func Ap2X402Settlement(payment map[string]any, ctx map[string]any) (map[string]any, error) {
	pa := ap2Get(payment, "payment_amount")
	network := ap2Or(ctx, "network", "base-sepolia")
	maxAmt, err := Ap2ToAtomicUnits(pa, ap2Or(ctx, "decimals", ap2Num(6)))
	if err != nil {
		return nil, err
	}
	merchant := ap2Get(ap2Get(payment, "payee"), "id")
	requirement := ap2New().
		set("scheme", "exact").
		set("network", network).
		set("maxAmountRequired", maxAmt).
		set("resource", ap2Or(ctx, "resourceUrl", "")).
		set("description", "AP2 payment mandate "+ap2Str(ap2Get(payment, "transaction_id"))).
		set("payTo", ap2Or(ctx, "payTo", merchant)).
		set("asset", ap2Or(ctx, "asset", ap2Get(pa, "currency"))).
		set("mimeType", "application/json").
		set("maxTimeoutSeconds", ap2Or(ctx, "maxTimeoutSeconds", ap2Num(60))).
		done()
	body, err := ap2Stringify(ap2Map("x402Version", ap2Num(1), "scheme", "exact", "network", network,
		"payload", ap2Map("transactionId", ap2Get(payment, "transaction_id"), "amount", ap2Get(pa, "amount"), "currency", ap2Get(pa, "currency"))))
	if err != nil {
		return nil, err
	}
	xPayment := base64.StdEncoding.EncodeToString([]byte(ap2WellFormed(body)))
	return ap2Map("rail", "x402", "amount", pa, "merchant", merchant,
		"payload", ap2Map("httpStatus", ap2Num(402), "x402Version", ap2Num(1), "error", "X-PAYMENT header is required",
			"accepts", []any{requirement}, "header", ap2Map("X-PAYMENT", xPayment))), nil
}

// Ap2StripeSptSettlement builds the Stripe Shared Payment Token adapter's payload: a shared token the buyer's agent grants the
// merchant to pull a bounded amount. The token is the mandate's payment instrument id, never a raw PAN. ctx (nil = none) may carry
// payTo (on_behalf_of).
func Ap2StripeSptSettlement(payment map[string]any, ctx map[string]any) (map[string]any, error) {
	inst := ap2Get(payment, "payment_instrument")
	if !ap2StrictEq(ap2Get(inst, "type"), "shared_payment_token") {
		return nil, ap2Fail("stripe-spt: the payment instrument must be of type shared_payment_token, got %s", ap2Str(ap2Get(inst, "type")))
	}
	pa := ap2Get(payment, "payment_amount")
	cur, ok := ap2Get(pa, "currency").(string)
	if !ok {
		return nil, ap2Fail("Cannot read properties of %s (reading 'toLowerCase')", ap2Str(ap2Get(pa, "currency")))
	}
	payload := ap2New().set("shared_payment_token", ap2Get(inst, "id")).set("amount", ap2Get(pa, "amount")).set("currency", strings.ToLower(cur))
	if pt := ctx["payTo"]; ap2Truthy(pt) {
		payload.set("on_behalf_of", pt)
	}
	return ap2Map("rail", "stripe-spt", "amount", pa, "merchant", ap2Get(ap2Get(payment, "payee"), "id"), "payload", payload.done()), nil
}
