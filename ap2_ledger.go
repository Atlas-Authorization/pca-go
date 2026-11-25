package pca

// Durable, serialised purchase state for open mandates, and single-use redemption of a verified purchase.

// Ap2PurchaseLedger keeps the purchase state under open mandates. Reserve is ONE atomic step: it refuses a transaction id that was
// already reserved under this open mandate (replayed = true), otherwise records it with its amount and returns the usage of every
// EARLIER reservation (so two concurrent purchases see each other and cannot share one budget). Back it with a unique key on
// (openMandateHash, transactionId) and a serialised sum (a row lock or one conditional write). Release undoes a reservation whose
// purchase then failed verification.
type Ap2PurchaseLedger interface {
	Reserve(openMandateHash, transactionID string, amountMinor float64) (ctx map[string]any, replayed bool, err error)
	Release(openMandateHash, transactionID string) error
}

// Ap2RedeemPurchase is Ap2VerifyPurchase plus single use and server-owned cumulative state. The usage context comes from ledger,
// never from the caller (o.Context is ignored), and the purchase's transaction id can be redeemed once. A missing or failing ledger
// denies: Reason is "ledger_required", "ledger_unavailable" or "replayed".
func Ap2RedeemPurchase(checkoutToken, paymentToken string, o Ap2PurchaseOptions, ledger Ap2PurchaseLedger) Ap2PurchaseResult {
	if ledger == nil {
		return Ap2PurchaseResult{Reason: "ledger_required"}
	}
	// A zero context is the most permissive one for budget and recurrence, so a failure here is final.
	o.Context = ap2Map("totalAmount", ap2Num(0), "totalUses", ap2Num(0))
	first := Ap2VerifyPurchase(checkoutToken, paymentToken, o)
	if !first.OK {
		return first
	}
	openHash := first.Payment.OpenHash
	txID, _ := first.Payment.Closed["transaction_id"].(string)
	amount := ap2N(ap2Get(ap2Get(first.Payment.Closed, "payment_amount"), "amount"))
	ctx, replayed, err := ledger.Reserve(openHash, txID, amount)
	if err != nil {
		return Ap2PurchaseResult{Reason: "ledger_unavailable"}
	}
	if replayed {
		return Ap2PurchaseResult{Reason: "replayed"}
	}
	o.Context = ctx
	final := Ap2VerifyPurchase(checkoutToken, paymentToken, o)
	if !final.OK {
		_ = ledger.Release(openHash, txID) // the reservation stays on failure: a failed release only ever over-counts spend
	}
	return final
}
