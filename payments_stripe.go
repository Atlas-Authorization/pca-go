package pca

// The durable charge budget (atomic compare-and-set), the real-time rail authorizer and the Stripe Issuing adapter (the reference
// @atlasauth/pca-payments rails + rails-stripe). Stripe: the issuing_authorization.request webhook is answered 200 {approved} with
// header Stripe-Version within 2 s; Stripe-Signature is t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">, default tolerance 5 min.
// REQUIRED OPERATOR SETTING: set the Issuing authorization timeout response to DECLINE and turn Autopilot off; the card limits are
// a second line, not a substitute.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// ---- durable budget -----------------------------------------------------------------------------------------------------

// ChargeBudgetRecord is a stored budget with its opaque CAS version.
type ChargeBudgetRecord struct {
	Budget  map[string]any
	Version int64
}

// ChargeBudgetStore is durable cumulative-budget state with an atomic compare-and-set: CompareAndSet succeeds only when the stored
// version still equals expected (nil = no record yet). Back it with one conditional write.
type ChargeBudgetStore interface {
	Get(key string) (*ChargeBudgetRecord, error)
	CompareAndSet(key string, expected *int64, budget map[string]any) (bool, error)
}

// ChargeStoreError: the store is missing or malformed, or a co-sign could not be committed.
type ChargeStoreError struct{ Msg string }

func (e *ChargeStoreError) Error() string { return e.Msg }

const payMaxCASAttempts = 8

func payValidRecord(r *ChargeBudgetRecord) bool {
	if r.Version < -maxSafeInt || r.Version > maxSafeInt || r.Budget == nil {
		return false
	}
	return payFinite(r.Budget["B"]) && payFinite(r.Budget["tau"]) && payFinite(r.Budget["asOf"])
}

func payWithBudget(mandate any, b map[string]any) map[string]any {
	m := paySpreadObj(mandate)
	m["budget"] = b
	return m
}

// AuthorizeChargeAtomic is AuthorizeCharge against the DURABLE budget in store (the mandate's own budget is only the initial
// value): an auto debit is committed with a compare-and-set before it is returned; losing the race re-reads and re-decides;
// persistent contention returns a deny. key "" = the grant hash.
func AuthorizeChargeAtomic(mandate, charge, verifiedGrant any, store ChargeBudgetStore, key string, decide ChargeDecider) (map[string]any, error) {
	if store == nil {
		return nil, &ChargeStoreError{"a ChargeBudgetStore with Get and CompareAndSet is required"}
	}
	if key == "" {
		h, err := payHash(verifiedGrant)
		if err != nil {
			return nil, err
		}
		key = h
	}
	for i := 0; i < payMaxCASAttempts; i++ {
		rec, err := store.Get(key)
		if err != nil {
			return nil, err
		}
		if rec != nil && !payValidRecord(rec) {
			return nil, &ChargeStoreError{"the store returned a malformed budget record"}
		}
		m := mandate
		var ver *int64
		if rec != nil {
			m, ver = payWithBudget(mandate, rec.Budget), &rec.Version
		}
		d, err := AuthorizeCharge(m, charge, verifiedGrant, decide)
		if err != nil || d["outcome"] != "auto" {
			return d, err
		}
		after, _ := d["budgetAfter"].(map[string]any)
		ok, err := store.CompareAndSet(key, ver, after)
		if err != nil {
			return nil, err
		}
		if ok {
			return d, nil
		}
	}
	d, err := AuthorizeCharge(mandate, charge, verifiedGrant, decide)
	if err != nil {
		return nil, err
	}
	rs, _ := d["reasons"].([]any)
	out := paySpreadObj(d)
	out["outcome"], out["t"], out["cost"], out["budgetAfter"] = "deny", jsNumber(3), jsNumber(0), d["budgetBefore"]
	out["reasons"] = append([]any{"budget_store_conflict"}, rs...)
	return out, nil
}

// ApplyHumanCosignAtomic is ApplyHumanCosign against the DURABLE budget, committed with a compare-and-set so a co-sign racing a
// charge is never lost or applied twice. Call it only after verifying the human co-sign; persistent contention is an error.
func ApplyHumanCosignAtomic(mandate, verifiedGrant any, store ChargeBudgetStore, now int64, full bool, key string) (map[string]any, error) {
	if store == nil {
		return nil, &ChargeStoreError{"a ChargeBudgetStore with Get and CompareAndSet is required"}
	}
	if key == "" {
		h, err := payHash(verifiedGrant)
		if err != nil {
			return nil, err
		}
		key = h
	}
	for i := 0; i < payMaxCASAttempts; i++ {
		rec, err := store.Get(key)
		if err != nil {
			return nil, err
		}
		if rec != nil && !payValidRecord(rec) {
			return nil, &ChargeStoreError{"the store returned a malformed budget record"}
		}
		m := mandate
		var ver *int64
		if rec != nil {
			m, ver = payWithBudget(mandate, rec.Budget), &rec.Version
		}
		bound, err := payBind(m, verifiedGrant)
		if err != nil {
			return nil, err
		}
		next, err := ApplyHumanCosign(bound, jsNumber(float64(now)), map[string]any{"full": full})
		if err != nil {
			return nil, err
		}
		b := next["budget"].(map[string]any)
		ok, err := store.CompareAndSet(key, ver, b)
		if err != nil {
			return nil, err
		}
		if ok {
			return b, nil
		}
	}
	return nil, &ChargeStoreError{"could not commit the co-sign: the budget record kept changing"}
}

// ---- the real-time authorization callback -------------------------------------------------------------------------------

// RailAuthorization is a live authorization request from a rail, normalised (amount in integer minor units of currency;
// merchantId from the rail's structured data, never a display name).
type RailAuthorization struct {
	ID, InstrumentID string
	Amount           any
	Currency         string
	MerchantID, MCC  *string
}

// InstrumentBinding: the mandate behind an instrument, the grant the caller verified, the budget key ("" = grant hash).
type InstrumentBinding struct {
	Mandate   any
	Grant     any
	BudgetKey string
}

// RailVerdict: approved only when PCA's own decision is auto.
type RailVerdict struct {
	Approved bool
	Reasons  []string
	Decision map[string]any
}

// RailAuthorizerOptions: LatencyBudget 0 = 1500 ms (Stripe waits 2000); Now nil = the wall clock (ms).
type RailAuthorizerOptions struct {
	Instruments   func(instrumentID string) (*InstrumentBinding, error)
	Store         ChargeBudgetStore
	Decide        ChargeDecider
	LatencyBudget time.Duration
	Now           func() int64
	OnStepUp      func(a RailAuthorization, d map[string]any)
}

func payDecline(reasons ...string) RailVerdict { return RailVerdict{Reasons: reasons} }

func payStrs(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, payToStr(x))
	}
	return out
}

// NewRailAuthorizer is the single code path from a rail request to a PCA decision. Total: a step-up, a deny, an unknown card, a
// timeout, an error are all declines.
func NewRailAuthorizer(o RailAuthorizerOptions) (func(a *RailAuthorization) RailVerdict, error) {
	budget := o.LatencyBudget
	if budget == 0 {
		budget = 1500 * time.Millisecond
	}
	if budget < 0 {
		return nil, errors.New("createRailAuthorizer: latencyBudgetMs must be positive")
	}
	now := o.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	decideOne := func(a *RailAuthorization) RailVerdict {
		if a == nil || a.ID == "" {
			return payDecline("malformed_authorization")
		}
		if !jsIsSafeInteger(a.Amount) || !(jsF(a.Amount) > 0) {
			return payDecline("amount_not_positive_minor_units")
		}
		if a.Currency == "" {
			return payDecline("currency_missing")
		}
		if a.MerchantID == nil || *a.MerchantID == "" {
			return payDecline("merchant_unknown")
		}
		if o.Instruments == nil {
			return payDecline("authorizer_error")
		}
		inst, err := o.Instruments(a.InstrumentID)
		if err != nil {
			return payDecline("authorizer_error")
		}
		if inst == nil {
			return payDecline("instrument_unknown")
		}
		charge := map[string]any{"merchant": *a.MerchantID, "amount": a.Amount, "currency": strings.ToUpper(a.Currency), "now": jsNumber(float64(now()))}
		if a.MCC != nil {
			charge["category"] = *a.MCC
		}
		d, err := AuthorizeChargeAtomic(inst.Mandate, charge, inst.Grant, o.Store, inst.BudgetKey, o.Decide)
		if err != nil {
			return payDecline("authorizer_error")
		}
		switch d["outcome"] {
		case "auto":
			return RailVerdict{Approved: true, Reasons: []string{}, Decision: d}
		case "step_up":
			if o.OnStepUp != nil {
				func() {
					defer func() { _ = recover() }() // a failing notifier must not change the answer
					o.OnStepUp(*a, d)
				}()
			}
			return RailVerdict{Reasons: append([]string{"step_up_required"}, payStrs(d["reasons"])...), Decision: d}
		}
		rs := payStrs(d["reasons"])
		if len(rs) == 0 {
			rs = []string{"denied"}
		}
		return RailVerdict{Reasons: rs, Decision: d}
	}
	return func(a *RailAuthorization) RailVerdict {
		ch := make(chan RailVerdict, 1)
		go func() {
			defer func() {
				if recover() != nil {
					ch <- payDecline("authorizer_error")
				}
			}()
			ch <- decideOne(a)
		}()
		t := time.NewTimer(budget)
		defer t.Stop()
		select {
		case v := <-ch:
			return v
		case <-t.C:
			// shortcut: a decision that finishes after the timeout may still have debited the budget with no approval sent (an
			// under-spend, the safe direction); an operator reconciles by cosign / refill
			return payDecline("latency_budget_exceeded")
		}
	}, nil
}

// ---- Stripe Issuing -----------------------------------------------------------------------------------------------------

const (
	StripeWebhookToleranceSec = 300
	StripeAPIVersion          = "2025-03-31.basil"
)

// StripeCardParams: the form parameters for POST /v1/issuing/cards (virtual, active) carrying the rail limits. Refused when an MCC
// has no Stripe category name. metadata may be nil.
func StripeCardParams(limits map[string]any, categoryNames map[string]any, cardholder any, metadata map[string]any) (map[string]any, error) {
	cur, ok := limits["currency"].(string)
	if !ok {
		return nil, errors.New("limits.currency.toLowerCase is not a function")
	}
	p := map[string]any{"cardholder": cardholder, "type": "virtual", "status": "active", "currency": strings.ToLower(cur),
		"spending_controls[spending_limits][0][amount]":   payToStr(payOptMap(limits, "perAuthorizationMax")),
		"spending_controls[spending_limits][0][interval]": "per_authorization",
		"spending_controls[spending_limits][1][amount]":   payToStr(payOptMap(limits, "totalMax")),
		"spending_controls[spending_limits][1][interval]": "all_time"}
	cats, ok := limits["categories"].([]any)
	if !ok {
		return nil, errors.New("limits.categories.forEach is not a function")
	}
	for i, mcc := range cats {
		name, has := categoryNames[payToStr(mcc)]
		if !has {
			return nil, fmt.Errorf("stripeCardParams: no Stripe category name for MCC %s", payToStr(mcc))
		}
		p[fmt.Sprintf("spending_controls[allowed_categories][%d]", i)] = name
	}
	for k, v := range metadata {
		p["metadata["+k+"]"] = v
	}
	return p, nil
}

func payOptMap(m map[string]any, k string) any {
	if v, has := m[k]; has {
		return v
	}
	return payU
}

func payHMAC(secret, msg string) []byte {
	h := hmac.New(sha256.New, []byte(wellFormedUTF8(secret)))
	h.Write([]byte(wellFormedUTF8(msg)))
	return h.Sum(nil)
}

// SignStripePayload computes the Stripe-Signature header Stripe would send (tests and local tooling).
func SignStripePayload(rawBody, secret string, tSec any) string {
	t := payToStr(tSec)
	return "t=" + t + ",v1=" + hex.EncodeToString(payHMAC(secret, t+"."+rawBody))
}

var (
	payStripeT   = regexp.MustCompile(`^[0-9]{1,12}$`)
	payStripeSig = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// VerifyStripeSignature verifies a Stripe-Signature header over the RAW body. Total: false on anything malformed, stale (beyond
// toleranceSec; pass StripeWebhookToleranceSec for the default) or mismatched. header and secret are JSON values (a non-string
// is refused).
func VerifyStripeSignature(rawBody string, header, secret any, nowSec, toleranceSec float64) bool {
	h, ok1 := header.(string)
	sc, ok2 := secret.(string)
	if !ok1 || !ok2 || sc == "" || !(toleranceSec > 0) {
		return false
	}
	t, hasT := "", false
	var v1 []string
	for _, part := range strings.Split(h, ",") {
		i := strings.IndexByte(part, '=')
		if i < 0 {
			continue
		}
		k, v := jsTrim(part[:i]), jsTrim(part[i+1:])
		if k == "t" {
			t, hasT = v, true
		} else if k == "v1" {
			v1 = append(v1, v)
		}
	}
	if !hasT || !payStripeT.MatchString(t) || len(v1) == 0 {
		return false
	}
	if !(finite(nowSec) && math.Abs(nowSec-jsStringToNumber(t)) <= toleranceSec) {
		return false
	}
	want := payHMAC(sc, t+"."+rawBody)
	ok := false
	for _, s := range v1 {
		if payStripeSig.MatchString(s) {
			got, _ := hex.DecodeString(s)
			if hmac.Equal(got, want) {
				ok = true
			}
		}
	}
	return ok
}

func payObj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// StripeAuthorizationFromEvent normalises an issuing_authorization.request event; nil when it is not a well-formed request with a
// pending amount.
func StripeAuthorizationFromEvent(event any) map[string]any {
	e := payObj(event)
	if e == nil || e["type"] != "issuing_authorization.request" {
		return nil
	}
	a := payObj(payObj(e["data"])["object"])
	pending := payObj(a["pending_request"])
	card := payObj(a["card"])
	merchant := payObj(a["merchant_data"])
	id, ok1 := a["id"].(string)
	cid, ok2 := card["id"].(string)
	if a == nil || pending == nil || !ok1 || !ok2 {
		return nil
	}
	amount := pending["amount"]
	cur, ok := pending["currency"].(string)
	if _, isNum := jsNum(amount); !isNum || !ok {
		return nil
	}
	out := map[string]any{"id": id, "instrumentId": cid, "amount": amount, "currency": cur}
	if nid, ok := merchant["network_id"].(string); ok && nid != "" {
		out["merchantId"] = nid
	}
	if cc, ok := merchant["category_code"].(string); ok {
		out["mcc"] = cc
	}
	return out
}

// RailAuthorizationFromStripe converts a normalised Stripe authorization into a RailAuthorization.
func RailAuthorizationFromStripe(a map[string]any) *RailAuthorization {
	if a == nil {
		return nil
	}
	r := &RailAuthorization{Amount: a["amount"]}
	r.ID, _ = a["id"].(string)
	r.InstrumentID, _ = a["instrumentId"].(string)
	r.Currency, _ = a["currency"].(string)
	if s, ok := a["merchantId"].(string); ok {
		r.MerchantID = &s
	}
	if s, ok := a["mcc"].(string); ok {
		r.MCC = &s
	}
	return r
}

// HTTPReply is a webhook handler's answer.
type HTTPReply struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func payReply(status int, body, version string) HTTPReply {
	return HTTPReply{Status: status, Headers: map[string]string{"Stripe-Version": version, "Content-Type": "application/json"}, Body: body}
}

// StripeWebhookOptions: Secret is the endpoint signing secret (whsec_...); Authorize answers from the PCA decision (e.g. a
// NewRailAuthorizer callback over RailAuthorizationFromStripe); StripeVersion "" = StripeAPIVersion; NowSec nil = the wall clock;
// ToleranceSec nil = StripeWebhookToleranceSec.
type StripeWebhookOptions struct {
	Secret        string
	Authorize     func(auth map[string]any) RailVerdict
	StripeVersion string
	NowSec        func() float64
	ToleranceSec  *float64
}

// NewStripeIssuingWebhook is the HTTP handler body for the issuing_authorization.request endpoint. Bad signature: 400 (nothing is
// decided). A request event gets 200 {approved} from the PCA decision; any other event type 200 {}. amount is never sent.
func NewStripeIssuingWebhook(o StripeWebhookOptions) func(rawBody string, signature any) HTTPReply {
	version := o.StripeVersion
	if version == "" {
		version = StripeAPIVersion
	}
	nowSec := o.NowSec
	if nowSec == nil {
		nowSec = func() float64 { return math.Floor(float64(time.Now().UnixMilli()) / 1000) }
	}
	tol := float64(StripeWebhookToleranceSec)
	if o.ToleranceSec != nil {
		tol = *o.ToleranceSec
	}
	return func(rawBody string, signature any) HTTPReply {
		if !VerifyStripeSignature(rawBody, signature, o.Secret, nowSec(), tol) {
			return payReply(400, `{"error":"bad_signature"}`, version)
		}
		if !json.Valid([]byte(rawBody)) {
			return payReply(400, `{"error":"bad_json"}`, version)
		}
		event, err := ParseJSONLenient([]byte(rawBody))
		if err != nil {
			return payReply(400, `{"error":"bad_json"}`, version)
		}
		if payObj(event)["type"] != "issuing_authorization.request" {
			return payReply(200, `{}`, version)
		}
		auth := StripeAuthorizationFromEvent(event)
		if auth == nil || o.Authorize == nil {
			return payReply(200, `{"approved":false}`, version)
		}
		if o.Authorize(auth).Approved {
			return payReply(200, `{"approved":true}`, version)
		}
		return payReply(200, `{"approved":false}`, version)
	}
}

// StripeSettlementFromTransaction normalises an issuing_transaction.created capture into a settlement (a capture's amount is
// negative in Stripe's ledger); nil for anything else.
func StripeSettlementFromTransaction(txn any) map[string]any {
	t := payObj(txn)
	if t == nil || t["type"] != "capture" {
		return nil
	}
	auth, ok1 := t["authorization"].(string)
	amt, ok2 := jsNum(t["amount"])
	cur, ok3 := t["currency"].(string)
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	out := map[string]any{"authorizationId": auth, "amount": payNum(-amt), "currency": cur, "captures": jsNumber(1)}
	if nid, ok := payObj(t["merchant_data"])["network_id"].(string); ok {
		out["merchantId"] = nid
	}
	return out
}
