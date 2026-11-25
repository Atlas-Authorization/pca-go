package pca

// AP2 mandate claim shapes (Intent / Cart / Payment, closed and open) and their validators. The validators follow the official AP2 JSON
// Schemas and are stricter where a lax reading would be unsafe (non-negative safe-integer amounts, well-formed JWKs). A mandate is a
// JSON object (map[string]any); every validator returns the list of problems (empty = valid).

import (
	"math"
	"strconv"
	"strings"
)

// The vct values of the four mandate kinds, and the namespaced claim carrying PCA's own proof inside a mandate object.
const (
	Ap2VctCheckout     = "mandate.checkout.1"
	Ap2VctCheckoutOpen = "mandate.checkout.open.1"
	Ap2VctPayment      = "mandate.payment.1"
	Ap2VctPaymentOpen  = "mandate.payment.open.1"
	Ap2PcaClaim        = "x_pca"
	// Ap2Commit is the AP2 repository commit whose schemas and documentation this package is checked against.
	Ap2Commit            = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
	Ap2PcaBindingVersion = 1
)

// Ap2Frequencies are the recurrence frequencies of payment.agent_recurrence.
var Ap2Frequencies = []string{"ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"}

// Ap2TypTerminal / Ap2TypIntermediate are the accepted typ headers of a terminal / intermediate key-binding hop.
var (
	Ap2TypTerminal     = []string{"kb+sd-jwt", "kb-sd-jwt"}
	Ap2TypIntermediate = []string{"kb+sd-jwt+kb", "kb-sd-jwt+kb"}
)

// ---- currencies and minor units ----------------------------------------------------------------------------------------

var ap2ZeroDecimal = map[string]bool{"BIF": true, "CLP": true, "DJF": true, "GNF": true, "ISK": true, "JPY": true, "KMF": true, "KRW": true, "PYG": true,
	"RWF": true, "UGX": true, "UYI": true, "VND": true, "VUV": true, "XAF": true, "XOF": true, "XPF": true}
var ap2ThreeDecimal = map[string]bool{"BHD": true, "IQD": true, "JOD": true, "KWD": true, "LYD": true, "OMR": true, "TND": true}
var ap2FourDecimal = map[string]bool{"CLF": true, "UYW": true}

// ap2Pow10 is 10 ** e for the exponents a currency can have (exact doubles).
var ap2Pow10 = [...]float64{1, 10, 100, 1000, 10000}

// Ap2CurrencyExponent is the ISO 4217 minor-unit exponent for currency (2 for any code not in the 0/3/4-digit tables). currency is a
// JSON value: the reference tests it as a string after coercion, so a non-string is refused with its JSON form in the message.
func Ap2CurrencyExponent(currency any) (int, error) {
	s := ap2Str(currency)
	if !ap2Alpha3(s) {
		return 0, ap2Fail("currency must be an ISO 4217 alpha-3 code, got %s", ap2JSON(currency))
	}
	if cs, ok := currency.(string); ok {
		switch {
		case ap2ZeroDecimal[cs]:
			return 0, nil
		case ap2ThreeDecimal[cs]:
			return 3, nil
		case ap2FourDecimal[cs]:
			return 4, nil
		}
	}
	return 2, nil
}

// Ap2ToMinorUnits converts a major-unit amount (120.5 USD) to integer minor units (12050). It refuses an amount that is not exactly
// representable with the currency's exponent: float drift (0.1 + 0.2) is refused rather than rounded away.
func Ap2ToMinorUnits(major any, currency any) (float64, error) {
	e, err := Ap2CurrencyExponent(currency)
	if err != nil {
		return 0, err
	}
	f, ok := jsNum(major)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, ap2Fail("amount must be a finite non-negative number, got %s", ap2Str(major))
	}
	if f == 0 {
		f = 0 // -0 prints as 0
	}
	fixed := strconv.FormatFloat(f, 'f', e, 64)
	if back, _ := strconv.ParseFloat(fixed, 64); back != f {
		return 0, ap2Fail("amount %s is not exactly representable in %s minor units", ap2Str(major), ap2Str(currency))
	}
	minor, _ := strconv.ParseFloat(strings.Replace(fixed, ".", "", 1), 64)
	if !jsIsSafeInteger(ap2Num(minor)) {
		return 0, ap2Fail("amount %s is outside the safe integer range in minor units", ap2Str(major))
	}
	return minor, nil
}

// Ap2FromMinorUnits is integer minor units to the major-unit number PCA budgets use (exact for any safe integer).
func Ap2FromMinorUnits(minor any, currency any) (float64, error) {
	e, err := Ap2CurrencyExponent(currency)
	if err != nil {
		return 0, err
	}
	f, ok := jsNum(minor)
	if !ok || !jsIsSafeInteger(minor) || f < 0 || (f == 0 && math.Signbit(f)) {
		return 0, ap2Fail("minor-unit amount must be a non-negative safe integer, got %s", ap2Str(minor))
	}
	return f / ap2Pow10[e], nil
}

// ---- validators --------------------------------------------------------------------------------------------------------

func ap2IsInt(v any) bool    { return jsIsInt(v) }
func ap2IsNonNeg(v any) bool { return jsIsNonNeg(v) }

func ap2MerchantProblems(v any, at string) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{at + ": not an object"}
	}
	var p []string
	if !ap2IsNonEmptyStr(ap2Get(m, "id")) {
		p = append(p, at+".id: required string")
	}
	if !ap2IsNonEmptyStr(ap2Get(m, "name")) {
		p = append(p, at+".name: required string")
	}
	if w := ap2Get(m, "website"); !ap2IsU(w) && !ap2IsStr(w) {
		p = append(p, at+".website: must be a string")
	}
	return p
}

func ap2AmountProblems(v any, at string) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{at + ": not an object"}
	}
	var p []string
	if !ap2IsNonNeg(ap2Get(m, "amount")) {
		p = append(p, at+".amount: must be a non-negative integer (minor units)")
	}
	if c, ok := ap2Get(m, "currency").(string); !ok || !ap2Alpha3(c) {
		p = append(p, at+".currency: must be an ISO 4217 alpha-3 code")
	}
	return p
}

func ap2InstrumentProblems(v any, at string) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{at + ": not an object"}
	}
	var p []string
	if !ap2IsNonEmptyStr(ap2Get(m, "id")) {
		p = append(p, at+".id: required string")
	}
	if !ap2IsNonEmptyStr(ap2Get(m, "type")) {
		p = append(p, at+".type: required string")
	}
	if d := ap2Get(m, "description"); !ap2IsU(d) && !ap2IsStr(d) {
		p = append(p, at+".description: must be a string")
	}
	return p
}

func ap2PispProblems(v any, at string) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{at + ": not an object"}
	}
	var p []string
	for _, k := range []string{"legal_name", "brand_name", "domain_name"} {
		if !ap2IsNonEmptyStr(ap2Get(m, k)) {
			p = append(p, at+"."+k+": required string")
		}
	}
	return p
}

func ap2TimeProblems(m map[string]any) []string {
	var p []string
	for _, k := range []string{"iat", "exp"} {
		if x := ap2Get(m, k); !ap2IsU(x) && !ap2IsNonNeg(x) {
			p = append(p, k+": must be an integer epoch-seconds")
		}
	}
	return p
}

func ap2CnfProblems(v any) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{"cnf: must be { jwk }"}
	}
	jwk, ok := ap2Obj(ap2Get(m, "jwk"))
	if !ok {
		return []string{"cnf: must be { jwk }"}
	}
	if _, err := Ap2AssertP256Jwk(jwk, "cnf.jwk"); err != nil {
		return []string{err.Error()}
	}
	return nil
}

func ap2PcaClaimProblems(m map[string]any) []string {
	if x := ap2Get(m, Ap2PcaClaim); !ap2IsU(x) {
		if _, ok := ap2Obj(x); !ok {
			return []string{Ap2PcaClaim + ": must be an object"}
		}
	}
	return nil
}

func ap2ListProblems(v any, at string, each func(x any, at string) []string) []string {
	l, ok := v.([]any)
	if !ok {
		return []string{at + ": must be an array"}
	}
	var p []string
	for i, x := range l {
		p = append(p, each(x, at+"["+strconv.Itoa(i)+"]")...)
	}
	return p
}

func ap2OneOf(list []string, v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func ap2PaymentConstraintProblems(c any, at string) []string {
	m, ok := ap2Obj(c)
	if !ok || !ap2IsStr(ap2Get(m, "type")) {
		return []string{at + ": constraint must be an object with a string type"}
	}
	typ := m["type"].(string)
	var p []string
	switch typ {
	case "payment.agent_recurrence":
		if !ap2OneOf(Ap2Frequencies, ap2Get(m, "frequency")) {
			p = append(p, at+".frequency: not a known frequency")
		}
		if mo := ap2Get(m, "max_occurrences"); !ap2IsU(mo) && !(ap2IsInt(mo) && jsF(mo) > 0) {
			p = append(p, at+".max_occurrences: must be a positive integer")
		}
		return p
	case "payment.allowed_payees":
		return ap2ListProblems(ap2Get(m, "allowed"), at+".allowed", ap2MerchantProblems)
	case "payment.allowed_payment_instruments":
		return ap2ListProblems(ap2Get(m, "allowed"), at+".allowed", ap2InstrumentProblems)
	case "payment.allowed_pisps":
		return ap2ListProblems(ap2Get(m, "allowed"), at+".allowed", ap2PispProblems)
	case "payment.amount_range":
		if cur, ok := ap2Get(m, "currency").(string); !ok || !ap2Alpha3(cur) {
			p = append(p, at+".currency: must be an ISO 4217 alpha-3 code")
		}
		mx, mn := ap2Get(m, "max"), ap2Get(m, "min")
		if !ap2IsNonNeg(mx) {
			p = append(p, at+".max: must be a non-negative integer (minor units)")
		}
		if !ap2IsU(mn) && !ap2IsNonNeg(mn) {
			p = append(p, at+".min: must be a non-negative integer (minor units)")
		}
		if ap2IsInt(mx) && ap2IsInt(mn) && jsF(mn) > jsF(mx) {
			p = append(p, at+": min exceeds max")
		}
		return p
	case "payment.budget":
		if cur, ok := ap2Get(m, "currency").(string); !ok || !ap2Alpha3(cur) {
			p = append(p, at+".currency: must be an ISO 4217 alpha-3 code")
		}
		if f, ok := jsNum(ap2Get(m, "max")); !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			p = append(p, at+".max: must be a non-negative number (major units)")
		}
		return p
	case "payment.execution_date":
		for _, k := range []string{"not_before", "not_after"} {
			if x := ap2Get(m, k); !ap2IsU(x) && !ap2IsStr(x) {
				p = append(p, at+"."+k+": must be a string")
			}
		}
		return p
	case "payment.reference":
		if ap2IsNonEmptyStr(ap2Get(m, "conditional_transaction_id")) {
			return nil
		}
		return []string{at + ".conditional_transaction_id: required string"}
	}
	return []string{at + ": unknown constraint type " + typ}
}

func ap2CheckoutConstraintProblems(c any, at string) []string {
	m, ok := ap2Obj(c)
	if !ok || !ap2IsStr(ap2Get(m, "type")) {
		return []string{at + ": constraint must be an object with a string type"}
	}
	typ := m["type"].(string)
	if typ == "checkout.allowed_merchants" {
		return ap2ListProblems(ap2Get(m, "allowed"), at+".allowed", ap2MerchantProblems)
	}
	if typ == "checkout.line_items" {
		items, ok := ap2Get(m, "items").([]any)
		if !ok || len(items) == 0 {
			return []string{at + ".items: must be a non-empty array"}
		}
		var p []string
		for i, it := range items {
			a := at + ".items[" + strconv.Itoa(i) + "]"
			im, ok := ap2Obj(it)
			if !ok {
				p = append(p, a+": not an object")
				continue
			}
			if !ap2IsNonEmptyStr(ap2Get(im, "id")) {
				p = append(p, a+".id: required string")
			}
			if q := ap2Get(im, "quantity"); !ap2IsInt(q) || jsF(q) <= 0 {
				p = append(p, a+".quantity: must be a positive integer")
			}
			p = append(p, ap2ListProblems(ap2Get(im, "acceptable_items"), a+".acceptable_items", func(x any, ax string) []string {
				xm, ok := ap2Obj(x)
				if !ok {
					return []string{ax + ": not an object"}
				}
				var q []string
				for _, k := range []string{"id", "title"} {
					if !ap2IsNonEmptyStr(ap2Get(xm, k)) {
						q = append(q, ax+"."+k+": required string")
					}
				}
				return q
			})...)
		}
		return p
	}
	return []string{at + ": unknown constraint type " + typ}
}

func ap2VctProblem(m map[string]any, want string) []string {
	if ap2StrictEq(ap2Get(m, "vct"), want) {
		return nil
	}
	return []string{"vct: must be " + want}
}

func ap2HasConstraint(v any, typ string) bool {
	l, ok := v.([]any)
	if !ok {
		return true // only an array is checked
	}
	for _, c := range l {
		if m, ok := ap2Obj(c); ok && ap2StrictEq(ap2Get(m, "type"), typ) {
			return true
		}
	}
	return false
}

// Ap2OpenPaymentMandateProblems lists the problems of an open payment mandate (mandate.payment.open.1).
func Ap2OpenPaymentMandateProblems(v any) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{"mandate: not an object"}
	}
	p := append([]string{}, ap2VctProblem(m, Ap2VctPaymentOpen)...)
	p = append(p, ap2TimeProblems(m)...)
	p = append(p, ap2CnfProblems(ap2Get(m, "cnf"))...)
	p = append(p, ap2PcaClaimProblems(m)...)
	p = append(p, ap2ListProblems(ap2Get(m, "constraints"), "constraints", ap2PaymentConstraintProblems)...)
	if !ap2HasConstraint(ap2Get(m, "constraints"), "payment.reference") {
		p = append(p, "constraints: must contain a payment.reference constraint")
	}
	if x := ap2Get(m, "payee"); !ap2IsU(x) {
		p = append(p, ap2MerchantProblems(x, "payee")...)
	}
	if x := ap2Get(m, "payment_amount"); !ap2IsU(x) {
		p = append(p, ap2AmountProblems(x, "payment_amount")...)
	}
	if x := ap2Get(m, "payment_instrument"); !ap2IsU(x) {
		p = append(p, ap2InstrumentProblems(x, "payment_instrument")...)
	}
	if x := ap2Get(m, "pisp"); !ap2IsU(x) {
		p = append(p, ap2PispProblems(x, "pisp")...)
	}
	if x := ap2Get(m, "execution_date"); !ap2IsU(x) && !ap2IsStr(x) {
		p = append(p, "execution_date: must be a string")
	}
	if x := ap2Get(m, "risk_data"); !ap2IsU(x) {
		if _, ok := ap2Obj(x); !ok {
			p = append(p, "risk_data: must be an object")
		}
	}
	return p
}

// Ap2PaymentMandateProblems lists the problems of a closed payment mandate (mandate.payment.1).
func Ap2PaymentMandateProblems(v any) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{"mandate: not an object"}
	}
	p := append([]string{}, ap2VctProblem(m, Ap2VctPayment)...)
	p = append(p, ap2TimeProblems(m)...)
	p = append(p, ap2PcaClaimProblems(m)...)
	if !ap2IsNonEmptyStr(ap2Get(m, "transaction_id")) {
		p = append(p, "transaction_id: required string")
	}
	p = append(p, ap2MerchantProblems(ap2Get(m, "payee"), "payee")...)
	p = append(p, ap2AmountProblems(ap2Get(m, "payment_amount"), "payment_amount")...)
	p = append(p, ap2InstrumentProblems(ap2Get(m, "payment_instrument"), "payment_instrument")...)
	if x := ap2Get(m, "pisp"); !ap2IsU(x) {
		p = append(p, ap2PispProblems(x, "pisp")...)
	}
	if x := ap2Get(m, "execution_date"); !ap2IsU(x) && !ap2IsStr(x) {
		p = append(p, "execution_date: must be a string")
	}
	if x := ap2Get(m, "risk_data"); !ap2IsU(x) {
		if _, ok := ap2Obj(x); !ok {
			p = append(p, "risk_data: must be an object")
		}
	}
	return p
}

// Ap2OpenCheckoutMandateProblems lists the problems of an open checkout mandate (mandate.checkout.open.1).
func Ap2OpenCheckoutMandateProblems(v any) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{"mandate: not an object"}
	}
	p := append([]string{}, ap2VctProblem(m, Ap2VctCheckoutOpen)...)
	p = append(p, ap2TimeProblems(m)...)
	p = append(p, ap2CnfProblems(ap2Get(m, "cnf"))...)
	p = append(p, ap2PcaClaimProblems(m)...)
	p = append(p, ap2ListProblems(ap2Get(m, "constraints"), "constraints", ap2CheckoutConstraintProblems)...)
	if !ap2HasConstraint(ap2Get(m, "constraints"), "checkout.line_items") {
		p = append(p, "constraints: must contain a checkout.line_items constraint")
	}
	return p
}

// Ap2CheckoutMandateProblems lists the problems of a closed checkout mandate (mandate.checkout.1).
func Ap2CheckoutMandateProblems(v any) []string {
	m, ok := ap2Obj(v)
	if !ok {
		return []string{"mandate: not an object"}
	}
	p := append([]string{}, ap2VctProblem(m, Ap2VctCheckout)...)
	p = append(p, ap2TimeProblems(m)...)
	p = append(p, ap2PcaClaimProblems(m)...)
	if !ap2IsNonEmptyStr(ap2Get(m, "checkout_jwt")) {
		p = append(p, "checkout_jwt: required string")
	}
	if !ap2IsNonEmptyStr(ap2Get(m, "checkout_hash")) {
		p = append(p, "checkout_hash: required string")
	}
	return p
}

// Ap2AssertValid returns v when problems(v) is empty, else an error naming every problem.
func Ap2AssertValid(v any, problems func(any) []string, what string) (any, error) {
	if p := problems(v); len(p) > 0 {
		return nil, ap2Fail("%s: %s", what, strings.Join(p, "; "))
	}
	return v, nil
}
