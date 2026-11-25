package pca

// Stripe Shared Payment Granted Tokens (the card-network rail of ACP): the object's shape, whether it is still usable for a capture,
// the usage limits to request for a PCA authority, and the check that a Shared Payment Token is no wider than the delegated payment
// token (and so the PCA proof) it serves. Values are JSON values (see acp.go).

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// AcpStripeSptObject is the `object` member of a Shared Payment Granted Token.
const AcpStripeSptObject = "shared_payment.granted_token"

func acpIsObj(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

// acpIsInt is the reference isInt: a safe integer that is not -0.
func acpIsInt(v any) bool { return jsIsInt(v) }

func acpIsLowerCurrency(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

func acpIsSptID(v any) bool {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "spt_") || len(s) == 4 {
		return false
	}
	for i := 4; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// AcpStripeSptProblems lists the problems with a Shared Payment Granted Token object (empty = well formed).
func AcpStripeSptProblems(t any) []string {
	m, ok := t.(map[string]any)
	if !ok {
		return []string{"the token must be an object"}
	}
	p := []string{}
	if acpGet(m, "object") != AcpStripeSptObject {
		p = append(p, `object must be "`+AcpStripeSptObject+`"`)
	}
	if !acpIsSptID(m["id"]) {
		p = append(p, "id must be an spt_ identifier")
	}
	if !acpIsInt(m["created"]) {
		p = append(p, "created must be an integer timestamp")
	}
	if _, isB := m["livemode"].(bool); !isB {
		p = append(p, "livemode must be a boolean")
	}
	if da := acpGet(m, "deactivated_at"); da != nil && !acpIsInt(da) {
		p = append(p, "deactivated_at must be null or an integer timestamp")
	}
	if dr := acpGet(m, "deactivated_reason"); dr != nil {
		s, isS := dr.(string)
		if !(isS && (s == "consumed" || s == "expired" || s == "resolved" || s == "revoked")) {
			p = append(p, "deactivated_reason must be null or one of consumed, expired, resolved, revoked")
		}
	}
	u, isU := m["usage_limits"].(map[string]any)
	if !isU {
		p = append(p, "usage_limits is required")
	} else {
		if !acpIsLowerCurrency(u["currency"]) {
			p = append(p, "usage_limits.currency must be a lowercase three-letter code")
		}
		if mf, _ := jsNum(u["max_amount"]); !acpIsInt(u["max_amount"]) || mf < 0 {
			p = append(p, "usage_limits.max_amount must be a non-negative integer in minor units")
		}
		if ea := acpGet(u, "expires_at"); ea != acpU && ea != nil && !acpIsInt(ea) {
			p = append(p, "usage_limits.expires_at must be an integer timestamp")
		}
	}
	if ud := acpGet(m, "usage_details"); ud != nil && ud != acpU {
		c, cok := acpGet(ud, "amount_captured").(map[string]any)
		vf, _ := jsNum(c["value"])
		if !cok || !acpIsInt(c["value"]) || vf < 0 || !acpIsLowerCurrency(c["currency"]) {
			p = append(p, "usage_details.amount_captured needs a non-negative integer value and a lowercase currency")
		}
	}
	for _, k := range []string{"payment_method_details", "agent_details", "shared_metadata"} {
		if v := acpGet(m, k); v != nil && v != acpU && !acpIsObj(v) {
			p = append(p, k+" must be null or an object")
		}
	}
	if pmd, isO := m["payment_method_details"].(map[string]any); isO {
		if _, isS := pmd["type"].(string); !isS {
			p = append(p, "payment_method_details.type must be a string")
		}
	}
	return p
}

// AcpParseStripeSpt returns the token when it is well formed, else an error listing every problem.
func AcpParseStripeSpt(t any) (map[string]any, error) {
	if p := AcpStripeSptProblems(t); len(p) > 0 {
		return nil, errors.New("stripe spt: " + strings.Join(p, "; "))
	}
	return t.(map[string]any), nil
}

func acpOK() map[string]any { return map[string]any{"ok": true} }

// AcpStripeSptUsable reports whether a token can still be used for this capture (use: now and amount as integers, currency,
// livemode, default true): it refuses a malformed token, a deactivated or expired one, the wrong mode, a different currency, a
// non-integer amount and one above max_amount minus what was already captured.
func AcpStripeSptUsable(t, use any) (map[string]any, error) {
	if p := AcpStripeSptProblems(t); len(p) > 0 {
		return acpCheckFail("malformed token: " + p[0]), nil
	}
	if acpNullish(use) {
		return nil, errors.New("Cannot read properties of null (reading 'now')")
	}
	m := t.(map[string]any)
	now, amount := acpGet(use, "now"), acpGet(use, "amount")
	amf, _ := jsNum(amount)
	if !acpIsInt(now) || !acpIsInt(amount) || amf <= 0 {
		return acpCheckFail("now and amount must be integers and the amount positive"), nil
	}
	lm := acpDefault(acpGet(use, "livemode"), true)
	if b, isB := lm.(bool); !isB || b != m["livemode"] {
		return acpCheckFail("the token is in the wrong mode"), nil
	}
	if dr := m["deactivated_reason"]; dr != nil {
		return acpCheckFail(fmt.Sprintf("the token is deactivated (%s)", acpS(dr))), nil
	}
	nf, _ := jsNum(now)
	if m["deactivated_at"] != nil {
		if daf, _ := jsNum(m["deactivated_at"]); daf <= nf {
			return acpCheckFail("the token is deactivated"), nil
		}
	}
	lim := m["usage_limits"].(map[string]any)
	if ef, isN := jsNum(lim["expires_at"]); isN && nf >= ef {
		return acpCheckFail("the token has expired"), nil
	}
	cur, isS := acpGet(use, "currency").(string)
	if !isS {
		return nil, errors.New("use.currency.toLowerCase is not a function")
	}
	if lim["currency"] != acpLower(cur) {
		return acpCheckFail("the capture currency differs from the token currency"), nil
	}
	var capturedValue float64
	if ud, isO := m["usage_details"].(map[string]any); isO {
		c, _ := ud["amount_captured"].(map[string]any)
		if c != nil {
			if c["currency"] != lim["currency"] {
				return acpCheckFail("the captured amount is in another currency"), nil
			}
			capturedValue, _ = jsNum(c["value"])
		}
	}
	maxF, _ := jsNum(lim["max_amount"])
	remaining := maxF - capturedValue
	if amf > remaining {
		return acpCheckFail(fmt.Sprintf("the amount %s exceeds the remaining %s", acpS(amount), jsNumberString(remaining))), nil
	}
	return acpOK(), nil
}

// AcpStripeUsageLimitsFor is the usage_limits to request for a PCA authority {maxAmount, currency, expiresAtMs?}: lowercase
// currency, integer minor units, expiry in whole seconds (rounded down). It refuses anything invalid.
func AcpStripeUsageLimitsFor(authority any) (map[string]any, error) {
	if acpNullish(authority) {
		return nil, errors.New("Cannot read properties of null (reading 'maxAmount')")
	}
	ma := acpGet(authority, "maxAmount")
	maf, _ := jsNum(ma)
	if !acpIsInt(ma) || maf <= 0 {
		return nil, errors.New("stripe spt: maxAmount must be a positive integer in minor units")
	}
	cur, isS := acpGet(authority, "currency").(string)
	if !isS || len(cur) != 3 || strings.Trim(cur, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return nil, errors.New("stripe spt: currency must be a three-letter code")
	}
	exp := acpGet(authority, "expiresAtMs")
	ef, _ := jsNum(exp)
	if exp != acpU && !(acpFinite(exp) && ef > 0) {
		return nil, errors.New("stripe spt: expiresAtMs must be a positive epoch-ms time")
	}
	out := map[string]any{"currency": strings.ToLower(cur), "max_amount": jsNumber(maf)}
	if exp != acpU {
		out["expires_at"] = jsNumber(math.Floor(ef / 1000))
	}
	return out, nil
}

// AcpStripeSptWithinClaims checks that a Shared Payment Token is no wider than the delegated payment token (and so the PCA proof)
// it serves: the same currency, max_amount not above the delegated amount, and an expiry present and not after the delegated
// token's. claims: amount, currency, exp.
func AcpStripeSptWithinClaims(t, claims any) (map[string]any, error) {
	if p := AcpStripeSptProblems(t); len(p) > 0 {
		return acpCheckFail("malformed token: " + p[0]), nil
	}
	if acpNullish(claims) {
		return nil, errors.New("Cannot read properties of null (reading 'currency')")
	}
	lim := t.(map[string]any)["usage_limits"].(map[string]any)
	cc, isS := acpGet(claims, "currency").(string)
	if !isS {
		return nil, errors.New("claims.currency.toLowerCase is not a function")
	}
	if lim["currency"] != acpLower(cc) {
		return acpCheckFail("the token currency differs from the delegated currency"), nil
	}
	maf, _ := jsNum(lim["max_amount"])
	amount := acpGet(claims, "amount")
	if fa, okA := jsNum(amount); !okA || !finite(fa) || acpGt(maf, amount) { // the delegated amount must be a finite number
		return acpCheckFail(fmt.Sprintf("max_amount %s exceeds the delegated amount %s", acpS(lim["max_amount"]), acpS(amount))), nil
	}
	ef, isN := jsNum(lim["expires_at"])
	if !isN {
		return acpCheckFail("the token has no expiry"), nil
	}
	if fe, okE := jsNum(acpGet(claims, "exp")); !okE || !finite(fe) || acpGt(ef*1000, acpGet(claims, "exp")) { // the delegated expiry must be a finite number
		return acpCheckFail("the token outlives the delegated payment token"), nil
	}
	return acpOK(), nil
}
