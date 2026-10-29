package pca

import (
	"math/big"
	"regexp"
	"strings"
)

// K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
// binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
//
// Signatures are Ed25519 (strict) over the UTF-8 bytes of HashCanonical({"kind": kind, "body": body}) (the digest string); body is
// the signed object without its `sig`. Escalation is integer-only. Every function is total.

const (
	k4PPM                = 1_000_000
	k4MaxMultiplierPPM   = 100 * k4PPM
	networkTokenBindKind = "pca.network_token_binding"
)

var (
	k4RefRe     = regexp.MustCompile(`^[A-Za-z0-9_.:\-]{8,128}$`)
	k4HexAddr   = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	k4HexQty    = regexp.MustCompile(`^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$`)
	k4HexCtx    = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	k4DigitRun  = regexp.MustCompile(`[0-9]+`)
	k4SpaceDash = regexp.MustCompile(`[\s\-]`)
)

// k4Minor: a safe integer >= 0 (not -0).
func k4Minor(v any) (int64, bool) {
	if !jsIsNonNeg(v) {
		return 0, false
	}
	f, _ := jsNum(v)
	return int64(f), true
}

func k4SafeInt(v any) (int64, bool) {
	if !jsIsInt(v) {
		return 0, false
	}
	f, _ := jsNum(v)
	return int64(f), true
}

// k4Sig: (ok, decoded). decoded=false when the key or signature does not decode.
func k4Sig(pub any, kind string, obj map[string]any) (ok bool, decoded bool) {
	body := make(map[string]any, len(obj))
	for k, v := range obj {
		if k != "sig" {
			body[k] = v
		}
	}
	ps, isStr := pub.(string)
	ss, isStr2 := obj["sig"].(string)
	if !isStr || !isStr2 {
		return false, false
	}
	pk, ok1 := DecodeB64uStrict(ps, -1)
	sg, ok2 := DecodeB64uStrict(ss, -1)
	if !ok1 || !ok2 {
		return false, false
	}
	h, err := HashCanonical(map[string]any{"kind": kind, "body": body})
	if err != nil {
		return false, false
	}
	return VerifyStrict(pk, []byte(h), sg), true
}

func k4Luhn(d string) bool {
	sum, dbl := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if dbl {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		dbl = !dbl
	}
	return sum%10 == 0
}

// LooksLikePan: a maximal digit run (spaces and hyphens removed) of 13..19 digits that passes Luhn.
func LooksLikePan(s string) bool {
	for _, r := range k4DigitRun.FindAllString(k4SpaceDash.ReplaceAllString(s, ""), -1) {
		if len(r) >= 13 && len(r) <= 19 && k4Luhn(r) {
			return true
		}
	}
	return false
}

// TokenRefError: "" when the opaque network-token reference is acceptable.
func TokenRefError(ref any) string {
	s, ok := ref.(string)
	if !ok || !k4RefRe.MatchString(s) {
		return "token_ref_malformed"
	}
	if LooksLikePan(s) {
		return "token_ref_looks_like_pan"
	}
	return ""
}

// VerifyNetworkTokenBinding returns "" when valid, else the reason. provider "" means any.
func VerifyNetworkTokenBinding(b any, grant any, holder, issuerNonce, provider string) string {
	m, ok := b.(map[string]any)
	if !ok || m["kind"] != networkTokenBindKind {
		return "binding_malformed"
	}
	if e := TokenRefError(m["token_ref"]); e != "" {
		return e
	}
	p, _ := m["provider"].(string)
	if p == "" || (provider != "" && p != provider) {
		return "provider_mismatch"
	}
	gd, err := HashCanonical(grant)
	if err != nil || m["grant_digest"] != gd {
		return "grant_digest_mismatch"
	}
	if m["holder"] != holder {
		return "holder_mismatch"
	}
	if m["issuer_nonce"] != issuerNonce {
		return "issuer_nonce_mismatch"
	}
	body := map[string]any{"kind": networkTokenBindKind, "v": jsNumber(1), "provider": p, "token_ref": m["token_ref"], "grant_digest": m["grant_digest"], "issuer_nonce": m["issuer_nonce"], "holder": m["holder"]}
	h, err := HashCanonical(body)
	hs, _ := m["holder"].(string)
	ps, _ := m["binding_proof"].(string)
	pk, ok1 := DecodeB64uStrict(hs, -1)
	sg, ok2 := DecodeB64uStrict(ps, -1)
	if err != nil || !ok1 || !ok2 {
		return "binding_malformed"
	}
	if !VerifyStrict(pk, []byte(h), sg) {
		return "binding_proof_invalid"
	}
	return ""
}

// PricingConfigError: "" when the principal-signed escalation pricing config is valid.
func PricingConfigError(c any) string {
	m, ok := c.(map[string]any)
	if !ok {
		return "config_malformed"
	}
	if f, isNum := jsNum(m["v"]); !isNum || f != 1 {
		return "config_malformed"
	}
	_, a := m["principal"].(string)
	_, b := m["currency"].(string)
	_, d := m["sig"].(string)
	if !a || !b || !d {
		return "config_malformed"
	}
	cost, o1 := k4Minor(m["interruptionCost"])
	mx, o2 := k4Minor(m["maxInterruptionCost"])
	_, o3 := k4Minor(m["hardCeilingLoss"])
	_, o4 := k4Minor(m["epoch"])
	if !o1 || !o2 || !o3 || !o4 {
		return "config_amounts_invalid"
	}
	if cost > mx {
		return "config_cost_above_max"
	}
	if st, o := k4SafeInt(m["tightenStepPpm"]); !o || st < 0 || st > k4MaxMultiplierPPM {
		return "config_step_invalid"
	}
	good, decoded := k4Sig(m["principal"], "pca.escalation_pricing", m)
	if !decoded {
		return "config_malformed"
	}
	if !good {
		return "config_signature_invalid"
	}
	return ""
}

// EscalationDecision is the verdict of DecideEscalation.
type EscalationDecision struct {
	Ask    bool
	Reason string
}

// DecideEscalation: ask a person iff pBadUpper * multiplier * loss > interruptionCost, integer arithmetic; anything else asks.
func DecideEscalation(config any, cal any, a any) EscalationDecision {
	if e := PricingConfigError(config); e != "" {
		return EscalationDecision{true, e}
	}
	cfg := config.(map[string]any)
	r, ok := a.(map[string]any)
	if !ok || r["currency"] != cfg["currency"] {
		return EscalationDecision{true, "currency_mismatch"}
	}
	loss, ok1 := k4Minor(r["loss"])
	p, ok2 := k4SafeInt(r["pBadUpperPpm"])
	if !ok1 || !ok2 || p < 0 || p > k4PPM {
		return EscalationDecision{true, "risk_input_invalid"}
	}
	cm, _ := cal.(map[string]any)
	mult, ok3 := k4SafeInt(cm["multiplierPpm"])
	if !ok3 || mult < k4PPM || mult > k4MaxMultiplierPPM {
		return EscalationDecision{true, "calibration_invalid"}
	}
	ceil, _ := k4Minor(cfg["hardCeilingLoss"])
	if loss > ceil {
		return EscalationDecision{true, "above_hard_ceiling"}
	}
	capped := new(big.Int).Mul(big.NewInt(p), big.NewInt(mult))
	one := new(big.Int).Mul(big.NewInt(k4PPM), big.NewInt(k4PPM))
	if capped.Cmp(one) > 0 {
		capped = one
	}
	lhs := new(big.Int).Mul(capped, big.NewInt(loss))
	cost, _ := k4Minor(cfg["interruptionCost"])
	rhs := new(big.Int).Mul(big.NewInt(cost), one)
	if lhs.Cmp(rhs) > 0 {
		return EscalationDecision{true, "expected_loss_exceeds_interruption_cost"}
	}
	return EscalationDecision{false, "expected_loss_within_interruption_cost"}
}

func k4AnswerOK(a any, principal string) bool {
	m, ok := a.(map[string]any)
	if !ok {
		return false
	}
	if f, isNum := jsNum(m["v"]); !isNum || f != 1 || m["principal"] != principal {
		return false
	}
	n, isStr := m["nonce"].(string)
	if !isStr || jsLen(n) < 8 {
		return false
	}
	if _, isStr2 := m["action_digest"].(string); !isStr2 {
		return false
	}
	if m["answer"] != "approve" && m["answer"] != "deny" {
		return false
	}
	good, decoded := k4Sig(principal, "pca.escalation_answer", m)
	return good && decoded
}

// UpdateCalibration folds principal-signed answers into the calibration; it can only raise the multiplier. cal is
// {multiplierPpm, seen[]}; risks maps action digest to its risk. Returns the new multiplier and the nonces seen in order.
func UpdateCalibration(config any, cal map[string]any, answers []any, risks map[string]any) (int64, []string) {
	mult, _ := k4SafeInt(cal["multiplierPpm"])
	startMult := mult
	var order []string
	seen := map[string]bool{}
	if s, ok := cal["seen"].([]any); ok {
		for _, x := range s {
			if n, ok := x.(string); ok {
				seen[n] = true
				order = append(order, n)
			}
		}
	}
	if PricingConfigError(config) != "" {
		return mult, order
	}
	cfg := config.(map[string]any)
	principal := cfg["principal"].(string)
	step, _ := k4SafeInt(cfg["tightenStepPpm"])
	for _, a := range answers {
		if !k4AnswerOK(a, principal) {
			continue
		}
		am := a.(map[string]any)
		nonce := am["nonce"].(string)
		if seen[nonce] {
			continue
		}
		seen[nonce] = true
		order = append(order, nonce)
		risk, known := risks[am["action_digest"].(string)]
		if am["answer"] != "deny" || !known {
			continue
		}
		if !DecideEscalation(config, map[string]any{"multiplierPpm": jsNumber(float64(mult))}, risk).Ask {
			mult += step
			if mult > k4MaxMultiplierPPM {
				mult = k4MaxMultiplierPPM
			}
		}
	}
	if mult < startMult {
		mult = startMult
	}
	return mult, order
}

func k4Lower(v any) string {
	if s, ok := v.(string); ok {
		return strings.ToLower(s)
	}
	return "\x00"
}

// VerifyGrantedPermission: "" when what the wallet granted is within the request and the grant, else a reason.
// g = {grantDigest, expiresAtSec}; contextOwner may be nil.
func VerifyGrantedPermission(g, sent, got any, allowedManagers []string, contextOwner func(string) (string, bool)) string {
	gm, _ := g.(map[string]any)
	sm, _ := sent.(map[string]any)
	r, ok := got.(map[string]any)
	if !ok {
		return "response_malformed"
	}
	perm, ok := r["permission"].(map[string]any)
	if !ok {
		return "response_malformed"
	}
	ctx, isStr := r["context"].(string)
	if !isStr || !k4HexCtx.MatchString(ctx) {
		return "context_malformed"
	}
	if contextOwner != nil {
		if o, has := contextOwner(ctx); has && o != gm["grantDigest"] {
			return "context_bound_to_other_grant"
		}
	}
	mgr, isStr := r["delegationManager"].(string)
	allowed := false
	for _, x := range allowedManagers {
		if strings.EqualFold(x, mgr) {
			allowed = true
		}
	}
	if !isStr || !k4HexAddr.MatchString(mgr) || !allowed {
		return "delegation_manager_not_allowed"
	}
	if k4Lower(r["chainId"]) != k4Lower(sm["chainId"]) {
		return "chain_mismatch"
	}
	if k4Lower(r["to"]) != k4Lower(sm["to"]) {
		return "recipient_mismatch"
	}
	if f, has := sm["from"]; has && f != nil && k4Lower(r["from"]) != k4Lower(f) {
		return "from_mismatch"
	}
	sperm, _ := sm["permission"].(map[string]any)
	pt, _ := perm["type"].(string)
	if pt != sperm["type"] || (pt != "native-token-allowance" && pt != "erc20-token-allowance") {
		return "permission_type_mismatch"
	}
	d, ok := perm["data"].(map[string]any)
	if !ok {
		return "response_malformed"
	}
	sd, _ := sperm["data"].(map[string]any)
	tok := func(m map[string]any) string {
		if s, ok := m["tokenAddress"].(string); ok {
			return strings.ToLower(s)
		}
		return ""
	}
	if tok(d) != tok(sd) {
		return "token_mismatch"
	}
	al, isStr := d["allowance"].(string)
	if !isStr || !k4HexQty.MatchString(al) {
		return "amount_malformed"
	}
	a1, _ := new(big.Int).SetString(al[2:], 16)
	sal, _ := sd["allowance"].(string)
	a2, _ := new(big.Int).SetString(sal[2:], 16)
	if a1.Cmp(a2) > 0 {
		return "amount_widened"
	}
	if perm["isAdjustmentAllowed"] != sperm["isAdjustmentAllowed"] && perm["isAdjustmentAllowed"] == true {
		return "adjustment_widened"
	}
	rules, isArr := r["rules"].([]any)
	if !isArr {
		return "expiry_missing"
	}
	var expiry int64
	have := false
	for _, x := range rules {
		rule, ok := x.(map[string]any)
		if !ok || rule["type"] != "expiry" {
			return "unknown_rule_type"
		}
		if have {
			return "duplicate_expiry"
		}
		rd, _ := rule["data"].(map[string]any)
		ts, ok := k4SafeInt(rd["timestamp"])
		if !ok {
			return "expiry_malformed"
		}
		expiry, have = ts, true
	}
	if !have {
		return "expiry_missing"
	}
	if lim, _ := k4SafeInt(gm["expiresAtSec"]); expiry > lim {
		return "expiry_extended"
	}
	return ""
}
