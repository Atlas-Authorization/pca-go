package pca

// Verification of the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal,
// consistent with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for
// this audience, committing to exactly this AP2 charge). Run it after the AP2 chain verification, which establishes the AP2 signatures.

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Ap2PcaBindingError is returned when Ap2VerifyPcaBinding lacks the server-held state the policy decision needs. Code is
// "mandate_required" or "charge_history_required".
type Ap2PcaBindingError struct {
	Code string
	Msg  string
}

func (e *Ap2PcaBindingError) Error() string { return e.Msg }

// Ap2PcaHookResult is what a verification hook reports: a hook that Enforced and not OK refuses; the threshold hook's T is the
// threshold it actually enforced.
type Ap2PcaHookResult struct {
	Enforced, OK bool
	Reason       string
	T            *float64
}

// Ap2PcaHook is an attestation, threshold or revocation verifier. ctx carries pcactn, grant and (when a time was given) nowEpoch.
type Ap2PcaHook func(ctx map[string]any) Ap2PcaHookResult

// Ap2VerifyPcaBindingInput is the input of Ap2VerifyPcaBinding. Mandate (the PCA mandate state THIS verifier holds, with its live
// budget) and Decide (the PCA policy engine) are required: the decision is never skipped. RecentChargeTimes (epoch ms of this
// holder's earlier admitted charges, from the verifier's own records) is required (non-nil) when the mandate limits the charge count.
type Ap2VerifyPcaBindingInput struct {
	Open, Closed map[string]any
	// OpenHash is the sd_hash of the open payment mandate hop.
	OpenHash string
	// ExpectedPrincipal is the Ed25519 key (b64u) that must have signed the grant.
	ExpectedPrincipal string
	// PqPins are verifier-side PQ pins by Ed25519 identity.
	PqPins map[string]string
	// Audience is this verifier's PCA audience.
	Audience string
	// Now is the verification time, epoch ms (nil = the clock).
	Now               *float64
	Mandate           map[string]any
	RecentChargeTimes []float64
	Decide            ChargeDecider
	Attestation       Ap2PcaHook
	Threshold         Ap2PcaHook
	Revocation        Ap2PcaHook
	EnforceFreshness  *FreshnessGate
	EnforceTaint      *TaintGate
}

// Ap2PcaBindingResult: OK with PCActn, Grant and Terms, or not OK with Reason.
type Ap2PcaBindingResult struct {
	OK                   bool
	Reason               string
	PCActn, Grant, Terms map[string]any
}

func ap2BindFail(format string, a ...any) Ap2PcaBindingResult {
	return Ap2PcaBindingResult{Reason: fmt.Sprintf(format, a...)}
}

func ap2Includes(list any, v any) bool {
	l, _ := list.([]any)
	for _, x := range l {
		if jsStrictEq(x, v) {
			return true
		}
	}
	return false
}

func ap2FindType(constraints any, t string) (map[string]any, bool) {
	l, _ := constraints.([]any)
	for _, c := range l {
		if m, ok := c.(map[string]any); ok && m["type"] == t {
			return m, true
		}
	}
	return nil, false
}

// ap2Gt is JS `a > b` for two numbers; anything that is not a number compares false.
func ap2Gt(a, b any) bool {
	x, ok1 := jsNum(a)
	y, ok2 := jsNum(b)
	return !(ok1 && ok2 && finite(x) && x <= y) // a cap may be infinite, the compared value may not
}

// ap2ConstraintsWithinTerms checks the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant).
func ap2ConstraintsWithinTerms(open, terms map[string]any) (string, error) {
	cur := terms["currency"]
	perTx, err := ap2MinorTerm(terms["perTransactionCap"], "perTransactionCap")
	if err != nil {
		return "", err
	}
	cs := open["constraints"]
	rng, ok := ap2FindType(cs, "payment.amount_range")
	if !ok {
		return "open mandate has no amount_range to compare with the PCA per-transaction cap", nil
	}
	if !jsStrictEq(rng["currency"], cur) {
		return "amount_range currency differs from the PCA terms", nil
	}
	if ap2Gt(rng["max"], jsNumber(perTx)) {
		return fmt.Sprintf("amount_range.max %s exceeds the PCA per-transaction cap %s", ap2Str(rng["max"]), jsNumberString(perTx)), nil
	}
	payees, ok := ap2FindType(cs, "payment.allowed_payees")
	if !ok {
		return "open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side", nil
	}
	allowed, _ := payees["allowed"].([]any)
	for _, m := range allowed {
		if !ap2Includes(terms["merchants"], ap2Get(m, "id")) {
			return "allowed_payees names a merchant outside the PCA allowlist", nil
		}
	}
	budget, ok := ap2FindType(cs, "payment.budget")
	if !ok {
		return "open mandate has no budget to compare with the PCA cumulative cap", nil
	}
	if !jsStrictEq(budget["currency"], cur) {
		return "budget exceeds the PCA cumulative cap", nil
	}
	sdk, major, err := Ap2BudgetReads(budget["max"], cur)
	if err != nil {
		return "", err
	}
	capMinor, err := ap2MinorTerm(terms["cumulativeCap"], "cumulativeCap")
	if err != nil {
		return "", err
	}
	if sdk > capMinor || major > capMinor {
		return "budget exceeds the PCA cumulative cap", nil
	}
	if maxTx, has := terms["maxTransactionsPerPeriod"]; has {
		rec, ok := ap2FindType(cs, "payment.agent_recurrence")
		if !ok || rec["max_occurrences"] == nil || ap2Gt(rec["max_occurrences"], maxTx) {
			return "max_occurrences is missing or exceeds the PCA transaction limit", nil
		}
	}
	if pe, has := terms["periodEnd"]; has {
		pef, _ := jsNum(pe)
		exp, hasExp := open["exp"]
		if !hasExp || ap2Gt(exp, jsNumber(math.Floor(pef/1000))) {
			return "open mandate outlives the PCA period", nil
		}
	}
	return "", nil
}

// Ap2VerifyPcaBinding verifies the PCA side of a verified AP2 payment chain. A refusal is a result with OK false; missing
// server-held state (Mandate, RecentChargeTimes, Decide) is an *Ap2PcaBindingError. Any other fault is a refusal carrying its message.
func Ap2VerifyPcaBinding(i Ap2VerifyPcaBindingInput) (res Ap2PcaBindingResult, err error) {
	if i.Decide == nil {
		return res, ap2Fail("Ap2VerifyPcaBinding needs the PCA policy engine as Decide")
	}
	if i.Mandate == nil {
		return res, &Ap2PcaBindingError{"mandate_required", "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped"}
	}
	if tm, _ := i.Mandate["terms"].(map[string]any); tm != nil {
		if _, limited := tm["maxTransactionsPerPeriod"]; limited {
			bad := i.RecentChargeTimes == nil
			for _, t := range i.RecentChargeTimes {
				bad = bad || math.IsNaN(t) || math.IsInf(t, 0)
			}
			if bad {
				return res, &Ap2PcaBindingError{"charge_history_required", "the mandate limits the charge count: pass recentChargeTimes from your own records"}
			}
		}
	}
	defer func() {
		if r := recover(); r != nil {
			res, err = ap2BindFail("%v", r), nil
		}
	}()
	res, ferr := ap2verifyPcaBinding(i)
	if ferr != nil {
		return ap2BindFail("%s", ferr.Error()), nil // totality: any fault is a refusal carrying the message
	}
	return res, nil
}

func ap2verifyPcaBinding(i Ap2VerifyPcaBindingInput) (Ap2PcaBindingResult, error) {
	ver := ap2Num(Ap2PcaBindingVersion)
	oc, _ := i.Open["x_pca"].(map[string]any)
	grant, _ := oc["grant"].(map[string]any)
	terms, _ := oc["terms"].(map[string]any)
	if oc == nil || !ap2StrictEq(ap2Get(oc, "v"), ver) || grant == nil || terms == nil {
		return ap2BindFail("open mandate carries no x_pca grant"), nil
	}
	if why, ok := VerifyChainPolicy([]any{grant}, i.ExpectedPrincipal, true, nil, i.PqPins, nil); !ok {
		return ap2BindFail("PCA grant: %s", why), nil
	}
	env := ReadEnvelope(grant)
	if env == nil {
		return ap2BindFail("PCA grant has no envelope"), nil
	}
	preds, err := MandatePredicates(terms)
	if err != nil {
		return res0, err
	}
	cavs, err := MandateCaveats(terms)
	if err != nil {
		return res0, err
	}
	for _, p := range [][2]any{{env["predicates"], preds}, {env["caveats"], cavs}} {
		a, e1 := HashCanonical(p[0])
		b, e2 := HashCanonical(p[1])
		if e1 != nil || e2 != nil {
			return res0, fmt.Errorf("canonical hash failed")
		}
		if a != b {
			return ap2BindFail("x_pca terms do not match the grant envelope"), nil
		}
	}
	rp, _ := env["risk_policy"].(map[string]any)
	if !jsStrictEq(rp["kappa"], terms["perTransactionCap"]) || !jsStrictEq(rp["bMax"], terms["cumulativeCap"]) {
		return ap2BindFail("x_pca terms do not match the grant risk policy"), nil
	}
	if within, err := ap2ConstraintsWithinTerms(i.Open, terms); err != nil {
		return res0, err
	} else if within != "" {
		return ap2BindFail("%s", within), nil
	}

	cc, _ := i.Closed["x_pca"].(map[string]any)
	pcactn, _ := cc["pcactn"].(map[string]any)
	charge, _ := cc["charge"].(map[string]any)
	if cc == nil || !ap2StrictEq(ap2Get(cc, "v"), ver) || pcactn == nil || charge == nil {
		return ap2BindFail("closed mandate carries no x_pca PCActn"), nil
	}
	amt, _ := i.Closed["payment_amount"].(map[string]any)
	payee, _ := i.Closed["payee"].(map[string]any)
	if amt == nil || payee == nil {
		return res0, ap2Fail("closed mandate lacks payment_amount or payee")
	}
	if !ap2StrictEq(ap2Get(charge, "currency"), ap2Get(amt, "currency")) || !ap2StrictEq(ap2Get(charge, "amount"), ap2Get(amt, "amount")) {
		return ap2BindFail("x_pca charge differs from the mandate payment_amount"), nil
	}
	cats, ok := terms["categories"].([]any)
	if !ok {
		return res0, ap2Fail("Cannot read properties of undefined (reading 'length')")
	}
	category, hasCat := charge["category"].(string)
	if len(cats) > 0 && (!hasCat || !ap2Includes(cats, category)) {
		return ap2BindFail("x_pca charge lacks an allowed category"), nil
	}

	now := float64(time.Now().UnixMilli())
	if i.Now != nil {
		now = *i.Now
	}
	core, err := VerifyPCActnCoreWith(pcactn, grant, int64(now), i.Audience, VerifyOptions{InsecureSkipPlanRootCheck: true,
		EnforceFreshness: i.EnforceFreshness, EnforceTaint: i.EnforceTaint})
	if err != nil {
		return res0, err
	}
	if !core.Allow {
		reason := core.Reason
		if reason == "" {
			reason = "rejected"
		}
		return ap2BindFail("PCActn: %s", reason), nil
	}
	hookCtx := map[string]any{"pcactn": pcactn, "grant": grant}
	if i.Now != nil {
		hookCtx["nowEpoch"] = jsNumber(*i.Now)
	}
	var enforcedT *float64 // the t the threshold hook REPORTS: a hook built for a smaller t cannot satisfy a charge that needs more
	for _, h := range []struct {
		name string
		hook Ap2PcaHook
	}{{"attestation", i.Attestation}, {"threshold", i.Threshold}, {"revocation", i.Revocation}} {
		if h.hook == nil {
			continue
		}
		r := h.hook(hookCtx)
		if h.name == "threshold" && r.Enforced && r.OK && r.T != nil && !math.IsNaN(*r.T) {
			enforcedT = r.T
		}
		if r.Enforced && !r.OK {
			why := r.Reason
			if why == "" {
				why = "rejected"
			}
			return ap2BindFail("PCActn: %s: %s", h.name, why), nil
		}
	}

	action, _ := pcactn["action"].(map[string]any)
	payeeID := ap2Get(payee, "id")
	if !jsStrictEq(ap2Get(action, "verb"), "charge") || !jsStrictEq(ap2Get(action, "resource"), "merchant:"+ap2Str(payeeID)) {
		return ap2BindFail("PCActn action is not a charge at this payee"), nil
	}
	params := map[string]any{"amount": ap2Get(charge, "amount"), "currency": ap2Get(charge, "currency")}
	if hasCat {
		params["category"] = category
	}
	if ap2IsU(params["amount"]) || ap2IsU(params["currency"]) {
		return res0, ap2Fail("canonical JSON cannot encode an undefined charge member")
	}
	pd, err := ParamsDigest(params)
	if err != nil {
		return res0, err
	}
	if !jsStrictEq(ap2Get(action, "params_digest"), pd) {
		return ap2BindFail("PCActn params do not commit to the x_pca charge"), nil
	}
	jkt, err := Ap2JwkThumbprint(ap2Get(ap2Get(i.Open, "cnf"), "jwk"))
	if err != nil {
		return res0, err
	}
	facts := map[string]any{"transactionId": ap2Get(i.Closed, "transaction_id"), "payeeId": payeeID, "amount": ap2Get(amt, "amount"),
		"currency": ap2Get(amt, "currency"), "instrumentId": ap2Get(ap2Get(i.Closed, "payment_instrument"), "id"), "openHash": i.OpenHash, "agentJkt": jkt}
	for _, v := range facts {
		if ap2IsU(v) {
			return res0, ap2Fail("canonical JSON cannot encode an undefined binding fact")
		}
	}
	nonce, err := Ap2PcaBindingNonce(facts)
	if err != nil {
		return res0, err
	}
	if !jsStrictEq(ap2Get(pcactn, "nonce"), nonce) {
		return ap2BindFail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key"), nil
	}
	perTx, err := ap2MinorTerm(terms["perTransactionCap"], "perTransactionCap")
	if err != nil {
		return res0, err
	}
	if ap2Gt(amt["amount"], jsNumber(perTx)) {
		return ap2BindFail("payment exceeds the PCA per-transaction cap"), nil
	}
	// The agent may not understate the risk of its own charge; a charge whose risk needs a human co-sign (t > 1) needs a threshold verifier.
	amount, _ := jsNum(amt["amount"])
	capF, _ := jsNum(terms["perTransactionCap"])
	recomputed := Ap2RiskRatio(amount, capF)
	claimed, ok := jsNum(ap2Get(ap2Get(pcactn, "risk_claim"), "r"))
	if !ok || !(claimed >= recomputed-1e-9) {
		return ap2BindFail("PCActn understates the risk of this charge"), nil
	}
	need := RequiredThresholdOf(claimed, jsF(rp["theta1"]), jsF(rp["theta2"]), false)
	if need.T > 1 && i.Threshold == nil {
		return ap2BindFail("this charge needs a threshold of %d (human co-sign); supply a threshold hook to verify it", need.T), nil
	}
	if need.T > 1 && !(enforcedT != nil && *enforcedT >= float64(need.T)) {
		got := "unreported"
		if enforcedT != nil {
			got = jsNumberString(*enforcedT)
		}
		return ap2BindFail("this charge needs a threshold of %d but the threshold hook enforced t=%s; build it with createThresholdVerifier({ t: %d })", need.T, got, need.T), nil
	}
	if !jsStrictEq(ap2Get(amt, "currency"), terms["currency"]) || !ap2Includes(terms["merchants"], payeeID) {
		return ap2BindFail("payment currency or payee is outside the PCA terms"), nil
	}

	mg, err1 := HashCanonical(i.Mandate["grant"])
	gg, err2 := HashCanonical(grant)
	if err1 != nil || err2 != nil || mg != gg {
		return ap2BindFail("the supplied PCA mandate is not the one in the open mandate"), nil
	}
	// grant was verified above under the caller-pinned principal; the decision is bound to it
	recent := make([]any, len(i.RecentChargeTimes))
	for k, t := range i.RecentChargeTimes {
		recent[k] = jsNumber(t)
	}
	spend := map[string]any{"merchant": payeeID, "amount": amt["amount"], "currency": amt["currency"], "recentChargeTimes": recent}
	if hasCat {
		spend["category"] = category
	}
	if i.Now != nil {
		spend["now"] = jsNumber(*i.Now)
	}
	decision, err := AuthorizeCharge(i.Mandate, spend, grant, i.Decide)
	if err != nil {
		return res0, err
	}
	switch decision["outcome"] {
	case "deny":
		var rs []string
		rl, _ := decision["reasons"].([]any)
		for _, r := range rl {
			rs = append(rs, ap2Str(r))
		}
		return ap2BindFail("PCA denies this charge: %s", strings.Join(rs, "; ")), nil
	case "step_up":
		if !(enforcedT != nil && *enforcedT >= 2) {
			return ap2BindFail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced"), nil
		}
	}
	return Ap2PcaBindingResult{OK: true, PCActn: pcactn, Grant: grant, Terms: terms}, nil
}

var res0 Ap2PcaBindingResult
