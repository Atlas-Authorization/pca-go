package pca

// Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities
// in ppm, money in minor units; no floats, no randomness, no clock). Every input is explicit and comes from a principal-SIGNED
// configuration; anything missing, out of range or unsigned means ASK. The only learned component is a per-principal multiplier
// that scales P(bad) UP, so it can only add asks; asking less needs a principal-signed autonomy raise. Signing takes the
// principal's 32-byte Ed25519 seed.

import (
	"errors"
	"math"
	"math/big"
)

const (
	// WalletPPM is one in parts per million.
	WalletPPM = 1000000
	// WalletMaxMultiplierPPM caps the learned multiplier.
	WalletMaxMultiplierPPM = 100 * WalletPPM
)

func walletIsMinor(v any) bool {
	return jsIsSafeInteger(v) && jsF(v) >= 0
}

func walletIsOne(v any) bool { return wNumEq(v, 1) }

func walletKindMsg(kind string, body any) ([]byte, error) {
	h, err := HashCanonical(map[string]any{"kind": kind, "body": body})
	return []byte(h), err
}

func walletSign(seed []byte, kind string, body any) (string, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return "", err
	}
	msg, err := walletKindMsg(kind, body)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(kp.Sign(msg)), nil
}

// walletVerifyKind checks the signature of a body; a body that cannot be hashed or a key / signature that is not base64url is an
// error (the reference throws).
func walletVerifyKind(principal, kind string, body any, sig string) (bool, error) {
	msg, err := walletKindMsg(kind, body)
	if err != nil {
		return false, err
	}
	pk, ok := DecodeB64uStrict(principal, -1)
	if !ok {
		return false, errors.New("bad base64url")
	}
	sg, ok := DecodeB64uStrict(sig, -1)
	if !ok {
		return false, errors.New("bad base64url")
	}
	return VerifyStrict(pk, msg, sg), nil
}

func walletWithoutSig(m map[string]any) map[string]any { return withoutKeys(m, "sig") }

// WalletSignPricingConfig signs a pricing configuration body with the principal's seed.
func WalletSignPricingConfig(body map[string]any, principalSeed []byte) (map[string]any, error) {
	sig, err := walletSign(principalSeed, "pca.escalation_pricing", body)
	if err != nil {
		return nil, err
	}
	out := withoutKeys(body)
	out["sig"] = sig
	return out, nil
}

// WalletPricingConfigError is why a signed pricing configuration is refused ("" when it verifies; a pure function of its content).
func WalletPricingConfigError(c any) string {
	x, ok := c.(map[string]any)
	if !ok {
		return "config_malformed"
	}
	principal, okP := x["principal"].(string)
	_, okC := x["currency"].(string)
	sig, okS := x["sig"].(string)
	if !walletIsOne(x["v"]) || !okP || !okC || !okS {
		return "config_malformed"
	}
	if !(walletIsMinor(x["interruptionCost"]) && walletIsMinor(x["maxInterruptionCost"]) && walletIsMinor(x["hardCeilingLoss"]) && walletIsMinor(x["epoch"])) {
		return "config_amounts_invalid"
	}
	if jsF(x["interruptionCost"]) > jsF(x["maxInterruptionCost"]) {
		return "config_cost_above_max"
	}
	step := x["tightenStepPpm"]
	if !jsIsSafeInteger(step) || jsF(step) < 0 || jsF(step) > WalletMaxMultiplierPPM {
		return "config_step_invalid"
	}
	good, err := walletVerifyKind(principal, "pca.escalation_pricing", walletWithoutSig(x), sig)
	if err != nil {
		return "config_malformed"
	}
	if !good {
		return "config_signature_invalid"
	}
	return ""
}

// WalletFreshCalibration is the starting calibration.
func WalletFreshCalibration() map[string]any {
	return map[string]any{"multiplierPpm": wN(WalletPPM), "seen": []any{}}
}

func walletDecision(ask bool, reason string) map[string]any {
	return map[string]any{"ask": ask, "reason": reason}
}

func walletBig(v any) *big.Int {
	f, _ := jsNum(v)
	return big.NewInt(int64(f))
}

// WalletDecideEscalation is pure and total: {ask, reason}. Anything unverifiable or out of range asks.
func WalletDecideEscalation(config map[string]any, cal any, a any) map[string]any {
	if e := WalletPricingConfigError(config); e != "" {
		return walletDecision(true, e)
	}
	am, ok := a.(map[string]any)
	if !ok || am["currency"] != config["currency"] {
		return walletDecision(true, "currency_mismatch")
	}
	loss, p := am["loss"], am["pBadUpperPpm"]
	if !walletIsMinor(loss) || wIsNegZero(loss) || !jsIsSafeInteger(p) || jsF(p) < 0 || wIsNegZero(p) || jsF(p) > WalletPPM {
		return walletDecision(true, "risk_input_invalid")
	}
	cm, _ := cal.(map[string]any)
	mult := cm["multiplierPpm"]
	if !(jsIsSafeInteger(mult) && jsF(mult) >= WalletPPM && jsF(mult) <= WalletMaxMultiplierPPM) {
		return walletDecision(true, "calibration_invalid")
	}
	if jsF(loss) > jsF(config["hardCeilingLoss"]) {
		return walletDecision(true, "above_hard_ceiling")
	}
	pe := new(big.Int).Mul(walletBig(p), walletBig(mult))
	ppm2 := new(big.Int).Mul(big.NewInt(WalletPPM), big.NewInt(WalletPPM))
	if pe.Cmp(ppm2) > 0 {
		pe = ppm2
	}
	lhs := new(big.Int).Mul(pe, walletBig(loss))
	rhs := new(big.Int).Mul(walletBig(config["interruptionCost"]), ppm2)
	if lhs.Cmp(rhs) > 0 {
		return walletDecision(true, "expected_loss_exceeds_interruption_cost")
	}
	return walletDecision(false, "expected_loss_within_interruption_cost")
}

// WalletSignAnswer signs an escalation answer body with the principal's seed.
func WalletSignAnswer(body map[string]any, principalSeed []byte) (map[string]any, error) {
	sig, err := walletSign(principalSeed, "pca.escalation_answer", body)
	if err != nil {
		return nil, err
	}
	out := withoutKeys(body)
	out["sig"] = sig
	return out, nil
}

func walletAnswerOK(av any, principal string) bool {
	a, ok := av.(map[string]any)
	if !ok || !walletIsOne(a["v"]) || a["principal"] != principal {
		return false
	}
	nonce, okN := a["nonce"].(string)
	_, okD := a["action_digest"].(string)
	if !okN || jsLen(nonce) < 8 || !okD || (a["answer"] != "approve" && a["answer"] != "deny") {
		return false
	}
	sig, okS := a["sig"].(string)
	if !okS {
		return false
	}
	good, err := walletVerifyKind(principal, "pca.escalation_answer", walletWithoutSig(a), sig)
	return err == nil && good
}

// WalletUpdateCalibration folds signed answers into the calibration. A DENY the principal gave to an action that the CURRENT
// pricing would have auto-approved is a miss and adds tightenStepPpm (capped); anything else changes nothing. The multiplier never
// decreases. risks maps an action digest to its risk.
func WalletUpdateCalibration(config map[string]any, cal map[string]any, answers []any, risks map[string]any) (map[string]any, error) {
	if WalletPricingConfigError(config) != "" {
		return cal, nil
	}
	if !wIsNumber(cal["multiplierPpm"]) {
		return nil, errors.New("calibration: multiplierPpm is not a number")
	}
	seenList, ok := cal["seen"].([]any)
	if !ok {
		return nil, errors.New("calibration: seen is not iterable")
	}
	mult0 := jsF(cal["multiplierPpm"])
	mult := mult0
	seen := map[string]bool{}
	order := append([]any{}, seenList...)
	for _, s := range seenList {
		if str, isS := s.(string); isS {
			seen[str] = true
		}
	}
	principal, _ := config["principal"].(string)
	for _, av := range answers {
		if !walletAnswerOK(av, principal) {
			continue
		}
		a := av.(map[string]any)
		nonce := a["nonce"].(string)
		if seen[nonce] {
			continue
		}
		seen[nonce] = true
		order = append(order, nonce)
		risk, has := risks[a["action_digest"].(string)]
		if a["answer"] != "deny" || !has {
			continue
		}
		if !WalletDecideEscalation(config, map[string]any{"multiplierPpm": jsNumber(mult), "seen": []any{}}, risk)["ask"].(bool) {
			mult = math.Min(WalletMaxMultiplierPPM, mult+jsF(config["tightenStepPpm"]))
		}
	}
	return map[string]any{"multiplierPpm": jsNumber(math.Max(mult, mult0)), "seen": order}, nil
}

// WalletSignAutonomyRaise signs an autonomy raise body with the principal's seed.
func WalletSignAutonomyRaise(body map[string]any, seed []byte) (map[string]any, error) {
	sig, err := walletSign(seed, "pca.autonomy_raise", body)
	if err != nil {
		return nil, err
	}
	out := withoutKeys(body)
	out["sig"] = sig
	return out, nil
}

// WalletApplyAutonomyRaise: a higher interruption cost means fewer asks. It needs the principal's signature, a strictly newer
// epoch and a cost within maxInterruptionCost; it errors otherwise.
func WalletApplyAutonomyRaise(config, raise map[string]any, principalSeed []byte) (map[string]any, error) {
	ok := false
	principal, okP := config["principal"].(string)
	sig, okS := raise["sig"].(string)
	if walletIsOne(raise["v"]) && okP && raise["principal"] == principal && okS {
		good, err := walletVerifyKind(principal, "pca.autonomy_raise", walletWithoutSig(raise), sig)
		ok = err == nil && good
	}
	if !ok {
		return nil, errors.New("applyAutonomyRaise: signature or principal invalid")
	}
	if !(jsF(raise["epoch"]) > jsF(config["epoch"])) {
		return nil, errors.New("applyAutonomyRaise: epoch must advance")
	}
	cost := raise["newInterruptionCost"]
	if !walletIsMinor(cost) || jsF(cost) > jsF(config["maxInterruptionCost"]) {
		return nil, errors.New("applyAutonomyRaise: above the configured maximum")
	}
	body := walletWithoutSig(config)
	body["interruptionCost"] = cost
	body["epoch"] = raise["epoch"]
	return WalletSignPricingConfig(body, principalSeed)
}
