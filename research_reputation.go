package pca

import (
	"errors"
	"fmt"
	"math"
)

// Reputation and underwriting: an explainable score in [0,1] from a subject's activity and disputes, a transparent premium curve, and
// signed coverage quotes the verifier recomputes. Inputs and results are JSON objects.

// MaxReputationRecords is the most events or disputes one reputation input may carry.
const MaxReputationRecords = 100_000

// CoverageQuoteDomain is the signing domain of a coverage quote.
const CoverageQuoteDomain = "atlas-pca/coverage-quote/v1\x00"

var reputationOutcomes = map[string]bool{"auto": true, "step_up": true, "deny": true, "executed": true}

// reputationListOr reads a member the way the reference defaults it to []: absent is empty, a non-array (even null) is invalid (nil, false).
func reputationListOr(m map[string]any, k string) ([]any, bool) {
	v, present := m[k]
	if !present {
		return []any{}, true
	}
	l, ok := v.([]any)
	return l, ok
}

// ValidateReputationInput returns why the input is unusable, or "" when it is sound.
func ValidateReputationInput(input map[string]any) string {
	subject, _ := input["subject"].(string)
	if subject == "" {
		return "subject must be a non-empty string"
	}
	events, ok1 := reputationListOr(input, "events")
	disputes, ok2 := reputationListOr(input, "disputes")
	if !ok1 || !ok2 {
		return "events and disputes must be arrays"
	}
	if len(events) > MaxReputationRecords || len(disputes) > MaxReputationRecords {
		return "too many records"
	}
	for _, e := range events {
		m := rsMap(e)
		o, _ := m["outcome"].(string)
		if m == nil || !reputationOutcomes[o] {
			return "event with an unknown outcome"
		}
	}
	for _, o := range disputes {
		d := rsMap(o)
		id, _ := d["id"].(string)
		if d == nil || id == "" {
			return "dispute without an id"
		}
		if s, _ := d["subject"].(string); s != subject || d["subject"] == nil {
			return "dispute for another subject"
		}
		if _, ok := d["slashed"].(bool); !ok {
			return "dispute.slashed must be a boolean"
		}
		if !rsFinite(d["at"]) || jsF(d["at"]) < 0 {
			return "dispute.at must be finite and >= 0"
		}
		if rsHas(d, "amount") && (!rsFinite(d["amount"]) || jsF(d["amount"]) < 0) {
			return "dispute.amount must be finite and >= 0"
		}
	}
	return ""
}

func reputationRec(subject any, actions, autos, stepUps, denies, slashes, disputes int, score float64, factors []any) map[string]any {
	n := func(i int) any { return jsNumber(float64(i)) }
	return map[string]any{"subject": subject, "actions": n(actions), "autos": n(autos), "stepUps": n(stepUps), "denies": n(denies),
		"slashes": n(slashes), "disputes": n(disputes), "score": rsN(score), "factors": factors}
}

// Reputation is the reputation of a subject: it starts at 1 and subtracts explainable penalties (the deny rate, a milder step-up rate
// and, dominant, slashed disputes); a subject with no history scores a neutral 0.5; unusable input fails closed to 0. The input is
// {subject, events: [{outcome}], disputes: [{id, subject, slashed, at, amount?}]}.
func Reputation(input map[string]any) map[string]any {
	if bad := ValidateReputationInput(input); bad != "" {
		subject := ""
		if s := input["subject"]; s != nil {
			subject = jsValueString(s)
		}
		return reputationRec(subject, 0, 0, 0, 0, 0, 0, 0, []any{"invalid input: " + bad})
	}
	events, _ := reputationListOr(input, "events")
	rawDisputes, _ := reputationListOr(input, "disputes")
	seen := map[string]bool{}
	var disputes []map[string]any
	for _, o := range rawDisputes {
		d := rsMap(o)
		if id := d["id"].(string); !seen[id] {
			seen[id] = true
			disputes = append(disputes, d)
		}
	}
	actions := len(events)
	var autos, stepUps, denies, slashes int
	for _, e := range events {
		switch rsMap(e)["outcome"] {
		case "auto":
			autos++
		case "step_up":
			stepUps++
		case "deny":
			denies++
		}
	}
	for _, d := range disputes {
		if d["slashed"] == true {
			slashes++
		}
	}
	if actions == 0 && len(disputes) == 0 {
		return reputationRec(input["subject"], actions, autos, stepUps, denies, slashes, 0, 0.5, []any{"unproven (no history)"})
	}
	factors := []any{}
	score := 1.0
	if actions > 0 {
		denyRate, stepUpRate := float64(denies)/float64(actions), float64(stepUps)/float64(actions)
		if denyRate > 0 {
			score -= float64(0.6 * denyRate)
			factors = append(factors, "deny rate "+rsToFixed(denyRate*100, 0)+"%")
		}
		if stepUpRate > 0 {
			score -= float64(0.15 * stepUpRate)
			factors = append(factors, "step-up rate "+rsToFixed(stepUpRate*100, 0)+"%")
		}
	}
	if slashes > 0 {
		score -= math.Min(0.8, 0.3*float64(slashes))
		plural := ""
		if slashes > 1 {
			plural = "s"
		}
		factors = append(factors, fmt.Sprintf("%d slashed dispute%s", slashes, plural))
	}
	if len(factors) == 0 {
		factors = append(factors, "clean history")
	}
	return reputationRec(input["subject"], actions, autos, stepUps, denies, slashes, len(disputes), math.Max(0, math.Min(1, score)), factors)
}

// ---- underwriting ----------------------------------------------------------------------------------------------

func reputationOpt(opts map[string]any, k string, dflt float64) float64 {
	v := opts[k]
	if v == nil {
		return dflt
	}
	return jsF(v) // a non-number is NaN
}

func reputationPricing(declined bool, premium, coverage float64, rationale string) map[string]any {
	return map[string]any{"declined": declined, "premium": rsN(premium), "coverage": rsN(coverage), "rationale": rationale}
}

// PriceCoverage prices coverage of exposure for a subject with the given score (nil: invalid):
// premium = baseRate * exposure * (1 + riskLoad * (1 - score)), declined below minScore. opts may carry baseRate (0.01), riskLoad (4)
// and minScore (0.25). A non-finite exposure counts as 0.
func PriceCoverage(score *float64, exposure float64, opts map[string]any) map[string]any {
	baseRate, riskLoad, minScore := reputationOpt(opts, "baseRate", 0.01), reputationOpt(opts, "riskLoad", 4), reputationOpt(opts, "minScore", 0.25)
	if score == nil || math.IsNaN(*score) || math.IsInf(*score, 0) || *score < 0 || *score > 1 {
		return reputationPricing(true, 0, 0, "invalid reputation score")
	}
	s := *score
	exp := 0.0
	if !math.IsNaN(exposure) && !math.IsInf(exposure, 0) {
		exp = math.Max(0, exposure)
	}
	if s < minScore {
		return reputationPricing(true, 0, 0, "reputation "+rsToFixed(s, 2)+" below underwriting floor "+rsNumStr(minScore))
	}
	load := 1 + float64(riskLoad*(1-s))
	return reputationPricing(false, baseRate*exp*load, exp, "base "+rsNumStr(baseRate)+" × exposure "+rsNumStr(exp)+" × load "+rsToFixed(load, 2)+" (score "+rsToFixed(s, 2)+")")
}

// ---- signed coverage quotes -------------------------------------------------------------------------------------

func reputationQuoteMessage(claim map[string]any) ([]byte, error) {
	body, ok := canonicalLenient(claim) // the reference signs canonicalBytesLenient: high-precision premiums are legitimate here
	if !ok {
		return nil, errors.New("canonicalize: non-finite number")
	}
	return append([]byte(CoverageQuoteDomain), body...), nil
}

// IssueCoverageQuote prices and signs a quote for a reputation. It errors on a bad score, expiry or exposure (it never signs a
// nonsense quote).
func IssueCoverageQuote(rep map[string]any, exposure float64, underwriter *KeyPair, now, ttlMs float64, opts map[string]any) (map[string]any, error) {
	if math.IsNaN(exposure) || math.IsInf(exposure, 0) || exposure < 0 {
		return nil, errors.New("issueCoverageQuote: exposure must be finite and >= 0")
	}
	if math.IsNaN(now) || math.IsInf(now, 0) || !(ttlMs > 0) || math.IsInf(ttlMs, 0) {
		return nil, errors.New("issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0")
	}
	if !rsIsNum(rep["score"]) || !rsFinite(rep["score"]) || jsF(rep["score"]) < 0 || jsF(rep["score"]) > 1 {
		return nil, errors.New("issueCoverageQuote: invalid reputation score")
	}
	score := jsF(rep["score"])
	baseRate, riskLoad, minScore := reputationOpt(opts, "baseRate", 0.01), reputationOpt(opts, "riskLoad", 4), reputationOpt(opts, "minScore", 0.25)
	p := PriceCoverage(&score, exposure, map[string]any{"baseRate": rsN(baseRate), "riskLoad": rsN(riskLoad), "minScore": rsN(minScore)})
	if _, has := rep["subject"]; !has { // `subject: rep.subject` is undefined, which the reference's canonicalizer refuses
		return nil, errors.New("canonicalize: unsupported type undefined")
	}
	claim := map[string]any{"v": jsNumber(1), "subject": rep["subject"], "score": rep["score"], "exposure": rsN(exposure), "baseRate": rsN(baseRate),
		"riskLoad": rsN(riskLoad), "minScore": rsN(minScore), "declined": p["declined"], "premium": p["premium"], "coverage": p["coverage"],
		"issued_at": rsN(now), "expires_at": rsN(now + ttlMs), "underwriter": underwriter.Public}
	msg, err := reputationQuoteMessage(claim)
	if err != nil {
		return nil, err
	}
	q := make(map[string]any, len(claim)+1)
	for k, v := range claim {
		q[k] = v
	}
	q["sig"] = B64u(underwriter.Sign(msg))
	return q, nil
}

func reputationVerdict(reason string) map[string]any {
	if reason == "" {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": reason}
}

// VerifyCoverageQuote verifies a quote: pinned underwriter, signature, validity window, and the premium RECOMPUTED from the stated
// inputs. It returns {ok: true} or {ok: false, reason} and never fails.
func VerifyCoverageQuote(quote any, underwriter string, now float64) (out map[string]any) {
	defer func() {
		if recover() != nil {
			out = reputationVerdict("malformed")
		}
	}()
	q := rsMap(quote)
	if q == nil {
		return reputationVerdict("malformed")
	}
	if v, ok := jsNum(q["v"]); !ok || v != 1 {
		return reputationVerdict("malformed")
	}
	sig, ok := q["sig"].(string)
	if !ok {
		return reputationVerdict("malformed")
	}
	for _, k := range []string{"score", "exposure", "baseRate", "riskLoad", "minScore", "premium", "coverage", "issued_at", "expires_at"} {
		if !rsFinite(q[k]) {
			return reputationVerdict("malformed")
		}
	}
	declined, ok1 := q["declined"].(bool)
	_, ok2 := q["subject"].(string)
	if !ok1 || !ok2 {
		return reputationVerdict("malformed")
	}
	if pinned, _ := q["underwriter"].(string); underwriter == "" || q["underwriter"] != any(underwriter) || pinned == "" {
		return reputationVerdict("underwriter")
	}
	claim := make(map[string]any, len(q))
	for k, v := range q {
		if k != "sig" {
			claim[k] = v
		}
	}
	msg, err := reputationQuoteMessage(claim)
	if err != nil {
		return reputationVerdict("malformed")
	}
	if !VerifyB64u(underwriter, msg, sig) {
		return reputationVerdict("signature")
	}
	if math.IsNaN(now) || math.IsInf(now, 0) || now < jsF(q["issued_at"]) {
		return reputationVerdict("not-yet-valid")
	}
	if !(now < jsF(q["expires_at"])) {
		return reputationVerdict("expired")
	}
	score := jsF(q["score"])
	p := PriceCoverage(&score, jsF(q["exposure"]), map[string]any{"baseRate": q["baseRate"], "riskLoad": q["riskLoad"], "minScore": q["minScore"]})
	if p["declined"] != any(declined) || jsF(p["premium"]) != jsF(q["premium"]) || jsF(p["coverage"]) != jsF(q["coverage"]) {
		return reputationVerdict("price-mismatch")
	}
	return reputationVerdict("")
}
