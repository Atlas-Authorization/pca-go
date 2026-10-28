package pca

// Optimistic-path verification (extension layer): bonded claims, the challenge window, fraud proofs (wire level) and
// guardian-signed settlement records. Inputs are parsed JSON values; nothing here panics on hostile input.
//
// A fraud proof is only convincing because the settlement layer RE-RUNS the Policy VM on its server-held open-time
// snapshot; FraudProofWireCheck does not do that (no native SDK evaluates the Policy VM decision). It checks that the
// proof is well formed, names this claim and bond, and carries the decision its kind requires.

import (
	"math"
)

const (
	claimDomain      = "atlas-pca/optimistic/v1\x00"
	settlementDomain = "atlas-pca/bond-settlement/v1\x00"
	irreversibleCls  = "irreversible"
	defaultRMargin   = 1e-9
)

// ChallengeWindowPolicy bounds a claim's issued_at skew and window length (milliseconds).
type ChallengeWindowPolicy struct {
	MinWindowMs, MaxWindowMs, MaxSkewMs float64
}

// DefaultChallengeWindowPolicy is the library default (1 s minimum, 24 h maximum, 5 s skew).
var DefaultChallengeWindowPolicy = ChallengeWindowPolicy{MinWindowMs: 1000, MaxWindowMs: 86_400_000, MaxSkewMs: 5000}

func extFinite(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// extObject treats a JSON object (and, like JavaScript, an array) as an object; anything else is not.
func extObject(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case []any:
		return map[string]any{}, true
	}
	return nil, false
}

// extSignedLenient verifies sig over domain || lenient-canonical(body); a body the lenient form refuses fails.
func extSignedLenient(pub, domain string, body map[string]any, sig any) (ok bool, canon bool) {
	s, isStr := sig.(string)
	c, cok := canonicalLenient(body)
	if !cok {
		return false, false
	}
	return isStr && verifyB64u(pub, append([]byte(domain), c...), s), true
}

// ClaimCheck returns the FIRST check a bonded claim fails, or "ok": malformed, irreversible, digest, claimed_r,
// window, signature. The claim must cover expectedPcactnDigest, be signed by signerPublic, and its window must sit
// within the policy of serverNow.
func ClaimCheck(claim any, expectedPcactnDigest, signerPublic string, serverNow float64, p ChallengeWindowPolicy) string {
	c, ok := extObject(claim)
	if !ok {
		return "malformed"
	}
	if rc, _ := c["reversibility_class"].(string); rc == irreversibleCls {
		return "irreversible"
	}
	if d, isStr := c["pcactn_digest"].(string); !isStr || d != expectedPcactnDigest {
		return "digest"
	}
	if _, ok := extFinite(c["claimed_r"]); !ok {
		return "claimed_r"
	}
	issued, ok1 := extFinite(c["issued_at"])
	window, ok2 := extFinite(c["challenge_window_ms"])
	if !ok1 || !ok2 || math.IsNaN(serverNow) || math.IsInf(serverNow, 0) ||
		math.Abs(issued-serverNow) > p.MaxSkewMs || window < p.MinWindowMs || window > p.MaxWindowMs {
		return "window"
	}
	body := make(map[string]any, len(c))
	for k, v := range c {
		if k != "sig" {
			body[k] = v
		}
	}
	good, canon := extSignedLenient(signerPublic, claimDomain, body, c["sig"])
	if !canon {
		return "malformed"
	}
	if !good {
		return "signature"
	}
	return "ok"
}

// ChallengeWindowEnd is the last instant (epoch ms) at which a challenge is accepted: issued_at + window.
func ChallengeWindowEnd(issuedAt, windowMs float64) float64 { return issuedAt + windowMs }

// WithinChallengeWindow is true while challenges are accepted: now <= issued_at + window (inclusive end).
func WithinChallengeWindow(issuedAt, windowMs, now float64) bool {
	return !math.IsNaN(now) && !math.IsInf(now, 0) && now <= ChallengeWindowEnd(issuedAt, windowMs)
}

// ClaimStatus is "open" while challenges are accepted, else "finalized".
func ClaimStatus(issuedAt, windowMs, now float64) string {
	if WithinChallengeWindow(issuedAt, windowMs, now) {
		return "open"
	}
	return "finalized"
}

// extNumEq is JavaScript === between two JSON values (numbers by value, otherwise by canonical form; both absent equal).
func extNumEq(m1, m2 map[string]any, k string) bool {
	a, h1 := m1[k]
	b, h2 := m2[k]
	if h1 != h2 {
		return false
	}
	if !h1 {
		return true
	}
	if x, ok := jsNum(a); ok {
		y, ok := jsNum(b)
		return ok && x == y
	}
	return extSame(a, b)
}

// FraudProofWireCheck returns the first wire-level check a fraud proof fails against the claim it names, or "ok":
// malformed, digest, bond, claimed_r, kind, consistency. See the file comment for what it does not do.
func FraudProofWireCheck(claim, proof any) string {
	c, ok1 := extMap(claim)
	p, ok2 := extMap(proof)
	if !ok1 || !ok2 {
		return "malformed"
	}
	d, ok := extMap(p["decision"])
	if !ok {
		return "malformed"
	}
	rel, ok1 := d["releaseGuardianShare"].(bool)
	opt, ok2 := d["optimisticAllowed"].(bool)
	r, ok3 := extFinite(d["r"])
	_, ok4 := p["pcactn_digest"].(string)
	_, ok5 := p["bond_ref"].(string)
	_, ok6 := p["reason"].(string)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return "malformed"
	}
	if !extNumEq(p, c, "pcactn_digest") {
		return "digest"
	}
	if !extNumEq(p, c, "bond_ref") {
		return "bond"
	}
	if !extNumEq(p, c, "claimed_r") {
		return "claimed_r"
	}
	kind, _ := p["kind"].(string)
	margin := defaultRMargin
	if m, ok := extFinite(p["r_margin"]); ok {
		margin = math.Max(0, m)
	}
	var holds bool
	switch kind {
	case "irreversible":
		ev := "" // proof.evidence?.action?.action?.reversibility_class
		if e, ok := extMap(p["evidence"]); ok {
			if a, ok := extMap(e["action"]); ok {
				if a2, ok := extMap(a["action"]); ok {
					ev, _ = a2["reversibility_class"].(string)
				}
			}
		}
		cc, _ := c["reversibility_class"].(string)
		holds = cc == irreversibleCls || ev == irreversibleCls
	case "policy-denied":
		holds = !rel
	case "optimistic-not-allowed":
		holds = rel && !opt
	case "risk-understated":
		cr, ok := extFinite(c["claimed_r"])
		holds = ok && rel && opt && r > cr+margin
	default:
		return "kind"
	}
	if holds {
		return "ok"
	}
	return "consistency"
}

func extNonEmpty(v any) bool { s, ok := v.(string); return ok && s != "" }

func extNonNeg(v any) (float64, bool) {
	f, ok := extFinite(v)
	return f, ok && f >= 0
}

// SettlementWireCheck returns the first check a settlement record fails, or "ok": malformed, suite, shape, split,
// signature. The record's guardian signature is checked last, over the lenient canonical body without `sig`/`pq_sig`.
func SettlementWireCheck(record any, guardianPublic string, pins ...map[string]string) string {
	r, ok := extMap(record)
	if !ok {
		return "malformed"
	}
	// a registered suite this SDK does not implement is `suite` here too (the reference implements it; this build must not accept)
	_, hasAlg := r["alg"]
	if _, known := resolveSigAlg(r["alg"], hasAlg); !known {
		return "suite"
	}
	action, _ := r["action"].(string)
	slash := action == "slash"
	amount, amountOK := extFinite(r["amount"])
	_, hasSplit := r["split"]
	ev, evOK := r["evidenceDigest"].(string)
	_, atOK := extFinite(r["at"])
	_, sigOK := r["sig"].(string)
	epochOK := true
	if e, has := r["guardian_epoch"]; has {
		f, ok := jsNum(e)
		epochOK = ok && jsIsSafeInteger(e) && f >= 0
	}
	if !extNonEmpty(r["claimId"]) || !(action == "open" || action == "release" || slash) ||
		!amountOK || amount <= 0 || !extNonEmpty(r["from"]) || !extNonEmpty(r["to"]) || !atOK || !evOK ||
		(slash && ev == "") || (!slash && ev != "") ||
		(slash && mapOrNil(r["split"]) == nil) || (!slash && hasSplit) || !sigOK || !epochOK {
		return "shape"
	}
	if slash {
		sp := r["split"].(map[string]any)
		sa, saOK := jsNum(sp["amount"])
		cr, o1 := extNonNeg(sp["challengerReward"])
		vc, o2 := extNonNeg(sp["victimCompensation"])
		tr, o3 := extNonNeg(sp["treasuryRemainder"])
		to, _ := r["to"].(string)
		ta, hasTA := sp["treasuryAccount"].(string)
		conserved := sa == amount && o1 && o2 && o3 && (cr+vc)+tr == amount && extNonEmpty(sp["victimAccount"]) && hasTA && ta == to
		if conserved {
			if sp["challengerAccount"] == nil {
				_, present := sp["challengerAccount"]
				conserved = present && cr == 0 && vc == 0 && tr == amount
			} else {
				conserved = extNonEmpty(sp["challengerAccount"])
			}
		}
		conserved = conserved && saOK
		if !conserved {
			return "split"
		}
	}
	body := make(map[string]any, len(r))
	for k, v := range r {
		if k != "sig" && k != "pq_sig" {
			body[k] = v
		}
	}
	good, canon := extSignedLenient(guardianPublic, settlementDomain, body, r["sig"])
	if !canon {
		return "malformed"
	}
	if su, _ := resolveSigAlg(r["alg"], hasAlg); su.needsPqPk {
		good = false
		c, _ := canonicalLenient(body)
		pk, isStr := r["pq_pk"].(string)
		pin, pinned := extPinsOf(pins).m[guardianPublic]
		if isStr && pk != "" && pinned && pin == pk {
			good = verifyLeafSuite(r["alg"], true, guardianPublic, callerVouchedPqKey(pk), append([]byte(settlementDomain), c...), r["sig"], r["pq_sig"])
		}
	}
	if !good {
		return "signature"
	}
	return "ok"
}
