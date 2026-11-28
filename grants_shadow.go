package pca

// Shadow policy rollout: run candidate policy bundles beside the enforced one, record every divergence as a verifier-signed diff, and
// gate promotion on zero unexplained widenings. The enforced decision is computed first and returned untouched, so a candidate that
// fails, returns junk or mutates its input cannot change the answer. Nothing here decides an action; it is analysis and rollout
// tooling. Decisions are the strings "allow", "deny" and "escalate".

import (
	"encoding/json"
	"errors"
	"strconv"
)

const (
	shadowDiffDomain          = "atlas-pca/shadow-diff/v1\x00"
	wideningExplanationDomain = "atlas-pca/shadow-widening-explanation/v1\x00"
	promotionApprovalDomain   = "atlas-pca/shadow-promotion-approval/v1\x00"
)

func grantsIsKind(x any) bool {
	_, ok := grantsRank(x)
	return ok
}

// ShadowCandidate is one candidate bundle: its digest (as listed in the enforced revision's `shadow`) and its pure decision function.
type ShadowCandidate struct {
	Digest string
	Decide func(input any) (any, error)
}

// RunShadow is the enforced decision, plus what each candidate would have said ({digest, decision | "error", diverged, widening}).
// The returned decision is the enforced one, always; a candidate error is an error outcome, never an answer.
func RunShadow(input any, enforced func(input any) (any, error), candidates []ShadowCandidate) (any, []map[string]any, error) {
	decision, err := enforced(input)
	if err != nil {
		return nil, nil, err
	}
	out := make([]map[string]any, 0, len(candidates))
	for _, c := range candidates {
		d, derr := grantsSafeDecide(c.Decide, grantsClone(input))
		if derr != nil || !grantsIsKind(d) {
			out = append(out, map[string]any{"digest": c.Digest, "decision": "error", "diverged": false, "widening": false})
			continue
		}
		out = append(out, map[string]any{"digest": c.Digest, "decision": d, "diverged": !grantsEq(d, decision), "widening": grantsRankGt(d, decision)})
	}
	return decision, out, nil
}

func grantsSafeDecide(f func(any) (any, error), in any) (d any, err error) {
	defer func() {
		if recover() != nil {
			d, err = nil, errors.New("candidate failed")
		}
	}()
	return f(in)
}

// ShadowRecordField is the `shadow` member of a decision record, from the outcomes.
func ShadowRecordField(outcomes []map[string]any) []any {
	out := make([]any, len(outcomes))
	for i, o := range outcomes {
		out[i] = map[string]any{"digest": o["digest"], "decision": o["decision"], "diverged": o["diverged"]}
	}
	return out
}

var shadowDiffKeys = []string{"v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer"}

// VerifyShadowDiff is a well formed diff signed by its own signer (and by `signer` when given). Never panics.
func VerifyShadowDiff(d any, signer ...string) bool {
	m, ok := d.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return false
	}
	_, wideningIsBool := m["widening"].(bool)
	if !k3Str(m["shadow_digest"], 128) || !k3Str(m["enforced_digest"], 128) || !k3Str(m["action_digest"], 128) || !grantsIsKind(m["enforced"]) || !grantsIsKind(m["shadow"]) ||
		!wideningIsBool || !k3Int(m["at"]) || !k3Str(m["signer"], 128) {
		return false
	}
	if m["enforced"] == m["shadow"] || m["widening"] != grantsRankGt(m["shadow"], m["enforced"]) {
		return false
	}
	if len(signer) > 0 && m["signer"] != signer[0] {
		return false
	}
	body, ok := extPick(m, shadowDiffKeys...)
	return ok && GrantsVerifyBody(shadowDiffDomain, body, m["signer"].(string), m["sig"])
}

// ShadowStats are the per-candidate counters.
type ShadowStats struct {
	Total     int `json:"total"`
	Diverged  int `json:"diverged"`
	Widened   int `json:"widened"`
	Tightened int `json:"tightened"`
	Errors    int `json:"errors"`
}

// ShadowLog collects the signed diffs and counters per candidate. In memory: persist Diffs to the decision log for the audit trail.
type ShadowLog struct {
	key  *KeyPair
	stat map[string]*ShadowStats
	list map[string][]map[string]any
}

// NewShadowLog opens an empty shadow log whose diffs are signed by k.
func NewShadowLog(k *KeyPair) *ShadowLog {
	return &ShadowLog{key: k, stat: map[string]*ShadowStats{}, list: map[string][]map[string]any{}}
}

// Signer is the b64u key that signs the diffs.
func (l *ShadowLog) Signer() string { return l.key.Public }

// Observe counts one observation; it signs and keeps a diff when the candidate diverged (nil otherwise).
func (l *ShadowLog) Observe(enforcedDigest, actionDigest string, enforced any, outcome map[string]any, at any) (map[string]any, error) {
	digest, _ := outcome["digest"].(string)
	s := l.stat[digest]
	if s == nil {
		s = &ShadowStats{}
		l.stat[digest] = s
	}
	s.Total++
	if outcome["decision"] == "error" {
		s.Errors++
		return nil, nil
	}
	if outcome["diverged"] != true {
		return nil, nil
	}
	s.Diverged++
	widening := outcome["widening"] == true
	if widening {
		s.Widened++
	} else {
		s.Tightened++
	}
	base := map[string]any{"v": json.Number("1"), "shadow_digest": digest, "enforced_digest": enforcedDigest, "action_digest": actionDigest,
		"enforced": enforced, "shadow": outcome["decision"], "widening": widening, "at": at, "signer": l.key.Public}
	sig, err := signBody(l.key, shadowDiffDomain, base)
	if err != nil {
		return nil, err
	}
	diff := grantsCloneMap(base)
	diff["sig"] = sig
	l.list[digest] = append(l.list[digest], diff)
	return diff, nil
}

// Stats is a copy of the counters of one candidate.
func (l *ShadowLog) Stats(digest string) ShadowStats {
	if s := l.stat[digest]; s != nil {
		return *s
	}
	return ShadowStats{}
}

// Diffs is a copy of the diffs kept for one candidate.
func (l *ShadowLog) Diffs(digest string) []map[string]any {
	return append([]map[string]any{}, l.list[digest]...)
}

// SignWideningExplanation: a principal states that this widening is intended (reason_digest binds the display-only reason text).
// e carries shadow_digest, action_digest and reason_digest.
func SignWideningExplanation(k *KeyPair, e map[string]any) (map[string]any, error) {
	base := map[string]any{"v": json.Number("1")}
	for kk, v := range e {
		base[kk] = v
	}
	base["principal"] = k.Public
	sig, err := signBody(k, wideningExplanationDomain, leasePick(base, []string{"v", "shadow_digest", "action_digest", "reason_digest", "principal"}))
	if err != nil {
		return nil, err
	}
	out := grantsCloneMap(base)
	out["sig"] = sig
	return out, nil
}

func grantsVerifyExplanation(e any) bool {
	m, ok := e.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return false
	}
	if !k3Str(m["shadow_digest"], 128) || !k3Str(m["action_digest"], 128) || !k3Str(m["reason_digest"], 128) || !k3Str(m["principal"], 128) {
		return false
	}
	body, ok := extPick(m, "v", "shadow_digest", "action_digest", "reason_digest", "principal")
	return ok && GrantsVerifyBody(wideningExplanationDomain, body, m["principal"].(string), m["sig"])
}

// SignPromotionApproval: a principal approves promoting the shadow candidate over the enforced revision. a carries shadow_digest,
// enforced_digest and at.
func SignPromotionApproval(k *KeyPair, a map[string]any) (map[string]any, error) {
	base := map[string]any{"v": json.Number("1")}
	for kk, v := range a {
		base[kk] = v
	}
	base["principal"] = k.Public
	sig, err := signBody(k, promotionApprovalDomain, leasePick(base, []string{"v", "shadow_digest", "enforced_digest", "at", "principal"}))
	if err != nil {
		return nil, err
	}
	out := grantsCloneMap(base)
	out["sig"] = sig
	return out, nil
}

func grantsVerifyApproval(a any) bool {
	m, ok := a.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return false
	}
	if !k3Str(m["shadow_digest"], 128) || !k3Str(m["enforced_digest"], 128) || !k3Int(m["at"]) || !k3Str(m["principal"], 128) {
		return false
	}
	body, ok := extPick(m, "v", "shadow_digest", "enforced_digest", "at", "principal")
	return ok && GrantsVerifyBody(promotionApprovalDomain, body, m["principal"].(string), m["sig"])
}

func grantsListHas(l []any, s string) bool {
	for _, x := range l {
		if grantsEq(x, s) {
			return true
		}
	}
	return false
}

// PromotionGate: may this candidate be promoted? Enough samples, no candidate failures, every diff verifies, zero unexplained
// widenings, and a principal-signed approval when the static verdict on the declared surfaces is "wider" or "unknown". o carries
// shadow_digest, enforced_digest, minSamples, principals, surface and optionally explanations and approval. Fails closed.
func PromotionGate(log *ShadowLog, o map[string]any) map[string]any {
	no := func(code, reason string, unexplained []string) map[string]any {
		r := map[string]any{"ok": false, "code": code, "reason": reason}
		if len(unexplained) > 0 {
			u := make([]any, len(unexplained))
			for i, x := range unexplained {
				u[i] = x
			}
			r["unexplained"] = u
		}
		return r
	}
	principals, isArr := o["principals"].([]any)
	surface, _ := o["surface"].(string)
	ms, _ := jsNum(o["minSamples"])
	if !k3Str(o["shadow_digest"], 128) || !k3Str(o["enforced_digest"], 128) || !k3Int(o["minSamples"]) || ms < 1 || !isArr ||
		(surface != "narrower" && surface != "equal" && surface != "wider" && surface != "unknown") {
		return no("bad_input", "bad gate options", nil)
	}
	sd, ed := o["shadow_digest"].(string), o["enforced_digest"].(string)
	s := log.Stats(sd)
	if float64(s.Total) < ms {
		return no("too_few_samples", strconv.Itoa(s.Total)+" observation(s), need "+jsNumberString(ms), nil)
	}
	if s.Errors > 0 {
		return no("shadow_errors", strconv.Itoa(s.Errors)+" observation(s) where the candidate failed", nil)
	}
	diffs := log.Diffs(sd)
	for _, d := range diffs {
		if !VerifyShadowDiff(d, log.Signer()) || d["shadow_digest"] != sd || d["enforced_digest"] != ed {
			return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing", nil)
		}
	}
	if len(diffs) != s.Diverged {
		return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing", nil)
	}
	var exps []any
	switch t := o["explanations"].(type) {
	case nil:
	case []any:
		exps = t
	case string: // `for of` over a string visits its characters; none is an explanation
	default:
		return no("bad_input", "evaluation error (fail closed)", nil)
	}
	explained := map[string]bool{}
	for _, e := range exps {
		if grantsVerifyExplanation(e) {
			em := e.(map[string]any)
			if grantsListHas(principals, em["principal"].(string)) && em["shadow_digest"] == sd {
				explained[em["action_digest"].(string)] = true
			}
		}
	}
	seen := map[string]bool{}
	unexplained := []string{}
	for _, d := range diffs {
		a, _ := d["action_digest"].(string)
		if d["widening"] == true && !explained[a] && !seen[a] {
			seen[a] = true
			unexplained = append(unexplained, a)
		}
	}
	grantsSortU16(unexplained)
	if len(unexplained) > 0 {
		return no("unexplained_widening", strconv.Itoa(len(unexplained))+" widening(s) without a principal's explanation", unexplained)
	}
	if surface == "wider" || surface == "unknown" {
		am, isMap := o["approval"].(map[string]any)
		if !isMap || !grantsVerifyApproval(am) || !grantsListHas(principals, am["principal"].(string)) || am["shadow_digest"] != sd || am["enforced_digest"] != ed {
			what := "not provably narrower"
			if surface == "wider" {
				what = "wider"
			}
			return no("advisory_wider", "the analyzer reports the candidate "+what+" on the declared surfaces: a principal-signed approval is required", nil)
		}
	}
	widenings := 0
	for _, d := range diffs {
		if d["widening"] == true {
			widenings++
		}
	}
	return map[string]any{"ok": true, "samples": jsNumber(float64(s.Total)), "widenings": jsNumber(float64(widenings)), "surface": surface}
}

// PromoteShadow is the body of the bundle revision that makes the candidate the enforced policy: its content at revision + 1,
// chained to the enforced revision, with the shadow list cleared. It needs a passing gate for exactly this candidate, and the
// candidate must be listed in the enforced revision's `shadow`. Sign it with SignBundle / AssembleBundle like any revision.
func PromoteShadow(enforced, candidate map[string]any, gate map[string]any, now any) (map[string]any, error) {
	digest, ok := BundleDigest(candidate)
	if !ok {
		return nil, errors.New("bundleDigest: not canonicalizable")
	}
	if gate["ok"] != true {
		return nil, errors.New("promoteShadow: the gate did not pass (" + jsMemberString(gate, "code") + ")")
	}
	shadow, _ := enforced["shadow"].([]any)
	if !grantsListHas(shadow, digest) {
		return nil, errors.New("promoteShadow: the candidate is not listed in the enforced revision's shadow")
	}
	if !k3Int(now) {
		return nil, errors.New("promoteShadow: bad time")
	}
	rev, _ := jsNum(enforced["revision"])
	prev, ok := BundleDigest(enforced)
	if !ok {
		return nil, errors.New("bundleDigest: not canonicalizable")
	}
	out := withoutKeys(candidate, "sigs", "shadow", "prev")
	out["revision"], out["prev"], out["issued_at"] = jsNumber(rev+1), prev, now
	return out, nil
}
