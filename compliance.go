package pca

// Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to the control language auditors use: EU AI
// Act Art. 12 / Art. 50, ISO/IEC 42001 clauses and SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR).
// Pure and read-only. HONEST SCOPE: an evidence mapping, not a legal certification; `satisfied` means the cryptographic evidence a
// control asks for is present in the supplied records. Inputs are decoded JSON values; property reads follow JavaScript semantics
// (a missing member is undefined, reading through null throws) so reports match the reference text for text.

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// ComplianceFrameworks are the frameworks a per-event compliance report covers.
var ComplianceFrameworks = []string{"eu-ai-act", "iso-42001", "soc2"}

var cmpFrameworkIDs = []string{"eu-ai-act", "soc2", "gdpr"}

func cmpOwn(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		if v, has := m[k]; has {
			return v
		}
	}
	return xpUndef
}

// cmpProp is o.k: it throws when o is null or undefined.
func cmpProp(o any, k string) any {
	if o == nil || xpIsUndef(o) {
		xpPanic("Cannot read properties of " + xpStr(o) + " (reading '" + k + "')")
	}
	return cmpOwn(o, k)
}

func cmpQ(o any, k string) any {
	if o == nil || xpIsUndef(o) {
		return xpUndef
	}
	return cmpOwn(o, k)
}

func cmpNullish(v any) bool { return v == nil || xpIsUndef(v) }

func cmpIsNum(v any) bool { _, ok := jsNum(v); return ok }

func cmpWalk(o any, path ...string) any {
	for _, k := range path {
		o = cmpProp(o, k)
	}
	return o
}

func cmpLength(v any) any {
	if cmpNullish(v) {
		xpPanic("Cannot read properties of " + xpStr(v) + " (reading 'length')")
	}
	return xpLength(v)
}

func cmpLenInt(v any) int {
	if f, ok := jsNum(v); ok {
		return int(f)
	}
	return 0
}

func cmpNowMs() any { return jsonNumberOf(time.Now().UnixMilli()) }

// cmpIsoString is `new Date(ms).toISOString()`; it panics for an invalid time (a RangeError there).
func cmpIsoString(ms any) string {
	f, ok := jsNum(ms)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 8.64e15 {
		xpPanic("Invalid time value")
	}
	t := time.UnixMilli(int64(f)).UTC()
	y := t.Year()
	var ys string
	switch {
	case y >= 0 && y <= 9999:
		ys = fmt.Sprintf("%04d", y)
	case y > 0:
		ys = fmt.Sprintf("+%06d", y)
	default:
		ys = fmt.Sprintf("-%06d", -y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1e6)
}

func cmpIso(ms any) string {
	if !xpIsFin(ms) {
		return "(unknown time)"
	}
	var s string
	if err := xpTry(func() { s = cmpIsoString(ms) }); err != nil {
		return "(unrepresentable time)"
	}
	return s
}

func cmpTs(ms any) map[string]any { return map[string]any{"epochMs": ms, "iso": cmpIso(ms)} }

// cmpNumOut is a computed number as JSON would carry it (NaN and the infinities print as null).
func cmpNumOut(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return jsNumber(f)
}

func cmpShort(key any, n int) string {
	s, ok := key.(string)
	if !ok || len(s) == 0 {
		return "(none)"
	}
	if xpLen16(s) <= n+1 {
		return s
	}
	return xpSlice16(s, 0, n) + "…"
}

type cmpSet struct {
	keys map[string]bool
	n    int
}

func (s *cmpSet) add(v any) {
	if s.keys == nil {
		s.keys = map[string]bool{}
	}
	var k string
	switch t := v.(type) {
	case bool:
		k = fmt.Sprintf("b:%v", t)
	case string:
		k = "s:" + t
	case nil:
		k = "z:null"
	case xpUndefT:
		k = "z:undef"
	default:
		if f, ok := jsNum(v); ok {
			if math.IsNaN(f) {
				k = "n:nan"
			} else {
				k = "n:" + xpNumStr(f)
			}
		} else {
			s.n++
			k = fmt.Sprintf("o:%d", s.n)
		}
	}
	s.keys[k] = true
}

// cmpPretty is JSON.stringify(v, null, 2).
func cmpPretty(v any, base string) string {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 {
			return "[]"
		}
		ind := base + "  "
		ps := make([]string, len(t))
		for i, x := range t {
			if xpIsUndef(x) {
				ps[i] = ind + "null"
			} else {
				ps[i] = ind + cmpPretty(x, ind)
			}
		}
		return "[\n" + strings.Join(ps, ",\n") + "\n" + base + "]"
	case map[string]any:
		var ps []string
		ind := base + "  "
		for _, k := range jsKeys(t) {
			if xpIsUndef(t[k]) {
				continue
			}
			ps = append(ps, ind+xpJSON(k)+": "+cmpPretty(t[k], ind))
		}
		if len(ps) == 0 {
			return "{}"
		}
		return "{\n" + strings.Join(ps, ",\n") + "\n" + base + "}"
	}
	return xpJSON(v)
}

// ---- AuditEvent ------------------------------------------------------------------------------------------------------------

func cmpIsBudgetAlloc(cv any) bool {
	m, ok := cv.(map[string]any)
	if !ok || m["type"] != "budget_alloc" {
		return false
	}
	f, fin := jsNum(m["limit"])
	return fin && xpIsFin(m["limit"]) && f >= 0
}

// ComplianceDescribeCaveat is a bounded, human-readable rendering of one caveat.
func ComplianceDescribeCaveat(cv any) string {
	m, ok := cv.(map[string]any)
	typ, tok := m["type"].(string)
	if !ok || !tok {
		return "(malformed caveat)"
	}
	if typ == "envelope" {
		np, ni := 0, 0
		if l, ok := m["predicates"].([]any); ok {
			np = len(l)
		}
		if l, ok := m["caveats"].([]any); ok {
			ni = len(l)
		}
		return fmt.Sprintf("policy envelope (%d predicate(s), %d caveat(s))", np, ni)
	}
	if cmpIsBudgetAlloc(cv) {
		return "budget allocation ≤ " + xpN(m["limit"])
	}
	var parts []string
	ks := jsKeys(m)
	if len(ks) > 8 {
		ks = ks[:8]
	}
	for _, k := range ks {
		if k == "type" {
			continue
		}
		if xpIsObj(m[k]) {
			parts = append(parts, k+"="+xpJSON(m[k]))
		} else {
			parts = append(parts, k+"="+xpN(m[k]))
		}
	}
	if len(parts) > 0 {
		return typ + "(" + strings.Join(parts, ", ") + ")"
	}
	return typ
}

// ComplianceDelegationHops are the delegation hops: issuer -> holder and the caveats each hop ADDED (append-only diff).
func ComplianceDelegationHops(chain any) []any {
	safe, _ := chain.([]any)
	hops := []any{}
	for i, cap := range safe {
		if !xpTruthy(cap) {
			continue
		}
		isRoot := i == 0
		parentLen := 0
		if i > 0 && xpTruthy(safe[i-1]) {
			if pc, ok := cmpOwn(safe[i-1], "caveats").([]any); ok {
				parentLen = len(pc)
			}
		}
		own, _ := cmpOwn(cap, "caveats").([]any)
		var added []any
		if isRoot {
			added = own
		} else if len(own) >= parentLen {
			added = own[parentLen:]
		}
		scope := make([]any, len(added))
		ss := make([]string, len(added))
		var budgetCv any
		for j, c := range added {
			ss[j] = ComplianceDescribeCaveat(c)
			scope[j] = ss[j]
			if budgetCv == nil && cmpIsBudgetAlloc(c) {
				budgetCv = c
			}
		}
		issuer, holder := cmpOwn(cap, "issuer"), cmpOwn(cap, "holder")
		joined := strings.Join(ss, "; ")
		var narrative string
		if isRoot {
			tail := ""
			if len(ss) > 0 {
				tail = " under: " + joined
			}
			narrative = fmt.Sprintf("Principal %s granted authority to %s%s.", cmpShort(issuer, 12), cmpShort(holder, 12), tail)
		} else {
			tail := " (rebind only, no new constraints)"
			if len(ss) > 0 {
				tail = ", narrowing scope: " + joined
			}
			narrative = fmt.Sprintf("%s delegated to %s%s.", cmpShort(issuer, 12), cmpShort(holder, 12), tail)
		}
		ac := make([]any, len(added))
		copy(ac, added)
		hop := map[string]any{"index": xpInt(i), "isRoot": isRoot, "scope": scope, "caveats": ac, "narrative": narrative}
		xpPut(hop, "issuer", issuer)
		xpPut(hop, "holder", holder)
		if budgetCv != nil {
			hop["budgetAlloc"] = budgetCv.(map[string]any)["limit"]
		}
		hops = append(hops, hop)
	}
	return hops
}

func cmpHumanOverride(threshold, requiredTier, thresholdCheck any) map[string]any {
	var shares []any
	if xpTruthy(threshold) {
		shares, _ = cmpOwn(threshold, "shares").([]any)
	}
	if len(shares) == 0 {
		return nil
	}
	// `threshold` is outside the signed body: never report a signed approval (or name approvers) from unverified shares.
	if thresholdCheck != "pass" {
		tc := "absent"
		if !cmpNullish(thresholdCheck) {
			tc = xpStr(thresholdCheck)
		}
		return map[string]any{"humanApproved": false, "approvers": []any{}, "guardianCosigners": []any{}, "roles": []any{}, "requiredTier": requiredTier,
			"narrative": fmt.Sprintf("%d co-signature share(s) were presented but NOT verified (threshold check: %s); no human approval is recorded.", len(shares), tc)}
	}
	approvers, guardians, roles := []any{}, []any{}, []any{}
	for _, s := range shares {
		if !xpTruthy(s) {
			continue
		}
		role, ok := cmpOwn(s, "role").(string)
		if !ok {
			continue
		}
		roles = append(roles, role)
		pk, pkOk := cmpOwn(s, "publicKey").(string)
		if role == "principal" && pkOk {
			approvers = append(approvers, pk)
		}
		if role == "guardian" && pkOk {
			guardians = append(guardians, pk)
		}
	}
	approved := len(approvers) > 0
	var narrative string
	if approved {
		extra := ""
		if len(guardians) > 0 {
			extra = fmt.Sprintf(" (plus %d guardian co-sign)", len(guardians))
		}
		narrative = fmt.Sprintf("Step-up approved by a signed human co-signature from principal %s%s at tier t=%s.", cmpShort(approvers[0], 12), extra, xpStr(requiredTier))
	} else {
		narrative = fmt.Sprintf("Co-signed by %d guardian share(s) at tier t=%s (no human principal signature present).", len(guardians), xpStr(requiredTier))
	}
	return map[string]any{"humanApproved": approved, "approvers": approvers, "guardianCosigners": guardians, "roles": roles, "requiredTier": requiredTier,
		"narrative": narrative}
}

func cmpFirstReasonOr(decision any, fallback string) any {
	rs, _ := cmpOwn(decision, "reasons").([]any)
	if len(rs) > 0 {
		if s, ok := rs[0].(string); ok {
			return s
		}
	}
	return fallback
}

func cmpResolveOutcome(verify, decision any) (string, any) {
	if !xpTruthy(verify) || cmpOwn(verify, "allow") != true {
		r := cmpQ(verify, "reason")
		if cmpNullish(r) {
			return "deny", "proof failed verification"
		}
		return "deny", r
	}
	switch {
	case !xpTruthy(decision):
		return "allow", "proof verified; no policy decision supplied"
	case xpTruthy(cmpOwn(decision, "admit")):
		return "allow", cmpFirstReasonOr(decision, "auto-admitted within policy and budget")
	case xpTruthy(cmpOwn(decision, "releaseGuardianShare")):
		return "step-up", cmpFirstReasonOr(decision, "policy satisfied but a co-signature is required")
	}
	return "deny", cmpFirstReasonOr(decision, "policy did not release authority (default-deny)")
}

func cmpSafeDigest(p any) string {
	if xpIsUndef(p) {
		return "(undigestible)"
	}
	var d string
	var err error
	if xpTry(func() { d, err = HashCanonical(p) }) != nil || err != nil {
		return "(undigestible)"
	}
	return d
}

func cmpStrOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

// ComplianceToAuditEvent is a normalized AuditEvent from a PCActn, the core verifier's result and the Policy-VM decision. inp is
// {pcactn, verify, decision?, now?, session?}; now (epoch ms) defaults to the clock.
func ComplianceToAuditEvent(inp any) (map[string]any, error) {
	var out map[string]any
	err := xpTry(func() { out = cmpToAuditEvent(inp) })
	return out, err
}

func cmpToAuditEvent(inp any) map[string]any {
	p := cmpProp(inp, "pcactn")
	verify := cmpOwn(inp, "verify")
	if cmpNullish(verify) {
		verify = map[string]any{"allow": false, "checks": map[string]any{}}
	}
	decision := cmpOwn(inp, "decision")
	now := cmpOwn(inp, "now")
	if cmpNullish(now) {
		now = cmpNowMs()
	}
	chain, _ := cmpQ(p, "cap_chain").([]any)
	hops := ComplianceDelegationHops(chain)
	var leaf, root any = xpUndef, xpUndef
	if len(chain) > 0 {
		leaf, root = chain[len(chain)-1], chain[0]
	}
	outcome, reason := cmpResolveOutcome(verify, decision)
	tier := cmpQ(cmpQ(decision, "requiredThreshold"), "t")
	var requiredTier any = xpInt(1)
	if !cmpNullish(tier) {
		requiredTier = tier
	}
	checksRaw := cmpOwn(verify, "checks")
	human := cmpHumanOverride(cmpQ(p, "threshold"), requiredTier, cmpQ(checksRaw, "threshold"))
	var checks any = map[string]any{}
	if !cmpNullish(checksRaw) {
		checks = checksRaw
	}
	cryptoOK := cmpOwn(checks, "wire") == "pass" && cmpOwn(checks, "leaf_signature") == "pass"

	action := cmpQ(p, "action")
	verb := cmpStrOr(cmpQ(action, "verb"), "(unknown verb)")
	resource := cmpStrOr(cmpQ(action, "resource"), "(unknown resource)")
	grantRef := cmpStrOr(cmpQ(p, "grant_ref"), "(none)")
	paramsDigest := cmpStrOr(cmpQ(action, "params_digest"), "(none)")
	counter := cmpQ(p, "counter")
	var counterOut any = xpInt(-1)
	if cmpIsNum(counter) {
		counterOut = counter
	}
	evidence := map[string]any{
		"pcactnDigest":                cmpSafeDigest(p),
		"leafSignature":               cmpStrOr(cmpQ(p, "sig"), "(unsigned)"),
		"signatureSuite":              cmpStrOr(cmpQ(p, "alg"), "ed25519"),
		"planRoot":                    cmpStrOr(cmpQ(cmpQ(p, "plan"), "root"), "(none)"),
		"paramsDigest":                paramsDigest,
		"grantRef":                    grantRef,
		"counter":                     counterOut,
		"cryptographicallyVerifiable": cryptoOK,
	}
	if n, ok := cmpQ(p, "nonce").(string); ok {
		evidence["nonce"] = n
	}

	risk := map[string]any{}
	if xpTruthy(decision) {
		rt := cmpOwn(decision, "requiredThreshold")
		for _, kv := range []struct {
			k string
			v any
		}{{"r", cmpOwn(decision, "r")}, {"tier", cmpQ(rt, "t")}, {"proof", cmpQ(rt, "proof")}, {"budget", cmpOwn(decision, "budget")}} {
			xpPut(risk, kv.k, kv.v)
		}
	}

	word := "STEP-UP"
	if outcome == "allow" {
		word = "ALLOWED"
	} else if outcome == "deny" {
		word = "DENIED"
	}
	proofWord := "proof not cryptographically verifiable"
	if cryptoOK {
		proofWord = "cryptographically verifiable proof"
	}
	humanWord := ""
	if human != nil && human["humanApproved"] == true {
		humanWord = "; human-signed step-up"
	}
	narrative := fmt.Sprintf("Agent %s %s to %s on %s (%d-hop chain rooted at principal %s; %s%s). %s",
		cmpShort(cmpQ(leaf, "holder"), 12), word, verb, resource, len(hops), cmpShort(cmpQ(root, "issuer"), 12), proofWord, humanWord, xpStr(reason))

	holder := cmpStrOr(cmpQ(leaf, "holder"), "(none)")
	sess := cmpOwn(inp, "session")
	var session any = grantRef
	if !cmpNullish(sess) {
		session = sess
	}
	agent := map[string]any{"holder": holder, "session": session}
	if pr, ok := cmpQ(root, "issuer").(string); ok {
		agent["principal"] = pr
	}
	depth := len(hops) - 1
	if depth < 0 {
		depth = 0
	}
	tsOf := func(v any) map[string]any {
		if cmpIsNum(v) {
			return cmpTs(v)
		}
		return map[string]any{"epochMs": nil, "iso": "(unknown time)"}
	}
	event := map[string]any{
		"schema":     "atlas-pca/audit-event/v1",
		"recordedAt": cmpTs(now),
		"agent":      agent,
		"delegation": map[string]any{"depth": xpInt(depth), "hops": hops},
		"action": map[string]any{"verb": verb, "resource": resource, "paramsDigest": paramsDigest,
			"reversibilityClass": cmpStrOr(cmpQ(action, "reversibility_class"), "(unknown)"), "summary": verb + " on " + resource},
		"decision":   map[string]any{"outcome": outcome, "reason": reason, "proofVerified": cmpOwn(verify, "allow") == true, "checks": checks},
		"risk":       risk,
		"timestamps": map[string]any{"issuedAt": tsOf(cmpQ(p, "iat")), "expiresAt": tsOf(cmpQ(p, "exp"))},
		"evidence":   evidence,
		"narrative":  narrative,
	}
	if human != nil {
		event["humanOverride"] = human
	}
	return event
}

// ---- control mappings ------------------------------------------------------------------------------------------------------

func cmpAssertFramework(fw any) {
	s, ok := fw.(string)
	for _, f := range ComplianceFrameworks {
		if ok && f == s {
			return
		}
	}
	xpPanic(fmt.Sprintf("pca-compliance: unknown framework '%s' (have: %s)", xpStr(fw), strings.Join(ComplianceFrameworks, ", ")))
}

// ComplianceControlMappings is the control mapping table, filtered to a framework when one is given (omitted = the whole table).
func ComplianceControlMappings(framework any, given bool) ([]any, error) {
	all := complianceControlMappings()
	if !given {
		return all, nil
	}
	var out []any
	err := xpTry(func() {
		cmpAssertFramework(framework)
		out = []any{}
		for _, m := range all {
			if m.(map[string]any)["framework"] == framework {
				out = append(out, m)
			}
		}
	})
	return out, err
}

// ---- ComplianceReport ------------------------------------------------------------------------------------------------------

type cmpStats struct {
	total, verifiable, denied, stepUp, allowed, human, withChain, withPlan int
	maxDepth                                                               any
	agents, principals                                                     int
	sampleDigest                                                           any
}

func cmpComputeStats(events []any) cmpStats {
	var agents, principals cmpSet
	s := cmpStats{maxDepth: xpInt(0), sampleDigest: xpUndef, total: len(events)}
	for _, e := range events {
		if !xpTruthy(e) {
			continue
		}
		if xpTruthy(cmpProp(cmpProp(e, "evidence"), "cryptographicallyVerifiable")) {
			s.verifiable++
		}
		switch cmpProp(cmpProp(e, "decision"), "outcome") {
		case "deny":
			s.denied++
		case "step-up":
			s.stepUp++
		default:
			s.allowed++
		}
		if xpTruthy(cmpQ(cmpOwn(e, "humanOverride"), "humanApproved")) {
			s.human++
		}
		hl := cmpLength(cmpProp(cmpProp(e, "delegation"), "hops"))
		if !xpIsUndef(hl) && xpGt(hl, 0) {
			s.withChain++
		}
		if cmpProp(cmpProp(e, "evidence"), "planRoot") != "(none)" {
			s.withPlan++
		}
		depth := cmpProp(cmpProp(e, "delegation"), "depth")
		if xpGt(depth, s.maxDepth) {
			s.maxDepth = depth
		}
		agents.add(cmpProp(cmpProp(e, "agent"), "holder"))
		if pr := cmpProp(cmpProp(e, "agent"), "principal"); !xpIsUndef(pr) {
			principals.add(pr)
		}
		d := cmpProp(cmpProp(e, "evidence"), "pcactnDigest")
		if xpIsUndef(s.sampleDigest) && d != "(undigestible)" {
			s.sampleDigest = d
		}
	}
	s.agents, s.principals = len(agents.keys), len(principals.keys)
	return s
}

type cmpEval struct {
	status, evidence string
	findings         []any
}

func cmpTri(ok, partial bool) string {
	if ok {
		return "satisfied"
	}
	if partial {
		return "partial"
	}
	return "not-evidenced"
}

func cmpEvaluateControl(id string, s cmpStats) cmpEval {
	findings := []any{}
	total := s.total
	digestNote := ""
	if !xpIsUndef(s.sampleDigest) {
		digestNote = " (e.g. " + cmpShort(s.sampleDigest, 16) + ")"
	}
	if total == 0 {
		return cmpEval{"not-evidenced", "no actions in the reporting period", []any{"no events supplied — nothing to evidence"}}
	}
	switch id {
	case "eu-ai-act:art-12":
		st := "satisfied"
		if s.verifiable < total {
			st = "partial"
			findings = append(findings, fmt.Sprintf("%d of %d entries are not cryptographically verifiable", total-s.verifiable, total))
		}
		return cmpEval{st, fmt.Sprintf("%d actions logged; %d/%d cite a cryptographically verifiable proof%s", total, s.verifiable, total, digestNote), findings}
	case "eu-ai-act:art-50":
		return cmpEval{"satisfied", fmt.Sprintf("%d actions each disclose the acting agent, the principal (%d distinct) and the automated decision outcome", total, s.principals), findings}
	case "iso-42001:A.6.2.8":
		return cmpEval{"satisfied", fmt.Sprintf("%d actions each carry a decision reason + risk/tier/budget reasoning trace", total), findings}
	case "iso-42001:A.9.2":
		wc := s.withChain
		if wc < total {
			findings = append(findings, fmt.Sprintf("%d entries have no delegation chain", total-wc))
		}
		return cmpEval{cmpTri(wc == total, wc > 0), fmt.Sprintf("%d/%d actions carry an explicit delegation chain (max depth %s, %d authorizing principal(s))", wc, total, xpStr(s.maxDepth), s.principals), findings}
	case "iso-42001:A.9.3":
		switch {
		case s.human > 0:
			return cmpEval{"satisfied", fmt.Sprintf("%d step-up(s) approved by a signed human co-signature; %d step-up(s) and %d denial(s) show oversight enforced", s.human, s.stepUp, s.denied), findings}
		case s.stepUp > 0 || s.denied > 0:
			findings = append(findings, "no human step-up co-signature was exercised in this period")
			return cmpEval{"partial", fmt.Sprintf("oversight boundary enforced (%d step-up(s), %d denial(s)) but no signed human co-signature observed in the period", s.stepUp, s.denied), findings}
		}
		findings = append(findings, "no higher-impact action required human oversight in this period")
		return cmpEval{"partial", "all actions were auto-admitted within policy; no oversight event was triggered in the period", findings}
	case "iso-42001:A.6.2.2":
		wp := s.withPlan
		if wp < total {
			findings = append(findings, fmt.Sprintf("%d entries are not bound to a committed plan root", total-wp))
		}
		return cmpEval{cmpTri(wp == total, wp > 0), fmt.Sprintf("%d/%d actions are bound to a committed plan root (intended-use binding)", wp, total), findings}
	case "soc2:CC6.1":
		if s.denied > 0 {
			findings = append(findings, fmt.Sprintf("%d out-of-scope action(s) denied — access control actively enforced", s.denied))
		}
		return cmpEval{"satisfied", fmt.Sprintf("deny-by-default access over %d actions (%d allowed, %d step-up, %d denied); all gated by signed predicates + attenuation", total, s.allowed, s.stepUp, s.denied), findings}
	case "soc2:CC6.2":
		wc := s.withChain
		if wc < total {
			findings = append(findings, fmt.Sprintf("%d entries are not traceable to an authorizing principal", total-wc))
		}
		return cmpEval{cmpTri(wc == total, wc > 0), fmt.Sprintf("%d agent identit(ies) traceable to %d authorizing principal(s) via signed delegation chains", s.agents, s.principals), findings}
	case "soc2:CC6.3":
		narrowed := xpToNum(s.maxDepth) >= 1
		st := "partial"
		if narrowed || s.denied > 0 {
			st = "satisfied"
		}
		if !narrowed && s.denied == 0 {
			findings = append(findings, "no attenuating hop or denial observed in the period")
		}
		return cmpEval{st, fmt.Sprintf("access narrowed by attenuation (max delegation depth %s) and %d denied action(s)", xpStr(s.maxDepth), s.denied), findings}
	}
	return cmpEval{"not-evidenced", "no evaluator for this control", []any{"unmapped control"}}
}

// ComplianceToReport is a structured ComplianceReport for opts.framework from AuditEvents: per-control status + evidence, the
// PCA-unique assurances and a coverage summary. opts.now (epoch ms) defaults to the clock.
func ComplianceToReport(events, opts any) (map[string]any, error) {
	var out map[string]any
	err := xpTry(func() { out = cmpToReport(events, opts) })
	return out, err
}

func cmpToReport(events, opts any) map[string]any {
	framework := cmpProp(opts, "framework")
	cmpAssertFramework(framework)
	var lst []any
	if l, ok := events.([]any); ok {
		for _, e := range l {
			if xpTruthy(e) {
				lst = append(lst, e)
			}
		}
	}
	now := cmpOwn(opts, "now")
	if cmpNullish(now) {
		now = cmpNowMs()
	}
	s := cmpComputeStats(lst)
	items := []any{}
	sat, partial, notEv := 0, 0, 0
	for _, mi := range complianceControlMappings() {
		m := mi.(map[string]any)
		if m["framework"] != framework {
			continue
		}
		r := cmpEvaluateControl(m["controlId"].(string), s)
		switch r.status {
		case "satisfied":
			sat++
		case "partial":
			partial++
		case "not-evidenced":
			notEv++
		}
		items = append(items, map[string]any{"controlId": m["controlId"], "controlTitle": m["controlTitle"], "clause": m["clause"], "framework": m["framework"],
			"status": r.status, "pcaEvidence": m["pcaEvidence"], "evidence": r.evidence, "findings": r.findings})
	}
	total := len(items)
	fraction := 0.0
	if total > 0 {
		fraction = float64(sat) / float64(total)
	}
	var iats []any
	for _, e := range lst {
		if x := cmpProp(cmpProp(cmpProp(e, "timestamps"), "issuedAt"), "epochMs"); xpIsFin(x) {
			iats = append(iats, x)
		}
	}
	var frm, to any = xpInt(0), xpInt(0)
	if len(iats) > 0 {
		frm, to = iats[0], iats[0]
		for _, x := range iats {
			if xpLt(x, frm) {
				frm = x
			}
			if xpGt(x, to) {
				to = x
			}
		}
	}
	st := s.total
	narr := "No events in scope."
	if st != 0 {
		narr = fmt.Sprintf("%d/%d entries cite a cryptographically verifiable proof; %d/%d carry an explicit delegation chain; %d step-up(s) carry a signed human co-signature.", s.verifiable, st, s.withChain, st, s.human)
	}
	extra := ""
	if partial > 0 {
		extra += fmt.Sprintf(", %d partial", partial)
	}
	if notEv > 0 {
		extra += fmt.Sprintf(", %d not evidenced", notEv)
	}
	return map[string]any{
		"schema": "atlas-pca/compliance-report/v1", "framework": framework, "generatedAt": cmpTs(now),
		"period": map[string]any{"from": cmpTs(frm), "to": cmpTs(to)}, "eventCount": xpInt(st),
		"assurances": map[string]any{"cryptographicallyVerifiable": st > 0 && s.verifiable == st, "explicitDelegationChain": st > 0 && s.withChain == st,
			"signedHumanOverrides": s.human > 0, "narrative": narr},
		"items": items,
		"coverage": map[string]any{"total": xpInt(total), "satisfied": xpInt(sat), "partial": xpInt(partial), "notEvidenced": xpInt(notEv),
			"satisfiedFraction": jsNumber(fraction), "satisfiedPercent": jsNumber(xpRound(float64(fraction * 100)))},
		"summary": fmt.Sprintf("%s: %d/%d controls satisfied%s over %d action(s).", xpStr(framework), sat, total, extra, st),
	}
}

// ---- renderers -------------------------------------------------------------------------------------------------------------

// ComplianceRenderJSON is the report as stable, pretty JSON (JSON.stringify(report, null, 2)).
func ComplianceRenderJSON(report any) (string, error) {
	var out string
	err := xpTry(func() { out = cmpPretty(report, "") })
	return out, err
}

var cmpStatusGlyph = map[string]string{"satisfied": "✓", "partial": "◐", "not-evidenced": "·"}

func cmpUpper(v any) string {
	s, ok := v.(string)
	if !ok {
		xpPanic("toUpperCase is not a function")
	}
	return strings.ToUpper(s)
}

func cmpGlyph(status any) string {
	if s, ok := status.(string); ok {
		if g, has := cmpStatusGlyph[s]; has {
			return g
		}
	}
	return "undefined"
}

func cmpYes(v any, no string) string {
	if xpTruthy(v) {
		return "YES"
	}
	return no
}

// ComplianceRenderMarkdown is the report as an auditor-facing Markdown document.
func ComplianceRenderMarkdown(r any) (string, error) {
	var out string
	err := xpTry(func() {
		g := func(path ...string) string { return xpStr(cmpWalk(r, path...)) }
		lines := []string{"# PCA compliance evidence — " + g("framework"), "",
			fmt.Sprintf("Generated %s · %s action(s) · coverage: %s/%s satisfied (%s%%)", g("generatedAt", "iso"), g("eventCount"), g("coverage", "satisfied"), g("coverage", "total"), g("coverage", "satisfiedPercent"))}
		if xpGt(cmpWalk(r, "eventCount"), 0) {
			lines = append(lines, "", fmt.Sprintf("Reporting period: %s → %s", g("period", "from", "iso"), g("period", "to", "iso")))
		}
		lines = append(lines, "", "## Why this trail is admissible (what PCA uniquely provides)", "",
			"- **Cryptographically verifiable** — "+cmpYes(cmpWalk(r, "assurances", "cryptographicallyVerifiable"), "PARTIAL")+": every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.",
			"- **Explicit delegation chain** — "+cmpYes(cmpWalk(r, "assurances", "explicitDelegationChain"), "PARTIAL")+": each action records who authorized what scope, hop by hop, rooted at a principal.",
			"- **Signed human-overrides** — "+cmpYes(cmpWalk(r, "assurances", "signedHumanOverrides"), "none in period")+": a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.",
			"", "> "+g("assurances", "narrative"), "", "## Coverage summary", "", "| Satisfied | Partial | Not evidenced | Total |", "| --- | --- | --- | --- |",
			fmt.Sprintf("| %s | %s | %s | %s |", g("coverage", "satisfied"), g("coverage", "partial"), g("coverage", "notEvidenced"), g("coverage", "total")),
			"", "## Controls", "", "| Control | Clause | Status | Evidence in period |", "| --- | --- | --- | --- |")
		items, ok := cmpWalk(r, "items").([]any)
		if !ok {
			xpPanic("items is not iterable")
		}
		for _, i := range items {
			lines = append(lines, fmt.Sprintf("| %s (`%s`) | %s | %s %s | %s |", xpStr(cmpProp(i, "controlTitle")), xpStr(cmpProp(i, "controlId")), xpStr(cmpProp(i, "clause")),
				cmpGlyph(cmpProp(i, "status")), cmpUpper(cmpProp(i, "status")), xpStr(cmpProp(i, "evidence"))))
		}
		lines = append(lines, "", "## Control detail", "")
		for _, i := range items {
			lines = append(lines, fmt.Sprintf("### %s — %s", xpStr(cmpProp(i, "controlId")), xpStr(cmpProp(i, "controlTitle"))), "",
				"- Clause: "+xpStr(cmpProp(i, "clause")),
				fmt.Sprintf("- Status: %s %s", cmpGlyph(cmpProp(i, "status")), cmpUpper(cmpProp(i, "status"))),
				"- PCA evidence basis: "+xpStr(cmpProp(i, "pcaEvidence")),
				"- Evidence in period: "+xpStr(cmpProp(i, "evidence")))
			if n := cmpLength(cmpProp(i, "findings")); !xpIsUndef(n) && xpGt(n, 0) {
				lines = append(lines, "- Findings:")
				for _, f := range xpIter(cmpProp(i, "findings")) {
					lines = append(lines, "  - "+xpStr(f))
				}
			}
			lines = append(lines, "")
		}
		lines = append(lines, "---", "", "_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._")
		out = strings.Join(lines, "\n")
	})
	return out, err
}
