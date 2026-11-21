package pca

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ---- explainVerification ---------------------------------------------------------------------------------------------------

// xpReasonTail is the part of the verifier reason after "<name>: ", or ok=false.
func xpReasonTail(name string, vr any) (string, bool) {
	r, ok := xpGet(vr, "reason").(string)
	if !ok {
		return "", false
	}
	pre := name + ": "
	if strings.HasPrefix(r, pre) {
		return r[len(pre):], true
	}
	return "", false
}

type xpPin struct {
	detail, remedy string
	hop            int
	hasHop         bool
}

func xpValidityPinpoint(p, now any) xpPin {
	exp, iat := xpGet(p, "exp"), xpGet(p, "iat")
	lifetime := xpToNum(exp) - xpToNum(iat)
	if !xpGt(exp, iat) {
		return xpPin{detail: fmt.Sprintf("exp %s ≤ iat %s: empty validity window", xpStr(exp), xpStr(iat)), remedy: "set exp strictly greater than iat."}
	}
	if lifetime > MaxLifetimeMs {
		return xpPin{detail: fmt.Sprintf("lifetime %sms exceeds the %dms maximum", xpNumStr(lifetime), MaxLifetimeMs),
			remedy: fmt.Sprintf("shorten the window to ≤ %dms (buildPCActn ttlMs).", MaxLifetimeMs)}
	}
	if !xpIsUndef(now) {
		if !(finite(xpToNum(now)) && xpLe(iat, xpAdd(now, MaxSkewMs))) {
			return xpPin{detail: fmt.Sprintf("iat %s is %sms in the future (> %dms clock-skew allowance)", xpStr(iat), xpNumStr(xpToNum(iat)-xpToNum(now)), MaxSkewMs),
				remedy: "fix the signer clock; do not pre-date actions."}
		}
		if !(finite(xpToNum(now)) && xpLe(now, exp)) {
			return xpPin{detail: fmt.Sprintf("expired %sms ago (exp %s, now %s)", xpNumStr(xpToNum(now)-xpToNum(exp)), xpStr(exp), xpStr(now)),
				remedy: "build a fresh action — a PCActn lifetime is short by design."}
		}
	}
	return xpPin{detail: "validity window invalid", remedy: "build a fresh action with a valid iat/exp window."}
}

var xpHopRe = regexp.MustCompile(`hop ([0-9]+)`)

func xpCapChainPinpoint(p any) xpPin {
	var reason string
	if chain, ok := xpGet(p, "cap_chain").([]any); ok {
		why, vok := VerifyChain(chain, "", false)
		if vok {
			reason = "chain root is not the grant this verifier expects"
		} else if why != "" {
			reason = why
		} else {
			reason = "capability chain invalid"
		}
	} else {
		reason = "cap_chain is not an array"
	}
	remedy := "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats."
	switch {
	case strings.Contains(reason, "root issuer") || strings.Contains(reason, "not the grant"):
		remedy = "root the chain at the principal key that minted the grant."
	case strings.Contains(reason, "widens"):
		remedy = "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation."
	case strings.Contains(reason, "caveat"):
		remedy = "attenuation is append-only: never drop, reorder or edit a parent caveat."
	case strings.Contains(reason, "signature"):
		remedy = "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite)."
	}
	out := xpPin{detail: reason, remedy: remedy}
	if m := xpHopRe.FindStringSubmatch(reason); m != nil {
		out.hop, _ = strconv.Atoi(m[1])
		out.hasHop = true
	}
	return out
}

func xpLeafSigPinpoint(p any) xpPin {
	chain, isList := xpGet(p, "cap_chain").([]any)
	idx := -1
	if isList {
		idx = len(chain) - 1
	}
	var leaf any = xpUndef
	if idx >= 0 {
		leaf = chain[idx]
	}
	alg := xpNN(xpGet(p, "alg"), "ed25519")
	remedy := "sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder."
	if !xpTruthy(leaf) {
		return xpPin{detail: "no leaf capability to check the signature against (empty/invalid chain)", remedy: remedy}
	}
	out := xpPin{detail: fmt.Sprintf("leaf hop #%d signature (holder %s, suite %s) does not verify", idx, xpShort(xpGet(leaf, "holder")), xpStr(alg)), remedy: remedy}
	if idx >= 0 {
		out.hop, out.hasHop = idx, true
	}
	return out
}

func xpTailOr(tail string, has bool, def string) string {
	if has {
		return tail
	}
	return def
}

func xpPinpoint(name string, p, vr, now any) xpPin {
	tail, has := xpReasonTail(name, vr)
	action, plan := xpOpt(p, "action"), xpOpt(p, "plan")
	switch name {
	case "wire":
		return xpPin{detail: xpTailOr(tail, has, "wire structure / strict-canonical-form check failed"),
			remedy: "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK."}
	case "version":
		return xpPin{detail: xpTailOr(tail, has, fmt.Sprintf("unsupported ver %s (verifier requires %d)", xpN(xpGet(p, "ver")), PCActnVer)),
			remedy: fmt.Sprintf("re-mint the action at wire version %d.", PCActnVer)}
	case "audience":
		return xpPin{detail: xpTailOr(tail, has, fmt.Sprintf("aud %s does not match this resource server / instance", xpJSON(xpGet(p, "aud")))),
			remedy: "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any)."}
	case "validity":
		v := xpValidityPinpoint(p, now)
		return xpPin{detail: xpTailOr(tail, has, v.detail), remedy: v.remedy}
	case "cap_chain":
		c := xpCapChainPinpoint(p)
		return xpPin{detail: xpTailOr(tail, has, c.detail), remedy: c.remedy, hop: c.hop, hasHop: c.hasHop}
	case "grant_ref_bound":
		return xpPin{detail: xpTailOr(tail, has, fmt.Sprintf("grant_ref %s is not the id of the root capability in cap_chain", xpShort(xpGet(p, "grant_ref")))),
			remedy: "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant."}
	case "plan_inclusion":
		return xpPin{detail: xpTailOr(tail, has, fmt.Sprintf("action (verb %s on %s) is not node %s of committed plan %s",
			xpJSON(xpOpt(action, "verb")), xpJSON(xpOpt(action, "resource")), xpJSON(xpOpt(plan, "node_id")), xpShort(xpOpt(plan, "root")))),
			remedy: "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn)."}
	case "leaf_signature":
		l := xpLeafSigPinpoint(p)
		return xpPin{detail: xpTailOr(tail, has, l.detail), remedy: l.remedy, hop: l.hop, hasHop: l.hasHop}
	case "counter", "counter_format":
		return xpPin{detail: xpTailOr(tail, has, fmt.Sprintf("counter %s is missing or not a non-negative safe integer", xpN(xpGet(p, "counter")))),
			remedy: "use a strictly increasing per-holder counter; a repeated counter is a replay."}
	case "malformed":
		return xpPin{detail: xpTailOr(tail, has, "the PCActn is structurally malformed"),
			remedy: "rebuild the action with the SDK; do not construct the wire object by hand."}
	}
	return xpPin{detail: xpTailOr(tail, has, name+" check failed"),
		remedy: fmt.Sprintf("satisfy the %s requirement (supply the corresponding verifier hook / proof).", name)}
}

func xpPassDetail(name string, p any) string {
	switch name {
	case "wire":
		return "wire structure + strict canonical form valid"
	case "version":
		return fmt.Sprintf("ver %s supported", xpN(xpGet(p, "ver")))
	case "audience":
		return fmt.Sprintf("aud %s matches this resource server", xpJSON(xpGet(p, "aud")))
	case "validity":
		return fmt.Sprintf("fresh: iat/exp window valid (lifetime %ss)", xpN((xpToNum(xpGet(p, "exp"))-xpToNum(xpGet(p, "iat")))/1000))
	case "cap_chain":
		chain, _ := xpGet(p, "cap_chain").([]any)
		var root any = xpUndef
		if len(chain) > 0 {
			root = chain[0]
		}
		return fmt.Sprintf("%d-hop chain verifies; root issuer %s", len(chain), xpShort(xpOpt(root, "issuer")))
	case "grant_ref_bound":
		return fmt.Sprintf("grant_ref %s is the id of the chain root", xpShort(xpGet(p, "grant_ref")))
	case "plan_inclusion":
		plan := xpOpt(p, "plan")
		return fmt.Sprintf("action is node %s of committed plan %s", xpJSON(xpOpt(plan, "node_id")), xpShort(xpOpt(plan, "root")))
	case "leaf_signature":
		chain, _ := xpGet(p, "cap_chain").([]any)
		var leaf any = xpUndef
		if len(chain) > 0 {
			leaf = chain[len(chain)-1]
		}
		return fmt.Sprintf("leaf holder %s signature valid (suite %s)", xpShort(xpOpt(leaf, "holder")), xpStr(xpNN(xpGet(p, "alg"), "ed25519")))
	case "counter", "counter_format":
		return fmt.Sprintf("counter %s well-formed", xpN(xpGet(p, "counter")))
	}
	return "ok"
}

func xpCleanCheck(c map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	out["detail"] = xpClean(c["detail"])
	return out
}

func xpVerification(verdict string, allow bool, checks []map[string]any, decisive map[string]any, summary string) map[string]any {
	cs := make([]any, len(checks))
	passed, failed, notEnf := []any{}, []any{}, []any{}
	for i, c := range checks {
		cs[i] = c
		switch c["status"] {
		case "pass":
			passed = append(passed, c["name"])
		case "fail":
			failed = append(failed, c["name"])
		case "not-enforced":
			notEnf = append(notEnf, c["name"])
		}
	}
	out := map[string]any{"kind": "verification", "verdict": verdict, "allow": allow, "checks": cs, "passed": passed, "failed": failed,
		"notEnforced": notEnf, "summary": summary}
	if decisive != nil {
		out["decisive"] = decisive
	}
	return out
}

func xpDeniedVerification(why string) map[string]any {
	e := map[string]any{"name": "malformed", "status": "fail", "title": xpCheckTitle["malformed"], "detail": why,
		"remedy": "pass the PCActn and the verifier result you verified.", "decisive": true}
	return xpVerification("deny", false, []map[string]any{e}, e, "Denied: "+why)
}

// ExplainVerification walks the normative checks of an offline verification in order: it summarizes what held for each pass and
// pinpoints the first failing check (which hop, which audience mismatch, which validity sub-case, ...) with a concrete remedy.
// opts may carry `now` (epoch ms) to tell "expired" from "clock skew" precisely. A malformed input is a denial, never a throw.
func ExplainVerification(pcaActn, verifyResult, opts any) map[string]any {
	if !xpIsObj(pcaActn) || !xpIsObj(verifyResult) {
		return xpDeniedVerification("the PCActn or the verifier result is missing")
	}
	var out map[string]any
	if err := xpTry(func() { out = xpExplainVerificationInner(pcaActn, verifyResult, opts) }); err != nil {
		return xpDeniedVerification("the PCActn or the verifier result is malformed")
	}
	return out
}

func xpExplainVerificationInner(p, vr, opts any) map[string]any {
	statuses := xpNN(xpGet(vr, "checks"), map[string]any{})
	ordered := append([]string{}, ExplainVerifyCheckOrder...)
	seen := map[string]bool{}
	for _, n := range ordered {
		seen[n] = true
	}
	for _, n := range xpKeys(statuses) {
		if !seen[n] {
			ordered = append(ordered, n)
		}
	}
	decisiveName, hasDecisive := "", false
	for _, n := range ordered {
		if s, _ := xpGet(statuses, n).(string); s == "fail" {
			decisiveName, hasDecisive = n, true
			break
		}
	}
	var checks []map[string]any
	var decisive map[string]any
	for _, name := range ordered {
		status := xpNN(xpGet(statuses, name), "skipped")
		title := name
		if t, ok := xpCheckTitle[name]; ok {
			title = t
		}
		var detail string
		var remedy string
		hasRemedy := false
		hop, hasHop := 0, false
		switch status {
		case "fail":
			pin := xpPinpoint(name, p, vr, xpRd(opts, "now"))
			detail, remedy, hasRemedy, hop, hasHop = pin.detail, pin.remedy, true, pin.hop, pin.hasHop
		case "pass":
			detail = xpPassDetail(name, p)
		case "not-enforced":
			detail = "not enforced by this verifier (no hook / opt-out)"
		case "unsupported":
			detail = "the PCActn carries a feature this verifier does not implement (never a pass)"
		default:
			detail = "not reached (a terminal earlier check stopped evaluation)"
		}
		entry := map[string]any{"name": name, "status": status, "title": title, "detail": detail}
		if hasRemedy {
			entry["remedy"] = remedy
		}
		if hasHop {
			entry["hop"] = xpInt(hop)
		}
		if hasDecisive && name == decisiveName {
			entry["decisive"] = true
			decisive = entry
		}
		checks = append(checks, entry)
	}

	// Allow only on an explicit `allow: true` that no check contradicts and that carries per-check statuses.
	_, hasChecks := xpGet(vr, "checks").(map[string]any)
	allowClaimed := xpGet(vr, "allow") == true
	claimed := allowClaimed && hasChecks
	contradicted := claimed && hasDecisive
	verdict := "deny"
	if claimed && !contradicted {
		verdict = "allow"
	}
	var summary string
	switch {
	case verdict == "allow":
		n := 0
		for _, c := range checks {
			if c["status"] == "pass" {
				n++
			}
		}
		summary = fmt.Sprintf("All %d evaluated checks passed (no check failed).", n)
	case allowClaimed && !hasChecks:
		summary = "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial)."
	case contradicted:
		t := decisiveName
		if decisive != nil {
			t = xpStr(decisive["title"])
		}
		summary = fmt.Sprintf("Denied: the verifier result says allow but the \"%s\" check failed (inconsistent result, treated as a denial).", t)
	case decisive != nil:
		summary = fmt.Sprintf("Denied at the \"%s\" check: %s", xpStr(decisive["title"]), xpStr(decisive["detail"]))
	default:
		if r, ok := xpGet(vr, "reason").(string); ok {
			summary = "Denied: " + r
		} else {
			summary = "Denied: a check failed"
		}
	}
	cleaned := make([]map[string]any, len(checks))
	for i, c := range checks {
		cleaned[i] = xpCleanCheck(c)
	}
	var cd map[string]any
	if decisive != nil {
		cd = xpCleanCheck(decisive)
	}
	return xpVerification(verdict, verdict == "allow", cleaned, cd, xpClean(summary))
}

var xpGlyph = map[string]string{"pass": "✓", "fail": "✗", "not-enforced": "·", "unsupported": "?", "skipped": "–"}

// ExplainVerificationText renders a verification explanation.
func ExplainVerificationText(e map[string]any) (string, error) {
	var out string
	err := xpTry(func() {
		lines := []string{"PCA verification — " + strings.ToUpper(xpStr(e["verdict"])), xpStr(e["summary"]), ""}
		for _, ci := range e["checks"].([]any) {
			c := ci.(map[string]any)
			mark := ""
			if xpTruthy(xpGet(c, "decisive")) {
				mark = " ◀ DECISIVE"
			}
			glyph := "undefined"
			if st, ok := c["status"].(string); ok {
				if g, has := xpGlyph[st]; has {
					glyph = g
				}
			}
			lines = append(lines, fmt.Sprintf("  %s %s %s%s", glyph, xpPadEnd(xpStr(c["name"]), 16), xpStr(c["detail"]), mark))
			if xpTruthy(xpGet(c, "decisive")) && xpTruthy(xpGet(c, "remedy")) {
				lines = append(lines, "      ↳ fix: "+xpStr(c["remedy"]))
			}
		}
		out = strings.Join(lines, "\n")
	})
	return out, err
}

// ---- explainDecision -------------------------------------------------------------------------------------------------------

func xpCaveatRemedy(typ string, r xpRest) string {
	g := func(k string) any {
		if v, ok := r.m[k]; ok {
			return v
		}
		return xpUndef
	}
	switch typ {
	case "expires":
		return fmt.Sprintf("the grant expired at %s (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.", xpN(g("at")))
	case "not_before":
		return fmt.Sprintf("the grant is not valid until %s (epoch ms); retry after that time.", xpN(g("at")))
	case "rate":
		return fmt.Sprintf("rate limit %s/%ss reached; wait for the window to clear or raise the 'rate' caveat.", xpN(g("max")), xpN(g("per_secs")))
	case "max_blast_radius":
		return fmt.Sprintf("the action's blast radius exceeds the caveat max %s; narrow the action or raise 'max_blast_radius'.", xpN(g("max")))
	case "reversibility_max":
		return fmt.Sprintf("the action is more severe than the allowed class '%s'; only that class or lower is permitted.", xpStr(g("class")))
	case "delegation_depth":
		return fmt.Sprintf("delegation depth exceeds max %s; act from a shallower hop or raise 'delegation_depth'.", xpN(g("max")))
	}
	return fmt.Sprintf("caveat '%s' is not satisfied; check its parameters against the action/context.", typ)
}

func xpCaveatDetail(typ string, r xpRest, satisfied any) string {
	bound := xpValueSummary(r)
	verb := "NARROWED/DENIED"
	if xpTruthy(satisfied) {
		verb = "held"
	}
	if len(bound) > 0 {
		return typ + "(" + bound + ") " + verb
	}
	return typ + " " + verb
}

var xpFailedCaveatsRe = regexp.MustCompile(`caveat\(s\) not satisfied: ([^\n\r\x{2028}\x{2029}]+)\z`)

func xpFailedCaveatTypes(reasons []any) map[string]bool {
	out := map[string]bool{}
	for _, r := range reasons {
		if m := xpFailedCaveatsRe.FindStringSubmatch(xpStr(r)); m != nil {
			for _, t := range strings.Split(m[1], ",") {
				if tt := jsTrim(t); tt != "" {
					out[tt] = true
				}
			}
		}
	}
	return out
}

func xpRiskBand(r, theta1, theta2, tier any) string {
	if xpIsUndef(theta1) || xpIsUndef(theta2) {
		return "effective tier t=" + xpStr(tier)
	}
	if xpLe(r, theta1) {
		return fmt.Sprintf("r %s ≤ θ1 %s → claim band (t=1)", xpN(r), xpN(theta1))
	}
	if xpLe(r, theta2) {
		return fmt.Sprintf("θ1 %s < r %s ≤ θ2 %s → standard band (t=2)", xpN(theta1), xpN(r), xpN(theta2))
	}
	return fmt.Sprintf("r %s > θ2 %s → strong band (t=3)", xpN(r), xpN(theta2))
}

func xpNoDecision(reason string) map[string]any {
	return map[string]any{"admit": false, "needStepUp": false, "releaseGuardianShare": false, "r": xpInt(1),
		"requiredThreshold": map[string]any{"t": xpInt(3), "proof": "human", "optimisticAllowed": false},
		"budget":            map[string]any{"B": xpInt(0), "tau": xpInt(0), "asOf": xpInt(0)}, "reasons": []any{reason}}
}

// ExplainDecision explains a Policy-VM decision: which predicate granted the (verb, resource) and under what `where` bound, which
// caveat narrowed or denied (type and offending value), the risk band and the admission path; for anything short of auto-admit the
// single decisive reason and remedy. opts may carry `envelope` and `context` ({action, caveat, chain}). A missing or malformed
// decision is a denial, never an allow.
func ExplainDecision(pcaActn, decision, opts any) (map[string]any, error) {
	var out map[string]any
	err := xpTry(func() {
		if !xpIsObj(decision) || !xpIsObj(xpGet(decision, "requiredThreshold")) {
			out = xpExplainDecisionInner(xpNoDecision("no policy decision supplied (default-deny)"), opts)
			return
		}
		if e := xpTry(func() { out = xpExplainDecisionInner(decision, opts) }); e != nil {
			out = xpExplainDecisionInner(xpNoDecision("the policy decision could not be explained (default-deny)"), map[string]any{})
		}
	})
	return out, err
}

func xpIncludes(r any, needle string) bool {
	s, ok := r.(string)
	if !ok {
		xpPanic("includes is not a function")
	}
	return strings.Contains(s, needle)
}

// xpEvalCaveat is `evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok`: the reference's camelCase context mapped onto the evaluator's.
func xpEvalCaveat(cv, caveatCtx, actionCtx any) bool {
	inner, _ := xpGet(actionCtx, "action").(map[string]any)
	if inner == nil {
		inner = map[string]any{}
	}
	c := map[string]any{}
	for _, p := range [][2]string{{"now", "now"}, {"delegationDepth", "delegation_depth"}, {"blastRadius", "blast_radius"},
		{"reversibilityClass", "reversibility_class"}, {"recentActionTimes", "recent_action_times"}} {
		if v := xpGet(caveatCtx, p[0]); !xpIsUndef(v) {
			c[p[1]] = v
		}
	}
	c["action"] = inner
	tc := &ToolCall{Args: map[string]any{}}
	if v, ok := xpGet(inner, "verb").(string); ok {
		tc.Tool = v
	}
	if v, ok := xpGet(inner, "params").(map[string]any); ok {
		tc.Args = v
	}
	if b, ok := xpGet(actionCtx, "toolBinding").(string); ok {
		tc.ToolSignatureDigest = &b
	}
	actx, _ := actionCtx.(map[string]any)
	if actx == nil {
		actx = map[string]any{}
	}
	ok, _ := EvaluateAgentCaveats([]any{cv}, c, actx, tc)
	return ok
}

func xpMapGet(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return xpUndef
}

func xpExplainDecisionInner(decision, opts any) map[string]any {
	env := xpRd(opts, "envelope")
	ctx := xpNN(xpGet(opts, "context"), map[string]any{})
	reasons, _ := xpGet(decision, "reasons").([]any)

	admitted := xpGet(decision, "admit") == true
	rgs := xpGet(decision, "releaseGuardianShare")
	disposition := "denied"
	if admitted {
		disposition = "auto-admit"
	} else if rgs == true {
		disposition = "step-up"
	}
	verdict := "deny"
	if admitted {
		verdict = "allow"
	}

	grant := map[string]any{}
	xpPut(grant, "granted", rgs)
	chain := xpGet(ctx, "chain")
	rootCap := xpOpt(chain, "0")
	if xpTruthy(rootCap) {
		xpPut(grant, "capabilityId", xpGet(rootCap, "id"))
	}
	ctxAction, ctxCaveat := xpGet(ctx, "action"), xpGet(ctx, "caveat")
	hasEnv := xpTruthy(env)
	if hasEnv && xpTruthy(ctxAction) {
		preds := xpGet(env, "predicates")
		am, _ := ctxAction.(map[string]any)
		if am == nil {
			am = map[string]any{}
		}
		arr, _ := preds.([]any)
		matchedIdx := -1
		b := &regexBudget{}
		for i, pr := range arr {
			if predicateMatches(pr, am, b) {
				matchedIdx = i
				break
			}
		}
		if matchedIdx >= 0 {
			matched := arr[matchedIdx]
			grant["granted"] = true
			grant["predicate"] = matched
			grant["predicateIndex"] = xpInt(matchedIdx)
			grant["where"] = xpWhereSummary(xpGet(matched, "where"))
		} else {
			_, reason := envelopePredicates(preds, am, &regexBudget{})
			grant["granted"] = false
			grant["reason"] = reason
		}
	} else if !xpTruthy(rgs) {
		for _, r := range reasons {
			if xpIncludes(r, "predicate") || xpIncludes(r, "not permitted") {
				grant["reason"] = r
				break
			}
		}
	}

	failedFromReasons := xpFailedCaveatTypes(reasons)
	canEval := !xpIsUndef(env) && !xpIsUndef(ctxCaveat) && !xpIsUndef(ctxAction)
	grantCaveats := xpNN(xpOpt(env, "caveats"), []any{})
	chain0 := xpOpt(chain, "0")
	rootCount := 0
	if !xpIsUndef(chain0) && chain0 != nil {
		cv0 := xpRd(chain0, "caveats")
		if xpIsUndef(cv0) || cv0 == nil {
			xpPanic("cannot read 'length' of undefined")
		}
		switch t := cv0.(type) {
		case []any:
			rootCount = len(t)
		case string:
			rootCount = xpLen16(t)
		}
	}
	var delegated any = []any{}
	if cl, ok := chain.([]any); ok && len(cl) > 1 {
		delegated = xpSliceFrom(xpNN(xpOpt(cl[len(cl)-1], "caveats"), []any{}), rootCount)
	}
	classify := func(cv any, isDelegated bool) map[string]any {
		typ, rest := xpCaveatType(cv), xpCaveatRest(cv)
		var satisfied any
		if canEval && xpTruthy(ctxCaveat) && xpTruthy(ctxAction) {
			satisfied = xpEvalCaveat(cv, ctxCaveat, ctxAction)
		} else if failedFromReasons[typ] {
			satisfied = false
		} else {
			satisfied = rgs
		}
		out := map[string]any{"type": typ}
		xpPut(out, "satisfied", satisfied)
		out["value"] = rest.m
		out["detail"] = xpCaveatDetail(typ, rest, satisfied)
		out["delegated"] = isDelegated
		if !xpTruthy(satisfied) {
			out["remedy"] = xpCaveatRemedy(typ, rest)
		}
		return out
	}
	var caveats []map[string]any
	for _, cv := range xpIter(grantCaveats) {
		caveats = append(caveats, classify(cv, false))
	}
	for _, cv := range xpIter(delegated) {
		caveats = append(caveats, classify(cv, true))
	}

	rt := xpGet(decision, "requiredThreshold")
	r := xpGet(decision, "r")
	envNN := !xpIsUndef(env) && env != nil
	var riskPolicy any = xpUndef
	if envNN {
		riskPolicy = xpRd(env, "risk_policy")
		if xpIsUndef(riskPolicy) || riskPolicy == nil {
			xpPanic("cannot read properties of undefined")
		}
	}
	theta1, theta2 := xpOpt(riskPolicy, "theta1"), xpOpt(riskPolicy, "theta2")
	tier, proof, optimistic := xpGet(rt, "t"), xpGet(rt, "proof"), xpGet(rt, "optimisticAllowed")
	risk := map[string]any{}
	xpPut(risk, "r", r)
	xpPut(risk, "tier", tier)
	xpPut(risk, "proof", proof)
	xpPut(risk, "optimisticAllowed", optimistic)
	risk["band"] = xpRiskBand(r, theta1, theta2, tier)
	if hasEnv {
		xpPut(risk, "theta1", theta1)
		xpPut(risk, "theta2", theta2)
	}

	var kappa any = xpUndef
	if envNN {
		kappa = xpGet(riskPolicy, "kappa")
	}
	var costVal any
	if !xpIsUndef(kappa) {
		rf, rok := jsNum(r)
		if !rok || math.IsInf(rf, 0) || math.IsNaN(rf) {
			rf = 1
		}
		kf, kok := jsNum(kappa)
		if !kok {
			kf = 0
		}
		costVal = jsNumber(RiskCost(rf, kf))
	}
	budgetDepleted := false
	for _, x := range reasons {
		if xpIncludes(x, "budget depleted") {
			budgetDepleted = true
			break
		}
	}
	var path string
	switch {
	case admitted:
		path = fmt.Sprintf("auto-admitted at t=%s (%s); metered", xpStr(tier), xpStr(proof))
	case !xpTruthy(rgs):
		path = "guardian share withheld — policy not satisfied (no autonomous or guardian path)"
	case budgetDepleted:
		path = "trust budget cannot cover the cost — step-up to t=3 (human recharge) required"
	default:
		path = fmt.Sprintf("step-up to t=%s (%s) co-signature required", xpStr(tier), xpStr(proof))
	}
	admission := map[string]any{"admit": admitted}
	xpPut(admission, "needStepUp", xpGet(decision, "needStepUp"))
	xpPut(admission, "releaseGuardianShare", rgs)
	xpPut(admission, "budget", xpGet(decision, "budget"))
	admission["path"] = path
	if costVal != nil {
		admission["cost"] = costVal
	}
	if !xpIsUndef(kappa) {
		admission["kappa"] = kappa
	}

	var decisive map[string]any
	if !admitted {
		granted := xpTruthy(xpMapGet(grant, "granted"))
		if !granted {
			decisive = map[string]any{"reason": xpNN(xpMapGet(grant, "reason"), "action not permitted by the envelope predicates (default-deny)"),
				"remedy": "grant a predicate that permits this verb+resource (and satisfies its where bound)."}
		} else {
			var firstFailed map[string]any
			for _, c := range caveats {
				if !xpTruthy(xpMapGet(c, "satisfied")) {
					firstFailed = c
					break
				}
			}
			switch {
			case firstFailed != nil:
				decisive = map[string]any{"reason": fmt.Sprintf("caveat '%s' narrowed the authority away: %s", xpStr(firstFailed["type"]), xpStr(firstFailed["detail"]))}
				if xpTruthy(xpMapGet(firstFailed, "remedy")) {
					decisive["remedy"] = firstFailed["remedy"]
				}
			case budgetDepleted:
				c := ""
				if costVal != nil {
					c = "=" + xpN(costVal)
				}
				decisive = map[string]any{"reason": fmt.Sprintf("risk %s is admissible but the trust budget cannot cover cost κ·r%s", xpN(r), c),
					"remedy": "recharge the budget with a human co-sign, or lower the action risk."}
			default:
				rem := "obtain the guardian/principal co-signature for this tier."
				if tf, ok := jsNum(tier); ok && tf == 3 {
					rem = "obtain a human step-up co-signature."
				}
				decisive = map[string]any{"reason": fmt.Sprintf("risk %s exceeds the auto threshold → step-up to t=%s (%s)", xpN(r), xpStr(tier), xpStr(proof)),
					"remedy": rem}
			}
		}
	}

	var summary string
	switch {
	case admitted:
		who := "policy"
		if xpTruthy(xpMapGet(grant, "predicate")) {
			who = "predicate #" + xpStr(xpMapGet(grant, "predicateIndex"))
		}
		summary = fmt.Sprintf("Auto-admitted: %s grants it, all caveats held, risk r=%s is in the t=%s band and the budget covers it.", who, xpN(r), xpStr(tier))
	case decisive != nil:
		w := "Needs step-up"
		if verdict == "deny" && disposition == "denied" {
			w = "Denied"
		}
		summary = w + ": " + xpStr(decisive["reason"])
	default:
		summary = fmt.Sprintf("Not auto-admitted (t=%s).", xpStr(tier))
	}

	cleanedCaveats := make([]any, len(caveats))
	for i, c := range caveats {
		cc := make(map[string]any, len(c))
		for k, v := range c {
			cc[k] = v
		}
		cc["detail"] = xpClean(c["detail"])
		cleanedCaveats[i] = cc
	}
	out := map[string]any{"kind": "decision", "verdict": verdict, "disposition": disposition, "grant": grant, "caveats": cleanedCaveats,
		"risk": risk, "admission": admission}
	if decisive != nil {
		cd := make(map[string]any, len(decisive))
		for k, v := range decisive {
			cd[k] = v
		}
		cd["reason"] = xpClean(decisive["reason"])
		out["decisive"] = cd
	}
	rs := make([]any, len(reasons))
	for i, x := range reasons {
		rs[i] = xpClean(x)
	}
	out["reasons"] = rs
	out["summary"] = xpClean(summary)
	return out
}

// ExplainDecisionText renders a decision explanation.
func ExplainDecisionText(e map[string]any) (string, error) {
	var out string
	err := xpTry(func() {
		lines := []string{fmt.Sprintf("PCA decision — %s (%s)", strings.ToUpper(xpStr(e["verdict"])), xpStr(e["disposition"])), xpStr(e["summary"]), ""}
		gr := e["grant"]
		pred := xpGet(gr, "predicate")
		if xpTruthy(xpGet(gr, "granted")) && xpTruthy(pred) {
			pv := xpGet(pred, "verb")
			var verbs string
			if l, ok := pv.([]any); ok {
				ps := make([]string, len(l))
				for i, x := range l {
					if x != nil {
						ps[i] = xpStr(x)
					}
				}
				verbs = strings.Join(ps, "|")
			} else {
				verbs = xpStr(pv)
			}
			lines = append(lines, fmt.Sprintf("  authority : predicate #%s of grant %s grants %s on %s", xpStr(xpGet(gr, "predicateIndex")),
				xpShort(xpGet(gr, "capabilityId")), verbs, xpStr(xpNN(xpGet(pred, "resource"), "*"))))
			lines = append(lines, "              where "+xpStr(xpGet(gr, "where")))
		} else {
			lines = append(lines, "  authority : NOT granted — "+xpStr(xpNN(xpGet(gr, "reason"), "no predicate permits this action")))
		}
		cavs := e["caveats"].([]any)
		if len(cavs) == 0 {
			lines = append(lines, "  caveats   : none")
		}
		for _, ci := range cavs {
			c := ci.(map[string]any)
			mark := "✗"
			if xpTruthy(xpGet(c, "satisfied")) {
				mark = "✓"
			}
			src := ""
			if xpTruthy(xpGet(c, "delegated")) {
				src = " [delegated]"
			}
			lines = append(lines, fmt.Sprintf("  caveat %s  : %s%s", mark, xpStr(c["detail"]), src))
			if !xpTruthy(xpGet(c, "satisfied")) && xpTruthy(xpGet(c, "remedy")) {
				lines = append(lines, "              ↳ fix: "+xpStr(c["remedy"]))
			}
		}
		risk := e["risk"]
		lines = append(lines, fmt.Sprintf("  risk      : %s; proof=%s, optimistic=%s", xpStr(xpGet(risk, "band")), xpStr(xpGet(risk, "proof")), xpStr(xpGet(risk, "optimisticAllowed"))))
		a := e["admission"]
		costStr := ""
		if cost := xpGet(a, "cost"); !xpIsUndef(cost) {
			costStr = fmt.Sprintf(", cost κ·r=%s (κ=%s)", xpN(cost), xpN(xpGet(a, "kappa")))
		}
		lines = append(lines, fmt.Sprintf("  budget    : %s%s; B after=%s", xpStr(xpGet(a, "path")), costStr, xpN(xpRd(xpGet(a, "budget"), "B"))))
		if dec := xpGet(e, "decisive"); xpTruthy(dec) {
			lines = append(lines, "", "  ◀ DECISIVE: "+xpStr(xpGet(dec, "reason")))
			if xpTruthy(xpGet(dec, "remedy")) {
				lines = append(lines, "      ↳ fix: "+xpStr(xpGet(dec, "remedy")))
			}
		}
		out = strings.Join(lines, "\n")
	})
	return out, err
}
