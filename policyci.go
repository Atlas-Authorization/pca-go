package pca

// The policy-safety CI gate. It drives the static analyzer over a PCA envelope, grant, compiled policy, bare
// {predicates, caveats} or a delegation chain and reports findings: five toggleable rules plus schema mismatch. SOUNDNESS: a
// hard `error` is emitted only from a PROVEN analyzer verdict; any undecidable feature fails safe to a `warn` / `info` that
// says so. Also the authoring gates (diff, test, coverage) and the command line (PolicyCiRun, PolicyCiParseArgs). Findings and
// results are plain JSON values.
//

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var pciDefaultDangerous = []any{"delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant",
	"revoke", "deploy", "shutdown", "rotate"}

var pciSeverityRank = map[string]int{"info": 1, "warn": 2, "error": 3}

var (
	pciScopeNarrowing = []string{"max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth"}
	pciBudgetGate     = []string{"max_blast_radius", "rate", "budget_alloc"}
)

// pciGuard runs f, mapping a reference-style throw (or any panic) to an error.
func pciGuard(f func() any) (any, error) { return anlTry(f) }

func pciIsRecord(x any) bool { _, ok := x.(map[string]any); return ok }

func pciIsObj(x any) bool {
	switch x.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func pciStrIn(s string, xs []string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func pciVerbsOf(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := []string{}
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}

func pciIsDangerousVerb(verb string, dangerous any) bool {
	v := strings.ToLower(verb)
	for _, kw := range anlReqList(dangerous) {
		if strings.Contains(v, strings.ToLower(anlStr(kw, "keyword"))) {
			return true
		}
	}
	return false
}

func pciIsWildcardResource(resource any) bool {
	if anlIsUndef(resource) {
		return true
	}
	s, ok := resource.(string)
	return ok && s == "*"
}

func pciHasCaveatOfType(caveats any, types []string) bool {
	for _, c := range anlReqList(caveats) {
		if m, ok := c.(map[string]any); ok {
			if t, ok := m["type"].(string); ok && pciStrIn(t, types) {
				return true
			}
		}
	}
	return false
}

func pciDescribeAction(a any) string {
	parts := []string{anlJS(anlGet(a, "verb")), anlJS(anlGet(a, "resource"))}
	params := anlGet(a, "params")
	if pm, ok := params.(map[string]any); ok && anlTruthy(params) && len(pm) > 0 {
		parts = append(parts, anlJSON(params))
	}
	if rc := anlGet(a, "reversibilityClass"); !anlIsUndef(rc) {
		parts = append(parts, "["+anlJS(rc)+"]")
	}
	return strings.Join(parts, " ")
}

func pciFind(rule, severity, message string, where ...string) map[string]any {
	f := map[string]any{"rule": rule, "severity": severity, "message": message}
	if len(where) > 0 {
		f["where"] = where[0]
	}
	return f
}

// ---- normalization ----

// PolicyCiIsCapability reports whether x is a minted grant / delegation hop: the content-addressed, signed shape of a capability.
func PolicyCiIsCapability(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"id", "issuer", "holder", "body_digest", "sig"} {
		if _, ok := m[k].(string); !ok {
			return false
		}
	}
	_, ok = m["caveats"].([]any)
	return ok
}

// PolicyCiIsEnvelope reports whether x is a signed policy envelope (the root intent grant payload).
func PolicyCiIsEnvelope(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	if _, ok := m["goal_commit"].(string); !ok {
		return false
	}
	if _, ok := m["predicates"].([]any); !ok {
		return false
	}
	if _, ok := m["caveats"].([]any); !ok {
		return false
	}
	return pciIsRecord(m["agent_binding"]) && pciIsRecord(m["risk_policy"])
}

func pciIsCompiled(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	_, a := m["predicates"].([]any)
	_, b := m["caveats"].([]any)
	_, c := m["actions"].([]any)
	return a && b && c && pciIsRecord(m["riskPolicy"])
}

func pciRuntimeCaveats(caveats []any) []any {
	out := []any{}
	for _, c := range caveats {
		if !pciIsObj(c) {
			continue
		}
		if m, ok := c.(map[string]any); ok && m["type"] == envelopeCaveat {
			continue
		}
		out = append(out, c)
	}
	return out
}

func pciGrantCaveats(cap any) []any {
	m, _ := cap.(map[string]any)
	cs, _ := m["caveats"].([]any)
	return pciRuntimeCaveats(cs)
}

func pciCat(a, b []any) []any { return append(append([]any{}, a...), b...) }

func pciFromGrant(grant any) map[string]any {
	env := ReadEnvelope(grant)
	if env == nil {
		return map[string]any{"ok": false, "reason": "grant has no readable `envelope` caveat (malformed or unsigned payload)"}
	}
	envCaveats, _ := env["caveats"].([]any)
	policy := map[string]any{"predicates": env["predicates"], "caveats": pciCat(envCaveats, pciGrantCaveats(grant)), "kind": "grant"}
	if rp, has := env["risk_policy"]; has {
		policy["riskPolicy"] = rp
	}
	return map[string]any{"ok": true, "policy": policy}
}

// PolicyCiNormalizePolicyInput reduces any single-policy input to its effective authority: {ok: true, policy: {predicates,
// caveats, riskPolicy?, kind}} or {ok: false, reason}.
func PolicyCiNormalizePolicyInput(input any) map[string]any {
	m, _ := input.(map[string]any)
	switch {
	case PolicyCiIsCapability(input):
		return pciFromGrant(input)
	case PolicyCiIsEnvelope(input):
		return map[string]any{"ok": true, "policy": map[string]any{"predicates": m["predicates"], "caveats": m["caveats"], "riskPolicy": m["risk_policy"], "kind": "envelope"}}
	case pciIsCompiled(input):
		return map[string]any{"ok": true, "policy": map[string]any{"predicates": m["predicates"], "caveats": m["caveats"], "riskPolicy": m["riskPolicy"], "kind": "compiled"}}
	}
	if _, ok := m["predicates"].([]any); ok {
		c, isList := m["caveats"].([]any)
		if !isList {
			c = []any{}
		}
		return map[string]any{"ok": true, "policy": map[string]any{"predicates": m["predicates"], "caveats": c, "kind": "bare"}}
	}
	return map[string]any{"ok": false, "reason": "unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })"}
}

// PolicyCiNormalizeChain normalizes a delegation chain (root to leaf) to one effective policy per hop: {ok: true, hops} or
// {ok: false, reason}.
func PolicyCiNormalizeChain(chainIn any) (map[string]any, error) {
	r, err := pciGuard(func() any { return pciNormalizeChain(chainIn) })
	m, _ := r.(map[string]any)
	return m, err
}

func pciNormalizeChain(chainIn any) map[string]any {
	chain := anlReqList(chainIn)
	if len(chain) == 0 {
		return map[string]any{"ok": false, "reason": "empty chain"}
	}
	allCaps := true
	for _, c := range chain {
		if !PolicyCiIsCapability(c) {
			allCaps = false
			break
		}
	}
	hops := []any{}
	if allCaps {
		env := ReadEnvelope(chain[0])
		if env == nil {
			return map[string]any{"ok": false, "reason": "root grant has no readable `envelope` caveat"}
		}
		envCaveats, _ := env["caveats"].([]any)
		for _, cap := range chain {
			hop := map[string]any{"predicates": env["predicates"], "caveats": pciCat(envCaveats, pciGrantCaveats(cap)), "kind": "chain-hop"}
			if rp, has := env["risk_policy"]; has {
				hop["riskPolicy"] = rp
			}
			hops = append(hops, hop)
		}
		return map[string]any{"ok": true, "hops": hops}
	}
	for i, c := range chain {
		r := PolicyCiNormalizePolicyInput(c)
		if r["ok"] != true {
			return map[string]any{"ok": false, "reason": fmt.Sprintf("hop %d: %s", i, r["reason"])}
		}
		hop := anlCopy(r["policy"].(map[string]any))
		hop["kind"] = "chain-hop"
		hops = append(hops, hop)
	}
	return map[string]any{"ok": true, "hops": hops}
}

// ---- rules ----

func pciAnalyzerInput(p map[string]any) map[string]any {
	return map[string]any{"predicates": p["predicates"], "caveats": p["caveats"]}
}

func pciDeclaredVerbs(predicates any) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range anlReqList(predicates) {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		for _, v := range pciVerbsOf(m["verb"]) {
			if v != "*" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func pciGateDescription(policy map[string]any) (string, bool) {
	gates := []string{}
	if pciHasCaveatOfType(policy["caveats"], pciBudgetGate) {
		names := []string{}
		for _, c := range anlReqList(policy["caveats"]) {
			if anlIncludes(pciStrAny(pciBudgetGate), anlGet(c, "type")) {
				names = append(names, anlJS(anlGet(c, "type")))
			}
		}
		gates = append(gates, strings.Join(names, "/"))
	}
	if rpm, ok := policy["riskPolicy"].(map[string]any); ok {
		if f, fin := anlFin(rpm["theta2"]); fin && f < 1 {
			gates = append(gates, "risk step-up (theta2 < 1)")
		}
	}
	if len(gates) == 0 {
		return "", false
	}
	return strings.Join(gates, ", "), true
}

func pciStrAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func pciRuleOverBroadGrant(policy map[string]any, dangerous any, opts any) []any {
	out := []any{}
	inp := pciAnalyzerInput(policy)
	hasScopeNarrowing := pciHasCaveatOfType(policy["caveats"], pciScopeNarrowing)
	for i, p := range anlReqList(policy["predicates"]) {
		if !pciIsObj(p) {
			continue
		}
		d, _ := p.(map[string]any)
		verbs := pciVerbsOf(d["verb"])
		where := fmt.Sprintf("predicates[%d]", i)
		w, _ := d["where"].([]any)
		hasWhere := len(w) > 0
		if pciStrIn("*", verbs) {
			out = append(out, pciFind("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' — authority over any action", where))
		}
		res, hasRes := d["resource"]
		if !hasRes {
			res = anlUndef
		}
		if pciIsWildcardResource(res) {
			dv := []any{}
			for _, v := range verbs {
				if pciIsDangerousVerb(v, dangerous) {
					dv = append(dv, v)
				}
			}
			if len(dv) > 0 {
				out = append(out, pciFind("over-broad-grant", "error", fmt.Sprintf("dangerous verb(s) %s granted on a WILDCARD resource ('*')", anlJSON(dv)), where))
			} else if !pciStrIn("*", verbs) {
				out = append(out, pciFind("over-broad-grant", "warn", "predicate matches ANY resource ('*') — consider a resource prefix", where))
			}
		}
		for _, v := range verbs {
			if v != "*" && pciIsDangerousVerb(v, dangerous) && !hasWhere && !hasScopeNarrowing {
				out = append(out, pciFind("over-broad-grant", "error",
					fmt.Sprintf("dangerous verb '%s' is granted with NO narrowing `where` and no scope-narrowing caveat (%s)", v, strings.Join(pciScopeNarrowing, "/")), where))
			}
		}
	}
	for _, v := range pciDeclaredVerbs(policy["predicates"]) {
		aa := anlAlwaysAllows(inp, v, opts)
		if aa["alwaysAllows"] == true && aa["approximate"] != true {
			out = append(out, pciFind("over-broad-grant", "error", fmt.Sprintf("grants EVERY action of '%s' — the authority has no effective constraint (always-allow)", v)))
		}
	}
	return out
}

func pciRulePrivilegeEscalation(hops []any, opts any) []any {
	out := []any{}
	for i := 1; i < len(hops); i++ {
		s := anlSubsumes(pciAnalyzerInput(hops[i-1].(map[string]any)), pciAnalyzerInput(hops[i].(map[string]any)), opts)
		where := fmt.Sprintf("hop[%d]", i)
		if s["subsumes"] == true {
			continue
		}
		if s["approximate"] == true {
			extra := ""
			if r, has := s["reason"]; has && anlTruthy(r) {
				extra = ": " + anlJS(r)
			}
			out = append(out, pciFind("privilege-escalation", "warn", fmt.Sprintf("could not prove hop %d attenuation (undecidable%s) — attenuation not verified", i, extra), where))
		} else {
			ex := ""
			if ce, has := s["counterexample"]; has && ce != nil {
				ex = fmt.Sprintf(" — child admits '%s' which its parent denies", pciDescribeAction(ce))
			}
			out = append(out, pciFind("privilege-escalation", "error",
				fmt.Sprintf("delegation hop %d ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)%s", i, ex), where))
		}
	}
	return out
}

var pciOrderedCaveats = [][3]string{{"expires", "at", "min"}, {"not_before", "at", "max"}, {"max_blast_radius", "max", "min"}, {"delegation_depth", "max", "min"}, {"budget_alloc", "limit", "min"}}
var pciNumericOps = []string{"lt", "lte", "gt", "gte", "eq"}

type pciCond struct {
	c map[string]any
	i int
}

func pciNonBindingConditions(where []any, predIndex int) []any {
	order := []string{}
	byField := map[string][]pciCond{}
	for i, c := range where {
		m, ok := anlLeaf(c)
		if !ok {
			continue
		}
		if _, hasRef := m["ref"]; hasRef {
			continue
		}
		if op, ok := m["op"].(string); !ok || !pciStrIn(op, pciNumericOps) {
			continue
		}
		if !anlIsFin(m["value"]) {
			continue
		}
		f := m["field"].(string)
		if _, seen := byField[f]; !seen {
			order = append(order, f)
		}
		byField[f] = append(byField[f], pciCond{m, i})
	}
	out := []any{}
	for _, field := range order {
		conds := byField[field]
		if len(conds) < 2 {
			continue
		}
		full := anlFullInterval
		for _, c := range conds {
			full = anlTighten(full, c.c["op"], c.c["value"])
		}
		if anlIntervalEmpty(full) {
			continue // the whole-predicate unsat case is reported separately
		}
		for ei, e := range conds {
			without := anlFullInterval
			for xi, x := range conds {
				if xi != ei {
					without = anlTighten(without, x.c["op"], x.c["value"])
				}
			}
			if without == full {
				out = append(out, pciFind("redundant-caveat", "info",
					fmt.Sprintf("condition on '%s' (%s %s) does not tighten the authority — redundant with the other bounds on this field", field, anlJS(e.c["op"]), anlJS(e.c["value"])),
					fmt.Sprintf("predicates[%d].where[%d]", predIndex, e.i)))
			}
		}
	}
	return out
}

func pciRuleRedundantCaveat(policy map[string]any) []any {
	out := []any{}
	caveats := anlReqList(policy["caveats"])
	seen := map[string]int{}
	for i, cv := range caveats {
		if !pciIsObj(cv) {
			continue
		}
		k := anlJSON(cv)
		if j, has := seen[k]; has {
			out = append(out, pciFind("redundant-caveat", "warn", fmt.Sprintf("caveat %d ('%s') is an exact duplicate of caveat %d — dead policy", i, anlJS(anlGet(cv, "type")), j), fmt.Sprintf("caveats[%d]", i)))
		} else {
			seen[k] = i
		}
	}
	for _, oc := range pciOrderedCaveats {
		typ, field, keep := oc[0], oc[1], oc[2]
		type iv struct {
			i int
			v float64
		}
		vals := []iv{}
		for i, cv := range caveats {
			if m, ok := cv.(map[string]any); ok && m["type"] == typ {
				if f, fin := anlFin(m[field]); fin {
					vals = append(vals, iv{i, f})
				}
			}
		}
		if len(vals) < 2 {
			continue
		}
		binding := vals[0].v
		for _, x := range vals[1:] {
			if (keep == "min" && x.v < binding) || (keep == "max" && x.v > binding) {
				binding = x.v
			}
		}
		for _, x := range vals {
			if x.v != binding {
				out = append(out, pciFind("redundant-caveat", "warn", fmt.Sprintf("caveat %d ('%s' %s=%s) is subsumed by a stricter '%s' (%s=%s) — it can never bite",
					x.i, typ, field, anlNumStr(x.v), typ, field, anlNumStr(binding)), fmt.Sprintf("caveats[%d]", x.i)))
			}
		}
	}
	for i, p := range anlReqList(policy["predicates"]) {
		pm, isMap := p.(map[string]any)
		var w []any
		if isMap {
			w, _ = pm["where"].([]any)
			if _, has := pm["where"].([]any); !has {
				continue
			}
		} else {
			continue
		}
		if !anlPredicateNumericSatisfiable(w) {
			out = append(out, pciFind("redundant-caveat", "warn", fmt.Sprintf("predicate %d can never match — its numeric `where` constraints are unsatisfiable (dead policy)", i), fmt.Sprintf("predicates[%d]", i)))
		} else {
			out = append(out, pciNonBindingConditions(w, i)...)
		}
	}
	return out
}

func pciRuleDangerousReachability(policy map[string]any, dangerous any, extraTargets any, opts any) []any {
	out := []any{}
	inp := pciAnalyzerInput(policy)
	targets := []any{}
	for _, v := range pciDeclaredVerbs(policy["predicates"]) {
		if pciIsDangerousVerb(v, dangerous) {
			targets = append(targets, map[string]any{"verb": v})
		}
	}
	targets = append(targets, anlReqList(extraTargets)...)
	gate, hasGate := pciGateDescription(policy)
	for _, t := range targets {
		verb := anlGet(t, "verb")
		resource := anlGet(t, "resource")
		var proven, approximate bool
		var reason any
		var witness string
		if !anlIsUndef(resource) {
			r := anlReachable(inp, map[string]any{"verb": verb, "resource": resource}, opts)
			approximate = r["approximate"] == true
			proven = anlTruthy(r["reachable"]) && !approximate
			reason = r["reason"]
			witness = anlJS(verb) + " " + anlJS(resource)
		} else {
			ad := anlAlwaysDenies(inp, verb, opts)
			approximate = ad["approximate"] == true
			proven = ad["alwaysDenies"] == false && !approximate
			reason = ad["reason"]
			if w, has := ad["witness"]; has {
				witness = pciDescribeAction(w)
			} else {
				witness = anlJS(verb)
			}
		}
		switch {
		case approximate:
			extra := ""
			if reason != nil && anlTruthy(reason) {
				extra = ": " + anlJS(reason)
			}
			out = append(out, pciFind("dangerous-reachability", "warn", fmt.Sprintf("could not decide reachability of dangerous verb '%s' (undecidable%s)", anlJS(verb), extra)))
		case proven && !hasGate:
			out = append(out, pciFind("dangerous-reachability", "error", fmt.Sprintf("dangerous action '%s' is REACHABLE with no budget / rate / step-up gate", witness)))
		case proven:
			out = append(out, pciFind("dangerous-reachability", "info", fmt.Sprintf("dangerous action '%s' is reachable but gated by %s", witness, gate)))
		}
	}
	return out
}

func pciIsNonTrivial(policy map[string]any, dangerous any) bool {
	for _, p := range anlReqList(policy["predicates"]) {
		if !pciIsObj(p) {
			continue
		}
		d, _ := p.(map[string]any)
		verbs := pciVerbsOf(d["verb"])
		w, _ := d["where"].([]any)
		hasWhere := len(w) > 0
		res, hasRes := d["resource"]
		if !hasRes {
			res = anlUndef
		}
		anyDanger := false
		for _, v := range verbs {
			if pciIsDangerousVerb(v, dangerous) {
				anyDanger = true
			}
		}
		if pciStrIn("*", verbs) || anyDanger || pciIsWildcardResource(res) || !hasWhere {
			return true
		}
	}
	return false
}

func pciRuleMissingSafetyFloor(policy map[string]any, requireExpiry, requireScopeGate bool, dangerous any) []any {
	out := []any{}
	if len(anlReqList(policy["predicates"])) == 0 {
		return out // nothing is granted; default-deny needs no floor
	}
	if requireExpiry && !pciHasCaveatOfType(policy["caveats"], []string{"expires"}) {
		out = append(out, pciFind("missing-safety-floor", "warn", "grant has no `expires` caveat — the authority never expires"))
	}
	if requireScopeGate && pciIsNonTrivial(policy, dangerous) && !pciHasCaveatOfType(policy["caveats"], pciBudgetGate) {
		out = append(out, pciFind("missing-safety-floor", "warn", fmt.Sprintf("non-trivial grant has no blast-radius / rate / budget gate (%s)", strings.Join(pciBudgetGate, "/"))))
	}
	return out
}

// ---- lint ----

// pciGuarded runs a rule: a rule that throws is a finding, not a crash and not silence (a gate must not pass a policy it
// could not finish checking).
func pciGuarded(rule string, run func() []any) (out []any) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprint(r)
			if e, ok := r.(error); ok {
				msg = e.Error()
			}
			out = []any{map[string]any{"rule": "internal-error", "severity": "error", "message": fmt.Sprintf("rule %s could not run: %s", rule, msg)}}
		}
	}()
	return run()
}

type pciConfig struct {
	overBroad, redundant, escalation, reach, floor bool
	obVerbs, drVerbs, drTargets                    any
	requireExpiry, requireScopeGate                bool
}

func pciResolveRules(rules any) pciConfig {
	var r any = map[string]any{}
	if rules != nil && !anlIsUndef(rules) {
		r = rules
	}
	ob, dr, sf := anlGet(r, "overBroadGrant"), anlGet(r, "dangerousReachability"), anlGet(r, "missingSafetyFloor")
	verbs := func(o any) any {
		if pciIsObj(o) && anlTruthy(anlGet(o, "dangerousVerbs")) {
			return anlGet(o, "dangerousVerbs")
		}
		return pciDefaultDangerous
	}
	cfg := pciConfig{
		overBroad: ob != false, escalation: anlGet(r, "privilegeEscalation") != false, redundant: anlGet(r, "redundantCaveat") != false,
		reach: dr != false, floor: sf != false, obVerbs: verbs(ob), drVerbs: verbs(dr), drTargets: []any{},
		requireExpiry: true, requireScopeGate: true,
	}
	if pciIsObj(dr) && anlTruthy(anlGet(dr, "targets")) {
		cfg.drTargets = anlGet(dr, "targets")
	}
	if pciIsObj(sf) {
		cfg.requireExpiry = anlGet(sf, "requireExpiry") != false
		cfg.requireScopeGate = anlGet(sf, "requireScopeGate") != false
	}
	return cfg
}

func pciAnalyzerOpts(opts any) map[string]any {
	if m, ok := opts.(map[string]any); ok {
		if mc, has := m["maxCombinations"]; has {
			return map[string]any{"maxCombinations": mc}
		}
	}
	return map[string]any{}
}

// pciRuleSchemaMismatch compares the policy with the action schema it is written for.
func pciRuleSchemaMismatch(policy map[string]any, schema, options any) []any {
	r := anlValidatePolicyAgainstSchema(map[string]any{"predicates": policy["predicates"], "caveats": policy["caveats"]}, schema, options)
	out := []any{}
	for _, f := range anlReqList(r["findings"]) {
		m := map[string]any{"rule": "schema-mismatch", "severity": anlGet(f, "severity"),
			"message": anlJS(anlGet(f, "code")) + ": " + anlJS(anlGet(f, "message"))}
		if w := anlGet(f, "where"); !anlIsUndef(w) {
			m["where"] = w
		}
		out = append(out, m)
	}
	return out
}

func pciSingleRules(cfg pciConfig, policy map[string]any, ao map[string]any) []any {
	out := []any{}
	if cfg.overBroad {
		out = append(out, pciGuarded("over-broad-grant", func() []any { return pciRuleOverBroadGrant(policy, cfg.obVerbs, ao) })...)
	}
	if cfg.redundant {
		out = append(out, pciGuarded("redundant-caveat", func() []any { return pciRuleRedundantCaveat(policy) })...)
	}
	if cfg.reach {
		out = append(out, pciGuarded("dangerous-reachability", func() []any { return pciRuleDangerousReachability(policy, cfg.drVerbs, cfg.drTargets, ao) })...)
	}
	if cfg.floor {
		out = append(out, pciGuarded("missing-safety-floor", func() []any {
			return pciRuleMissingSafetyFloor(policy, cfg.requireExpiry, cfg.requireScopeGate, cfg.obVerbs)
		})...)
	}
	return out
}

func pciOptsOf(opts any) any {
	if opts == nil || anlIsUndef(opts) {
		return map[string]any{}
	}
	return opts
}

func pciMalformed(reason any) []any {
	return []any{map[string]any{"rule": "malformed-policy", "severity": "error", "message": reason}}
}

// PolicyCiLintPolicy lints a single PCA policy (an envelope, a minted grant, a compiled policy or a bare {predicates, caveats?}).
// All findings (empty = clean). opts: {rules?, schema?, schemaOptions?, maxCombinations?}.
func PolicyCiLintPolicy(input, opts any) ([]any, error) {
	r, err := pciGuard(func() any { return pciLintPolicy(input, pciOptsOf(opts)) })
	l, _ := r.([]any)
	return l, err
}

func pciLintPolicy(input, opts any) []any {
	norm := PolicyCiNormalizePolicyInput(input)
	if norm["ok"] != true {
		return pciMalformed(norm["reason"])
	}
	cfg := pciResolveRules(anlGet(opts, "rules"))
	ao := pciAnalyzerOpts(opts)
	policy := norm["policy"].(map[string]any)
	out := pciSingleRules(cfg, policy, ao)
	if schema := anlGet(opts, "schema"); !anlIsUndef(schema) {
		out = append(out, pciGuarded("schema-mismatch", func() []any { return pciRuleSchemaMismatch(policy, schema, anlOget(opts, "schemaOptions")) })...)
	}
	return out
}

// PolicyCiLintChain lints a delegation chain (root to leaf): privilege escalation across every consecutive pair, then the
// single-policy rules on the acting LEAF's effective authority.
func PolicyCiLintChain(chain, opts any) ([]any, error) {
	r, err := pciGuard(func() any { return pciLintChain(chain, pciOptsOf(opts)) })
	l, _ := r.([]any)
	return l, err
}

func pciLintChain(chain, opts any) []any {
	norm := pciNormalizeChain(chain)
	if norm["ok"] != true {
		return pciMalformed(norm["reason"])
	}
	cfg := pciResolveRules(anlGet(opts, "rules"))
	ao := pciAnalyzerOpts(opts)
	hops := norm["hops"].([]any)
	out := []any{}
	if cfg.escalation {
		out = append(out, pciGuarded("privilege-escalation", func() []any { return pciRulePrivilegeEscalation(hops, ao) })...)
	}
	if len(hops) > 0 {
		out = append(out, pciSingleRules(cfg, hops[len(hops)-1].(map[string]any), ao)...)
	}
	return out
}

func pciLint(input, opts any) []any {
	if _, isList := input.([]any); isList {
		return pciLintChain(input, pciOptsOf(opts))
	}
	return pciLintPolicy(input, pciOptsOf(opts))
}

// PolicyCiLint lints an input: an array is a delegation chain; anything else is a single policy.
func PolicyCiLint(input, opts any) ([]any, error) {
	r, err := pciGuard(func() any { return pciLint(input, opts) })
	l, _ := r.([]any)
	return l, err
}

func pciRankKey(k any) (string, bool) {
	s := anlJS(k)
	_, ok := pciSeverityRank[s]
	return s, ok
}

// PolicyCiSummarize rolls labeled findings into counts and an exit code (0 ok, 1 a finding reaches the threshold, 2 nothing was
// linted).
func PolicyCiSummarize(results, opts any) (map[string]any, error) {
	r, err := pciGuard(func() any { return pciSummarize(results, pciOptsOf(opts)) })
	m, _ := r.(map[string]any)
	return m, err
}

func pciSummarize(results, opts any) map[string]any {
	maxSeverity := anlNN(anlGet(opts, "maxSeverity"), "error")
	mk, ok := pciRankKey(maxSeverity)
	if !ok { // an unknown threshold would make every comparison false and pass everything
		anlFail("summarize: maxSeverity must be one of info, warn, error")
	}
	counts := map[string]int{"error": 0, "warn": 0, "info": 0}
	list, isList := results.([]any)
	if !isList || len(list) == 0 {
		return map[string]any{"results": []any{}, "counts": map[string]any{"error": 0, "warn": 0, "info": 0}, "maxSeverity": maxSeverity, "ok": false, "exitCode": 2, "reason": "no policies were linted"}
	}
	failing := 0
	threshold := pciSeverityRank[mk]
	for _, r := range list {
		for _, f := range anlReqList(anlGet(r, "findings")) {
			sev := "error" // a severity that is not one of the three counts as an error
			if s, ok := pciRankKey(anlGet(f, "severity")); ok {
				sev = s
			}
			counts[sev]++
			if pciSeverityRank[sev] >= threshold {
				failing++
			}
		}
	}
	ok = failing == 0
	exit := 1
	if ok {
		exit = 0
	}
	return map[string]any{"results": results, "counts": map[string]any{"error": counts["error"], "warn": counts["warn"], "info": counts["info"]}, "maxSeverity": maxSeverity, "ok": ok, "exitCode": exit}
}

// PolicyCiLintPolicies lints a list of labeled policies (or chains) and rolls the findings into a summary.
func PolicyCiLintPolicies(items, opts any) (map[string]any, error) {
	r, err := pciGuard(func() any {
		o := pciOptsOf(opts)
		results := []any{}
		for i, item := range anlReqList(items) {
			label := anlNN(anlGet(item, "label"), fmt.Sprintf("policy[%d]", i))
			results = append(results, map[string]any{"label": label, "findings": pciLint(anlGet(item, "policy"), o)})
		}
		return pciSummarize(results, o)
	})
	m, _ := r.(map[string]any)
	return m, err
}

// ---- pinned lint rule list ----

const pciLintRulesDomain = "atlas-pca/action-lint-rules/v1"

var pciLintRules = [][3]string{
	{"LD-001", "error", "a destroy-like verb whose effects do not delete"},
	{"LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"},
	{"LD-003", "error", "a numeric parameter without min and max"},
	{"LD-004", "error", "a money-moving action without idempotency"},
	{"LD-005", "error", "personal data can leave without the matching effect"},
	{"LD-006", "error", "a declared reversibility or blast below the effective floor"},
	{"LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"},
	{"LD-008", "error", "resource id '*' with scope one"},
	{"LD-009", "error", "a duplicate verb or alias collision"},
	{"LD-010", "error", "a write marked reversible with no compensating action in the pack"},
	{"LD-011", "error", "review state confirmed without a valid attestation for this digest"},
	{"LD-012", "error", "a structural param rule that the effective traits require is violated"},
	{"LD-013", "error", "a read-only action that can mutate or handles credentials"},
	{"LD-014", "error", "one binding in two defs"},
	{"LW-001", "warning", "description missing or too long, or title not imperative"},
	{"LW-002", "warning", "a string parameter without max_len"},
	{"LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"},
	{"LW-004", "warning", "an unreviewed def in a stable pack"},
	{"LW-005", "warning", "a dismissed suggested trait without a reason"},
	{"LW-006", "warning", "an array parameter without max_items"},
	{"LW-007", "warning", "a critical parameter without provenance_min"},
	{"LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"},
	{"LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"},
	{"LW-010", "warning", "since is missing"},
}

// PolicyCiLintRulesDigest is the digest the CI gate pins: the ordered (id, severity, title) list of the action-kit lint rules.
func PolicyCiLintRulesDigest() string {
	rules := make([]any, len(pciLintRules))
	for i, r := range pciLintRules {
		rules[i] = map[string]any{"id": r[0], "severity": r[1], "title": r[2]}
	}
	h, _ := hashCanonicalV(map[string]any{"d": pciLintRulesDomain, "rules": rules})
	return h
}

var pciDigestRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// PolicyCiCheckLintRulesPin enforces the pinned digest of the lint rule list: pinText is the content of the pin file (one
// digest, surrounding whitespace ignored). Adding, removing or rewording a rule fails until the pin is updated.
func PolicyCiCheckLintRulesPin(pinText string, actualIn ...string) map[string]any {
	actual := PolicyCiLintRulesDigest()
	if len(actualIn) > 0 {
		actual = actualIn[0]
	}
	pinned := pbTrim(pinText)
	if !pciDigestRe.MatchString(pinned) {
		return map[string]any{"ok": false, "message": "the lint rules pin is not a digest (expected 43 base64url characters)"}
	}
	if pinned == actual {
		return map[string]any{"ok": true, "message": fmt.Sprintf("lint rules digest %s matches the pin", actual)}
	}
	return map[string]any{"ok": false, "message": fmt.Sprintf("lint rules digest %s differs from the pin %s: the rule list changed; review it and update the pin", actual, pinned)}
}

// ---- authoring gates ----

func pciBad(line string) map[string]any {
	return map[string]any{"ok": false, "exitCode": 2, "lines": []any{line}}
}

// PolicyCiToAnalyzerPolicy reads a policy document as the analyzer reads it: any shape lint accepts, plus optional `vetoes`
// and `tighten` members.
func PolicyCiToAnalyzerPolicy(doc any) map[string]any {
	n := PolicyCiNormalizePolicyInput(doc)
	if n["ok"] != true {
		return n
	}
	np := n["policy"].(map[string]any)
	policy := map[string]any{"predicates": np["predicates"], "caveats": np["caveats"]}
	if m, ok := doc.(map[string]any); ok {
		if v, ok := m["vetoes"].([]any); ok {
			policy["vetoes"] = v
		}
		if v, ok := m["tighten"].([]any); ok {
			policy["tighten"] = v
		}
	}
	return map[string]any{"ok": true, "policy": policy}
}

// PolicyCiDiffCommand: does this change widen authority, or raise the most that can leave? {ok, exitCode (0 ok, 1 gate failed,
// 2 unusable input), lines}.
func PolicyCiDiffCommand(oldDoc, newDoc, o any) (map[string]any, error) {
	r, err := pciGuard(func() any {
		o := pciOptsOf(o)
		a, b := PolicyCiToAnalyzerPolicy(oldDoc), PolicyCiToAnalyzerPolicy(newDoc)
		if a["ok"] != true {
			return pciBad(fmt.Sprintf("old policy: %s", a["reason"]))
		}
		if b["ok"] != true {
			return pciBad(fmt.Sprintf("new policy: %s", b["reason"]))
		}
		opts := map[string]any{}
		if verb := anlGet(o, "verb"); !anlIsUndef(verb) {
			ex := map[string]any{"verb": verb}
			if v := anlGet(o, "amountField"); anlTruthy(v) {
				ex["amountField"] = v
			}
			if anlTruthy(anlGet(o, "integer")) {
				ex["integer"] = true
			}
			if v := anlGet(o, "windowSecs"); !anlIsUndef(v) {
				ex["windowSecs"] = v
			}
			opts = map[string]any{"exposure": ex}
		}
		d := anlDiffPolicies(a["policy"], b["policy"], opts)
		allow := map[string]any{"widen": anlGet(o, "allowWiden") == true}
		if v := anlGet(o, "maxExposureIncrease"); !anlIsUndef(v) {
			allow["maxExposureIncrease"] = v
		}
		gate := anlDiffGate(d, allow)
		lines := []any{}
		if d["equivalent"] == true {
			lines = append(lines, "no change in what is admitted")
		} else if sum, ok := d["summary"].([]any); ok && len(sum) > 0 {
			lines = append(lines, sum...)
		} else {
			lines = append(lines, "no witness found")
		}
		if gate["ok"] != true {
			for _, r := range anlReqList(gate["reasons"]) {
				lines = append(lines, "FAIL: "+anlJS(r))
			}
		}
		exit := 1
		verdict := "FAIL"
		if gate["ok"] == true {
			exit, verdict = 0, "PASS"
		}
		lines = append(lines, verdict)
		return map[string]any{"ok": gate["ok"] == true, "exitCode": exit, "lines": lines}
	})
	m, _ := r.(map[string]any)
	return m, err
}

// PolicyCiTestCommand is the `test` gate: a policy test document against a policy. {ok, exitCode, lines}.
func PolicyCiTestCommand(policyDoc, testsDoc, o any) (map[string]any, error) {
	r, err := pciGuard(func() any {
		o := pciOptsOf(o)
		p := PolicyCiToAnalyzerPolicy(policyDoc)
		if p["ok"] != true {
			return pciBad(fmt.Sprintf("policy: %s", p["reason"]))
		}
		tm, _ := testsDoc.(map[string]any)
		if _, isList := tm["cases"].([]any); tm == nil || tm["kind"] != "pca-policy-tests" || !isList {
			return pciBad("tests: not a pca-policy-tests document")
		}
		topts := map[string]any{}
		if v := anlGet(o, "requireDigest"); !anlIsUndef(v) {
			topts["requireDigest"] = v
		}
		res := anlRunPolicyTests(p["policy"], testsDoc, topts)
		lines := []any{}
		for _, f := range anlReqList(res["failures"]) {
			by := ""
			if eb := anlGet(f, "expectedDecidedBy"); anlTruthy(eb) {
				by = " by " + anlJS(eb)
			}
			lines = append(lines, fmt.Sprintf("FAIL %s: expected %s%s, got %s by %s", anlJS(anlGet(f, "name")), anlJS(anlGet(f, "expected")), by,
				anlJS(anlGet(f, "got")), anlJS(anlNN(anlGet(f, "decidedBy"), "no clause"))))
		}
		if res["digestMatch"] != true {
			word := "note"
			if anlTruthy(anlGet(o, "requireDigest")) {
				word = "FAIL"
			}
			lines = append(lines, word+": the policy differs from the one the examples were confirmed against")
		}
		exit, verdict := 1, "FAIL"
		if res["ok"] == true {
			exit, verdict = 0, "PASS"
		}
		lines = append(lines, fmt.Sprintf("%d/%d examples %s", res["passed"], res["total"], verdict))
		return map[string]any{"ok": res["ok"] == true, "exitCode": exit, "lines": lines}
	})
	m, _ := r.(map[string]any)
	return m, err
}

// PolicyCiCoverageCommand is the `coverage` gate: how much of a policy a body of traffic exercises, and whether that clears the
// minimums. {ok, exitCode, lines}.
func PolicyCiCoverageCommand(policyDoc, trafficDoc, o any) (map[string]any, error) {
	r, err := pciGuard(func() any { return pciCoverageCommand(policyDoc, trafficDoc, pciOptsOf(o)) })
	m, _ := r.(map[string]any)
	return m, err
}

func pciCoverageCommand(policyDoc, trafficDoc, o any) map[string]any {
	p := PolicyCiToAnalyzerPolicy(policyDoc)
	if p["ok"] != true {
		return pciBad(fmt.Sprintf("policy: %s", p["reason"]))
	}
	var actions []any
	have := false
	if l, ok := trafficDoc.([]any); ok {
		actions, have = l, true
	} else if tm, ok := trafficDoc.(map[string]any); ok {
		if cases, ok := tm["cases"].([]any); ok {
			have = true
			for _, c := range cases {
				if cm, isRec := c.(map[string]any); isRec {
					a, has := cm["action"]
					if !has {
						a = anlUndef
					}
					actions = append(actions, a)
				} else {
					actions = append(actions, c)
				}
			}
		}
	}
	valid := have
	for _, a := range actions {
		am, ok := a.(map[string]any)
		if !ok {
			valid = false
			break
		}
		if _, ok := am["verb"].(string); !ok {
			valid = false
			break
		}
		if _, ok := am["resource"].(string); !ok {
			valid = false
			break
		}
	}
	if !valid {
		return pciBad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document")
	}
	r := anlCoverage(p["policy"], actions, map[string]any{})
	minimum := map[string]any{}
	for _, k := range [][2]string{{"minClauses", "clauses"}, {"minBoundaries", "boundaries"}, {"minMutation", "mutation"}, {"maxSurvivors", "maxSurvivors"}} {
		if v := anlGet(o, k[0]); !anlIsUndef(v) {
			minimum[k[1]] = v
		}
	}
	gate := anlCoverageGate(r, minimum)
	score, mutants := anlGet(r, "score"), anlGet(r, "mutants")
	pct := func(k string) string { return anlToFixed(anlToNumber(anlGet(score, k))*100, 0) }
	lines := []any{fmt.Sprintf("clauses decisive %s%%, boundaries covered %s%%, mutants killed %s%% (%s/%s)", pct("clauses"), pct("boundaries"), pct("mutation"),
		anlJS(anlGet(mutants, "killed")), anlNumStr(anlToNumber(anlGet(mutants, "total"))-anlToNumber(anlGet(mutants, "equivalent"))))}
	for _, id := range anlReqList(r["untested"]) {
		lines = append(lines, "untested: "+anlJS(id))
	}
	for _, sv := range anlReqList(anlGet(mutants, "survivors")) {
		kill := ""
		if k := anlGet(sv, "killer"); anlTruthy(k) {
			kill = " (kill with " + anlJSON(k) + ")"
		}
		lines = append(lines, "survives: "+anlJS(anlGet(sv, "description"))+kill)
	}
	for _, x := range anlReqList(gate["reasons"]) {
		lines = append(lines, "FAIL: "+anlJS(x))
	}
	exit, verdict := 1, "FAIL"
	if gate["ok"] == true {
		exit, verdict = 0, "PASS"
	}
	lines = append(lines, verdict)
	return map[string]any{"ok": gate["ok"] == true, "exitCode": exit, "lines": lines}
}

// ---- command line ----

var pciSeverities = []string{"error", "warn", "info"}

// PolicyCiHelp is the usage text.
const PolicyCiHelp = `pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]
  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
  pca-policy-ci test <policy.json> <tests.json> [--require-digest]
  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --schema <file>                   Also check each policy against this signed action schema (JSON)
  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.`

// PolicyCiParseArgs reads the command line as {args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}} or {error}.
func PolicyCiParseArgs(argv []string) map[string]any {
	files := []any{}
	maxSeverity, format := "error", "text"
	quiet, help := false, false
	schema, pin := "", ""
	hasSchema, hasPin := false, false
	sevErr := map[string]any{"error": "--max-severity expects one of " + strings.Join(pciSeverities, "|")}
	fmtErr := map[string]any{"error": "--format expects 'text' or 'github'"}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		next := func() (string, bool) {
			i++
			if i < len(argv) {
				return argv[i], true
			}
			return "", false
		}
		switch {
		case a == "--help" || a == "-h":
			help = true
		case a == "--quiet" || a == "-q":
			quiet = true
		case a == "--lint-rules-pin":
			v, ok := next()
			if !ok || strings.HasPrefix(v, "-") {
				return map[string]any{"error": "--lint-rules-pin expects a file"}
			}
			pin, hasPin = v, true
		case a == "--max-severity":
			v, ok := next()
			if !ok || !pciStrIn(v, pciSeverities) {
				return sevErr
			}
			maxSeverity = v
		case strings.HasPrefix(a, "--max-severity="):
			v := a[len("--max-severity="):]
			if !pciStrIn(v, pciSeverities) {
				return sevErr
			}
			maxSeverity = v
		case a == "--schema":
			v, ok := next()
			if !ok {
				return map[string]any{"error": "--schema expects a file"}
			}
			schema, hasSchema = v, true
		case strings.HasPrefix(a, "--schema="):
			schema, hasSchema = a[len("--schema="):], true
		case a == "--format":
			v, ok := next()
			if !ok || (v != "text" && v != "github") {
				return fmtErr
			}
			format = v
		case strings.HasPrefix(a, "--format="):
			v := a[len("--format="):]
			if v != "text" && v != "github" {
				return fmtErr
			}
			format = v
		case strings.HasPrefix(a, "-"):
			return map[string]any{"error": fmt.Sprintf("unknown option '%s'", a)}
		default:
			files = append(files, a)
		}
	}
	args := map[string]any{"files": files, "maxSeverity": maxSeverity, "format": format, "quiet": quiet, "help": help}
	if hasSchema {
		args["schema"] = schema
	}
	if hasPin {
		args["lintRulesPin"] = pin
	}
	return map[string]any{"args": args}
}

// pciReadText reads a file the way the reference does (invalid UTF-8 becomes U+FFFD); the error text names the path as given.
func pciReadText(dir, path string) (string, error) {
	full := path
	if dir != "" && !filepath.IsAbs(path) {
		full = filepath.Join(dir, path)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		code, text, op := "E"+fmt.Sprint(err), "", "open"
		switch {
		case errors.Is(err, fs.ErrNotExist):
			code, text = "ENOENT", "no such file or directory"
		case errors.Is(err, fs.ErrPermission):
			code, text = "EACCES", "permission denied"
		case errors.Is(err, syscall.EISDIR):
			code, text, op = "EISDIR", "illegal operation on a directory", "read"
		default:
			text = strings.ToLower(err.Error())
		}
		return "", fmt.Errorf("%s: %s, %s '%s'", code, text, op, path)
	}
	return string(([]rune(string(b)))), nil
}

func pciLintFile(dir, path string, schema any) []any {
	text, err := pciReadText(dir, path)
	if err != nil {
		return pciMalformed("cannot read file: " + err.Error())
	}
	doc, err := ParseJSONLenient([]byte(text))
	if err != nil {
		return pciMalformed("invalid JSON: " + err.Error())
	}
	opts := map[string]any{}
	if !anlIsUndef(schema) {
		opts["schema"] = schema
	}
	return pciGuarded("lint", func() []any { return pciLint(doc, opts) })
}

var pciGhLevel = map[string]string{"error": "error", "warn": "warning", "info": "notice"}
var pciTextTag = map[string]string{"error": "ERROR", "warn": "WARN", "info": "INFO"}

func pciPrintText(results []any, quiet bool, write func(string)) {
	for _, r := range results {
		rm := r.(map[string]any)
		findings := rm["findings"].([]any)
		if !quiet {
			write("\n" + anlJS(rm["label"]) + ":")
		}
		if len(findings) == 0 {
			if !quiet {
				write("  (clean)")
			}
			continue
		}
		for _, fv := range findings {
			f := fv.(map[string]any)
			loc := ""
			if w, has := f["where"]; has && w != nil {
				loc = " [" + anlJS(w) + "]"
			}
			tag := pciTextTag[f["severity"].(string)]
			write(fmt.Sprintf("  %-5s %s%s: %s", tag, anlJS(f["rule"]), loc, anlJS(f["message"])))
		}
	}
}

func pciEscapeGh(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// pciEscapeGhProp also escapes `:` and `,`, or a file name can add properties or end the command.
func pciEscapeGhProp(s string) string {
	return strings.NewReplacer(":", "%3A", ",", "%2C").Replace(pciEscapeGh(s))
}

func pciPrintGithub(results []any, write func(string)) {
	for _, r := range results {
		rm := r.(map[string]any)
		for _, fv := range rm["findings"].([]any) {
			f := fv.(map[string]any)
			props := fmt.Sprintf("file=%s,title=%s", pciEscapeGhProp(anlJS(rm["label"])), pciEscapeGhProp(anlJS(f["rule"])))
			loc := ""
			if w, has := f["where"]; has && w != nil {
				loc = anlJS(w) + ": "
			}
			write(fmt.Sprintf("::%s %s::%s", pciGhLevel[f["severity"].(string)], props, pciEscapeGh(loc+anlJS(f["message"]))))
		}
	}
}

func pciReadJSON(dir, path string) (doc any, reason string, ok bool) {
	text, err := pciReadText(dir, path)
	if err == nil {
		doc, err = ParseJSONLenient([]byte(text))
	}
	if err != nil {
		return nil, fmt.Sprintf("%s: %s", path, err.Error()), false
	}
	return doc, "", true
}

var pciJSNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
var pciHexRe = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)
var pciOctRe = regexp.MustCompile(`^0[oO][0-7]+$`)
var pciBinRe = regexp.MustCompile(`^0[bB][01]+$`)

// pciFlagNumber is `Number(v)` of a flag value when it is a non-blank finite number.
func pciFlagNumber(flags map[string]any, k string) (float64, bool) {
	v, ok := flags[k].(string)
	if !ok || pbTrim(v) == "" {
		return 0, false
	}
	t := pbTrim(v)
	var n float64
	var err error
	switch {
	case pciHexRe.MatchString(t):
		var u uint64
		u, err = strconv.ParseUint(t[2:], 16, 64)
		n = float64(u)
		if err != nil {
			n, err = pciBigRadix(t[2:], 16), nil
		}
	case pciOctRe.MatchString(t):
		var u uint64
		u, err = strconv.ParseUint(t[2:], 8, 64)
		n = float64(u)
		if err != nil {
			n, err = pciBigRadix(t[2:], 8), nil
		}
	case pciBinRe.MatchString(t):
		var u uint64
		u, err = strconv.ParseUint(t[2:], 2, 64)
		n = float64(u)
		if err != nil {
			n, err = pciBigRadix(t[2:], 2), nil
		}
	case pciJSNumber.MatchString(t):
		n, err = strconv.ParseFloat(t, 64)
		if err != nil {
			if ne, isNum := err.(*strconv.NumError); isNum && ne.Err == strconv.ErrRange {
				err = nil
			}
		}
	default:
		return 0, false
	}
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	return n, true
}

func pciBigRadix(digits string, base int) float64 {
	n := 0.0
	for _, c := range digits {
		d, _ := strconv.ParseInt(string(c), 16, 32)
		n = n*float64(base) + float64(d)
	}
	return n
}

var pciValued = []string{"--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors"}
var pciBools = []string{"--allow-widen", "--integer", "--require-digest"}

func pciRunAuthoring(dir, cmd string, rest []string, write func(string)) (int, error) {
	files := []string{}
	flags := map[string]any{}
	flagOrder := []string{}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case pciStrIn(a, pciValued):
			i++
			if i >= len(rest) {
				write(a + " expects a value")
				return 2, nil
			}
			if _, seen := flags[a]; !seen {
				flagOrder = append(flagOrder, a)
			}
			flags[a] = rest[i]
		case pciStrIn(a, pciBools):
			if _, seen := flags[a]; !seen {
				flagOrder = append(flagOrder, a)
			}
			flags[a] = true
		case strings.HasPrefix(a, "-"):
			write(fmt.Sprintf("unknown option '%s'", a))
			return 2, nil
		default:
			files = append(files, a)
		}
	}
	for _, k := range flagOrder {
		if pciStrIn(k, pciValued) && k != "--verb" && k != "--amount-field" {
			if _, ok := pciFlagNumber(flags, k); !ok {
				write(fmt.Sprintf("%s expects a number, got '%s'", k, flags[k]))
				return 2, nil
			}
		}
	}
	if len(files) != 2 {
		write(fmt.Sprintf("error: %s takes exactly two files", cmd))
		write(PolicyCiHelp)
		return 2, nil
	}
	docs := make([]any, 2)
	for i, f := range files {
		doc, reason, ok := pciReadJSON(dir, f)
		if !ok {
			write(reason)
			return 2, nil
		}
		docs[i] = doc
	}
	opt := func(flag, key string, out map[string]any) {
		if n, ok := pciFlagNumber(flags, flag); ok {
			out[key] = n
		}
	}
	var r map[string]any
	var err error
	switch cmd {
	case "diff":
		o := map[string]any{"allowWiden": flags["--allow-widen"] == true}
		if v, ok := flags["--verb"].(string); ok {
			o["verb"] = v
		}
		if v, ok := flags["--amount-field"].(string); ok {
			o["amountField"] = v
		}
		o["integer"] = flags["--integer"] == true
		opt("--window-secs", "windowSecs", o)
		opt("--max-exposure-increase", "maxExposureIncrease", o)
		r, err = PolicyCiDiffCommand(docs[0], docs[1], o)
	case "test":
		r, err = PolicyCiTestCommand(docs[0], docs[1], map[string]any{"requireDigest": flags["--require-digest"] == true})
	default:
		o := map[string]any{}
		opt("--min-clauses", "minClauses", o)
		opt("--min-boundaries", "minBoundaries", o)
		opt("--min-mutation", "minMutation", o)
		opt("--max-survivors", "maxSurvivors", o)
		r, err = PolicyCiCoverageCommand(docs[0], docs[1], o)
	}
	if err != nil {
		return 0, err
	}
	for _, l := range r["lines"].([]any) {
		write(l.(string))
	}
	return r["exitCode"].(int), nil
}

// PolicyCiRun runs the command line (`<files...>`, `diff`, `test`, `coverage`); write receives each output line. It returns
// the exit code: 0 ok, 1 a gate failed, 2 unusable input. The error is non-nil only when a gate hits an internal fault.
func PolicyCiRun(argv []string, write func(string)) (int, error) { return pciRun(argv, write, "") }

func pciRun(argv []string, write func(string), dir string) (code int, err error) {
	if len(argv) > 0 && (argv[0] == "diff" || argv[0] == "test" || argv[0] == "coverage") {
		return pciRunAuthoring(dir, argv[0], argv[1:], write)
	}
	parsed := PolicyCiParseArgs(argv)
	if e, bad := parsed["error"]; bad {
		write(e.(string))
		write(PolicyCiHelp)
		return 2, nil
	}
	args := parsed["args"].(map[string]any)
	if args["help"] == true {
		write(PolicyCiHelp)
		return 0, nil
	}
	pinFailed := false
	if pinFile, has := args["lintRulesPin"].(string); has {
		var r map[string]any
		text, rerr := pciReadText(dir, pinFile)
		if rerr != nil {
			r = map[string]any{"ok": false, "message": "cannot read the lint rules pin: " + rerr.Error()}
		} else {
			r = PolicyCiCheckLintRulesPin(text)
		}
		verdict := "FAIL"
		if r["ok"] == true {
			verdict = "PASS"
		}
		write(fmt.Sprintf("%s — %s", verdict, r["message"]))
		pinFailed = r["ok"] != true
		if len(args["files"].([]any)) == 0 {
			if pinFailed {
				return 1, nil
			}
			return 0, nil
		}
	}
	fileList := args["files"].([]any)
	if len(fileList) == 0 {
		write("error: no policy files given")
		write(PolicyCiHelp)
		return 2, nil
	}
	var schema any = anlUndef
	if sf, has := args["schema"].(string); has {
		doc, reason, ok := pciReadJSON(dir, sf)
		if !ok {
			write(reason)
			return 2, nil
		}
		schema = doc
	}
	results := []any{}
	for _, f := range fileList {
		results = append(results, map[string]any{"label": f, "findings": pciLintFile(dir, f.(string), schema)})
	}
	summary := pciSummarize(results, map[string]any{"maxSeverity": args["maxSeverity"]})
	if args["format"] == "github" {
		pciPrintGithub(results, write)
	} else {
		pciPrintText(results, args["quiet"] == true, write)
	}
	if reason, has := summary["reason"]; has && anlTruthy(reason) {
		write("error: " + anlJS(reason))
	}
	c := summary["counts"].(map[string]any)
	verdict := "FAIL"
	if summary["ok"] == true {
		verdict = "PASS"
	}
	write(fmt.Sprintf("\n%s — %d error(s), %d warning(s), %d info across %d policy/policies (fail threshold: %s)",
		verdict, c["error"], c["warn"], c["info"], len(results), anlJS(summary["maxSeverity"])))
	exit := summary["exitCode"].(int)
	if pinFailed && exit < 1 {
		exit = 1
	}
	return exit, nil
}
