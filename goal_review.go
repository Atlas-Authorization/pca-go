package pca

// Principal review and signing for a Goal IR (the TypeScript reference is @atlasauth/pca-goal `review`).
//
// PolicyCard: a deterministic, template-only rendering of the WHOLE Goal from the same phrase table as the plain text card, with exact
// numbers. Lossless-or-refuse: a clause that cannot be rendered and digested makes the card fail; the card is never truncated. The
// reviewer-fatigue limits are hard caps that REFUSE a goal or diff that is too large to read; callers may only tighten them. Semantic
// diff: clause-level, widenings first; anything not PROVEN narrower counts as a widening. GoalApproval: a pinned reviewer signs the
// digests of goal, compiled policy, card, ontology, tests, instruction and model set; goalLoadApprovedGoal trusts nothing the
// submission claims about itself (recomputes every digest, recompiles, re-renders, re-runs the confirmed examples) and never panics.
//
// The compiler is injected as a GoalReviewKernel (goalProvedKernel in the pcagoalkernel build wires the proved one).

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// GoalReviewKernel is the compiler and decision entry points this flow needs (injected). Pure and total. Analyze, Decide and
// NewlyAllowed are optional (nil).
type GoalReviewKernel struct {
	Compile      func(goal, ont any) map[string]any
	PolicyDigest func(policy any) string
	Analyze      func(policy any) []any
	Decide       func(goal, ont, act, hist any) string
	NewlyAllowed func(prev, next, ont any, limit int) map[string]any
}

// GoalReviewError is the reference's ReviewError.
type GoalReviewError struct{ Code, Detail string }

func (e *GoalReviewError) Error() string { return "goal review: " + e.Code + ": " + e.Detail }

const (
	goalReviewDCard    = "atlas-pca/policy-card/v1"
	goalReviewDClause  = "atlas-pca/goal-clause/v1"
	GoalApprovalKind   = "goal-approval"
	goalReviewDefTTLMs = int64(3_600_000)
	// MaxGoalApprovalTTLMs is the longest validity of a goal approval (24 h).
	MaxGoalApprovalTTLMs = int64(24 * 3_600_000)
)

var goalReviewLimitKeys = []string{"max_grants", "max_prohibits", "max_bounds", "max_escalate_on", "max_examples", "max_card_lines", "max_card_bytes",
	"max_diff_changes", "max_diff_widenings", "max_witnesses"}

var goalReviewLimitDefaults = map[string]int64{"max_grants": 32, "max_prohibits": 64, "max_bounds": 32, "max_escalate_on": 32, "max_examples": 40,
	"max_card_lines": 200, "max_card_bytes": 24576, "max_diff_changes": 60, "max_diff_widenings": 12, "max_witnesses": 20}

// GoalApprovalSignedFields are the signed members of a goal approval.
var GoalApprovalSignedFields = []string{"v", "goal_digest", "policy_digest", "card_digest", "ontology_digest", "tests_digest", "nl_digest",
	"model_set_digest", "reviewer", "approved_at", "expires_at"}

var goalReviewFieldReason = [][2]string{{"goal_digest", "goal_digest_mismatch"}, {"policy_digest", "policy_digest_mismatch"},
	{"ontology_digest", "ontology_mismatch"}, {"tests_digest", "tests_digest_mismatch"}, {"nl_digest", "nl_digest_mismatch"},
	{"model_set_digest", "model_set_digest_mismatch"}, {"card_digest", "card_digest_mismatch"}}

func goalReviewFail(code, format string, a ...any) {
	panic(&GoalReviewError{Code: code, Detail: fmt.Sprintf(format, a...)})
}

// goalReviewSafeInt is the codec's safe-integer test: a number, integral, |n| <= 2^53-1, not negative zero.
func goalReviewSafeInt(v any) bool {
	if _, isBool := v.(bool); isBool {
		return false
	}
	f, ok := jsNum(v)
	return ok && f == math.Trunc(f) && math.Abs(f) <= maxSafeInt && !(f == 0 && math.Signbit(f))
}

// goalReviewGet is dict.get(k): nil for an absent member or a non-object.
func goalReviewGet(m any, k string) any {
	if mm, ok := m.(map[string]any); ok {
		if v, ok := mm[k]; ok {
			return v
		}
	}
	return nil
}

// goalReviewReq is d[k]: a missing member (KeyError) panics.
func goalReviewReq(m any, k string) any {
	mm, ok := m.(map[string]any)
	if !ok {
		anlFail("not an object (reading '%s')", k)
	}
	v, has := mm[k]
	if !has {
		anlFail("missing member '%s'", k)
	}
	return v
}

func goalReviewIsStr(v any) bool { _, ok := v.(string); return ok }

func goalReviewEqS(v any, s string) bool { x, ok := v.(string); return ok && x == s }

func goalReviewIsOne(v any) bool { f, ok := jsNum(v); return ok && f == 1 }

// goalReviewTry runs f and reports whether it completed without panicking.
func goalReviewTry(f func()) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	f()
	return true
}

// goalReviewLe / goalReviewGe are JavaScript `<=` / `>=` (two strings compare by code unit, anything else as numbers).
func goalReviewLe(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return !utf16Less(bs, as)
	}
	return anlToNumber(a) <= anlToNumber(b)
}

func goalReviewGe(a, b any) bool { return goalReviewLe(b, a) }

func goalReviewHash(v any) string {
	h, err := HashCanonical(v)
	if err != nil {
		panic(err)
	}
	return h
}

func goalReviewJSON(v any) string {
	s, ok := canonicalLenient(v)
	if !ok {
		goalReviewFail("unrenderable", "a clause has no canonical form (float, undefined or cycle)")
	}
	return s
}

func goalReviewLimits(o any) map[string]int64 {
	out := map[string]int64{}
	for k, v := range goalReviewLimitDefaults {
		out[k] = v
	}
	m, ok := o.(map[string]any)
	if !ok || len(m) == 0 {
		return out
	}
	for _, k := range goalReviewLimitKeys {
		v := m[k]
		if goalReviewSafeInt(v) {
			if f, _ := jsNum(v); f >= 0 && f < float64(out[k]) {
				out[k] = int64(f)
			}
		}
	}
	return out
}

// goalEffectiveLimits: caller overrides may only TIGHTEN a limit (a larger number is ignored).
func goalEffectiveLimits(o any) map[string]any {
	out := map[string]any{}
	for k, v := range goalReviewLimits(o) {
		out[k] = goalNum(v)
	}
	return out
}

// GoalEffectiveLimits is goalEffectiveLimits.
func GoalEffectiveLimits(o any) map[string]any { return goalEffectiveLimits(o) }

func goalReviewLine(id any, kind, text string, clause any, severity string) map[string]any {
	return map[string]any{"id": id, "kind": kind, "severity": severity, "text": text,
		"clause_digest": goalReviewHash(map[string]any{"d": goalReviewDClause, "kind": kind, "clause": clause})}
}

// goalReviewSafeText is a clause's text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped.
func goalReviewSafeText(f func() string, clause any) string {
	var t string
	if goalReviewTry(func() {
		t = f()
		if strings.Contains(t, "undefined") {
			anlFail("unknown clause shape")
		}
	}) {
		return t
	}
	return goalReviewJSON(clause)
}

func goalReviewGoalDigest(goal any) (d string) {
	if !goalReviewTry(func() { d = goalGoalDigest(goal) }) {
		goalReviewFail("unrenderable", "the Goal has no canonical form (float, undefined or cycle)")
	}
	return d
}

func goalReviewBig(what string, n int, mx int64) {
	if int64(n) > mx {
		goalReviewFail("card_too_large", "%d %s exceed the cap of %d: split the goal into smaller goals", n, what, mx)
	}
}

// goalRenderPolicyCard renders the card. Deterministic, no model, no locale. Panics *GoalReviewError: `holes` (a draft is not reviewable
// for signing), `wildcard_unacknowledged`, `card_too_large` (a fatigue cap), `unrenderable`. opts.allowHoles renders a DRAFT for display.
func goalRenderPolicyCard(goal any, testsV any, opts any) map[string]any {
	tests := []any{}
	if testsV != nil && !anlIsUndef(testsV) {
		tests = anlReqList(testsV)
	}
	L := goalReviewLimits(goalReviewGet(opts, "limits"))
	gm, isObj := goal.(map[string]any)
	if !isObj {
		goalReviewFail("unrenderable", "not a Goal IR")
	}
	lists := map[string][]any{}
	for _, k := range []string{"grants", "prohibits", "bounds", "escalateOn", "holes"} {
		l, ok := gm[k].([]any)
		if !ok {
			goalReviewFail("unrenderable", "not a Goal IR")
		}
		lists[k] = l
	}
	validity, vok := gm["validity"].(map[string]any)
	deleg, dok := gm["deleg"].(map[string]any)
	if !vok || !dok {
		goalReviewFail("unrenderable", "not a Goal IR")
	}
	grants, prohibits, bounds, escalateOn, holes := lists["grants"], lists["prohibits"], lists["bounds"], lists["escalateOn"], lists["holes"]
	goalReviewBig("grants", len(grants), L["max_grants"])
	goalReviewBig("prohibitions", len(prohibits), L["max_prohibits"])
	goalReviewBig("bounds", len(bounds), L["max_bounds"])
	goalReviewBig("escalation triggers", len(escalateOn), L["max_escalate_on"])
	goalReviewBig("boundary examples", len(tests), L["max_examples"])
	goalReviewBig("card lines", 4+len(grants)+len(prohibits)+len(bounds)+len(escalateOn)+len(holes)+len(tests), L["max_card_lines"])
	if len(holes) > 0 && !anlTruthy(goalReviewGet(opts, "allowHoles")) {
		goalReviewFail("holes", "%d unresolved question(s): a goal with holes is a draft and cannot be signed", len(holes))
	}
	ack, _ := gm["wildcardAck"].([]any)
	if ack == nil {
		ack = []any{}
	}
	lines := []any{}
	principal := anlOwn(gm, "principal")
	lines = append(lines, goalReviewLine("principal", "meta",
		fmt.Sprintf("Acting for principal %s. Nothing outside this card is allowed (default deny).", goalReviewJSON(principal)), principal, "info"))
	for _, g := range grants {
		wild := false
		if res := anlGet(g, "res"); res != nil && !anlIsUndef(res) {
			wild = goalReviewEqS(anlGet(res, "k"), "any")
		}
		if wild && !anlIncludes(ack, anlGet(g, "gid")) {
			goalReviewFail("wildcard_unacknowledged", "grant %s allows ANY resource without a wildcard acknowledgement", goalReviewJSON(anlGet(g, "gid")))
		}
		sev := "info"
		if wild {
			sev = "red"
		}
		lines = append(lines, goalReviewLine(anlGet(g, "gid"), "grant", goalReviewSafeText(func() string {
			suffix := ""
			if wild {
				suffix = " WILDCARD acknowledged by the principal."
			}
			return fmt.Sprintf("%s.%s", goalGrantLine(g), suffix)
		}, g), g, sev))
	}
	for _, p := range prohibits {
		pr := anlGet(p, "res")
		sev := "info"
		if pr != nil && !anlIsUndef(pr) && goalReviewEqS(anlGet(pr, "k"), "any") {
			sev = "red"
		}
		lines = append(lines, goalReviewLine(anlGet(p, "pid"), "prohibit", goalReviewSafeText(func() string { return goalProhibitLine(p) + "." }, p), p, sev))
	}
	for _, b := range bounds {
		lines = append(lines, goalReviewLine(anlGet(b, "bid"), "bound", goalReviewSafeText(func() string { return goalBoundLine(b) + "." }, b), b, "info"))
	}
	lines = append(lines, goalReviewLine("validity", "validity", goalReviewSafeText(func() string { return goalValidityLine(validity) + "." }, validity), validity, "info"))
	dsev := "red"
	if anlTruthy(anlOwn(deleg, "narrowOnly")) {
		dsev = "info"
	}
	lines = append(lines, goalReviewLine("delegation", "delegation", goalReviewSafeText(func() string { return goalDelegationLine(deleg) + "." }, deleg), deleg, dsev))
	for i, c := range escalateOn {
		lines = append(lines, goalReviewLine(fmt.Sprintf("escalate_on[%d]", i), "escalate", goalReviewSafeText(func() string { return goalEscalateLine(c) + "." }, c), c, "info"))
	}
	for i, h := range holes {
		lines = append(lines, goalReviewLine(fmt.Sprintf("hole[%d]", i), "hole",
			goalReviewSafeText(func() string { return goalHoleLine(h) + ". Everything depending on it is dropped." }, h), h, "red"))
	}
	for _, t := range tests {
		act := anlGet(t, "act")
		adms, isList := anlGet(anlGet(t, "hist"), "adms").([]any)
		if !isList {
			anlFail("adms has no length")
		}
		n := len(adms)
		ans := anlGet(t, "answer")
		after := ""
		if n > 0 {
			after = fmt.Sprintf(" after %d earlier admitted action(s)", n)
		}
		verdict := "DENIED"
		if goalReviewEqS(ans, "ask") {
			verdict = "ASKED about"
		} else if goalReviewEqS(ans, "allow") {
			verdict = "ALLOWED"
		}
		lines = append(lines, goalReviewLine("example:"+anlJS(anlGet(t, "id")), "example",
			fmt.Sprintf("EXAMPLE you confirmed: %s on %s with %s%s must be %s.", goalReviewJSON(anlGet(act, "verb")), goalReviewJSON(anlGet(act, "res")),
				goalReviewJSON(anlGet(act, "params")), after, verdict), t, "info"))
	}
	goalReviewBig("card lines", len(lines), L["max_card_lines"])
	card := map[string]any{"v": goalNum(1), "goal_digest": goalReviewGoalDigest(goal), "ontology_digest": anlOwn(gm, "ontDigest"), "nl_digest": anlOwn(gm, "nlDigest"),
		"principal": principal, "lines": lines}
	card = anlU(card)
	cb, ok := canonicalLenient(card)
	if !ok {
		anlFail("canonicalize: card has no canonical form")
	}
	goalReviewBig("bytes of card", len(cb), L["max_card_bytes"])
	return card
}

func goalCardDigest(card any) string {
	return goalReviewHash(map[string]any{"d": goalReviewDCard, "card": card})
}

// goalCardToText is the plain-text form of a card for any console or terminal. Red lines are prefixed `!!`.
func goalCardToText(card any) string {
	parts := []string{}
	for _, l := range anlReqList(goalReviewReq(card, "lines")) {
		p := "   "
		if goalReviewEqS(goalReviewReq(l, "severity"), "red") {
			p = "!! "
		}
		parts = append(parts, p+anlJS(goalReviewReq(l, "text")))
	}
	return strings.Join(parts, "\n")
}

// ---- semantic diff ---------------------------------------------------------------------------------------------------------------

func goalReviewSame(a, b any) bool { return goalReviewJSON(a) == goalReviewJSON(b) }

func goalReviewConjuncts(c any) []any {
	k := anlGet(c, "k")
	if goalReviewEqS(k, "and") {
		return append(append([]any{}, goalReviewConjuncts(anlGet(c, "a"))...), goalReviewConjuncts(anlGet(c, "b"))...)
	}
	if goalReviewEqS(k, "true") {
		return []any{}
	}
	return []any{c}
}

func goalReviewWhereNoWider(oldW, newW any) bool {
	have := map[string]bool{}
	for _, c := range goalReviewConjuncts(newW) {
		have[goalReviewJSON(c)] = true
	}
	for _, c := range goalReviewConjuncts(oldW) {
		if !have[goalReviewJSON(c)] {
			return false
		}
	}
	return true
}

func goalReviewGrantDir(o, n any) string {
	if goalReviewSame(o, n) {
		return "neutral"
	}
	if anlStrictEq(anlGet(o, "verb"), anlGet(n, "verb")) && goalReviewSame(anlGet(o, "res"), anlGet(n, "res")) && goalReviewWhereNoWider(anlGet(o, "cond"), anlGet(n, "cond")) {
		return "narrow"
	}
	return "unknown"
}

func goalReviewProhibitDir(o, n any) string {
	if goalReviewSame(o, n) {
		return "neutral"
	}
	// A prohibition that triggers on MORE (old.cond is a conjunction containing new.cond) is a narrowing of the allow set.
	if goalReviewSame(anlGet(o, "target"), anlGet(n, "target")) && goalReviewSame(anlGet(o, "res"), anlGet(n, "res")) && goalReviewWhereNoWider(anlGet(n, "cond"), anlGet(o, "cond")) {
		return "narrow"
	}
	return "unknown"
}

func goalReviewRest(b any) map[string]any {
	m, ok := b.(map[string]any)
	if !ok {
		anlFail("bound is not an object")
	}
	out := anlCopy(m)
	out["cap"] = nil
	return out
}

func goalReviewBoundDir(o, n any) string {
	if goalReviewSame(o, n) {
		return "neutral"
	}
	if !goalReviewSame(goalReviewRest(o), goalReviewRest(n)) || !goalReviewSame(anlGet(anlGet(o, "cap"), "u"), anlGet(anlGet(n, "cap"), "u")) {
		return "unknown"
	}
	on, nn := anlGet(anlGet(o, "cap"), "n"), anlGet(anlGet(n, "cap"), "n")
	if anlLt(nn, on) {
		return "narrow"
	}
	if anlGt(nn, on) {
		return "widen"
	}
	if jsStrictEq(nn, on) {
		return "neutral"
	}
	return "unknown" // a cap that is not ordered (NaN) is unknown, never neutral
}

func goalReviewIdle(x any) any {
	if f, ok := jsNum(x); ok && f == 0 {
		return math.Inf(1)
	}
	return x
}

func goalReviewValidityDir(o, n any) string {
	if goalReviewSame(o, n) {
		return "neutral"
	}
	nb, na, ni := anlGet(n, "notBefore"), anlGet(n, "notAfter"), goalReviewIdle(anlGet(n, "maxIdle"))
	ob, oa, oi := anlGet(o, "notBefore"), anlGet(o, "notAfter"), goalReviewIdle(anlGet(o, "maxIdle"))
	if goalReviewGe(nb, ob) && goalReviewLe(na, oa) && goalReviewLe(ni, oi) {
		return "narrow"
	}
	if goalReviewLe(nb, ob) && goalReviewGe(na, oa) && goalReviewGe(ni, oi) {
		return "widen"
	}
	return "unknown"
}

func goalReviewDelegationDir(o, n any) string {
	if goalReviewSame(o, n) {
		return "neutral"
	}
	touchO, touchN := anlReqList(anlGet(o, "mayTouch")), anlReqList(anlGet(n, "mayTouch"))
	sub := true
	for _, x := range touchN {
		if !anlIncludes(touchO, x) {
			sub = false
			break
		}
	}
	sup := true
	for _, x := range touchO {
		if !anlIncludes(touchN, x) {
			sup = false
			break
		}
	}
	on, nn := anlTruthy(anlGet(o, "narrowOnly")), anlTruthy(anlGet(n, "narrowOnly"))
	if goalReviewLe(anlGet(n, "maxDepth"), anlGet(o, "maxDepth")) && sub && (nn || !on) {
		return "narrow"
	}
	if goalReviewGe(anlGet(n, "maxDepth"), anlGet(o, "maxDepth")) && sup && (on || !nn) {
		return "widen"
	}
	return "unknown"
}

type goalReviewPair struct{ id, v any }

// goalReviewKey is the identity of a clause id (a JavaScript Map key). shortcut: object ids compare by value, not identity.
func goalReviewKey(id any) string {
	switch t := id.(type) {
	case string:
		return "s:" + t
	case nil:
		return "z:"
	case bool:
		return fmt.Sprint("b:", t)
	}
	if anlIsUndef(id) {
		return "u:"
	}
	if f, ok := jsNum(id); ok {
		return "n:" + anlNumStr(f)
	}
	return "o:" + anlJSON(id)
}

func goalReviewPairs(prev, nxt []goalReviewPair, kind, added, removed string, changed func(o, n any) string, text func(id, v any) string) []any {
	out := []any{}
	pm := map[string]any{}
	for _, p := range prev {
		pm[goalReviewKey(p.id)] = p.v
	}
	nm := map[string]bool{}
	for _, p := range nxt {
		nm[goalReviewKey(p.id)] = true
	}
	for _, p := range nxt {
		old, has := pm[goalReviewKey(p.id)]
		if !has {
			out = append(out, map[string]any{"change": "added", "kind": kind, "id": p.id, "direction": added, "text": "ADDED " + text(p.id, p.v)})
		} else if !goalReviewSame(old, p.v) {
			out = append(out, map[string]any{"change": "changed", "kind": kind, "id": p.id, "direction": changed(old, p.v),
				"text": fmt.Sprintf("CHANGED %s (was: %s)", text(p.id, p.v), text(p.id, old))})
		}
	}
	for _, p := range prev {
		if !nm[goalReviewKey(p.id)] {
			out = append(out, map[string]any{"change": "removed", "kind": kind, "id": p.id, "direction": removed, "text": "REMOVED " + text(p.id, p.v)})
		}
	}
	return out
}

func goalReviewPairsOf(xs any, idKey string) []goalReviewPair {
	out := []goalReviewPair{}
	for _, x := range anlReqList(xs) {
		out = append(out, goalReviewPair{anlGet(x, idKey), x})
	}
	return out
}

func goalReviewIsWide(c any) bool {
	d := goalReviewReq(c, "direction")
	return goalReviewEqS(d, "widen") || goalReviewEqS(d, "unknown")
}

// goalDiffGoals is the clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first.
// Panics `diff_too_large` / `too_many_widenings` past the fatigue caps: a diff a human cannot read is not offered as one.
func goalDiffGoals(prev, nxt any, kernel *GoalReviewKernel, opts any) map[string]any {
	L := goalReviewLimits(goalReviewGet(opts, "limits"))
	gl := func(id, g any) string {
		return fmt.Sprintf("grant %s: %s on %s when %s", goalReviewJSON(id), goalReviewJSON(anlGet(g, "verb")), goalRes(anlGet(g, "res")), goalCond(anlGet(g, "cond")))
	}
	pl := func(id, p any) string {
		t := anlGet(p, "target")
		var tgt string
		if goalReviewEqS(anlGet(t, "k"), "verb") {
			tgt = goalReviewJSON(anlGet(t, "verb"))
		} else {
			tgt = "effect class " + goalReviewJSON(anlGet(t, "cls"))
		}
		return fmt.Sprintf("prohibition %s: %s on %s when %s", goalReviewJSON(id), tgt, goalRes(anlGet(p, "res")), goalCond(anlGet(p, "cond")))
	}
	changes := []any{}
	changes = append(changes, goalReviewPairs(goalReviewPairsOf(anlGet(prev, "grants"), "gid"), goalReviewPairsOf(anlGet(nxt, "grants"), "gid"), "grant", "widen", "narrow", goalReviewGrantDir, gl)...)
	changes = append(changes, goalReviewPairs(goalReviewPairsOf(anlGet(prev, "prohibits"), "pid"), goalReviewPairsOf(anlGet(nxt, "prohibits"), "pid"), "prohibit", "narrow", "widen", goalReviewProhibitDir, pl)...)
	changes = append(changes, goalReviewPairs(goalReviewPairsOf(anlGet(prev, "bounds"), "bid"), goalReviewPairsOf(anlGet(nxt, "bounds"), "bid"), "bound", "narrow", "widen", goalReviewBoundDir,
		func(id, b any) string {
			return fmt.Sprintf("bound %s: %s (%s)", goalReviewJSON(id), goalBoundLine(b), goalQuantity(anlGet(b, "cap")))
		})...)
	byJSON := func(xs any) []goalReviewPair {
		out := []goalReviewPair{}
		for _, c := range anlReqList(xs) {
			out = append(out, goalReviewPair{goalReviewJSON(c), c})
		}
		return out
	}
	changes = append(changes, goalReviewPairs(byJSON(anlGet(prev, "escalateOn")), byJSON(anlGet(nxt, "escalateOn")), "escalate", "narrow", "widen",
		func(a, b any) string { return "unknown" }, func(_, c any) string { return "escalation when " + goalCond(c) })...)
	add := func(kind, id, dir, text string) {
		changes = append(changes, map[string]any{"change": "changed", "kind": kind, "id": id, "direction": dir, "text": text})
	}
	pv, nv := anlGet(prev, "validity"), anlGet(nxt, "validity")
	if !goalReviewSame(pv, nv) {
		add("validity", "validity", goalReviewValidityDir(pv, nv), fmt.Sprintf("CHANGED validity: %s (was: %s)", goalReviewJSON(nv), goalReviewJSON(pv)))
	}
	pd, nd := anlGet(prev, "deleg"), anlGet(nxt, "deleg")
	if !goalReviewSame(pd, nd) {
		add("delegation", "delegation", goalReviewDelegationDir(pd, nd), fmt.Sprintf("CHANGED delegation: %s (was: %s)", goalReviewJSON(nd), goalReviewJSON(pd)))
	}
	// Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
	if !anlStrictEq(anlGet(prev, "principal"), anlGet(nxt, "principal")) {
		add("meta", "principal", "unknown", fmt.Sprintf("CHANGED principal: %s (was: %s)", goalReviewJSON(anlGet(nxt, "principal")), goalReviewJSON(anlGet(prev, "principal"))))
	}
	if !anlStrictEq(anlGet(prev, "ontDigest"), anlGet(nxt, "ontDigest")) {
		add("meta", "ontology", "unknown", fmt.Sprintf("CHANGED ontology: every term now means what the new vocabulary says (was %s, now %s)",
			goalReviewJSON(anlGet(prev, "ontDigest")), goalReviewJSON(anlGet(nxt, "ontDigest"))))
	}
	if !goalReviewSame(anlGet(prev, "wildcardAck"), anlGet(nxt, "wildcardAck")) {
		add("meta", "wildcard_ack", "unknown", fmt.Sprintf("CHANGED wildcard acknowledgements: %s (was: %s)",
			goalReviewJSON(anlGet(nxt, "wildcardAck")), goalReviewJSON(anlGet(prev, "wildcardAck"))))
	}
	if !anlStrictEq(anlGet(prev, "nlDigest"), anlGet(nxt, "nlDigest")) {
		add("meta", "instruction", "neutral", "CHANGED the instruction text the goal was interpreted from")
	}
	widenings := 0
	for _, c := range changes {
		if goalReviewIsWide(c) {
			widenings++
		}
	}
	if int64(len(changes)) > L["max_diff_changes"] {
		goalReviewFail("diff_too_large", "%d changes exceed the cap of %d: review the new goal as a whole instead", len(changes), L["max_diff_changes"])
	}
	if int64(widenings) > L["max_diff_widenings"] {
		goalReviewFail("too_many_widenings", "%d widenings exceed the cap of %d per review", widenings, L["max_diff_widenings"])
	}
	var na map[string]any
	if ont := goalReviewGet(opts, "ontology"); anlTruthy(ont) && kernel != nil && kernel.NewlyAllowed != nil {
		na = kernel.NewlyAllowed(prev, nxt, ont, int(L["max_witnesses"]))
	}
	maxW := int(L["max_witnesses"])
	newly := []any{}
	complete := false
	if len(na) > 0 {
		w := anlReqList(na["witnesses"])
		newly = append(newly, w...)
		if len(newly) > maxW {
			newly = newly[:maxW]
		}
		complete = anlTruthy(na["complete"]) && len(w) <= maxW
	}
	ordered := []any{}
	for _, c := range changes {
		if goalReviewIsWide(c) {
			ordered = append(ordered, c)
		}
	}
	for _, c := range changes {
		if !goalReviewIsWide(c) {
			ordered = append(ordered, c)
		}
	}
	return map[string]any{"v": goalNum(1), "from_goal_digest": goalReviewGoalDigest(prev), "to_goal_digest": goalReviewGoalDigest(nxt),
		"newly_allowed": newly, "newly_allowed_complete": complete, "changes": ordered, "widenings": goalNum(int64(widenings))}
}

func goalDiffToText(d any) string {
	head := []string{}
	for _, w := range anlReqList(goalReviewReq(d, "newly_allowed")) {
		head = append(head, fmt.Sprintf("!! NEWLY ALLOWED: %s on %s with %s", goalReviewJSON(goalReviewReq(w, "verb")), goalReviewJSON(goalReviewReq(w, "res")), goalReviewJSON(goalReviewReq(w, "params"))))
	}
	if !anlTruthy(goalReviewReq(d, "newly_allowed_complete")) {
		head = append(head, "!! The list of newly allowed actions is incomplete or unavailable: read every widening below.")
	}
	for _, c := range anlReqList(goalReviewReq(d, "changes")) {
		p := "   "
		if goalReviewIsWide(c) {
			p = "!! "
		}
		head = append(head, p+anlJS(goalReviewReq(c, "text")))
	}
	return strings.Join(head, "\n")
}

// ---- GoalApproval ---------------------------------------------------------------------------------------------------------------

type goalReviewDerived struct {
	ok      bool
	reason  string
	policy  any
	digests map[string]any
}

func goalReviewBad(reason string) goalReviewDerived { return goalReviewDerived{reason: reason} }

func goalReviewDerive(sub any, kernel *GoalReviewKernel, limits any) goalReviewDerived {
	sm, isObj := sub.(map[string]any)
	if !isObj {
		return goalReviewBad("malformed_submission")
	}
	goal, gok := sm["goal"].(map[string]any)
	ont, ook := sm["ontology"].(map[string]any)
	instruction, iok := sm["instruction"].(string)
	modelSet, mok := sm["model_set"].([]any)
	if !gok || !ook || !iok || !mok {
		return goalReviewBad("malformed_submission")
	}
	for _, m := range modelSet {
		if !goalReviewIsStr(m) {
			return goalReviewBad("malformed_submission")
		}
	}
	tests := []any{}
	if tv, has := sm["tests"]; has {
		l, ok := tv.([]any)
		if !ok {
			return goalReviewBad("malformed_submission")
		}
		tests = l
	}
	var card map[string]any
	var cardErr any
	func() {
		defer func() { cardErr = recover() }()
		var lim any = map[string]any{}
		if limits != nil && !anlIsUndef(limits) {
			lim = map[string]any{"limits": limits}
		}
		card = goalRenderPolicyCard(goal, tests, lim)
	}()
	if cardErr != nil {
		if re, ok := cardErr.(*GoalReviewError); ok {
			return goalReviewBad(re.Code)
		}
		return goalReviewBad("malformed_goal")
	}
	var gd, nl, ts, ms string
	if !goalReviewTry(func() {
		gd = goalGoalDigest(goal)
		nl = goalNlDigest(instruction)
		ts = goalTestsDigest(tests)
		ms = goalModelSetDigest(modelSet)
	}) {
		return goalReviewBad("malformed_goal")
	}
	if want, ok := goal["nlDigest"].(string); !ok || nl != want {
		return goalReviewBad("instruction_mismatch")
	}
	var compiled map[string]any
	if !goalReviewTry(func() { compiled = kernel.Compile(goal, ont) }) {
		return goalReviewBad("compile_error")
	}
	if compiled == nil {
		anlFail("compiler returned nothing")
	}
	if !anlTruthy(goalReviewReq(compiled, "ok")) {
		return goalReviewBad("compile_error")
	}
	var policy any
	var pd string
	analyzerBad := false
	if !goalReviewTry(func() {
		policy = goalReviewReq(compiled, "policy")
		found := []any{}
		if kernel.Analyze != nil {
			found = kernel.Analyze(policy)
		}
		if len(found) > 0 {
			analyzerBad = true
			return
		}
		pd = kernel.PolicyDigest(policy)
	}) || analyzerBad {
		return goalReviewBad("analyzer_error")
	}
	if len(tests) > 0 {
		if kernel.Decide == nil {
			return goalReviewBad("tests_unverifiable")
		}
		// Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
		for _, t := range tests {
			var got string
			if !goalReviewTry(func() {
				o := any(ont)
				if anlTruthy(anlGet(t, "rels")) {
					c := anlCopy(ont)
					c["rels"] = goalReviewReq(t, "rels")
					o = c
				}
				got = kernel.Decide(goal, o, goalReviewReq(t, "act"), goalReviewReq(t, "hist"))
			}) {
				return goalReviewBad("tests_unverifiable")
			}
			want := "escalate"
			if a := goalReviewReq(t, "answer"); goalReviewEqS(a, "allow") {
				want = "allow"
			} else if goalReviewEqS(a, "deny") {
				want = "deny"
			}
			if got != want {
				return goalReviewBad("tests_contradicted")
			}
		}
	}
	return goalReviewDerived{ok: true, policy: policy, digests: map[string]any{
		"goal_digest": gd, "policy_digest": pd, "card_digest": goalCardDigest(card), "ontology_digest": goalReviewGet(goal, "ontDigest"),
		"tests_digest": ts, "nl_digest": nl, "model_set_digest": ms}}
}

// goalApproveGoal is the human step: sign the exact goal. Re-derives everything the loader will; panics when the goal is not signable
// (holes, wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a test the compiled policy contradicts,
// an instruction that does not match `nlDigest`). opts: kernel (*GoalReviewKernel, required), now, ttlMs, limits, base, alg, pq.
func goalApproveGoal(sub any, reviewerSecret any, opts any) map[string]any {
	now := int64(0)
	if nv := goalReviewGet(opts, "now"); nv == nil || anlIsUndef(nv) {
		now = time.Now().UnixMilli()
	} else if goalReviewSafeInt(nv) {
		f, _ := jsNum(nv)
		now = int64(f)
	} else {
		anlFail("approveGoal: invalid time or ttl")
	}
	ttl := goalReviewDefTTLMs
	if tv := goalReviewGet(opts, "ttlMs"); tv != nil && !anlIsUndef(tv) {
		if !goalReviewSafeInt(tv) {
			anlFail("approveGoal: invalid time or ttl")
		}
		f, _ := jsNum(tv)
		ttl = int64(f)
	}
	if ttl <= 0 || ttl > MaxGoalApprovalTTLMs {
		anlFail("approveGoal: invalid time or ttl")
	}
	kernel, _ := goalReviewGet(opts, "kernel").(*GoalReviewKernel)
	if kernel == nil {
		anlFail("approveGoal: a review kernel is required (the proved compiler is not native)")
	}
	d := goalReviewDerive(sub, kernel, goalReviewGet(opts, "limits"))
	if !d.ok {
		anlFail("approveGoal: %s", d.reason)
	}
	if base := goalReviewGet(opts, "base"); base != nil && !anlIsUndef(base) {
		goalDiffGoals(base, sub.(map[string]any)["goal"], nil, map[string]any{"limits": goalReviewGet(opts, "limits")})
	}
	body := anlCopy(d.digests)
	body["v"] = goalNum(1)
	body["reviewer"] = goalSignerId(reviewerSecret)
	body["approved_at"] = goalNum(now)
	body["expires_at"] = goalNum(now + ttl)
	return goalSignGoalArtifact(GoalApprovalKind, body, reviewerSecret, goalReviewGet(opts, "alg"), goalReviewGet(opts, "pq"))
}

func goalReviewFailRes(reason string) map[string]any {
	return map[string]any{"ok": false, "reason": reason}
}

// goalLoadApprovedGoal is the only door from a submitted goal to an enforceable one. Recomputes the goal digest, recompiles the policy,
// re-renders the card and re-derives the tests, instruction and model-set digests from the submission; trusts nothing the submission or
// the approval says about itself. Never panics. opts: kernel (required), reviewers (pinned), ontology_digest, now, limits.
func goalLoadApprovedGoal(sub any, approval any, opts any) (res map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			res = goalReviewFailRes("malformed_approval")
		}
	}()
	if _, ok := opts.(map[string]any); !ok {
		anlFail("opts is not an object")
	}
	var now any = goalNum(time.Now().UnixMilli())
	if nv := goalReviewGet(opts, "now"); nv != nil && !anlIsUndef(nv) {
		now = nv
	}
	reviewers, isList := goalReviewGet(opts, "reviewers").([]any)
	if !isList || len(reviewers) == 0 {
		return goalReviewFailRes("no_reviewers_pinned")
	}
	a, isObj := approval.(map[string]any)
	if !isObj || !(goalReviewSafeInt(a["v"]) && goalReviewIsOne(a["v"])) || !goalReviewIsStr(a["sig"]) || !goalReviewIsStr(a["reviewer"]) ||
		!goalReviewSafeInt(a["approved_at"]) || !goalReviewSafeInt(a["expires_at"]) {
		return goalReviewFailRes("malformed_approval")
	}
	for _, fr := range goalReviewFieldReason {
		if !goalReviewIsStr(a[fr[0]]) {
			return goalReviewFailRes("malformed_approval")
		}
	}
	kernel, _ := goalReviewGet(opts, "kernel").(*GoalReviewKernel)
	if kernel == nil {
		return goalReviewFailRes("malformed_approval")
	}
	d := goalReviewDerive(sub, kernel, goalReviewGet(opts, "limits"))
	if !d.ok {
		return goalReviewFailRes(d.reason)
	}
	goal := sub.(map[string]any)["goal"].(map[string]any)
	if od := goalReviewGet(opts, "ontology_digest"); od != nil && !anlIsUndef(od) && !anlStrictEq(goalReviewGet(goal, "ontDigest"), od) {
		return goalReviewFailRes("ontology_mismatch")
	}
	for _, fr := range goalReviewFieldReason {
		if a[fr[0]] != d.digests[fr[0]] {
			return goalReviewFailRes(fr[1])
		}
	}
	pinned := false
	for _, p := range reviewers {
		var pk any = p
		if !goalReviewIsStr(p) {
			pk = anlGet(p, "pk")
		}
		if pk == a["reviewer"] {
			pinned = true
			break
		}
	}
	if !pinned {
		return goalReviewFailRes("reviewer_not_pinned")
	}
	ap, _ := jsNum(a["approved_at"])
	ex, _ := jsNum(a["expires_at"])
	if ex-ap <= 0 || ex-ap > float64(MaxGoalApprovalTTLMs) {
		return goalReviewFailRes("ttl_too_long")
	}
	if !(finite(anlToNumber(now)) && goalReviewLe(a["approved_at"], now)) {
		return goalReviewFailRes("not_yet_valid")
	}
	if !(finite(anlToNumber(now)) && !goalReviewGe(now, a["expires_at"])) {
		return goalReviewFailRes("expired")
	}
	if !goalVerifyGoalArtifact(GoalApprovalKind, a, "reviewer", reviewers) {
		return goalReviewFailRes("bad_signature")
	}
	gdig, _ := d.digests["goal_digest"].(string)
	pdig, _ := d.digests["policy_digest"].(string)
	ref := map[string]any{"goal_digest": gdig, "policy_digest": pdig}
	gs, err := IntentGoalV3(ApprovedGoalRef{GoalDigest: gdig, PolicyDigest: pdig})
	if err != nil {
		panic(err)
	}
	return map[string]any{"ok": true, "approved": map[string]any{"goal": goal, "ontology": sub.(map[string]any)["ontology"], "policy": d.policy, "ref": ref,
		"goal_string": gs, "intent_policy": map[string]any{"approved_goal": ref}, "instruction": sub.(map[string]any)["instruction"],
		"reviewer": a["reviewer"], "expires_at": a["expires_at"]}}
}

// GoalRenderPolicyCard is goalRenderPolicyCard.
func GoalRenderPolicyCard(goal, tests, opts any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalRenderPolicyCard(goal, tests, opts); return nil })
	return
}

// GoalCardDigest is goalCardDigest.
func GoalCardDigest(card any) (s string, err error) {
	_, err = anlTry(func() any { s = goalCardDigest(card); return nil })
	return
}

// GoalCardToText is goalCardToText.
func GoalCardToText(card any) (s string, err error) {
	_, err = anlTry(func() any { s = goalCardToText(card); return nil })
	return
}

// GoalDiffGoals is goalDiffGoals.
func GoalDiffGoals(prev, nxt any, kernel *GoalReviewKernel, opts any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalDiffGoals(prev, nxt, kernel, opts); return nil })
	return
}

// GoalDiffToText is goalDiffToText.
func GoalDiffToText(d any) (s string, err error) {
	_, err = anlTry(func() any { s = goalDiffToText(d); return nil })
	return
}

// GoalApproveGoal is goalApproveGoal.
func GoalApproveGoal(sub, reviewerSecret, opts any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalApproveGoal(sub, reviewerSecret, opts); return nil })
	return
}

// GoalLoadApprovedGoal is goalLoadApprovedGoal (it never fails).
func GoalLoadApprovedGoal(sub, approval, opts any) map[string]any {
	return goalLoadApprovedGoal(sub, approval, opts)
}
