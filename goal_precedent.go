package pca

// Progressive authorization (the TypeScript reference is @atlasauth/pca-goal `precedent`). Widening is only by an escalation request
// answered by a principal-signed escalation answer. A verified answer becomes an append-only hash-chained precedent bound to (policy
// digest, decision cell, the answered action's exact quantities as a ceiling). A recorded cell decision is never flipped except by a
// principal-signed revocation. P1 the allow set grows only by cells with a valid principal signature bound to the policy digest; P2 no
// replay of an answer onto another policy digest, cell or beyond the signed ceiling; P3 a Deny is never turned into Allow (precedents
// act only on Escalate); P4 Escalate never becomes Allow implicitly. NOT covered by any signature: the relation facts (`rels`) and the
// log itself (the integrity of the head is the verifier's to anchor).

import "math"

const goalPrecedentGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

func goalPrecedentUnitKey(q any) string {
	u := anlGet(q, "u")
	if goalReviewEqS(anlGet(u, "k"), "money") {
		return "money:" + anlJS(anlGet(u, "ccy"))
	}
	return anlJS(anlGet(u, "k"))
}

// goalCeilingsOf keys the ceilings by parameter AND unit (kind + currency): a EUR answer never covers a GBP action.
func goalCeilingsOf(params any) map[string]any {
	pm, ok := params.(map[string]any)
	if !ok {
		anlFail("params is not an object")
	}
	out := map[string]any{}
	for _, k := range jsKeys(pm) {
		v := pm[k]
		if goalReviewEqS(anlGet(v, "k"), "q") {
			out[k+"|"+goalPrecedentUnitKey(anlGet(v, "q"))] = anlGet(anlGet(v, "q"), "n")
		}
	}
	return out
}

func goalPrecedentCaseOf(a any) map[string]any {
	act := anlGet(anlGet(a, "pcactn"), "action")
	verb, vok := anlGet(act, "verb").(string)
	res, rok := anlGet(act, "resource").(string)
	if !vok || !rok {
		anlFail("the signed action has no verb and resource")
	}
	var params map[string]any
	switch p := anlGet(a, "params").(type) {
	case nil:
	case map[string]any:
		params = p
	default:
		anlFail("params is not an object")
	}
	return map[string]any{"act": goalMkAct(verb, res, params, nil), "rels": anlGet(a, "rels")}
}

func goalSignRevocation(p any, secret any) map[string]any {
	return goalSignPayload("precedent-revocation", p, secret)
}

// goalAnswerBodyFor is the answer body for a request: bind it to the request's exact (policy, action, history head); sign it as an
// escalation answer.
func goalAnswerBodyFor(req any, o any) map[string]any {
	return anlU(map[string]any{"v": goalNum(1), "kind": "pca-escalation-answer", "principal": anlGet(o, "principal"), "policy_digest": anlGet(req, "policy_digest"),
		"action_digest": anlGet(req, "action_digest"), "history_head": anlGet(req, "history_head"), "decision": anlGet(o, "decision"),
		"iat": anlGet(o, "iat"), "expires_at": anlGet(o, "expires_at"), "nonce": anlGet(o, "nonce")})
}

// goalPrecedentHead is the escalation history head of a recorded last counter (nil: none).
func goalPrecedentHead(last any) string {
	var p *int64
	if last != nil && !anlIsUndef(last) {
		n, ok := safeInt(last)
		if !ok {
			anlFail("last counter is not a safe integer")
		}
		p = &n
	}
	h, err := EscalationHistoryHead(p)
	if err != nil {
		panic(err)
	}
	return h
}

func goalPrecedentMap(v any, what string) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		anlFail("%s is not an object", what)
	}
	return m
}

// goalPrecedentTruthy is Python truthiness (an empty object or list is false).
func goalPrecedentTruthy(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	}
	return anlTruthy(v)
}

func goalPrecedentEntryDigest(e map[string]any) string {
	var answered any
	switch a := e["answered"].(type) {
	case nil:
	case map[string]any:
		if len(a) > 0 {
			c := anlCopy(a)
			c["lastCounter"] = a["lastCounter"]
			answered = c
		}
	default:
		if goalPrecedentTruthy(a) {
			anlFail("answered is not an object")
		}
	}
	return goalReviewHash(map[string]any{
		"d": "atlas-pca/goal-precedent-entry/v1", "seq": e["seq"], "prev": e["prev"], "kind": e["kind"], "answer": e["answer"], "answered": answered,
		"cell": e["cell"], "ceilings": e["ceilings"], "revocation": e["revocation"]})
}

// GoalPrecedentLog is the append-only hash-chained precedent log. principals: the pinned signers allowed to answer and revoke (the
// verifier's own list): bare Ed25519 keys or {pk, pq_pk?} pins.
type GoalPrecedentLog struct {
	Entries    []map[string]any
	principals []any
}

// NewGoalPrecedentLog is an empty log over the verifier's pinned signers.
func NewGoalPrecedentLog(principals []any) *GoalPrecedentLog {
	return &GoalPrecedentLog{principals: principals}
}

// Head is the digest of the last entry (all zeros for an empty log).
func (l *GoalPrecedentLog) Head() string {
	if len(l.Entries) == 0 {
		return goalPrecedentGenesis
	}
	s, _ := l.Entries[len(l.Entries)-1]["digest"].(string)
	return s
}

func (l *GoalPrecedentLog) pinFor(pk any) any {
	for _, p := range l.principals {
		var k any = p
		if !goalReviewIsStr(p) {
			k = anlGet(p, "pk")
		}
		if anlStrictEq(k, pk) {
			return p
		}
	}
	return nil
}

func (l *GoalPrecedentLog) pins() []PinnedSigner {
	out := make([]PinnedSigner, 0, len(l.principals))
	for _, p := range l.principals {
		if s, ok := p.(string); ok {
			out = append(out, PinnedSigner{PK: s})
			continue
		}
		pk, _ := anlGet(p, "pk").(string)
		pq, _ := anlGet(p, "pq_pk").(string)
		out = append(out, PinnedSigner{PK: pk, PQPK: pq})
	}
	return out
}

func goalPrecedentActionDigest(pcactn any) (string, bool) {
	m, ok := pcactn.(map[string]any)
	if !ok {
		return "", false
	}
	d, err := EscalationActionDigest(m)
	if err != nil {
		panic(err)
	}
	return d, true
}

// answerFault is everything about an answer that does not depend on the clock: shape, pinned signature, bindings, params digest.
// "" = none.
func (l *GoalPrecedentLog) answerFault(answer any, answered any) string {
	if EscalationAnswerShapeError(answer) != "" {
		return "malformed answer"
	}
	am := goalPrecedentMap(normalizeJSON(answer), "answer")
	pin := l.pinFor(goalReviewReq(am, "principal"))
	if pin == nil {
		return "bad signature"
	}
	var pk any = pin
	var pq any = ""
	if !goalReviewIsStr(pin) {
		pk = anlGet(pin, "pk")
		if s, ok := anlGet(pin, "pq_pk").(string); ok {
			pq = s
		}
	}
	if !verifyArtifactSig(EscalationAnswerDomain, am, pk, pq) {
		return "bad signature"
	}
	pcactn := goalReviewReq(answered, "pcactn")
	if want, ok := goalPrecedentActionDigest(pcactn); !ok || am["action_digest"] != want {
		return "answer is bound to another action"
	}
	if am["history_head"] != goalPrecedentHead(goalReviewGet(answered, "lastCounter")) {
		return "answer is bound to another history state"
	}
	pd, err := ParamsDigest(goalReviewReq(answered, "params"))
	if err != nil {
		panic(err)
	}
	if pd != goalReviewReq(goalReviewReq(pcactn, "action"), "params_digest") {
		return "params do not match the signed action"
	}
	return ""
}

// VerifyChain recomputes the whole chain (append-only integrity), every signature and binding, and every derived cell and ceiling.
func (l *GoalPrecedentLog) VerifyChain(space *GoalSpace) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	var prev any = goalPrecedentGenesis
	for i, e := range l.Entries {
		if !anlStrictEq(e["seq"], goalNum(int64(i))) || !anlStrictEq(e["prev"], prev) || goalPrecedentEntryDigest(e) != e["digest"] {
			return false
		}
		if e["kind"] == "answer" {
			if !goalPrecedentTruthy(e["answer"]) || !goalPrecedentTruthy(e["answered"]) || l.answerFault(e["answer"], e["answered"]) != "" {
				return false
			}
			ans := goalPrecedentMap(e["answered"], "answered")
			c, has := e["ceilings"]
			if e["cell"] != goalCellKey(space, goalPrecedentCaseOf(ans)) || !has || anlJSON(c) != anlJSON(goalCeilingsOf(ans["params"])) {
				return false
			}
		} else if !(goalPrecedentTruthy(e["revocation"]) && goalVerifyPayload(e["revocation"], "precedent-revocation", l.principals)) {
			return false
		}
		prev = e["digest"]
	}
	return true
}

func (l *GoalPrecedentLog) live(policy, cell, now any) map[string]any {
	revoked := []any{}
	for _, e := range l.Entries {
		if e["kind"] == "revocation" {
			revoked = append(revoked, goalReviewReq(goalReviewReq(goalReviewReq(e, "revocation"), "payload"), "target_entry"))
		}
	}
	for i := len(l.Entries) - 1; i >= 0; i-- {
		e := l.Entries[i]
		if e["kind"] != "answer" {
			continue
		}
		ans := goalReviewReq(e, "answer")
		if !anlStrictEq(goalReviewReq(ans, "policy_digest"), policy) || !anlStrictEq(e["cell"], cell) || !anlGt(goalReviewReq(ans, "expires_at"), now) {
			continue
		}
		if !anlIncludes(revoked, goalReviewReq(e, "digest")) {
			return e
		}
	}
	return nil
}

func goalPrecedentNow(now any) int64 {
	f, ok := jsNum(now)
	if !ok || f != math.Trunc(f) {
		anlFail("the verifier clock is not a safe integer (fail closed)")
	}
	if f > maxSafeInt+1 {
		f = maxSafeInt + 1
	} else if f < -maxSafeInt-1 {
		f = -maxSafeInt - 1
	}
	return int64(f)
}

// Append verifies the answer (pinned signer, bound to this grant's policy digest and this exact action and history, unexpired) and
// records it.
func (l *GoalPrecedentLog) Append(answer, answered, grant any, space *GoalSpace, now any) map[string]any {
	pcactn := goalReviewReq(answered, "pcactn")
	pdig, err := EscalationPolicyDigest(goalPrecedentMap(grant, "grant"))
	if err != nil {
		panic(err)
	}
	adig, ok := goalPrecedentActionDigest(pcactn)
	if !ok {
		anlFail("pcactn is not an object")
	}
	v := VerifyEscalationAnswer(answer, l.pins(), EscalationBinding{PolicyDigest: pdig, ActionDigest: adig,
		HistoryHead: goalPrecedentHead(goalReviewGet(answered, "lastCounter"))}, goalPrecedentNow(now))
	if !v.OK {
		return map[string]any{"ok": false, "reason": v.Reason}
	}
	if fault := l.answerFault(answer, answered); fault != "" {
		return map[string]any{"ok": false, "reason": fault}
	}
	cell := goalCellKey(space, goalPrecedentCaseOf(goalPrecedentMap(answered, "answered")))
	existing := l.live(goalReviewReq(answer, "policy_digest"), cell, now)
	if existing != nil && !anlStrictEq(goalReviewReq(goalReviewReq(existing, "answer"), "decision"), goalReviewReq(answer, "decision")) {
		return map[string]any{"ok": false, "reason": "conflicts with a recorded decision; revoke it first"}
	}
	return map[string]any{"ok": true, "entry": l.push(map[string]any{"kind": "answer", "answer": answer, "answered": answered, "cell": cell,
		"ceilings": goalCeilingsOf(goalReviewReq(answered, "params"))})}
}

// Revoke records a principal-signed revocation of a recorded precedent.
func (l *GoalPrecedentLog) Revoke(rev any) map[string]any {
	if !goalVerifyPayload(rev, "precedent-revocation", l.principals) {
		return map[string]any{"ok": false, "reason": "bad signature"}
	}
	p := goalReviewReq(rev, "payload")
	found := false
	for _, e := range l.Entries {
		if e["kind"] == "answer" && anlStrictEq(goalReviewReq(e, "digest"), goalReviewReq(p, "target_entry")) &&
			anlStrictEq(goalReviewReq(goalReviewReq(e, "answer"), "policy_digest"), goalReviewReq(p, "policy_digest")) && anlStrictEq(e["cell"], goalReviewReq(p, "cell")) {
			found = true
			break
		}
	}
	if !found {
		return map[string]any{"ok": false, "reason": "no such precedent"}
	}
	return map[string]any{"ok": true, "entry": l.push(map[string]any{"kind": "revocation", "revocation": rev})}
}

func (l *GoalPrecedentLog) push(e map[string]any) map[string]any {
	base := map[string]any{"seq": goalNum(int64(len(l.Entries))), "prev": l.Head()}
	for k, v := range e {
		if !anlIsUndef(v) {
			base[k] = v
		}
	}
	entry := anlCopy(base)
	entry["digest"] = goalPrecedentEntryDigest(base)
	l.Entries = append(l.Entries, entry)
	return entry
}

// Lookup is the recorded decision covering this case under this policy, if any (cell match, ceilings respected, unexpired, unrevoked);
// nil otherwise.
func (l *GoalPrecedentLog) Lookup(policyDigest any, space *GoalSpace, c any, now any) map[string]any {
	e := l.live(policyDigest, goalCellKey(space, c), now)
	if e == nil {
		return nil
	}
	ceil := goalPrecedentMap(e["ceilings"], "ceilings")
	now2 := goalCeilingsOf(anlGet(anlGet(c, "act"), "params"))
	for k, v := range now2 {
		cv, has := ceil[k]
		if !has {
			return nil // beyond the signed ceiling (the ceiling is -infinity)
		}
		if anlGt(v, cv) {
			return nil // beyond the signed ceiling
		}
	}
	for k := range ceil {
		if _, has := now2[k]; !has {
			return nil // same parameters and units as the signed witness
		}
	}
	return map[string]any{"decision": goalReviewReq(goalReviewReq(e, "answer"), "decision"), "entry": e}
}

// goalAuthorizeWithPrecedents is the policy decision refined by precedents. Precedents act only on Escalate (P3, P4); a tampered log
// fails closed.
func goalAuthorizeWithPrecedents(goal, ont any, policyDigest any, log *GoalPrecedentLog, c any, now any) map[string]any {
	base, _ := goalDecideCase(goal, ont, c)["decision"].(string)
	if base != "escalate" {
		return map[string]any{"decision": base, "via": "policy"}
	}
	space := goalBuildSpace([]any{goal}, nil)
	if !log.VerifyChain(space) {
		return map[string]any{"decision": "escalate", "via": "policy"}
	}
	hit := log.Lookup(policyDigest, space, c, now)
	if hit == nil {
		return map[string]any{"decision": "escalate", "via": "policy"}
	}
	d := "deny"
	if hit["decision"] == "allow" {
		d = "allow"
	}
	return map[string]any{"decision": d, "via": "precedent", "precedent": hit["entry"]}
}

// GoalCeilingsOf is goalCeilingsOf.
func GoalCeilingsOf(params any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalCeilingsOf(params); return nil })
	return
}

// GoalSignRevocation is goalSignRevocation.
func GoalSignRevocation(p any, secret any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalSignRevocation(p, secret); return nil })
	return
}

// GoalAnswerBodyFor is goalAnswerBodyFor.
func GoalAnswerBodyFor(req, o any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalAnswerBodyFor(req, o); return nil })
	return
}

// GoalAuthorizeWithPrecedents is goalAuthorizeWithPrecedents.
func GoalAuthorizeWithPrecedents(goal, ont any, policyDigest string, log *GoalPrecedentLog, c any, now any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalAuthorizeWithPrecedents(goal, ont, policyDigest, log, c, now); return nil })
	return
}
