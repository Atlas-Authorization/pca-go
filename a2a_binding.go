package pca

// The rest of the A2A binding beyond the typed core in a2a.go: proof-carrying tasks and messages, the per-task verification guard,
// the extension declaration, the AUTH_REQUIRED mapping, per-hop delegation, push-token binding, the AP2 payment-mandate envelope and
// signed task-update receipts. Values are JSON values (see acp.go); results are JSON values shaped like the reference. Per-hop PCActn
// verification itself is the ordinary verifier's job (VerifyPCActnCoreWith, or a Verify hook); this is what surrounds it.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The A2A binding constants.
const (
	A2ATaskStateAuthRequired  = "TASK_STATE_AUTH_REQUIRED"
	A2ATaskStateInputRequired = "TASK_STATE_INPUT_REQUIRED"
	A2AReceiptDomain          = "atlas-pca/a2a-receipt/v1\x00"
	A2ANeedKey                = A2APcaExtensionURI + "#need"
	A2AReceiptKey             = A2APcaExtensionURI + "#receipt"
)

// A2AAp2Context is the JSON-LD context of the AP2 payment-mandate envelope.
var A2AAp2Context = []string{"https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2"}

var a2acParamKeys = map[string]bool{"aud": true, "suites": true, "grants": true, "policy_digest": true}

// A2ADefaultRequiredChecks are the checks that must PASS for a task to be admitted unless the caller names its own list: without a
// revocation hook a task is refused.
var A2ADefaultRequiredChecks = []string{"counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"}

// A2AAuthorityError: a verifier configured without any authority (a grant or an expected root issuer); a chain is never its own
// authority.
type A2AAuthorityError struct{}

func (e *A2AAuthorityError) Error() string {
	return "pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority"
}

// a2acSame is JavaScript === on JSON values or undefined.
func a2acSame(a, b any) bool {
	if a == acpU || b == acpU {
		return a == acpU && b == acpU
	}
	return jsStrictEq(a, b)
}

// ---- proof-carrying tasks ---------------------------------------------------------------------------------------------

// A2AAttachPcaToTask is a copy of the task with the PCActn on its metadata (the input is not mutated).
func A2AAttachPcaToTask(task, pca any) (map[string]any, error) {
	if acpNullish(task) {
		return nil, errors.New("Cannot read properties of null (reading 'metadata')")
	}
	out := acpSpread(task)
	md := acpSpread(acpDefault(acpGet(task, "metadata"), map[string]any{}))
	md[A2APcaExtensionURI] = pca
	out["metadata"] = md
	return out, nil
}

// A2AAttachPcaToMessage is A2AAttachPcaToTask for a message.
func A2AAttachPcaToMessage(message, pca any) (map[string]any, error) {
	return A2AAttachPcaToTask(message, pca)
}

func a2acReadPca(metadata any) map[string]any {
	m, _ := acpGet(metadata, A2APcaExtensionURI).(map[string]any)
	return m
}

// A2AExtractPca is the PCActn a task carries: its metadata, then the status message, then the most recent history message; nil if
// none.
func A2AExtractPca(task any) map[string]any {
	tm, ok := task.(map[string]any)
	if !ok {
		return nil
	}
	if p := a2acReadPca(tm["metadata"]); p != nil {
		return p
	}
	if p := a2acReadPca(acpGet(acpGet(tm["status"], "message"), "metadata")); p != nil {
		return p
	}
	if h, isL := tm["history"].([]any); isL {
		for i := len(h) - 1; i >= 0; i-- {
			if p := a2acReadPca(acpGet(h[i], "metadata")); p != nil {
				return p
			}
		}
	}
	return nil
}

// A2AExtractPcaFromMessage is the PCActn a message carries; nil if none.
func A2AExtractPcaFromMessage(message any) map[string]any {
	return a2acReadPca(acpGet(message, "metadata"))
}

// ---- verification -----------------------------------------------------------------------------------------------------

// A2AVerdict is a PCActn verdict source's answer.
type A2AVerdict struct {
	Allow   bool
	Checks  map[string]bool
	Reasons []string
}

// A2AVerifyOptions configure the task guards. One authority is required: Grant (from your store) or a non-empty ExpectedRootIssuer
// (the chain root is then admitted only when its issuer is that principal).
type A2AVerifyOptions struct {
	Aud                string         // this verifier's own audience
	ExpectedRootIssuer *string        // nil = unset
	Grant              map[string]any // nil = unset
	Now                *int64         // epoch ms; nil = the wall clock
	Require            *bool          // the middleware only: false lets a task with no proof pass (default true)
	RequireChecks      []string       // nil = A2ADefaultRequiredChecks
	AllowedSuites      []string
	PQPins             map[string]string
	// Context returns the evidence the verdict needs (params, plan, planAuthorized); nil = none.
	Context func(pcActn any) map[string]any
	// Verify replaces the core verifier as the verdict source.
	Verify func(pcActn, grant, ctx map[string]any) A2AVerdict
	// Revocation is the caller's revocation hook: enforced reports whether it spoke for the proof, ok its verdict.
	Revocation func(pcActn, grant, ctx map[string]any) (enforced, ok bool, reason string)
	// HumanSignerSet backs a mandate's human_present claim (see A2AVerifyPaymentMandate).
	HumanSignerSet []any
}

func a2acAssertAuthority(o A2AVerifyOptions) error {
	if o.Grant != nil || (o.ExpectedRootIssuer != nil && *o.ExpectedRootIssuer != "") {
		return nil
	}
	return &A2AAuthorityError{}
}

func a2acCoreVerdict(pm, gm map[string]any, o A2AVerifyOptions, ctx map[string]any) A2AVerdict {
	now := time.Now().UnixMilli()
	if o.Now != nil {
		now = *o.Now
	}
	roots := []string{}
	plan, _ := ctx["plan"].(map[string]any)
	if ctx["planAuthorized"] == true || ctx["plan_authorized"] == true {
		if root, isS := plan["root"].(string); isS {
			roots = append(roots, root)
		}
	}
	vo := VerifyOptions{AllowedSuites: o.AllowedSuites, AuthorizedPlanRoots: roots, PQPins: o.PQPins}
	if o.Grant == nil && vo.PQPins == nil {
		vo.PQPins = map[string]string{} // the root is admitted only under the pinned principal: pins are then enforced
	}
	v, err := VerifyPCActnCoreWith(pm, gm, now, o.Aud, vo)
	if err != nil {
		return A2AVerdict{Reasons: []string{err.Error()}, Checks: map[string]bool{}}
	}
	checks := make(map[string]bool, len(v.Checks)+2)
	for k, b := range v.Checks {
		checks[k] = b
	}
	reasons := append([]string{}, v.Reasons...)
	if len(reasons) == 0 && v.Reason != "" {
		reasons = []string{v.Reason}
	}
	allow := v.Allow
	if o.Revocation != nil {
		if enforced, ok, why := o.Revocation(pm, gm, ctx); enforced {
			checks["revocation"] = ok
			if !ok {
				allow = false
				if why == "" {
					why = "rejected"
				}
				reasons = append(reasons, why)
			}
		}
	}
	if params, isO := ctx["params"].(map[string]any); isO {
		if action, isA := pm["action"].(map[string]any); isA {
			d, err := ParamsDigest(params)
			checks["params_digest"] = err == nil && action["params_digest"] == d
		}
	}
	return A2AVerdict{Allow: allow, Checks: checks, Reasons: reasons}
}

// a2acVerifyPca is the PCActn authorization shared by the task and payment-mandate surfaces, under a known authority: the stored
// grant, or the chain root only when its issuer is the expected principal.
func a2acVerifyPca(p any, o A2AVerifyOptions, extra []string) (map[string]any, error) {
	if err := a2acAssertAuthority(o); err != nil {
		return nil, err
	}
	pm, isM := p.(map[string]any)
	_, isL := p.([]any)
	if p == nil || (!isM && !isL) {
		return map[string]any{"ok": false, "reason": "PCActn is not an object"}, nil
	}
	var root any = acpU
	if chain, isC := acpGet(p, "cap_chain").([]any); isC && len(chain) > 0 {
		root = chain[0]
	}
	if root == acpU || !acpTruthy(root) {
		return map[string]any{"ok": false, "reason": "PCActn carries no capability chain", "pcActn": p}, nil
	}
	if o.ExpectedRootIssuer != nil && !a2acSame(acpGet(root, "issuer"), *o.ExpectedRootIssuer) {
		return map[string]any{"ok": false, "reason": "chain root issuer does not match the expected principal", "pcActn": p}, nil
	}
	grant := o.Grant
	if grant == nil {
		grant, _ = root.(map[string]any)
	}
	var ctx map[string]any
	if o.Context != nil {
		ctx = o.Context(p)
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	var verdict A2AVerdict
	switch {
	case o.Verify != nil:
		verdict = o.Verify(pm, grant, ctx)
	case !isM || grant == nil:
		verdict = A2AVerdict{Reasons: []string{"PCActn and grant must be objects"}, Checks: map[string]bool{}}
	default:
		verdict = a2acCoreVerdict(pm, grant, o, ctx)
	}
	names := o.RequireChecks
	if names == nil {
		names = A2ADefaultRequiredChecks
	}
	names = append(append([]string{}, names...), extra...)
	allow := verdict.Allow
	for _, n := range names {
		allow = allow && verdict.Checks[n]
	}
	checks := make(map[string]any, len(verdict.Checks))
	for k, b := range verdict.Checks {
		checks[k] = b
	}
	reasons := []any{}
	for _, r := range verdict.Reasons {
		if r != "" {
			reasons = append(reasons, r)
		}
	}
	result := map[string]any{"allow": allow, "checks": checks, "reasons": reasons}
	if allow {
		return map[string]any{"ok": true, "result": result, "pcActn": p}, nil
	}
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, r.(string))
	}
	reason := strings.Join(parts, "; ")
	if reason == "" {
		reason = "PCActn verification failed"
	}
	result["reason"] = reason
	return map[string]any{"ok": false, "reason": reason, "result": result, "pcActn": p}, nil
}

// A2AVerifyTask verifies the proof-carrying action on a task. Fail closed: no PCActn, or one that does not verify, is refused. The
// result is {ok, reason?, result?, pcActn?}; a verifier with no authority is an *A2AAuthorityError.
func A2AVerifyTask(task any, o A2AVerifyOptions) (map[string]any, error) {
	if err := a2acAssertAuthority(o); err != nil {
		return nil, err
	}
	p := A2AExtractPca(task)
	if p == nil {
		return map[string]any{"ok": false, "reason": "no proof-carrying action attached to this task"}, nil
	}
	return a2acVerifyPca(p, o, nil)
}

// A2AMiddleware is a per-task guard. Require (default true): a task with no proof is refused; with false it passes, but a task
// that DOES carry a proof must still verify.
func A2AMiddleware(o A2AVerifyOptions) (func(task any) (map[string]any, error), error) {
	if err := a2acAssertAuthority(o); err != nil {
		return nil, err
	}
	return func(task any) (map[string]any, error) {
		p := A2AExtractPca(task)
		if p == nil {
			if o.Require == nil || *o.Require {
				return map[string]any{"ok": false, "reason": "proof-carrying action required but none attached to task"}, nil
			}
			return map[string]any{"ok": true}, nil
		}
		return a2acVerifyPca(p, o, nil)
	}, nil
}

// ---- extension declaration --------------------------------------------------------------------------------------------

// A2APcaExtensionDeclaration is the AgentExtension an agent card declares for the PCA extension.
func A2APcaExtensionDeclaration(params map[string]any, required bool) map[string]any {
	return map[string]any{"uri": A2APcaExtensionURI, "description": "Per-action proofs of authority (PCActn) on tasks and messages",
		"required": required, "params": params}
}

// A2AReadPcaExtension reads and validates the PCA extension from an Agent Card. A malformed declaration is a refusal, never a guess.
// The result is {ok, code?, required?, params?, grants?}.
func A2AReadPcaExtension(card any) map[string]any {
	bad := func(code string) map[string]any { return map[string]any{"ok": false, "code": code} }
	exts, isL := acpGet(acpGet(card, "capabilities"), "extensions").([]any)
	if !isL {
		return bad("not_declared")
	}
	var found []map[string]any
	for _, e := range exts {
		if em, isO := e.(map[string]any); isO && em["uri"] == A2APcaExtensionURI {
			found = append(found, em)
		}
	}
	if len(found) == 0 {
		return bad("not_declared")
	}
	if len(found) > 1 {
		return bad("bad_declaration")
	}
	e := found[0]
	if _, isB := e["required"].(bool); acpHas(e, "required") && !isB {
		return bad("bad_declaration")
	}
	p, isO := e["params"].(map[string]any)
	if !isO {
		return bad("bad_params")
	}
	for k := range p {
		if !a2acParamKeys[k] {
			return bad("bad_params")
		}
	}
	if aud, isS := p["aud"].(string); !isS || jsLen(aud) == 0 || jsLen(aud) > 512 {
		return bad("bad_params")
	}
	if acpHas(p, "suites") {
		l, isL2 := p["suites"].([]any)
		if !isL2 || len(l) > 16 {
			return bad("bad_params")
		}
		for _, s := range l {
			if ss, isS := s.(string); !isS || jsLen(ss) == 0 || jsLen(ss) > 64 {
				return bad("bad_params")
			}
		}
	}
	if acpHas(p, "policy_digest") {
		if pd, isS := p["policy_digest"].(string); !isS || jsLen(pd) == 0 || jsLen(pd) > 128 {
			return bad("bad_params")
		}
	}
	grants := []any{}
	if acpHas(p, "grants") {
		details, code := ParsePcaGrantDetails(p["grants"])
		if code != "" {
			return bad("bad_grants")
		}
		for _, d := range details {
			grants = append(grants, d)
		}
	}
	return map[string]any{"ok": true, "required": e["required"] == true, "params": p, "grants": grants}
}

// A2AClientOptsIntoPca reports whether the A2A-Extensions service parameter lists the PCA extension (exact URI in a comma-separated
// list).
func A2AClientOptsIntoPca(header any) bool {
	h, ok := header.(string)
	if !ok {
		return false
	}
	for _, u := range strings.Split(h, ",") {
		if jsTrim(u) == A2APcaExtensionURI {
			return true
		}
	}
	return false
}

// ---- AUTH_REQUIRED mapping --------------------------------------------------------------------------------------------

// A2AIsAuthRequired reports whether a task state is AUTH_REQUIRED (either spelling).
func A2AIsAuthRequired(state any) bool {
	s, ok := state.(string)
	return ok && (s == A2ATaskStateAuthRequired || s == "auth-required")
}

func a2acNowISO(now any) (string, error) {
	f, ok := jsNum(now)
	if !ok {
		return "", errors.New("Invalid time value")
	}
	s, valid := acpISO(f)
	if !valid {
		return "", errors.New("Invalid time value")
	}
	return s, nil
}

// A2AAuthRequiredStatus is the TaskStatus an agent sets to ask for authority: AUTH_REQUIRED plus a message carrying the typed need.
// o: now (epoch ms), messageId, text. It refuses a need the codec would refuse.
func A2AAuthRequiredStatus(need any, o map[string]any) (map[string]any, error) {
	nm, _ := need.(map[string]any)
	enc, err := EncodePcaNeed(nm)
	if err != nil {
		return nil, err
	}
	stamp, err := a2acNowISO(acpGet(o, "now"))
	if err != nil {
		return nil, err
	}
	text := acpDefault(acpGet(o, "text"), fmt.Sprintf("Authority needed: %s on %s", acpS(nm["verb"]), acpS(nm["resource"])))
	msg := map[string]any{"role": "agent", "parts": []any{map[string]any{"kind": "text", "text": text}},
		"extensions": []any{A2APcaExtensionURI}, "metadata": map[string]any{A2ANeedKey: enc}}
	if mid := acpGet(o, "messageId"); mid != acpU {
		msg["messageId"] = mid
	}
	return map[string]any{"state": A2ATaskStateAuthRequired, "timestamp": stamp, "message": msg}, nil
}

// A2AReadAuthRequiredNeed is the need parked in a task status message, decoded ({ok: true, need} or {ok: false, code}); nil when
// there is none.
func A2AReadAuthRequiredNeed(task any) map[string]any {
	md, isO := acpGet(acpGet(acpGet(task, "status"), "message"), "metadata").(map[string]any)
	if !isO {
		return nil
	}
	v, has := md[A2ANeedKey]
	if !has {
		return nil
	}
	need, code := DecodeA2ANeed(v)
	if code != "" {
		return map[string]any{"ok": false, "code": code}
	}
	return map[string]any{"ok": true, "need": need}
}

func a2acNeedDigest(need any) (string, error) {
	return HashCanonical(map[string]any{"d": a2aNeedDomain, "need": need})
}

// A2AAnswerMessage is the answer message: a PCActn for exactly the parked need, plus the need's digest.
func A2AAnswerMessage(need, pca, messageID any) (map[string]any, error) {
	d, err := a2acNeedDigest(need)
	if err != nil {
		return nil, err
	}
	return map[string]any{"role": "user", "messageId": messageID, "parts": []any{map[string]any{"kind": "text", "text": "authority provided"}},
		"metadata": map[string]any{A2APcaExtensionURI: pca, A2ANeedKey: d}}, nil
}

// A2AResumeGateOf is the pure gate of AUTH_REQUIRED resumption over the reference's option object {state, needEncoded,
// answerNeedDigest, proofAction}: "" means the full verifier may now be asked, else the refusal code. An absent proofAction is no
// proof; a null one is an error, as in the reference.
func A2AResumeGateOf(o map[string]any) (string, error) {
	if !A2AIsAuthRequired(o["state"]) {
		return "task_not_auth_required", nil
	}
	var need map[string]any
	if enc, has := o["needEncoded"]; has {
		need, _ = DecodeA2ANeed(enc)
	}
	if need == nil {
		return "no_valid_need", nil
	}
	d, err := a2acNeedDigest(need)
	if err != nil {
		return "", err
	}
	got, has := o["answerNeedDigest"]
	if !has {
		got = acpU
	}
	if !a2acSame(got, d) {
		return "answer_not_bound_to_need", nil
	}
	action, has := o["proofAction"]
	if !has {
		return "no_proof", nil
	}
	if action == nil {
		return "", errors.New("Cannot read properties of null (reading 'verb')")
	}
	if !a2acSame(acpGet(action, "verb"), need["verb"]) || !a2acSame(acpGet(action, "resource"), need["resource"]) {
		return "action_mismatch", nil
	}
	return "", nil
}

// A2AResumeAuthRequired resumes a Task parked in AUTH_REQUIRED. Allowed only when the task is in AUTH_REQUIRED, its status carries a
// decodable need, the answer cites that need's digest, the answer carries a PCActn for the need's exact verb and resource, and that
// PCActn passes the verifier for THIS agent. The state change alone, or a proof for another action, resumes nothing.
func A2AResumeAuthRequired(task, answer any, o A2AVerifyOptions) (map[string]any, error) {
	status, _ := acpGet(task, "status").(map[string]any)
	statusMd, _ := acpGet(acpGet(status, "message"), "metadata").(map[string]any)
	md, _ := acpGet(answer, "metadata").(map[string]any)
	p := A2AExtractPcaFromMessage(answer)
	gate := map[string]any{}
	if _, has := status["state"]; has {
		gate["state"] = status["state"]
	}
	if v, has := statusMd[A2ANeedKey]; has {
		gate["needEncoded"] = v
	}
	if v, has := md[A2ANeedKey]; has {
		gate["answerNeedDigest"] = v
	}
	if v, has := p["action"]; has {
		gate["proofAction"] = v
	}
	refusal, err := A2AResumeGateOf(gate)
	if err != nil {
		return nil, err
	}
	if refusal != "" {
		return map[string]any{"ok": false, "reason": refusal}, nil
	}
	v, err := A2AVerifyTask(map[string]any{"id": acpGet(task, "id"), "status": map[string]any{"state": "TASK_STATE_WORKING"},
		"metadata": map[string]any{A2APcaExtensionURI: p}}, o)
	if err != nil {
		return nil, err
	}
	if v["ok"] == true {
		return map[string]any{"ok": true, "verification": v}, nil
	}
	reason := acpDefault(v["reason"], "proof_rejected")
	return map[string]any{"ok": false, "reason": reason}, nil
}

// ---- per-hop delegation -----------------------------------------------------------------------------------------------

// A2AChainExtends reports whether next (capability ids, root first) extends prev: attenuation only appends hops, so the earlier chain
// is a prefix.
func A2AChainExtends(prev, next []any) bool {
	if len(next) < len(prev) {
		return false
	}
	for k, id := range prev {
		if !a2acSame(next[k], id) {
			return false
		}
	}
	return true
}

// A2ACheckChains checks that every hop's chain (a list of capability ids) is non-empty and extends the one before it. The result is
// {ok, failedHop?, reason?}.
func A2ACheckChains(chains any) (map[string]any, error) {
	list, err := a2acIter(chains)
	if err != nil {
		return nil, err
	}
	var prev []any
	for i, c := range list {
		ids, isL := c.([]any)
		if !isL || len(ids) == 0 {
			return map[string]any{"ok": false, "failedHop": i, "reason": "no_chain"}, nil
		}
		if prev != nil && !A2AChainExtends(prev, ids) {
			return map[string]any{"ok": false, "failedHop": i, "reason": "chain_does_not_extend_previous_hop"}, nil
		}
		prev = ids
	}
	return map[string]any{"ok": true}, nil
}

// A2ADelegationHop is one hop of a delegation: a task and the options it is verified under.
type A2ADelegationHop struct {
	Task any
	Opts A2AVerifyOptions
}

// A2AVerifyDelegation verifies a chain of delegated tasks, one per A2A hop, each on its own (its own PCActn, audience and
// authority); the capability chain must EXTEND the previous hop's. It stops at the first failure; empty input is refused.
func A2AVerifyDelegation(hops []A2ADelegationHop) (map[string]any, error) {
	chains := []any{}
	if len(hops) == 0 {
		return map[string]any{"ok": false, "reason": "no_hops", "chains": chains}, nil
	}
	var last []any
	for i, h := range hops {
		v, err := A2AVerifyTask(h.Task, h.Opts)
		if err != nil {
			return nil, err
		}
		if v["ok"] != true {
			return map[string]any{"ok": false, "failedHop": i, "reason": acpDefault(v["reason"], "rejected"), "chains": chains}, nil
		}
		p := A2AExtractPca(h.Task)
		list, isL := acpGet(p, "cap_chain").([]any)
		if !isL {
			return map[string]any{"ok": false, "failedHop": i, "reason": "no_chain", "chains": chains}, nil
		}
		ids := make([]any, len(list))
		for k, c := range list {
			if acpNullish(c) {
				return nil, errors.New("Cannot read properties of null (reading 'id')")
			}
			ids[k] = acpGet(c, "id")
		}
		if last != nil && !A2AChainExtends(last, ids) {
			return map[string]any{"ok": false, "failedHop": i, "reason": "chain_does_not_extend_previous_hop", "chains": chains}, nil
		}
		chains = append(chains, ids)
		last = ids
	}
	return map[string]any{"ok": true, "chains": chains}, nil
}

// ---- push notifications and anti-enumeration --------------------------------------------------------------------------

// A2APcaPushToken is the per-task push token. It refuses a salt shorter than 16 characters (the secret must not be guessable).
func A2APcaPushToken(taskID any, chainIDs []string, salt any) (string, error) {
	s, ok := salt.(string)
	if !ok || jsLen(s) < 16 {
		return "", errors.New("pcaPushToken: the salt must be a secret of at least 16 characters")
	}
	cd, err := PcaGrantChainDigest(chainIDs)
	if err != nil {
		return "", err
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/a2a-push/v1", "task_id": taskID, "chain": cd, "salt": s})
}

// A2ACheckPushNotification is the receiver-side check of a delivered push notification {token, payload}: the token must be the one
// recomputed from expected {taskId, chainIds, salt}, and the payload must be about that task. The result is {ok, reason?}; it errs
// on a salt shorter than 16 characters.
func A2ACheckPushNotification(expected, delivered any) (map[string]any, error) {
	if acpNullish(expected) || acpNullish(delivered) {
		return nil, errors.New("Cannot read properties of null")
	}
	token, isS := acpGet(delivered, "token").(string)
	if !isS || token == "" {
		return map[string]any{"ok": false, "reason": "no_token"}, nil
	}
	var ids []string
	l, _ := acpGet(expected, "chainIds").([]any)
	for _, x := range l {
		s, isStr := x.(string)
		if !isStr {
			return nil, errors.New("chainIds must be strings")
		}
		ids = append(ids, s)
	}
	want, err := A2APcaPushToken(acpGet(expected, "taskId"), ids, acpGet(expected, "salt"))
	if err != nil {
		return nil, err
	}
	if !timingSafeEq([]byte(token), []byte(want)) {
		return map[string]any{"ok": false, "reason": "token_mismatch"}, nil
	}
	var found any = acpU
	payload := acpGet(delivered, "payload")
	for _, f := range [][2]string{{"task", "id"}, {"statusUpdate", "taskId"}, {"artifactUpdate", "taskId"}} {
		if v := acpGet(acpGet(payload, f[0]), f[1]); v != acpU && v != nil {
			found = v
			break
		}
	}
	if a2acSame(found, acpGet(expected, "taskId")) {
		return map[string]any{"ok": true}, nil
	}
	return map[string]any{"ok": false, "reason": "task_mismatch"}, nil
}

// A2AUniformTaskNotFound is the one error servers return for "no such task" and "not yours" alike (no existence leak).
func A2AUniformTaskNotFound() map[string]any {
	return map[string]any{"code": "TaskNotFoundError", "message": "task not found"}
}

// ---- payment mandate envelope -----------------------------------------------------------------------------------------

// a2acHumanPresent is true only when the PCActn's threshold shares verify at t=3 (agent, guardian and principal) under the signer
// set. Never panics.
// shortcut: the agent role needs an explicit agent share; the reference also lets an Ed25519 leaf signature stand for it. Upgrade
// when a mandate whose agent signs only with the leaf must count as human-present.
func a2acHumanPresent(p, signerSet any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	pm, isM := p.(map[string]any)
	ss, isL := signerSet.([]any)
	if !isM || !isL {
		return false
	}
	roles := map[string]bool{}
	for _, e := range ss {
		r, _ := acpGet(e, "role").(string)
		roles[r] = true
	}
	if len(roles) != 3 || !roles["agent"] || !roles["guardian"] || !roles["principal"] {
		return false
	}
	msg, err := ThresholdMessage(pm)
	if err != nil {
		return false
	}
	th, _ := pm["threshold"].(map[string]any)
	shares, _ := th["shares"].([]any)
	verified := map[string]bool{}
	for _, s := range shares {
		sh, isO := s.(map[string]any)
		if !isO {
			continue
		}
		role, _ := sh["role"].(string)
		if VerifyThresholdShare(map[string]any{"role": role, "t": 3, "signer_set": ss, "threshold_message": b64.EncodeToString(msg), "share": sh}) {
			verified[role] = true
		}
	}
	return verified["agent"] && verified["guardian"] && verified["principal"]
}

func a2acSafeNonNeg(v any) bool {
	f, ok := jsNum(v)
	return ok && jsIsSafeInteger(v) && f >= 0
}

// A2APaymentMandateFromPca maps a PCActn to an AP2 payment-mandate envelope whose authority is carried BY REFERENCE
// (x_pca.pcactn_digest). o: amount ({currency, value} in integer minor units), paymentMethod, merchant, humanPresent,
// humanSignerSet, issuerPublic, now. It refuses anything the envelope cannot honestly carry.
func A2APaymentMandateFromPca(pca any, o any) (map[string]any, error) {
	if acpNullish(pca) || acpNullish(o) {
		return nil, errors.New("Cannot read properties of null")
	}
	chain, _ := acpGet(pca, "cap_chain").([]any)
	var leaf any = acpU
	if len(chain) > 0 && !acpNullish(chain[len(chain)-1]) {
		leaf = acpGet(chain[len(chain)-1], "holder")
	}
	issuer := acpDefault(acpGet(o, "issuerPublic"), leaf)
	if issuer == acpU {
		return nil, errors.New("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain")
	}
	amount := acpGet(o, "amount")
	if acpNullish(amount) {
		return nil, errors.New("Cannot read properties of null (reading 'value')")
	}
	if !a2acSafeNonNeg(acpGet(amount, "value")) {
		return nil, errors.New("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units")
	}
	var hp any = acpGet(o, "humanPresent")
	if acpNullish(hp) {
		hp = false
		if ss := acpGet(o, "humanSignerSet"); acpTruthy(ss) {
			hp = a2acHumanPresent(pca, ss)
		}
	}
	var now any = acpGet(o, "now")
	stamp, err := func() (string, error) {
		if acpNullish(now) {
			return acpISOMs(time.Now().UnixMilli()), nil
		}
		return a2acNowISO(now)
	}()
	if err != nil {
		return nil, err
	}
	action := acpGet(pca, "action")
	if acpNullish(action) {
		return nil, errors.New("Cannot read properties of undefined (reading 'verb')")
	}
	digest, err := HashCanonical(pca)
	if err != nil {
		return nil, err
	}
	xPca := map[string]any{"pcactn_digest": digest}
	for _, e := range []struct {
		k string
		v any
	}{{"aud", acpGet(pca, "aud")}, {"verb", acpGet(action, "verb")}, {"resource", acpGet(action, "resource")},
		{"params_digest", acpGet(action, "params_digest")}, {"grant_ref", acpGet(pca, "grant_ref")}} {
		if e.v != acpU {
			xPca[e.k] = e.v
		}
	}
	xPca["leaf_holder"] = acpDefault(leaf, issuer)
	contents := map[string]any{"amount": acpSpread(amount), "payment_method": acpSpread(acpGet(o, "paymentMethod")), "human_present": hp}
	if m := acpGet(o, "merchant"); m != acpU {
		contents["merchant"] = m
	}
	contents["x_pca"] = xPca
	ctx := make([]any, len(A2AAp2Context))
	for i, c := range A2AAp2Context {
		ctx[i] = c
	}
	return map[string]any{"@context": ctx, "type": []any{"VerifiableCredential", "PaymentMandate"}, "issuer": issuer,
		"issuanceDate": stamp, "credentialSubject": contents}, nil
}

func acpISOMs(ms int64) string {
	s, _ := acpISO(float64(ms))
	return s
}

// A2APcaBindingFromPaymentMandate is the PCA binding read back out of a payment mandate (the round trip of x_pca).
func A2APcaBindingFromPaymentMandate(mandate any) (map[string]any, error) {
	if acpNullish(mandate) {
		return nil, errors.New("Cannot read properties of null (reading 'credentialSubject')")
	}
	cs := acpGet(mandate, "credentialSubject")
	if acpNullish(cs) {
		return nil, errors.New("Cannot read properties of undefined (reading 'x_pca')")
	}
	return acpSpread(acpGet(cs, "x_pca")), nil
}

func a2acMandateBindingError(m, p any, params map[string]any, o A2AVerifyOptions) string {
	x, isO := acpGet(m, "x_pca").(map[string]any)
	if !isO {
		return "payment mandate carries no x_pca binding"
	}
	action := acpGet(p, "action")
	var leaf any = acpU
	if chain, isL := acpGet(p, "cap_chain").([]any); isL && len(chain) > 0 {
		leaf = chain[len(chain)-1]
	}
	sub := func(k string) any {
		if acpNullish(action) {
			return acpU
		}
		return acpGet(action, k)
	}
	for _, b := range []struct {
		k string
		v any
	}{{"aud", acpGet(p, "aud")}, {"verb", sub("verb")}, {"resource", sub("resource")}, {"params_digest", sub("params_digest")},
		{"grant_ref", acpGet(p, "grant_ref")}, {"leaf_holder", acpGet(leaf, "holder")}} {
		xv, has := x[b.k].(string)
		if !has || !a2acSame(xv, b.v) {
			return "payment mandate x_pca." + b.k + " is not the PCActn's"
		}
	}
	amt, isA := acpGet(m, "amount").(map[string]any)
	f, _ := jsNum(amt["value"])
	_, curOK := amt["currency"].(string)
	if !isA || !jsIsSafeInteger(amt["value"]) || f < 0 || (f == 0 && 1/f < 0) || !curOK {
		return "payment mandate amount is malformed (value must be a non-negative integer in minor units)"
	}
	pf, _ := jsNum(params["amount"])
	if !acpHas(params, "amount") || !jsIsSafeInteger(params["amount"]) || pf < 0 || (pf == 0 && 1/pf < 0) {
		return "the PCActn params carry no integer minor-unit amount to bind the mandate amount to"
	}
	if _, isS := params["currency"].(string); !acpHas(params, "currency") || !isS {
		return "the PCActn params carry no currency to bind the mandate currency to"
	}
	if f != pf || amt["currency"] != params["currency"] {
		return "payment mandate amount / currency differ from the authorized PCActn params"
	}
	var merchant, pMerchant any = acpU, acpU
	if mm, isM := m.(map[string]any); isM {
		if v, has := mm["merchant"]; has {
			merchant = v
		}
	}
	if v, has := params["merchant"]; has {
		pMerchant = v
	}
	if !a2acSame(merchant, pMerchant) {
		return "payment mandate merchant differs from the authorized PCActn params"
	}
	if acpHas(params, "payment_method") {
		a, e1 := HashCanonical(acpGet(m, "payment_method"))
		b, e2 := HashCanonical(params["payment_method"])
		if acpGet(m, "payment_method") == acpU || e1 != nil || e2 != nil || a != b {
			return "payment mandate payment_method differs from the authorized PCActn params"
		}
	}
	hp, isB := acpGet(m, "human_present").(bool)
	if !isB {
		return "payment mandate human_present must be a boolean"
	}
	if hp && !(o.HumanSignerSet != nil && a2acHumanPresent(p, o.HumanSignerSet)) {
		return "payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)"
	}
	return ""
}

// A2AVerifyPaymentMandate verifies a payment mandate against the PCActn it references. The mandate is NOT signed: every field a
// payer acts on must be authorized by the PCActn (digest and x_pca fields, the opened params' amount, currency, merchant and payment
// method, a verified t=3 co-signature for human_present), and the PCActn itself must verify, with params_digest required. The
// result is {ok, reason?, result?, pcActn?}.
func A2AVerifyPaymentMandate(mandate, pca any, o A2AVerifyOptions) (map[string]any, error) {
	if err := a2acAssertAuthority(o); err != nil {
		return nil, err
	}
	var bound, digest any
	err := func() error {
		cs, err := a2acMember(mandate, "credentialSubject")
		if err != nil {
			return err
		}
		x, err := a2acMember(cs, "x_pca")
		if err != nil {
			return err
		}
		if bound, err = a2acMember(x, "pcactn_digest"); err != nil {
			return err
		}
		d, err := HashCanonical(pca)
		digest = d
		return err
	}()
	if err != nil {
		return map[string]any{"ok": false, "reason": "malformed payment mandate or PCActn: " + err.Error()}, nil
	}
	if !a2acSame(bound, digest) {
		return map[string]any{"ok": false, "reason": "payment mandate is not bound to this PCActn (pcactn_digest mismatch)", "pcActn": pca}, nil
	}
	_, isM := pca.(map[string]any)
	_, isL := pca.([]any)
	if pca == nil || (!isM && !isL) {
		return map[string]any{"ok": false, "reason": "PCActn is not an object"}, nil
	}
	var ctx map[string]any
	if o.Context != nil {
		ctx = o.Context(pca)
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	params, isP := ctx["params"].(map[string]any)
	if !isP {
		return map[string]any{"ok": false, "reason": "context.params (the PCActn params plaintext) is required to bind the payment mandate", "pcActn": pca}, nil
	}
	if why := a2acMandateBindingError(acpGet(mandate, "credentialSubject"), pca, params, o); why != "" {
		return map[string]any{"ok": false, "reason": why, "pcActn": pca}, nil
	}
	o.Context = func(any) map[string]any { return ctx }
	return a2acVerifyPca(pca, o, []string{"params_digest"})
}

// ---- signed task-update receipts --------------------------------------------------------------------------------------

// A2ASignTaskReceipt signs a receipt. secret is the 32-byte Ed25519 seed of the executing agent; o: taskId, state, chainIds,
// issuedAt, prev (the previous receipt of the same task). It refuses malformed input, a prev of another task or one already
// terminal.
func A2ASignTaskReceipt(secret []byte, o map[string]any) (map[string]any, error) {
	if len(secret) != ed25519.SeedSize {
		return nil, errors.New("signTaskReceipt: the secret must be a 32-byte Ed25519 seed")
	}
	taskID, isS := acpGet(o, "taskId").(string)
	state, _ := acpGet(o, "state").(string)
	issued := acpGet(o, "issuedAt")
	ids, isL := acpGet(o, "chainIds").([]any)
	if !isS || taskID == "" || jsLen(taskID) > 256 || !a2aStates[state] || !k3Int(issued) || !isL || len(ids) == 0 {
		return nil, errors.New("signTaskReceipt: malformed input")
	}
	prev := acpGet(o, "prev")
	seq, prevDigest := any(jsNumber(0)), any(nil)
	if acpTruthy(prev) {
		if acpGet(prev, "task_id") != taskID || a2aTerminal[acpS(acpGet(prev, "state"))] {
			return nil, errors.New("signTaskReceipt: prev is for another task or already terminal")
		}
		pseq, _ := jsNum(acpGet(prev, "seq"))
		seq = jsNumber(pseq + 1)
		d, ok := A2AReceiptDigest(prev)
		if !ok {
			return nil, errors.New("signTaskReceipt: prev has no canonical form")
		}
		prevDigest = d
	}
	chainIDs := make([]string, len(ids))
	for i, x := range ids {
		s, isStr := x.(string)
		if !isStr {
			return nil, errors.New("signTaskReceipt: chainIds must be strings")
		}
		chainIDs[i] = s
	}
	chain, err := PcaGrantChainDigest(chainIDs)
	if err != nil {
		return nil, err
	}
	pub := ed25519.NewKeyFromSeed(secret).Public().(ed25519.PublicKey)
	body := map[string]any{"v": jsNumber(1), "task_id": taskID, "state": state, "seq": seq, "prev": prevDigest, "chain": chain,
		"issued_at": issued, "signer": b64.EncodeToString(pub)}
	cb, err := canonBytes(body)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(secret), append([]byte(A2AReceiptDomain), cb...))
	out := make(map[string]any, len(body)+1)
	for k, v := range body {
		out[k] = v
	}
	out["sig"] = b64.EncodeToString(sig)
	return out, nil
}

// A2AAttachReceipt is a copy of a status update or message with the receipt on its metadata.
func A2AAttachReceipt(carrier, receipt any) (map[string]any, error) {
	if acpNullish(carrier) {
		return nil, errors.New("Cannot read properties of null (reading 'metadata')")
	}
	out := acpSpread(carrier)
	md := acpSpread(acpDefault(acpGet(carrier, "metadata"), map[string]any{}))
	md[A2AReceiptKey] = receipt
	out["metadata"] = md
	return out, nil
}

// A2AReceiptOfPayload is the (unverified) receipt a push or stream payload carries (statusUpdate, task or message metadata); nil
// when none.
func A2AReceiptOfPayload(payload any) any {
	pm, ok := payload.(map[string]any)
	if !ok {
		return nil
	}
	for _, k := range []string{"statusUpdate", "task", "message"} {
		if md, isO := acpGet(pm[k], "metadata").(map[string]any); isO && acpHas(md, A2AReceiptKey) {
			return md[A2AReceiptKey]
		}
	}
	return nil
}
