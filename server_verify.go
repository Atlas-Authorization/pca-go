package pca

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// ServerVerify is the resource-server verifier with the full verdict: one call reports allow, the recomputed risk r, the
// requiredThreshold, every check as pass | fail | not-enforced | unsupported, the reasons (in order), the budget after the decision
// and, when asked for, the per-check assurance report (allow, r, requiredThreshold, checks, reasons, budget?, assurance?, k1Bound?).
// It never panics: any internal error becomes a fail-closed verdict.
//
// Options (ServerVerifyInput.Opts, a JSON-shaped map; an absent key is "not given"): grant (the verifier's OWN stored grant,
// required), now, audience (a string; JSON null is the explicit opt-out), insecureSkipPlanRootCheck, context {params, subject, env,
// plan, planAuthorized, reversibilityClass, risk, budget, recentActionTimes, revocationEpoch, beacon}, require (default
// ServerDefaultRequiredChecks), allowedSuites, pqPins, operation {verb, resource, params?}, intent, intentV2, freshAt,
// requireRiskInputs, assurance, requireAssurance, allowUnsupported. The hooks, the opt-in enforcement gates and the caveat-language
// input are code, so they are typed fields beside the map.
//
// The legacy unbound-PQ opt-out is not offered: a pure-PQ or hybrid signer is always checked against its holder_pq commitment.
func ServerVerify(pcactn any, in ServerVerifyInput) map[string]any {
	o := in.Opts
	if o == nil {
		o = map[string]any{}
	}
	v := svGuarded(func() map[string]any { return serverVerifyRun(pcactn, o, in) })
	// a verdict that stopped before the checks ran (undecodable, wire, verifier error) still reports its outcomes when asked
	if svWantsAssurance(o) {
		if _, has := v["assurance"]; !has {
			checks, _ := v["checks"].(map[string]string)
			src := AssuranceSources{}
			for _, n := range svSortedKeys(checks) {
				src.Checks = append(src.Checks, NamedStatus{Name: n, Status: checks[n]})
			}
			v["assurance"] = BuildAssuranceReport(src).ToMap()
		}
	}
	return v
}

// ServerDefaultRequiredChecks is the minimum enforcement profile of the stateless verifier: ServerVerify allows only when every one
// of these passed (the replay counter is the stateful layer's; see Authorize).
func ServerDefaultRequiredChecks() []string {
	return []string{"counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"}
}

// ServerHookResult is what a verifier hook reports: whether it enforced, whether it passed, why not, and (threshold hook) the t it enforced.
type ServerHookResult struct {
	Enforced  bool
	OK        bool
	Reason    string
	HasReason bool
	T         *float64
}

// ServerHook is a verifier hook (attestation | threshold | revocation | zk); it receives {pcactn, grant, nowEpoch}. A hook that
// panics denies (the core reports `malformed`).
type ServerHook func(ctx map[string]any) ServerHookResult

// ServerHooks are the verifier hooks of ServerVerify; a nil hook reports its check as not-enforced.
type ServerHooks struct {
	Attestation, Threshold, Revocation, Zk ServerHook
}

// ServerAttestationGate is the opt-in attestation gate: Verifier takes the attestation slot in place of Hooks.Attestation, and unless
// NotRequired is set a not-enforced result fails closed.
type ServerAttestationGate struct {
	Verifier    ServerHook
	NotRequired bool
}

// ServerEnforce are the opt-in enforcement gates forwarded to the core (taint, freshness, attestation). Each gate that is set fails closed.
type ServerEnforce struct {
	Taint       *TaintGate
	Freshness   *FreshnessGate
	Attestation *ServerAttestationGate
}

// ServerVerifyInput is everything ServerVerify reads besides the PCActn.
type ServerVerifyInput struct {
	Opts    map[string]any
	Hooks   ServerHooks
	Enforce ServerEnforce
	// K1 is the caveat-language input (nil: none; a chain that carries a K1 caveat is then refused).
	K1 *K1Input
}

const (
	svPass   = "pass"
	svFail   = "fail"
	svNotEnf = "not-enforced"
	svUnsup  = "unsupported"
)

const svNoBudget = "budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge"
const svUnsupportedWhy = ": unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)"
const svPlanDefaultDeny = "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)"

// svThrow carries the message of a fault the reference raises as an exception (it becomes a fail-closed verdict).
type svThrow string

func svPanicMessage(r any) string {
	switch x := r.(type) {
	case svThrow:
		return string(x)
	case error:
		if x.Error() != "" {
			return x.Error()
		}
	case string:
		if x != "" {
			return x
		}
	}
	return "unknown"
}

func svGuarded(f func() map[string]any) (out map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			out = svFailClosed("verifier error (fail closed): "+svPanicMessage(r), nil)
		}
	}()
	return f()
}

func svFailClosed(reason string, checks map[string]string) map[string]any {
	c := map[string]string{}
	for k, v := range checks {
		c[k] = v
	}
	c["malformed"] = svFail
	return map[string]any{
		"allow":             false,
		"r":                 jsNumber(1),
		"requiredThreshold": map[string]any{"t": jsNumber(3), "proof": "strong", "optimisticAllowed": false},
		"checks":            c,
		"reasons":           []string{reason},
	}
}

func svWantsAssurance(o map[string]any) bool {
	_, has := o["requireAssurance"]
	return o["assurance"] == true || has
}

func svSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func svMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func svStrings(v any) []string {
	out := []string{}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, isS := x.(string); isS {
				out = append(out, s)
			} else {
				out = append(out, jsValueString(x))
			}
		}
	}
	return out
}

// svState is the verdict combinator: ordered checks and ordered reasons.
type svState struct {
	order   []string
	st      map[string]string
	reasons []string
}

func newSvState() *svState { return &svState{st: map[string]string{}} }

func (s *svState) set(n, v string) {
	if _, has := s.st[n]; !has {
		s.order = append(s.order, n)
	}
	s.st[n] = v
}
func (s *svState) fail(n, why string)       { s.set(n, svFail); s.reasons = append(s.reasons, n+": "+why) }
func (s *svState) failRaw(n, reason string) { s.set(n, svFail); s.reasons = append(s.reasons, reason) }
func (s *svState) push(m string)            { s.reasons = append(s.reasons, m) }
func (s *svState) hasFail() bool {
	for _, v := range s.st {
		if v == svFail {
			return true
		}
	}
	return false
}
func (s *svState) named() []NamedStatus {
	out := make([]NamedStatus, 0, len(s.order))
	for _, n := range s.order {
		out = append(out, NamedStatus{Name: n, Status: s.st[n]})
	}
	return out
}

// svHookInt is the threshold a hook reported as the verified core reads it: floor, NaN unreported, the infinities clamped to the
// safe-integer extremes.
func svHookInt(h *float64) (float64, bool) {
	if h == nil || math.IsNaN(*h) {
		return 0, false
	}
	if *h >= 9007199254740991 {
		return 9007199254740991, true
	}
	if *h <= -9007199254740991 {
		return -9007199254740991, true
	}
	return math.Floor(*h), true
}

// svCoreResult is the core verifier's outcome: every check with its status and the FIRST failure reason.
type svCoreResult struct {
	st     *svState
	reason string
}

func (c *svCoreResult) allow() bool { return !c.st.hasFail() }

func svDecode(s string) (any, string) {
	if ArtifactTooLarge(s) {
		return nil, ArtifactSizeReason
	}
	v, err := StrictParse(s)
	if err != nil {
		return nil, err.Error()
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, "decodePCActn: not an object"
	}
	return v, ""
}

// svRunHook runs a hook (nil: nothing enforced) and records its check; a panic propagates to the core's `malformed` handler.
func svRunHook(c *svCoreResult, name string, h ServerHook, hctx map[string]any, fail func(string, string)) {
	var res ServerHookResult
	if h != nil {
		res = h(hctx)
	}
	switch {
	case !res.Enforced:
		c.st.set(name, svNotEnf)
	case res.OK:
		c.st.set(name, svPass)
	default:
		why := "rejected"
		if res.HasReason {
			why = res.Reason
		}
		fail(name, why)
	}
}

// svCore is the core verifier with the reference's statuses and reason texts. The plan_root_authorized check is reported
// not-enforced here: the server decides it from its own plan context.
func svCore(p, grant, o map[string]any, nowObj any, nowNum float64, nowI int64, in ServerVerifyInput, v2 *IntentV2Context, freshAt *FreshAtPolicy) (c *svCoreResult) {
	c = &svCoreResult{st: newSvState()}
	fail := func(name, why string) {
		c.st.set(name, svFail)
		if c.reason == "" {
			c.reason = name + ": " + why
		}
	}
	defer func() {
		if r := recover(); r != nil {
			c.st.set("malformed", svFail)
			if c.reason == "" {
				c.reason = "malformed PCActn: " + svPanicMessage(r)
			}
		}
	}()
	set := c.st.set
	var allowed []string
	if l, ok := o["allowedSuites"].([]any); ok {
		allowed = svStrings(l)
	}
	set("wire", svPass)

	if ver, _ := safeInt(p["ver"]); ver == PCActnVer {
		set("version", svPass)
	} else {
		fail("version", fmt.Sprintf("unsupported ver %s (this verifier requires %d)", jsMemberString(p, "ver"), PCActnVer))
	}

	// audience: the signed aud must equal this verifier's audience; null is the explicit opt-out; absent fails closed
	aud, audKnown := o["audience"]
	audStr, audIsStr := aud.(string)
	hasAud := false
	if s, ok := p["aud"].(string); ok && s != "" {
		hasAud = true
	}
	switch {
	case !audKnown:
		if hasAud {
			fail("audience", "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)")
		} else {
			set("audience", svNotEnf)
		}
	case aud == nil:
		set("audience", svNotEnf)
	case audIsStr && p["aud"] == any(audStr):
		set("audience", svPass)
	default:
		fail("audience", "aud does not match this resource server / instance")
	}

	iat, _ := safeInt(p["iat"])
	exp, _ := safeInt(p["exp"])
	switch {
	case !jsIsSafeInteger(nowObj):
		fail("validity", "the verifier clock is not a safe integer epoch-ms")
	case exp <= iat:
		fail("validity", "exp must be greater than iat")
	case exp-iat > MaxLifetimeMs:
		fail("validity", fmt.Sprintf("lifetime exceeds %d ms", MaxLifetimeMs))
	case float64(iat) > nowNum+MaxSkewMs:
		fail("validity", "iat is in the future (clock skew)")
	case nowNum > float64(exp):
		fail("validity", "the PCActn has expired")
	default:
		set("validity", svPass)
	}

	// the capability chain: non-empty, rooted at the grant, then the walk
	chain, _ := p["cap_chain"].([]any)
	if len(chain) == 0 {
		fail("cap_chain", "empty chain")
	} else {
		rootCap, _ := chain[0].(map[string]any)
		rh, e1 := CapHash(rootCap)
		gh, e2 := CapHash(grant)
		switch {
		case e1 != nil || e2 != nil || rh != gh:
			fail("cap_chain", "chain root is not the grant")
		case len(chain) > MaxChainHops:
			fail("cap_chain", fmt.Sprintf("chain too long (max %d hops)", MaxChainHops))
		case caveatLimitExceeded(chain):
			fail("cap_chain", CaveatLimitReason)
		default:
			gi, hasI := grant["issuer"].(string)
			if why, ok := VerifyChainPolicy(chain, gi, hasI, allowed, nil, grant); ok {
				set("cap_chain", svPass)
			} else {
				fail("cap_chain", why)
			}
		}
	}

	// grant_ref_bound (normative): the signed grant_ref is the id of the ROOT capability of the presented chain
	{
		gr, _ := p["grant_ref"].(string)
		rootID := ""
		if len(chain) > 0 {
			if rc, ok := chain[0].(map[string]any); ok {
				rootID, _ = rc["id"].(string)
			}
		}
		if gr != "" && rootID != "" && gr == rootID {
			set("grant_ref_bound", svPass)
		} else {
			fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")
		}
	}

	// plan inclusion: the leaf is recomputed from the action itself
	plan, _ := p["plan"].(map[string]any)
	action, _ := p["action"].(map[string]any)
	cond, condOK := plan["conditions_digest"].(string)
	if !condOK {
		cond, _ = conditionsDigest(nil, nil)
	}
	planRootWire, _ := plan["root"].(string)
	proof, _ := plan["inclusion_proof"].(map[string]any)
	leaf, lerr := planLeaf(plan["node_id"], action, cond)
	if lerr == nil && VerifyInclusion(planRootWire, proof, leaf) {
		set("plan_inclusion", svPass)
	} else {
		fail("plan_inclusion", "action is not a node of the committed plan")
	}
	set("plan_root_authorized", svNotEnf)

	// the leaf-holder signature over the canonical body, dispatched by `alg`
	if len(chain) > 0 {
		leafCap, _ := chain[len(chain)-1].(map[string]any)
		holder, _ := leafCap["holder"].(string)
		alg, algPresent := p["alg"]
		var committed *string
		if hq, isStr := leafCap["holder_pq"].(string); isStr {
			committed = &hq
		}
		suiteErr := ""
		if !suiteAllowed(alg, algPresent, allowed) {
			suiteErr = "signature suite '" + jsMemberString(p, "alg") + "' is not allowed by this verifier's suite policy"
		} else {
			suiteErr = PqBindingError(alg, algPresent, p["pq_pk"], committed, "leaf")
		}
		if suiteErr != "" {
			fail("leaf_signature", suiteErr)
		} else {
			hq, hasHq := leafCap["holder_pq"]
			leafKey, bound := resolvePqVerifyKey(alg, algPresent, p["pq_pk"], pqAuthority{holderPq: hq, hasHolderPq: hasHq})
			msg, merr := ThresholdMessage(p)
			_, sigIsStr := p["sig"].(string)
			if bound && sigIsStr && merr == nil && verifyLeafSuite(alg, algPresent, holder, leafKey, msg, p["sig"], p["pq_sig"]) {
				set("leaf_signature", svPass)
			} else {
				fail("leaf_signature", "signature does not verify under the leaf holder key / suite")
			}
		}
	} else {
		fail("leaf_signature", "signature does not verify under the leaf holder key / suite")
	}

	if cn, ok := safeInt(p["counter"]); ok && cn >= 0 {
		set("counter_format", svPass)
	} else {
		fail("counter_format", "missing or not a non-negative safe integer")
	}

	// Intent Layer M2: reported iff the PCActn carries `intent` or the policy is active
	if evaluated, why := decideIntent(p, grant, IntentPolicyFromJSON(o["intent"])); evaluated {
		if why == "" {
			set("intent", svPass)
		} else {
			fail("intent", why)
		}
	}
	// Intent Layer v2
	for _, cc := range decideIntentV2(p, grant, v2, nowNum).checks {
		if cc.ok {
			set(cc.name, svPass)
		} else {
			fail(cc.name, cc.why)
		}
	}
	// consistency token
	if fa := decideFreshAt(p, freshAt, nowI); fa.status != "none" {
		if fa.status == "pass" {
			set("fresh_at", svPass)
		} else {
			fail("fresh_at", fa.reason)
		}
	}

	// M1 taint gate
	if g := in.Enforce.Taint; g != nil {
		if why := taintGateReason(g, p["provenance"]); why != "" {
			fail("taint_gate", why)
		} else {
			set("taint_gate", svPass)
		}
	} else {
		set("taint_gate", svNotEnf)
	}

	// M3 freshness gate: its check is named `freshness`
	if g := in.Enforce.Freshness; g != nil {
		fr, _ := p["freshness"].(map[string]any)
		if why := freshnessGateReason(g, fr, nowI); why != "" {
			fail("freshness", why)
		} else {
			set("freshness", svPass)
		}
	}

	hctx := map[string]any{"pcactn": p, "grant": grant, "nowEpoch": nowObj}
	// M5 attestation: the gate's verifier takes the slot; with the gate on, a not-enforced result fails closed unless not required
	att := in.Hooks.Attestation
	gate := in.Enforce.Attestation
	if gate != nil && gate.Verifier != nil {
		att = gate.Verifier
	}
	svRunHook(c, "attestation", att, hctx, fail)
	if gate != nil && !gate.NotRequired && c.st.st["attestation"] == svNotEnf {
		fail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)")
	}
	svRunHook(c, "threshold", in.Hooks.Threshold, hctx, fail)
	svRunHook(c, "revocation", in.Hooks.Revocation, hctx, fail)

	// a carried zk proof that no zk verifier enforced is never silently accepted
	if _, has := p["zk_compliance"]; has {
		svRunHook(c, "zk_compliance", in.Hooks.Zk, hctx, fail)
		if c.st.st["zk_compliance"] == svNotEnf {
			fail("zk_compliance", zkNoVerifierReason)
		}
	}
	if _, has := p["bond_ref"]; has {
		set("bond", svNotEnf)
	}
	return c
}

func serverVerifyRun(pcactn any, o map[string]any, in ServerVerifyInput) map[string]any {
	p0 := pcactn
	if s, isStr := pcactn.(string); isStr {
		v, why := svDecode(s)
		if why != "" {
			return svFailClosed("undecodable PCActn: "+why, nil)
		}
		p0 = v
	}
	switch p0.(type) {
	case map[string]any, []any:
	default:
		return svFailClosed("PCActn is not an object", nil)
	}

	nowObj := o["now"]
	if nowObj == nil {
		nowObj = jsNumber(float64(time.Now().UnixMilli()))
	}
	nowNum, nowIsNum := jsNum(nowObj)
	if !nowIsNum {
		nowNum = math.NaN()
	}
	if math.IsNaN(nowNum) || math.IsInf(nowNum, 0) {
		return svFailClosed("the verifier clock is not a finite time", nil)
	}
	nowI := int64(math.MaxInt64)
	if jsIsSafeInteger(nowObj) {
		nowI = int64(nowNum)
	}

	grantO := o["grant"]
	grant := svMap(grantO)
	op := svMap(o["operation"])
	ctxIn := svMap(o["context"])
	ctx := map[string]any{}
	for k, v := range ctxIn {
		ctx[k] = v
	}
	// the operation's params are the action params (predicates, caveats, digest); a context that disagrees is flagged below
	ctxParams, ctxHasParams := ctxIn["params"]
	if opParams, has := op["params"]; has {
		ctx["params"] = opParams
	}

	// F-1: remember the threshold the hook says it enforced, so it can be compared with the SERVER-derived t below
	var hookT *float64
	if userThreshold := in.Hooks.Threshold; userThreshold != nil {
		in.Hooks.Threshold = func(c map[string]any) ServerHookResult {
			r := userThreshold(c)
			if r.Enforced {
				hookT = r.T
			}
			return r
		}
	}

	// Rules 20 and 21 read the signed envelope of the stored grant: when it carries any, the v2 pipeline needs the plaintext params
	// and the host env even if the host configured no v2 context.
	needsModel := grant != nil && needsModelRules(grant)
	var v2 *IntentV2Context
	if jsTruthy(o["intentV2"]) || needsModel {
		raw := map[string]any{}
		for k, x := range svMap(o["intentV2"]) {
			raw[k] = x
		}
		if raw["params"] == nil {
			if pv, has := ctx["params"]; has {
				raw["params"] = pv
			} else {
				delete(raw, "params")
			}
		}
		if raw["env"] == nil {
			if ev, has := ctx["env"]; has {
				raw["env"] = ev
			} else {
				delete(raw, "env")
			}
		}
		v2 = IntentV2ContextFromJSON(raw)
	}
	var freshAt *FreshAtPolicy
	if o["freshAt"] != nil {
		freshAt = FreshAtPolicyFromJSON(o["freshAt"])
	}

	// a wire-form failure is terminal: nothing else is evaluated on a malformed object
	if why := ValidateWireV2(p0); why != "" {
		return svFailClosed("wire: "+why, map[string]string{"wire": svFail})
	}
	p := p0.(map[string]any)
	coreGrant := grant
	if coreGrant == nil {
		coreGrant = map[string]any{}
	}
	core := svCore(p, coreGrant, o, nowObj, nowNum, nowI, in, v2, freshAt)
	if grant == nil {
		// the reference reads the stored grant's members and throws on anything that is not one
		if grantO == nil {
			panic(svThrow("Cannot read properties of null (reading 'id')"))
		}
		panic(svThrow("Cannot read properties of undefined (reading 'length')"))
	}

	unsupported := []string{}
	vs := newSvState()
	for _, n := range core.st.order {
		vs.set(n, core.st.st[n])
	}
	if _, has := p["bond_ref"]; has && vs.st["bond"] == svNotEnf {
		unsupported = append(unsupported, "bond")
	}
	coreAllow := core.allow()
	if !coreAllow && core.reason != "" {
		vs.reasons = append(vs.reasons, core.reason)
	}
	var v2d *v2Decision
	if _, has := p["intent_session"]; has || needsModel {
		d := decideIntentV2(p, grant, v2, nowNum)
		v2d = &d
		// the core keeps only its FIRST failure reason; the v2 checks are the escalate-class ones, so every failed one is reported
		results := make([]V2CheckResult, 0, len(d.checks))
		for _, c := range d.checks {
			results = append(results, V2CheckResult{Name: c.name, OK: c.ok, Reason: c.why, HasReason: !c.ok})
		}
		vs.reasons = FoldV2Reasons(vs.reasons, results)
	}

	// server-side PQ pin for a non-Ed25519 grant (fail closed: no pin for the issuer, or a different key, denies)
	pqPins := svMap(o["pqPins"])
	if pqPins != nil {
		alg := any("ed25519")
		if av, has := grant["alg"]; has && av != nil {
			alg = av
		}
		issuer, issuerIsStr := grant["issuer"].(string)
		pinV, hasPin := pqPins[issuer]
		hasPin = hasPin && issuerIsStr
		pin, pinIsStr := pinV.(string)
		pk, pkIsStr := grant["pq_pk"].(string)
		switch {
		case alg == any("ed25519"):
			if hasPin {
				vs.fail("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused")
			} else {
				vs.set("pq_pin", svPass)
			}
		case pinIsStr && pkIsStr && pin == pk:
			vs.set("pq_pin", svPass)
		case !hasPin:
			vs.fail("pq_pin", "no server-side PQ pin for the grant issuer (suite "+jsValueString(alg)+")")
		default:
			vs.fail("pq_pin", "the grant pq_pk does not match the server-side pin")
		}
	}

	// grant_ref binds the object to this grant
	if gr, isStr := p["grant_ref"].(string); isStr && any(gr) == grant["id"] {
		vs.set("grant_ref", svPass)
	} else {
		vs.fail("grant_ref", "does not reference the supplied grant")
	}

	action := svMap(p["action"])
	if action == nil {
		action = map[string]any{}
	}
	signedDigest := action["params_digest"]
	hashOf := func(v any) string {
		h, err := HashCanonical(v)
		if err != nil {
			panic(svThrow(err.Error()))
		}
		return h
	}

	// the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
	if op != nil {
		ov, ovOK := op["verb"].(string)
		orr, orOK := op["resource"].(string)
		signed := jsMemberString(action, "verb") + " on " + jsMemberString(action, "resource")
		_, opHasParams := op["params"]
		switch {
		case !ovOK || !orOK:
			vs.fail("operation", "the server operation has no verb / resource (fail closed)")
		case action["verb"] != any(ov) || action["resource"] != any(orr):
			vs.fail("operation", "the proof is for "+signed+", but this operation is "+ov+" on "+orr)
		case opHasParams && any(hashOf(op["params"])) != signedDigest:
			vs.fail("operation", "the proof's params_digest does not match the params of this "+ov+" operation")
		case opHasParams && ctxHasParams && hashOf(ctxParams) != hashOf(op["params"]):
			vs.fail("operation", "context.params differ from the operation params")
		default:
			vs.set("operation", svPass)
		}
	}

	// params plaintext must open the committed digest
	if pv, has := ctx["params"]; has {
		if any(hashOf(pv)) == signedDigest {
			vs.set("params_digest", svPass)
		} else {
			vs.fail("params_digest", "supplied params do not hash to action.params_digest")
		}
	} else {
		vs.set("params_digest", svNotEnf)
	}

	// the verifier's own copy of the plan must be the committed one
	planO := ctx["plan"]
	planSupplied := jsTruthy(planO)
	planWire := svMap(p["plan"])
	if planWire == nil {
		planWire = map[string]any{}
	}
	var planNodes []map[string]any
	rootMatches := false
	if planSupplied {
		list, isList := planO.([]any)
		if !isList {
			panic(svThrow("ctx.plan.map is not a function"))
		}
		for _, n := range list {
			if n == nil {
				panic(svThrow("Cannot read properties of null (reading 'id')"))
			}
			nm := svMap(n)
			if nm == nil {
				nm = map[string]any{}
			}
			planNodes = append(planNodes, nm)
		}
		known, kok := planRoot(planNodes)
		rootMatches = kok && any(known) == planWire["root"]
	}
	skip := o["insecureSkipPlanRootCheck"] == true
	authO := ctx["planAuthorized"]
	switch {
	case !planSupplied:
		if skip {
			vs.set("plan_root_authorized", svNotEnf)
		} else {
			vs.fail("plan_root_authorized", svPlanDefaultDeny)
		}
	case !rootMatches:
		vs.fail("plan_root_authorized", "known plan does not match plan.root")
	case authO == true:
		vs.set("plan_root_authorized", svPass)
	case authO == false:
		vs.fail("plan_root_authorized", "the plan root has not been authorized by the principal")
	case skip:
		vs.set("plan_root_authorized", svNotEnf)
	default:
		vs.fail("plan_root_authorized", svPlanDefaultDeny)
	}

	// the guardian-signed revocation epoch (reported as `freshness`)
	if jsTruthy(ctx["revocationEpoch"]) {
		re := svMap(ctx["revocationEpoch"])
		eo := EpochCheckOptions{GuardianPublic: "\x00not-a-guardian", Now: nowNum}
		if g, isStr := re["guardianPublic"].(string); isStr {
			eo.GuardianPublic = g
		}
		if gid, isStr := grant["id"].(string); isStr {
			eo.GrantRef = &gid
		}
		if f, ok := jsNum(re["lastAcceptedEpoch"]); ok {
			eo.LastAcceptedEpoch = &f
		}
		if fr, isMap := p["freshness"].(map[string]any); isMap {
			if f, ok := jsNum(fr["epoch"]); ok {
				eo.PCActnEpoch = &f
			}
		}
		if re["maxAgeMs"] != nil {
			if f, ok := jsNum(re["maxAgeMs"]); ok {
				eo.MaxAgeMs = &f
			}
		}
		r := CheckRevocationEpoch(re["epoch"], eo)
		// an `enforce.freshness` failure from the core stands (a passing epoch never overwrites it)
		if r.OK {
			if vs.st["freshness"] != svFail {
				vs.set("freshness", svPass)
			}
		} else {
			why := r.Reason
			if why == "" {
				why = "revocation epoch rejected"
			}
			vs.fail("freshness", why)
		}
	} else if _, has := vs.st["freshness"]; !has {
		vs.set("freshness", svNotEnf)
	}

	// the dead-man liveness beacon
	if jsTruthy(ctx["beacon"]) {
		bc := svMap(ctx["beacon"])
		chk := map[string]any{"issuers": bc["issuers"], "now": nowObj, "scope": grant["id"]}
		if inst, has := bc["instance"]; has {
			chk["instance"] = inst
		}
		if jsTruthy(bc["pqPins"]) {
			chk["pqPins"] = bc["pqPins"]
		}
		bm := svMap(bc["beacon"])
		r := VerifyLivenessBeaconValue(bc["beacon"], chk)
		replayed := false
		if r.OK && bc["lastAcceptedSeq"] != nil {
			seq, sOK := jsNum(bm["seq"])
			last, lOK := jsNum(bc["lastAcceptedSeq"])
			replayed = sOK && lOK && seq < last
		}
		refBinds := false
		if r.OK && !replayed && bm != nil {
			fr, _ := p["freshness"].(map[string]any)
			ref, refIsStr := fr["beacon_ref"].(string)
			br, berr := BeaconRef(bm)
			refBinds = refIsStr && berr == nil && ref == br
		}
		switch {
		case !r.OK:
			why := r.Reason
			if why == "" {
				why = "beacon rejected"
			}
			vs.fail("beacon", why)
		case replayed:
			vs.fail("beacon", "beacon seq "+jsValueString(bm["seq"])+" is older than the last accepted "+jsValueString(bc["lastAcceptedSeq"])+" (replay)")
		case !refBinds:
			vs.fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon")
		default:
			vs.set("beacon", svPass)
		}
	} else {
		vs.set("beacon", svNotEnf)
	}

	// require-when-bound: a grant whose agent_binding constrains the model / measurement / operator / weights REQUIRES a bound attestation
	grantEnv := ReadEnvelope(grant)
	if grantEnv != nil && requiresAttestation(grantEnv["agent_binding"]) && vs.st["attestation"] != svPass {
		vs.fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED")
	}

	chain, _ := p["cap_chain"].([]any)
	depth := len(chain) - 1
	if depth < 0 {
		depth = 0
	}
	// fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0)
	_, budgetGiven := ctx["budget"]
	budgetCtx := ctx["budget"]
	budgetIn := budgetCtx
	if budgetCtx == nil {
		budgetIn = map[string]any{"B": jsNumber(0), "tau": nowObj, "asOf": nowObj}
	}
	if jsTruthy(budgetCtx) {
		vs.set("budget", svPass)
	} else {
		vs.set("budget", svNotEnf)
	}
	if !budgetGiven {
		vs.push(svNoBudget)
	}

	// taint: ONLY a verifier-supplied value counts (the agent's own provenance.taint_level can only lower risk)
	risk := map[string]any{}
	for k, x := range svMap(ctx["risk"]) {
		risk[k] = x
	}
	if req, isList := o["requireRiskInputs"].([]any); isList && len(req) > 0 {
		var missing []string
		_, planKey := ctx["plan"]
		for _, k := range svStrings(req) {
			f, ok := jsNum(risk[k])
			if !(ok && riskFinite(f)) && !(k == "semanticDistance" && planKey) {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			vs.fail("risk_inputs", "required risk input(s) not supplied by the server: "+strings.Join(missing, ", "))
		} else {
			vs.set("risk_inputs", svPass)
		}
	}

	// reversibility: the verifier's authoritative class wins; the agent may only be STRICTER
	declared, hasDeclared := action["reversibility_class"]
	reversibility := declared
	if sc := ctx["reversibilityClass"]; sc != nil {
		dr, sr := reversibilityRank(declared), reversibilityRank(sc)
		if dr < sr {
			shown := "undefined"
			if hasDeclared {
				shown = jsValueString(declared)
			}
			vs.fail("reversibility", "declared class '"+shown+"' is less restrictive than the authoritative '"+jsValueString(sc)+"'")
		} else {
			vs.set("reversibility", svPass)
		}
		if dr > sr {
			reversibility = declared
		} else {
			reversibility = sc
		}
	}
	inner := map[string]any{"verb": action["verb"], "resource": action["resource"]}
	if pv, has := ctx["params"]; has {
		inner["params"] = pv
	}
	if reversibility != nil {
		inner["reversibility_class"] = reversibility
	}
	actionCtx := map[string]any{"action": inner}
	if ctx["subject"] != nil {
		actionCtx["subject"] = ctx["subject"]
	}
	predEnv := ctx["env"]
	if _, has := p["intent_session"]; has {
		predEnv = v2Env(p, grant, v2, nowI, ctx["env"])
	}
	if predEnv != nil {
		actionCtx["env"] = predEnv
	}
	// signed `tool_binding` (D): binds the semantic firewall (tool_schema caveats) to the tool the agent signed
	if tb, isStr := p["tool_binding"].(string); isStr {
		actionCtx["toolBinding"] = tb
	}

	din := map[string]any{"grant": grant, "trustedRoot": grant, "action": actionCtx, "risk": risk, "budget": budgetIn, "now": nowObj}
	if pqPins != nil {
		din["pqPins"] = pqPins
	}
	if _, isList := planO.([]any); isList {
		din["plan"] = planO
	}
	if nid, has := planWire["node_id"]; has {
		din["nodeId"] = nid
	}
	cc := map[string]any{"delegationDepth": jsNumber(float64(depth))}
	if ctx["recentActionTimes"] != nil {
		cc["recentActionTimes"] = ctx["recentActionTimes"]
	}
	din["caveatContext"] = cc
	var k1Decide *K1Input
	if in.K1 != nil {
		kc := *in.K1
		kc.HasNarrow, kc.Narrow = false, nil
		kc.ActionDigest, _ = DischargeActionDigest(p)
		k1Decide = &kc
	}
	if _, isNum := jsNum(p["caution"]); isNum {
		din["rFloor"] = p["caution"]
	}
	d := DecideNative(din, k1Decide)
	release := d["releaseGuardianShare"] == true

	// caveats added by delegation hops (beyond the root's) are conjunctive too
	var k1Bound []any
	if len(chain) > 0 {
		gcs, gOK := grant["caveats"].([]any)
		if !gOK {
			panic(svThrow("Cannot read properties of undefined (reading 'length')"))
		}
		leafM := svMap(chain[len(chain)-1])
		lcs, lOK := leafM["caveats"].([]any)
		if !lOK {
			panic(svThrow("Cannot read properties of undefined (reading 'slice')"))
		}
		extra := []any{}
		if len(lcs) > len(gcs) {
			extra = append(extra, lcs[len(gcs):]...)
		}
		// K1 caveat types (and the caveats of a verified narrow block) are evaluated over the whole chain
		useK1 := in.K1 != nil && in.K1.HasNarrow
		for _, c := range lcs {
			if IsK1Caveat(c) {
				useK1 = true
			}
		}
		var k1r *K1Result
		if useK1 {
			var ki *K1Input
			if in.K1 != nil {
				kc := *in.K1
				kc.ActionDigest, _ = DischargeActionDigest(p)
				ki = &kc
			}
			r := EvaluateK1(grant, chain, ki, K1Context{Now: nowNum, Action: inner})
			k1r = &r
			k1Bound = []any{}
			for _, b := range r.Bound {
				k1Bound = append(k1Bound, map[string]any{"caveat": b.Caveat, "hop": jsNumber(float64(b.Hop)), "capHash": b.CapHash})
			}
		}
		var plain []any
		if k1r != nil {
			plain = k1r.Plain
		}
		cctx := map[string]any{"now": nowObj, "action": inner, "delegation_depth": depth}
		if risk["blastRadius"] != nil {
			cctx["blast_radius"] = risk["blastRadius"]
		}
		// the SAME class decide() used for the envelope caveats: the action's own, else the signed plan node's
		revClass := inner["reversibility_class"]
		if nid, isStr := planWire["node_id"].(string); revClass == nil && isStr && planNodes != nil {
			for _, n := range planNodes {
				if n != nil && n["id"] == any(nid) {
					revClass = n["reversibility_class"]
					break
				}
			}
		}
		if revClass != nil {
			cctx["reversibility_class"] = revClass
		}
		if ctx["recentActionTimes"] != nil {
			cctx["recent_action_times"] = ctx["recentActionTimes"]
		}
		tc := &ToolCall{Tool: "", Args: map[string]any{}}
		if verb, ok := inner["verb"].(string); ok {
			tc.Tool = verb
		}
		if params, ok := inner["params"].(map[string]any); ok {
			tc.Args = params
		}
		if tb, ok := actionCtx["toolBinding"].(string); ok {
			tc.ToolSignatureDigest = &tb
		}
		cvOK, failed := evaluateAgentCaveats(k1StockList(any(extra), plain), cctx, actionCtx, tc, &regexBudget{})
		if cvOK && (k1r == nil || k1r.OK) {
			vs.set("delegated_caveats", svPass)
		} else {
			all := append([]string{}, failed...)
			why := ""
			if k1r != nil {
				all = append(all, k1r.Failed...)
				if !k1r.OK {
					why = " (" + strings.Join(k1r.Reasons, "; ") + ")"
				}
			}
			vs.fail("delegated_caveats", "delegation caveat(s) not satisfied: "+strings.Join(all, ", ")+why)
		}
	}

	// policy: the check mirrors the Policy VM's release decision; its reasons (also the informational ones when released) are kept in order
	if release {
		vs.set("policy", svPass)
	} else {
		vs.set("policy", svFail)
	}
	if dr, isList := d["reasons"].([]any); isList {
		for _, x := range dr {
			vs.push("policy: " + jsValueString(x))
		}
	}

	// threshold: t > 1 needs a proof only an enforced threshold hook gives, and the hook must report at least the SERVER-derived t (F-1)
	rt := svMap(d["requiredThreshold"])
	tF, _ := jsNum(rt["t"])
	tReq := int(tF)
	proofKind, _ := rt["proof"].(string)
	if tReq > 1 && release {
		switch vs.st["threshold"] {
		case svPass:
			if hi, ok := svHookInt(hookT); !(ok && hi >= float64(tReq)) {
				reported := "unreported"
				if hookT != nil {
					reported = jsNumberString(*hookT)
				}
				vs.failRaw("threshold", fmt.Sprintf("threshold: threshold hook enforced t=%s but the server requires t=%d (below the server-derived threshold; derive t from server-held data)", reported, tReq))
			}
		case svFail:
			vs.failRaw("threshold", fmt.Sprintf("threshold: t=%d required and the threshold proof was rejected", tReq))
		default:
			vs.failRaw("threshold", fmt.Sprintf("threshold: t=%d (%s) required but no threshold verifier is enforced", tReq, proofKind))
		}
	}

	required := ServerDefaultRequiredChecks()
	if rq, has := o["require"]; has && rq != nil {
		l, isList := rq.([]any)
		if !isList {
			panic(svThrow("required.map is not a function"))
		}
		required = svStrings(l)
	}
	wantAssurance := svWantsAssurance(o)
	src := AssuranceSources{PCActn: p, ThresholdT: hookT}
	if in.Hooks.Attestation != nil {
		src.Hooks.Attestation = in.Hooks.Attestation
	}
	if in.Hooks.Zk != nil {
		src.Hooks.Zk = in.Hooks.Zk
	}
	if in.Hooks.Threshold != nil {
		src.Hooks.Threshold = in.Hooks.Threshold
	}
	if in.Hooks.Revocation != nil {
		src.Hooks.Revocation = in.Hooks.Revocation
	}
	if g := in.Enforce.Attestation; g != nil && g.Verifier != nil {
		src.AttestationHook = g.Verifier
	}
	if v2d != nil && v2d.legacy {
		src.Degraded = map[string]string{"tighten": LegacyPolarityDegraded}
	}
	if jsTruthy(o["requireAssurance"]) {
		src.Checks = vs.named()
		if unmet := svUnmetAssurance(BuildAssuranceReport(src), o["requireAssurance"]); unmet == "" {
			vs.set("assurance", svPass)
		} else {
			vs.failRaw("assurance", unmet)
		}
	}

	allow := !vs.hasFail() && release && coreAllow
	checks := map[string]string{}
	for k, x := range vs.st {
		checks[k] = x
	}
	for _, n := range unsupported {
		if checks[n] == svNotEnf {
			checks[n] = svUnsup
		}
	}
	finishAssurance := func(final map[string]string) map[string]any {
		s := src
		s.Checks = nil
		for _, n := range vs.order {
			s.Checks = append(s.Checks, NamedStatus{Name: n, Status: checks[n]})
		}
		var refreshed []NamedStatus
		for _, n := range svSortedKeys(final) {
			refreshed = append(refreshed, NamedStatus{Name: n, Status: final[n]})
		}
		return RefreshAssurance(BuildAssuranceReport(s), refreshed).ToMap()
	}

	// a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed
	allowUnsupported := svStrings(o["allowUnsupported"])
	var refused []string
	for _, n := range unsupported {
		listed := false
		for _, a := range allowUnsupported {
			listed = listed || a == n
		}
		if !listed {
			refused = append(refused, n)
		}
	}
	if len(refused) > 0 {
		rs := append([]string{}, vs.reasons...)
		for _, n := range refused {
			rs = append(rs, n+svUnsupportedWhy)
		}
		ev := EnforceRequired(false, checks, rs, required)
		out := map[string]any{"allow": ev.Allow, "r": d["r"], "requiredThreshold": rt, "checks": ev.Checks, "reasons": ev.Reasons}
		if wantAssurance {
			out["assurance"] = finishAssurance(ev.Checks)
		}
		return out
	}
	ev := EnforceRequired(allow, checks, vs.reasons, required)
	out := map[string]any{"allow": ev.Allow, "r": d["r"], "requiredThreshold": rt, "checks": ev.Checks, "reasons": ev.Reasons}
	if allow && jsTruthy(budgetCtx) {
		out["budget"] = d["budget"]
	}
	if svHasMaxUses(k1Bound) {
		out["k1Bound"] = k1Bound
	}
	// an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
	if !ev.Allow && jsTruthy(budgetCtx) {
		anyChecks := map[string]any{}
		for k, x := range ev.Checks {
			anyChecks[k] = x
		}
		anyReasons := make([]any, len(ev.Reasons))
		for i, r := range ev.Reasons {
			anyReasons[i] = r
		}
		if DecisionOf(map[string]any{"allow": false, "checks": anyChecks, "reasons": anyReasons}) == "escalate" {
			out["budget"] = d["budget"]
		}
	}
	if !ev.Allow && len(ev.Reasons) == 0 {
		out["reasons"] = []string{"denied"}
	}
	if wantAssurance {
		out["assurance"] = finishAssurance(ev.Checks)
	}
	return out
}

func svHasMaxUses(bound []any) bool {
	for _, b := range bound {
		if cv, ok := svMap(b)["caveat"].(map[string]any); ok && cv["type"] == CaveatMaxUses {
			return true
		}
	}
	return false
}

// svUnmetAssurance is the reference's unmetAssurance over a requirement given as JSON: it is read through
// AssuranceRequirement.UnmarshalJSON and checked by UnmetAssurance, so an unknown key or value refuses (fail closed) here exactly as
// in the single function.
func svUnmetAssurance(report AssuranceReport, reqO any) string {
	m := svMap(reqO)
	if m == nil {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "assurance: unknown assurance requirement(s): invalid (fail closed)"
	}
	var r AssuranceRequirement
	if err := json.Unmarshal(b, &r); err != nil {
		return "assurance: unknown assurance requirement(s): invalid (fail closed)"
	}
	return UnmetAssurance(report, r)
}
