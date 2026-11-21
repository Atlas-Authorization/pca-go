package pca

// PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, Access Evaluations boxcar, the
// COAZ MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over {"path", "body"} maps and the three
// Search APIs (subject / resource / action).
//
// Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any raised error is
// decision false. The risk decision (Decide / DeriveDecideInput) defaults to the native Policy VM and may be replaced through the config.
// AdmitsConcrete defaults to PolicyVMAdmitsConcrete (config may override).

import (
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	AuthzenApprovalKey   = "pca_approval"
	AuthzenActionKey     = "pca_action"
	AuthzenProvenanceKey = "pca_provenance"
	// AuthzenDefaultMaxEvaluations is the boxcar size limit when the config sets none.
	AuthzenDefaultMaxEvaluations = 100
	AuthzenEvaluationPath        = "/access/v1/evaluation"
	AuthzenEvaluationsPath       = "/access/v1/evaluations"
	AuthzenCoazToolPath          = "/access/v1/mcp/tool/evaluation"
	AuthzenSearchSubjectPath     = "/access/v1/search/subject"
	AuthzenSearchResourcePath    = "/access/v1/search/resource"
	AuthzenSearchActionPath      = "/access/v1/search/action"
	AuthzenMaxSearchLimit        = 1000
)

// AuthzenDecision is the injected risk decision of a verified PCActn.
type AuthzenDecision struct {
	ReleaseGuardianShare bool
	Admit                bool
	R                    any
	RequiredThreshold    map[string]any // {t, proof, optimisticAllowed}
	Reasons              []any
}

// AuthzenEnforce are the optional verifier gates of a resolved context.
type AuthzenEnforce struct {
	Freshness   *FreshnessGate
	Taint       *TaintGate
	Attestation any // not supported: a non-nil value fails closed
}

// AuthzenContext is what Resolve returns for a request: the grant, its policy and the optional chain / plan / risk / budget.
type AuthzenContext struct {
	Grant    any
	Chain    any
	Policy   any
	Plan     any
	Risk     any
	Budget   any
	Enforce  *AuthzenEnforce
	ToAction func(req map[string]any) map[string]any
}

// AuthzenAuthorizerResult is the verdict of the replay / revocation authorizer.
type AuthzenAuthorizerResult struct {
	Allow  bool
	Reason any
}

// AuthzenConfig configures the PDP. Resolve is required.
type AuthzenConfig struct {
	Resolve func(req map[string]any) (*AuthzenContext, error)
	// Audience: nil = absent (the verifier gets no audience and refuses); AcceptAnyAudience = the explicit opt-out (the PCActn's own
	// `aud` is taken); otherwise an exact audience.
	Audience                  *string
	AcceptAnyAudience         bool
	AuthorizedPlanRoots       []string
	InsecureSkipPlanRootCheck bool
	Now                       func() int64
	ToolCapability            func(name string) (string, error)
	RequireProof              *bool // nil = true
	Authorizer                func(in map[string]any) (AuthzenAuthorizerResult, error)
	RequireAuthorizer         *bool // nil = true
	MaxEvaluations            *int
	Decide                    func(input any) (*AuthzenDecision, error)
	DeriveDecideInput         func(pcactn map[string]any, dctx map[string]any) (any, error)
	AdmitsConcrete            func(policy any, action any) (bool, error)
}

type azUndefT struct{}

var azUndef any = azUndefT{}

func azIsUndef(v any) bool { _, ok := v.(azUndefT); return ok }

func azIsNum(x any) bool { _, ok := anlFin(x); return ok }

// azJS is a JavaScript template-literal rendering of a JSON value.
func azJS(v any) string {
	if azIsUndef(v) || anlIsUndef(v) {
		return "undefined"
	}
	return jsValueString(v)
}

func azProp(x any, k string) any {
	if x == nil || azIsUndef(x) {
		anlFail("Cannot read properties of %s (reading '%s')", map[bool]string{true: "null", false: "undefined"}[x == nil], k)
	}
	if m, ok := x.(map[string]any); ok {
		if v, has := m[k]; has {
			return v
		}
	}
	return azUndef
}

func azTruthy(v any) bool { return !azIsUndef(v) && anlTruthy(v) }

func azStr(v any) (string, bool) { s, ok := v.(string); return s, ok }

func azErrText(r any) string {
	var s string
	switch t := r.(type) {
	case error:
		s = t.Error()
	case string:
		s = t
	default:
		s = fmt.Sprint(t)
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// ---- guards -----------------------------------------------------------------------------------------------------------------

func azTypeID(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	_, a := m["type"].(string)
	_, b := m["id"].(string)
	return a && b
}

func IsAuthzenSubject(x any) bool  { return azTypeID(x) }
func IsAuthzenResource(x any) bool { return azTypeID(x) }

func IsAuthzenAction(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m["name"].(string)
	return ok
}

func IsAccessEvaluationRequest(x any) bool {
	m, ok := x.(map[string]any)
	if !ok || !IsAuthzenSubject(m["subject"]) || !IsAuthzenAction(m["action"]) || !IsAuthzenResource(m["resource"]) {
		return false
	}
	if c, has := m["context"]; has {
		if _, ok := c.(map[string]any); !ok {
			return false
		}
	}
	return true
}

func IsAccessEvaluationsRequest(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m["evaluations"].([]any)
	return ok
}

func IsCoazToolAuthorizationRequest(x any) bool {
	m, ok := x.(map[string]any)
	if !ok || !IsAuthzenSubject(m["subject"]) {
		return false
	}
	tool, ok := m["tool"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = tool["name"].(string)
	return ok
}

func azIsRequiredThreshold(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	t, ok := anlFin(m["t"])
	if !ok || (t != 1 && t != 2 && t != 3) {
		return false
	}
	_, p := m["proof"].(string)
	_, o := m["optimisticAllowed"].(bool)
	return p && o
}

// ---- AARP -------------------------------------------------------------------------------------------------------------------

func azApprovalOf(resp any) map[string]any {
	ctx := azProp(resp, "context")
	if azIsUndef(ctx) {
		return nil
	}
	p, ok := azProp(ctx, AuthzenApprovalKey).(map[string]any)
	if !ok || p["approval_required"] != true {
		return nil
	}
	id, ok := p["auth_req_id"].(string)
	if !ok {
		return nil
	}
	tier := 2
	if f, ok := anlFin(p["tier"]); ok && f == 3 {
		tier = 3
	}
	var rt any = p["required_threshold"]
	if !azIsRequiredThreshold(rt) {
		proof := "standard"
		if tier == 3 {
			proof = "strong"
		}
		rt = map[string]any{"t": tier, "proof": proof, "optimisticAllowed": false}
	}
	gc := ""
	if s, ok := p["goal_commit"].(string); ok {
		gc = s
	}
	var risk any = 1
	if azIsNum(p["risk"]) {
		risk = p["risk"]
	}
	reason := "approval required"
	if s, ok := p["reason"].(string); ok {
		reason = s
	}
	var at any = 0
	if azIsNum(p["requested_at"]) {
		at = p["requested_at"]
	}
	return map[string]any{
		"approval_required":  true,
		"auth_req_id":        id,
		"tier":               tier,
		"required_threshold": rt,
		"goal_commit":        gc,
		"risk":               risk,
		"reason":             reason,
		"requested_at":       at,
	}
}

// ApprovalOf is the AARP pending-approval reference of a decision (nil when none). An error is the reference's throw on a
// null / undefined decision.
func ApprovalOf(resp any) (res map[string]any, err error) {
	r, err := anlTry(func() any {
		m := azApprovalOf(resp)
		if m == nil {
			return nil
		}
		return m
	})
	if err != nil || r == nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// IsApprovalRequired reports whether the decision carries an AARP pending approval.
func IsApprovalRequired(resp any) (bool, error) {
	m, err := ApprovalOf(resp)
	return m != nil, err
}

// ---- mapping ----------------------------------------------------------------------------------------------------------------

func azDeny(reason string, id string, status int) map[string]any {
	context := map[string]any{"reason_admin": map[string]any{"denied": true, "reason": reason}, "reason_user": map[string]any{"message": reason}}
	if status != 0 {
		context["error"] = map[string]any{"status": status, "message": reason}
	}
	if id != "" {
		context["id"] = id
	}
	return map[string]any{"decision": false, "context": context}
}

func azPermit(reason string) map[string]any {
	return map[string]any{"decision": true, "context": map[string]any{"reason_admin": map[string]any{"reason": reason}}}
}

func azPickReversibility(req map[string]any) (string, bool) {
	if act, ok := req["action"].(map[string]any); ok {
		if p, ok := act["properties"].(map[string]any); ok {
			if s, ok := p["reversibility_class"].(string); ok {
				return s, true
			}
		}
	}
	if c, ok := req["context"].(map[string]any); ok {
		if s, ok := c["reversibility_class"].(string); ok {
			return s, true
		}
	}
	return "", false
}

func azEnvFromContext(context any) map[string]any {
	m, ok := context.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]any{}
	for k, v := range m {
		if k != AuthzenActionKey && k != AuthzenApprovalKey {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// AuthzenDefaultToAction maps an Access Evaluation request to a PCA action: verb = action.name; resource = "type:id" (just the
// type when id is empty); params = resource.properties overlaid by action.properties; subject = subject.properties; env = context
// minus the PCA keys.
func AuthzenDefaultToAction(req map[string]any) map[string]any {
	res, _ := req["resource"].(map[string]any)
	act, _ := req["action"].(map[string]any)
	typ, _ := res["type"].(string)
	id, _ := res["id"].(string)
	resource := typ
	if len(id) > 0 {
		resource = typ + ":" + id
	}
	params := map[string]any{}
	if p, ok := res["properties"].(map[string]any); ok {
		for k, v := range p {
			params[k] = v
		}
	}
	if p, ok := act["properties"].(map[string]any); ok {
		for k, v := range p {
			params[k] = v
		}
	}
	out := map[string]any{"verb": act["name"], "resource": resource, "params": params}
	if rc, ok := azPickReversibility(req); ok {
		out["reversibilityClass"] = rc
	}
	if subj, ok := req["subject"].(map[string]any); ok {
		if p, ok := subj["properties"].(map[string]any); ok {
			out["subject"] = p
		}
	}
	if env := azEnvFromContext(req["context"]); env != nil {
		out["env"] = env
	}
	return out
}

// azCarried: the forwarded PCActn, nil when absent, malformed = true when it is present but unusable.
func azCarried(context any) (p map[string]any, malformed bool) {
	m, ok := context.(map[string]any)
	if !ok {
		return nil, false
	}
	raw, has := m[AuthzenActionKey]
	if !has || raw == nil {
		return nil, false
	}
	s, ok := raw.(string)
	if !ok {
		return nil, true
	}
	v, err := ParsePCActn(s)
	if err != nil {
		return nil, true
	}
	return v, false
}

func azParamsOf(action map[string]any) map[string]any {
	if p, ok := action["params"].(map[string]any); ok {
		return p
	}
	return map[string]any{}
}

func azFreshBudget(grant any, now int64) map[string]any {
	var b any = 0
	if env := ReadEnvelope(grant); env != nil {
		if rp, ok := env["risk_policy"].(map[string]any); ok && azIsNum(rp["bMax"]) {
			b = rp["bMax"]
		}
	}
	n := jsNumber(float64(now))
	return map[string]any{"B": b, "tau": n, "asOf": n}
}

func azApprovalRequired(p map[string]any, d *AuthzenDecision, grant any, now int64) map[string]any {
	tier := 2
	if t, ok := anlFin(d.RequiredThreshold["t"]); ok && t >= 3 {
		tier = 3
	}
	var reason any = fmt.Sprintf("requires tier-%d co-sign", tier)
	if len(d.Reasons) > 0 {
		reason = d.Reasons[0]
	}
	act, _ := p["action"].(map[string]any)
	body := map[string]any{"d": "atlas-pca/authzen/aarp/v1", "verb": act["verb"], "resource": act["resource"], "params_digest": act["params_digest"], "at": jsNumber(float64(now))}
	if c, has := p["counter"]; has {
		body["counter"] = c
	}
	id, err := HashCanonical(body)
	if err != nil {
		panic(err)
	}
	gc := ""
	if env := ReadEnvelope(grant); env != nil {
		gc, _ = env["goal_commit"].(string)
	}
	pending := map[string]any{
		"approval_required":  true,
		"auth_req_id":        id,
		"tier":               tier,
		"required_threshold": d.RequiredThreshold,
		"goal_commit":        gc,
		"risk":               d.R,
		"reason":             reason,
		"requested_at":       jsNumber(float64(now)),
	}
	var reasons any = d.Reasons
	if d.Reasons == nil {
		reasons = nil
	}
	return map[string]any{"decision": false, "context": map[string]any{
		"id":               id,
		"reason_admin":     map[string]any{"stage": "step_up", "risk": d.R, "threshold": d.RequiredThreshold, "reasons": reasons},
		"reason_user":      map[string]any{"message": "approval required before this action can proceed"},
		AuthzenApprovalKey: pending,
	}}
}

func azMergeEvaluation(defaults map[string]any, item any) map[string]any {
	if item == nil {
		anlFail("Cannot read properties of null (reading 'subject')")
	}
	it, _ := item.(map[string]any)
	pick := func(k string) any {
		if v := it[k]; v != nil {
			return v
		}
		return defaults[k]
	}
	subject, action, resource := pick("subject"), pick("action"), pick("resource")
	if !IsAuthzenSubject(subject) || !IsAuthzenAction(action) || !IsAuthzenResource(resource) {
		return nil
	}
	out := map[string]any{"subject": subject, "action": action, "resource": resource}
	if c := it["context"]; c != nil {
		out["context"] = c
	} else if c, has := defaults["context"]; has {
		out["context"] = c
	}
	return out
}

// ---- the PDP ----------------------------------------------------------------------------------------------------------------

// AuthzenPdp is the AuthZEN Policy Decision Point.
type AuthzenPdp struct {
	cfg AuthzenConfig
}

// NewAuthzenPdp builds a PDP over the config.
func NewAuthzenPdp(cfg AuthzenConfig) *AuthzenPdp { return &AuthzenPdp{cfg: cfg} }

func (p *AuthzenPdp) now() int64 {
	if p.cfg.Now != nil {
		return p.cfg.Now()
	}
	return time.Now().UnixMilli()
}

func (p *AuthzenPdp) admits(policy, action any) bool {
	f := p.cfg.AdmitsConcrete
	if f == nil {
		f = PolicyVMAdmitsConcrete
	}
	ok, err := f(policy, action)
	if err != nil {
		panic(err)
	}
	return ok
}

func azFlag(b *bool) bool { return b == nil || *b }

// Evaluate is the Access Evaluation of one request (a map as the guards accept it). It never panics: any failure is a deny.
func (p *AuthzenPdp) Evaluate(req map[string]any) (out map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			out = azDeny("evaluation error (fail closed): "+azErrText(r), "", 500)
		}
	}()
	return p.evaluate(req)
}

func (p *AuthzenPdp) evaluate(req map[string]any) map[string]any {
	c := p.cfg
	now := p.now()
	if c.Resolve == nil {
		panic(errors.New("authzen: config.resolve is not provided (fail closed)"))
	}
	ctx, err := c.Resolve(req)
	if err != nil {
		panic(err)
	}
	if ctx == nil {
		return azDeny("no PCA authority resolved for this request", "", 0)
	}
	toAction := ctx.ToAction
	if toAction == nil {
		toAction = AuthzenDefaultToAction
	}
	mapped := toAction(req)
	carried, malformed := azCarried(req["context"])
	if malformed {
		return azDeny("context carries a malformed PCActn", "", 0)
	}
	if carried == nil {
		if azFlag(c.RequireProof) {
			return azDeny("a signed PCActn is required (requireProof)", "", 0)
		}
		if p.admits(ctx.Policy, mapped) {
			return azPermit("statically admissible under the declared authority")
		}
		return azDeny("action is not admissible under the declared authority", "", 0)
	}
	pc := carried
	if azFlag(c.RequireAuthorizer) && c.Authorizer == nil {
		return azDeny("no replay/revocation authorizer is configured (requireAuthorizer)", "", 0)
	}
	// the proof must be FOR this request: verb + resource, and the attributes must hash to the signed params_digest
	rawAct, has := pc["action"]
	if !has || rawAct == nil {
		who := "undefined"
		if has {
			who = "null"
		}
		panic(errors.New("Cannot read properties of " + who + " (reading 'verb')"))
	}
	act, _ := rawAct.(map[string]any)
	verb, hv := act["verb"]
	if !hv {
		verb = azUndef
	}
	resource, hr := act["resource"]
	if !hr {
		resource = azUndef
	}
	if verb != mapped["verb"] || resource != mapped["resource"] {
		return azDeny(fmt.Sprintf("the PCActn authorizes %s on %s, not the requested %s on %s", azJS(verb), azJS(resource), azJS(mapped["verb"]), azJS(mapped["resource"])), "", 0)
	}
	reqParams := azParamsOf(mapped)
	digest, err := ParamsDigest(reqParams)
	if err != nil {
		panic(err)
	}
	if act["params_digest"] != digest {
		return azDeny("the request attributes do not match the PCActn's signed params_digest", "", 0)
	}
	audience := ""
	switch {
	case c.Audience != nil:
		audience = *c.Audience
	case c.AcceptAnyAudience:
		if aud, ok := pc["aud"].(string); ok && aud != "" {
			audience = aud
		}
	}
	var enforce AuthzenEnforce
	if ctx.Enforce != nil {
		enforce = *ctx.Enforce
	}
	if enforce.Attestation != nil {
		panic(errors.New("authzen: enforce.attestation is not supported by this verifier (fail closed)"))
	}
	grant, _ := ctx.Grant.(map[string]any)
	verdict, err := VerifyPCActnCoreWith(pc, grant, now, audience, VerifyOptions{
		AuthorizedPlanRoots: c.AuthorizedPlanRoots, InsecureSkipPlanRootCheck: c.InsecureSkipPlanRootCheck,
		EnforceFreshness: enforce.Freshness, EnforceTaint: enforce.Taint,
	})
	if err != nil {
		panic(err)
	}
	if !verdict.Allow {
		// the reference reports each check as a status (pass / fail / not-enforced), and a wire failure stops at the wire check
		statuses := map[string]string{"wire": "fail"}
		if verdict.Checks["wire"] {
			statuses = gwStatuses(verdict, "not-enforced")
		}
		checks := map[string]any{}
		for k, v := range statuses {
			checks[k] = v
		}
		reason := verdict.Reason
		if reason == "" {
			reason = "PCActn verification failed"
		}
		return map[string]any{"decision": false, "context": map[string]any{
			"reason_admin": map[string]any{"denied": true, "stage": "verify", "checks": checks, "reason": reason},
			"reason_user":  map[string]any{"message": "the proof-carrying action did not verify"}}}
	}

	var budget any = ctx.Budget
	if budget == nil {
		budget = azFreshBudget(ctx.Grant, now)
	}
	chain := ctx.Chain
	if chain == nil {
		chain = pc["cap_chain"]
	}
	var risk any = ctx.Risk
	if risk == nil {
		risk = map[string]any{}
	}
	dctx := map[string]any{"grant": ctx.Grant, "chain": chain, "params": reqParams, "risk": risk, "budget": budget, "now": jsNumber(float64(now))}
	if ctx.Plan != nil {
		dctx["plan"] = ctx.Plan
	}
	if s := mapped["subject"]; s != nil {
		dctx["subject"] = s
	}
	if e := mapped["env"]; e != nil {
		dctx["env"] = e
	}
	derive, decide := c.DeriveDecideInput, c.Decide
	if derive == nil {
		derive = AuthzenNativeDeriveDecideInput // the default is the native Policy VM
	}
	if decide == nil {
		decide = AuthzenNativeDecide
	}
	in, err := derive(pc, dctx)
	if err != nil {
		panic(err)
	}
	decision, err := decide(in)
	if err != nil {
		panic(err)
	}
	var reasons any
	if decision.Reasons != nil {
		reasons = decision.Reasons
	}
	if !decision.ReleaseGuardianShare {
		return map[string]any{"decision": false, "context": map[string]any{
			"reason_admin": map[string]any{"denied": true, "stage": "policy", "reasons": reasons, "risk": decision.R},
			"reason_user":  map[string]any{"message": "the policy does not permit this action"}}}
	}
	if decision.Admit {
		if c.Authorizer != nil {
			ain := map[string]any{"operation": map[string]any{"verb": mapped["verb"], "resource": mapped["resource"], "params": reqParams}, "pcactn": pc}
			if cm, ok := req["context"].(map[string]any); ok {
				if pv, has := cm[AuthzenProvenanceKey]; has {
					ain["provenance"] = pv
				}
			}
			az, err := c.Authorizer(ain)
			if err != nil {
				panic(err)
			}
			if !az.Allow {
				return map[string]any{"decision": false, "context": map[string]any{
					"reason_admin": map[string]any{"denied": true, "stage": "authorize", "reason": az.Reason},
					"reason_user":  map[string]any{"message": "the proof-carrying action was not authorized"}}}
			}
		}
		return map[string]any{"decision": true, "context": map[string]any{"reason_admin": map[string]any{"stage": "policy", "risk": decision.R, "threshold": decision.RequiredThreshold}}}
	}
	return azApprovalRequired(pc, decision, ctx.Grant, now)
}

// Evaluations is the Access Evaluations boxcar. An error is the reference's throw on a malformed item or request.
func (p *AuthzenPdp) Evaluations(req any) (res map[string]any, err error) {
	r, err := anlTry(func() any { return p.evaluations(req) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (p *AuthzenPdp) evaluations(req any) map[string]any {
	items, ok := azProp(req, "evaluations").([]any)
	if !ok {
		return map[string]any{"evaluations": []any{}}
	}
	semantic := "execute_all"
	if opts, ok := azProp(req, "options").(map[string]any); ok {
		if s := opts["evaluations_semantic"]; s != nil {
			if str, ok := s.(string); ok {
				semantic = str
			} else {
				semantic = ""
			}
		}
	}
	refuse := func(reason string) map[string]any {
		out := make([]any, len(items))
		for i := range items {
			out[i] = azDeny(reason, "", 400)
		}
		return map[string]any{"evaluations": out}
	}
	if semantic != "execute_all" && semantic != "deny_on_first_deny" && semantic != "permit_on_first_permit" {
		return refuse("unsupported evaluations_semantic")
	}
	mx := AuthzenDefaultMaxEvaluations
	if p.cfg.MaxEvaluations != nil {
		mx = *p.cfg.MaxEvaluations
	}
	if len(items) > mx {
		return refuse(fmt.Sprintf("too many evaluations (limit %d)", mx))
	}
	defaults := req.(map[string]any)
	merged := make([]map[string]any, len(items))
	for i, it := range items {
		merged[i] = azMergeEvaluation(defaults, it)
	}
	out := []any{}
	for _, m := range merged {
		var r map[string]any
		if m == nil {
			r = azDeny("incomplete evaluation (missing subject/action/resource)", "", 400)
		} else {
			r = p.Evaluate(m)
		}
		out = append(out, r)
		if semantic == "deny_on_first_deny" && r["decision"] == false {
			break
		}
		if semantic == "permit_on_first_permit" && r["decision"] == true {
			break
		}
	}
	return map[string]any{"evaluations": out}
}

// EvaluateTool is the COAZ MCP-tool authorization: the tool call is mapped to an action on an `mcp_tool` resource.
func (p *AuthzenPdp) EvaluateTool(req map[string]any) map[string]any {
	tool, _ := req["tool"].(map[string]any)
	name, _ := tool["name"].(string)
	capability := name
	if p.cfg.ToolCapability != nil {
		var err error
		capability, err = p.cfg.ToolCapability(name)
		if err != nil {
			r := azDeny("evaluation error (fail closed): "+azErrText(err), "", 500)
			return map[string]any{"decision": false, "tool": name, "required_capability": "", "context": r["context"]}
		}
	}
	action := map[string]any{"name": capability}
	if args, has := tool["arguments"]; has {
		action["properties"] = args
	}
	mapped := map[string]any{"subject": req["subject"], "action": action, "resource": map[string]any{"type": "mcp_tool", "id": name}}
	if c, has := req["context"]; has {
		mapped["context"] = c
	}
	resp := p.Evaluate(mapped)
	out := map[string]any{"decision": resp["decision"], "tool": name, "required_capability": capability}
	if c, has := resp["context"]; has {
		out["context"] = c
	}
	return out
}

// ---- handler ----------------------------------------------------------------------------------------------------------------

func azStatus(status int, body any) map[string]any {
	return map[string]any{"status": status, "body": body}
}

func azErrBody(msg string) map[string]any { return map[string]any{"error": msg} }

// AuthzenHandler is the framework-agnostic handler over {"path", "body"} maps -> {"status", "body"}. A malformed body is a 400 (a
// PEP enforces it as a deny); any raised error is a 500 with no detail.
func AuthzenHandler(pdp *AuthzenPdp) func(req map[string]any) map[string]any {
	route := func(req map[string]any) map[string]any {
		path, has := req["path"]
		if !has {
			path = azUndef
		}
		body := req["body"]
		switch path {
		case AuthzenEvaluationPath:
			if !IsAccessEvaluationRequest(body) {
				return azStatus(400, azErrBody("invalid AuthZEN Access Evaluation request"))
			}
			return azStatus(200, pdp.Evaluate(body.(map[string]any)))
		case AuthzenEvaluationsPath:
			// an absent or empty `evaluations` array is a plain single Access Evaluation
			if bm, ok := body.(map[string]any); ok {
				ev, has := bm["evaluations"]
				if l, isList := ev.([]any); !has || (isList && len(l) == 0) {
					if !IsAccessEvaluationRequest(body) {
						return azStatus(400, azErrBody("invalid AuthZEN Access Evaluations request"))
					}
					return azStatus(200, pdp.Evaluate(bm))
				}
			}
			if !IsAccessEvaluationsRequest(body) {
				return azStatus(400, azErrBody("invalid AuthZEN Access Evaluations request"))
			}
			res, err := pdp.Evaluations(body)
			if err != nil {
				panic(err)
			}
			return azStatus(200, res)
		case AuthzenCoazToolPath:
			if !IsCoazToolAuthorizationRequest(body) {
				return azStatus(400, azErrBody("invalid COAZ MCP-tool authorization request"))
			}
			return azStatus(200, pdp.EvaluateTool(body.(map[string]any)))
		}
		return azStatus(404, azErrBody("unknown AuthZEN path: "+azJS(path)))
	}
	return func(req map[string]any) (out map[string]any) {
		defer func() {
			if recover() != nil { // a PEP treats non-200 as a deny; never leak internals
				out = azStatus(500, azErrBody("internal error"))
			}
		}()
		return route(req)
	}
}

// ---- search -----------------------------------------------------------------------------------------------------------------

func azNonEmpty(x any) bool { s, ok := x.(string); return ok && len(s) > 0 }

func azPropsOK(m map[string]any) bool {
	p, has := m["properties"]
	if !has {
		return true
	}
	_, ok := p.(map[string]any)
	return ok
}

func azEntity(x any, needID bool) bool {
	m, ok := x.(map[string]any)
	if !ok || !azNonEmpty(m["type"]) {
		return false
	}
	if needID && !azNonEmpty(m["id"]) {
		return false
	}
	return azPropsOK(m)
}

func azSearchAction(x any) bool {
	m, ok := x.(map[string]any)
	return ok && azNonEmpty(m["name"]) && azPropsOK(m)
}

func azSafeNonNegInt(v any) bool {
	if _, isBool := v.(bool); isBool {
		return false
	}
	f, ok := jsNum(v)
	if !ok || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Signbit(f) {
		return false
	}
	return f <= 9007199254740991
}

func azPageOK(m map[string]any) bool {
	pv, has := m["page"]
	if !has {
		return true
	}
	p, ok := pv.(map[string]any)
	if !ok {
		return false
	}
	if t, has := p["token"]; has {
		if _, ok := t.(string); !ok {
			return false
		}
	}
	if l, has := p["limit"]; has && !azSafeNonNegInt(l) {
		return false
	}
	return azPropsOK(p)
}

func azSearchBase(b map[string]any) bool {
	if c, has := b["context"]; has {
		if _, ok := c.(map[string]any); !ok {
			return false
		}
	}
	return azPageOK(b)
}

func IsSubjectSearch(b any) bool {
	m, ok := b.(map[string]any)
	return ok && azSearchBase(m) && azEntity(m["subject"], false) && azSearchAction(m["action"]) && azEntity(m["resource"], true)
}

func IsResourceSearch(b any) bool {
	m, ok := b.(map[string]any)
	return ok && azSearchBase(m) && azEntity(m["subject"], true) && azSearchAction(m["action"]) && azEntity(m["resource"], false)
}

func IsActionSearch(b any) bool {
	m, ok := b.(map[string]any)
	if !ok || !azSearchBase(m) {
		return false
	}
	_, hasAction := m["action"]
	return !hasAction && azEntity(m["subject"], true) && azEntity(m["resource"], true)
}

// AuthzenSearchProvider supplies the three searches; a nil function means that search is unsupported. A function receives the
// request (the searched entity's id stripped for subject / resource search) and returns {results, page?, context?}.
type AuthzenSearchProvider struct {
	SearchSubject  func(req map[string]any) (any, error)
	SearchResource func(req map[string]any) (any, error)
	SearchAction   func(req map[string]any) (any, error)
}

// SearchMetadata is the fragment for /.well-known/authzen-configuration; a missing endpoint means that search is unsupported.
func SearchMetadata(base string, p AuthzenSearchProvider) map[string]any {
	out := map[string]any{}
	if p.SearchSubject != nil {
		out["search_subject_endpoint"] = base + AuthzenSearchSubjectPath
	}
	if p.SearchResource != nil {
		out["search_resource_endpoint"] = base + AuthzenSearchResourcePath
	}
	if p.SearchAction != nil {
		out["search_action_endpoint"] = base + AuthzenSearchActionPath
	}
	return out
}

func azStripID(req map[string]any, key string) map[string]any {
	e := anlCopy(req[key].(map[string]any))
	delete(e, "id")
	out := anlCopy(req)
	out[key] = e
	return out
}

func azShape(r any, limit any, typeOK func(any) bool) map[string]any {
	resultsIn, ok := azProp(r, "results").([]any)
	if !ok {
		anlFail("results.filter is not a function")
	}
	seen := map[string]bool{}
	results := []any{}
	for _, t := range resultsIn {
		k := anlJSON(t)
		if !typeOK(t) || seen[k] {
			continue
		}
		seen[k] = true
		results = append(results, t)
	}
	capped := results
	if lf, ok := jsNum(limit); ok && lf > 0 && int(lf) < len(results) {
		capped = results[:int(lf)]
	}
	// a provider that ignores the limit would hide results behind a page marker we cannot resume: fail closed
	if len(capped) < len(results) {
		anlFail("provider returned more than the page limit")
	}
	out := map[string]any{}
	rm, _ := r.(map[string]any)
	if pg := rm["page"]; azTruthy(pg) {
		pgm, ok := pg.(map[string]any)
		if !ok {
			anlFail("Cannot use 'in' operator to search for 'next_token'")
		}
		page := map[string]any{}
		if nt, has := pgm["next_token"]; has {
			page["next_token"] = nt
		}
		page["count"] = len(capped)
		if tot, has := pgm["total"]; has {
			page["total"] = tot
		}
		if props := pgm["properties"]; azTruthy(props) {
			page["properties"] = props
		}
		out["page"] = page
	}
	if c := rm["context"]; azTruthy(c) {
		out["context"] = c
	}
	out["results"] = capped
	return out
}

// AuthzenSearchHandler returns nil for a path that is not a search path, so it can be chained after AuthzenHandler's result.
func AuthzenSearchHandler(p AuthzenSearchProvider) func(req map[string]any) map[string]any {
	limitOf := func(body map[string]any) any {
		if pg, ok := body["page"].(map[string]any); ok {
			if l, has := pg["limit"]; has {
				return l
			}
		}
		return azUndef
	}
	typeIs := func(typ any) func(any) bool {
		return func(e any) bool { return azProp(e, "type") == typ }
	}
	route := func(req map[string]any) map[string]any {
		path, has := req["path"]
		if !has {
			path = azUndef
		}
		body := req["body"]
		switch path {
		case AuthzenSearchSubjectPath:
			if p.SearchSubject == nil {
				return azStatus(404, azErrBody("subject search is not supported"))
			}
			if !IsSubjectSearch(body) {
				return azStatus(400, azErrBody("invalid AuthZEN subject search request"))
			}
			b := body.(map[string]any)
			r, err := p.SearchSubject(azStripID(b, "subject"))
			if err != nil {
				panic(err)
			}
			return azStatus(200, azShape(r, limitOf(b), typeIs(b["subject"].(map[string]any)["type"])))
		case AuthzenSearchResourcePath:
			if p.SearchResource == nil {
				return azStatus(404, azErrBody("resource search is not supported"))
			}
			if !IsResourceSearch(body) {
				return azStatus(400, azErrBody("invalid AuthZEN resource search request"))
			}
			b := body.(map[string]any)
			r, err := p.SearchResource(azStripID(b, "resource"))
			if err != nil {
				panic(err)
			}
			return azStatus(200, azShape(r, limitOf(b), typeIs(b["resource"].(map[string]any)["type"])))
		case AuthzenSearchActionPath:
			if p.SearchAction == nil {
				return azStatus(404, azErrBody("action search is not supported"))
			}
			if !IsActionSearch(body) {
				return azStatus(400, azErrBody("invalid AuthZEN action search request"))
			}
			b := body.(map[string]any)
			r, err := p.SearchAction(b)
			if err != nil {
				panic(err)
			}
			return azStatus(200, azShape(r, limitOf(b), func(any) bool { return true }))
		}
		return nil
	}
	return func(req map[string]any) (out map[string]any) {
		defer func() {
			if recover() != nil {
				out = azStatus(500, azErrBody("internal error"))
			}
		}()
		return route(req)
	}
}
