package pca

// AuthorizeExecution: the full-policy check for one local execution (an agent framework tool call, a gateway request), for
// verifiers that have the PCActn in hand rather than an HTTP request.
//
// VerifyPCActnCore alone checks that a proof is genuine (signatures, chain, plan, audience, validity, counter format). It does
// not read the grant's limits, so a validly signed $400 payment under a $100 grant passes it. AuthorizeExecution runs, in order:
//
//  1. configuration: the audience, a grant source, the replay / budget store and the revocation check are REQUIRED; a missing
//     one denies every call (fail closed, never a downgrade to signature-only);
//  2. operation binding: the PCActn's signed verb (and resource, when the caller names one) must be the operation that is about
//     to execute;
//  3. the full server verifier, through Authorize (the one pipeline): the grant from the caller's store, the operation's params
//     against the signed params digest, the grant's predicates, limits and caveats (root, envelope and delegated), revocation,
//     the replay counter and the trust budget, with risk priced from server-side inputs.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ExecutionOperation is the operation that is about to execute: what the PCActn must have been signed for.
type ExecutionOperation struct {
	// Verb is the PCA verb of this operation (e.g. "stripe.refund"). Must equal the signed action.verb.
	Verb string
	// Resource is the PCA resource of this operation. When non-empty it must equal the signed action.resource.
	Resource string
	// Params are the parameters the operation will execute with. They must hash to the signed action.params_digest.
	Params map[string]any
	// Provenance is the provenance bundle the agent presented with this call (ProvenanceRecorder.ForAction); nil = unlabelled.
	Provenance any
}

// ExecutionHooks are the verifier hooks forwarded to Authorize (revocation always comes from IsRevoked).
type ExecutionHooks struct {
	// Threshold verifies a threshold co-signature (nil: none is enforced).
	Threshold ThresholdHook
	// Attestation and Zk are the verifier's own hooks. One that implements AttestationVerifierHook / ZkVerifierHook
	// (*AttestationVerifier, *ZkVerifier) is forwarded to Authorize and decides its check (see AuthorizeInput.Attestation and
	// AuthorizeInput.Zk); either way the assurance report labels the check with it (see AssuranceHooks). Nil means none: a
	// carried zk_compliance proof and a grant that binds the agent are then refused.
	Attestation any
	Zk          any
}

// AuthorizeExecutionOptions configures AuthorizeExecution. Audience, a grant source, State and IsRevoked are required.
type AuthorizeExecutionOptions struct {
	// Audience is this verifier's audience id (REQUIRED). A PCActn whose signed aud differs is denied.
	Audience string
	// Grant is the grant the PCActn must chain to. Give this or ResolveGrant (one is required).
	Grant map[string]any
	// ResolveGrant looks the grant up in YOUR store by the PCActn's signed grant_ref. Never return a grant taken from the call.
	// A nil grant is "unknown grant_ref"; an error denies (fail closed).
	ResolveGrant func(grantRef string, pcactn map[string]any) (map[string]any, error)
	// State holds the replay counters and trust budgets per agent (REQUIRED). Share one store across processes.
	State StateStore
	// IsRevoked answers whether the grant is revoked (REQUIRED): a verifier that cannot answer this must not authorize.
	IsRevoked func(grant, pcactn map[string]any) (bool, error)
	// IsPlanAuthorized says whether the principal authorized this plan root for this grant. Default: a one-step plan is
	// authorized when it is exactly the step that was signed (the grant's permissions are the policy).
	IsPlanAuthorized func(grantRef, planRoot string) bool
	// Risk returns the server-side risk inputs for this operation. Default AmountRisk: blastRadius = amount / kappa from the
	// verified params.amount and the grant's risk policy. Inputs not supplied are priced at the worst case by the verifier.
	Risk func(grant map[string]any, params map[string]any, pcactn map[string]any) map[string]any
	// Hooks are the verifier hooks forwarded to Authorize.
	Hooks ExecutionHooks
	// Require lists further checks that must report pass, on top of the full-mode defaults.
	Require []string
	// K1 is the caveat language v2 input (pins, presented discharges and narrow block, revoked discharges, SPIFFE id, history).
	// Nil: every K1 caveat in the chain refuses (fail closed).
	K1 *K1Input
	// UsesStore is the consume-once store max_uses caveats spend from.
	UsesStore StateStore
	// AllowedSuites are the accepted signature suites. Default ["ed25519"].
	AllowedSuites []string
	// PqPins are the server-side PQ pins issuer -> pq_pk, needed only if you accept a post-quantum suite.
	PqPins map[string]string
	// Now is the verifier clock (epoch ms). Nil: the wall clock. A clock returning 0 means time 0.
	Now func() int64
	// RequireAssurance is the high-assurance policy forwarded to Authorize: weaker, missing, failed, unlabelled, awaiting-audit
	// or unsupported evidence denies (check `assurance`).
	RequireAssurance *AssuranceRequirement
	// EnforceTaint and EnforceFreshness are the opt-in core gates; each gate that is set fails closed.
	EnforceTaint     *TaintGate
	EnforceFreshness *FreshnessGate
	// MultiInstance: more than one process or node shares State: a store that only the in-process lock can serialise is
	// refused, and every call is denied with the reason.
	MultiInstance *bool
	// ClaimRetries is the number of re-verifications after an atomic claim's budget conflict before the call is denied
	// (default 3). A negative value is a configuration error and denies every call.
	ClaimRetries *int
	// Provenance configures the provenance gate (pinned mediators, the facts of your action definitions, server-observed content).
	Provenance *ArgProvenanceOptions
}

// ExecutionDenialKind says why a full-policy check refused.
type ExecutionDenialKind string

// The denial kinds.
const (
	ExecutionDenyConfig  ExecutionDenialKind = "config"
	ExecutionDenyBinding ExecutionDenialKind = "binding"
	ExecutionDenyAuthn   ExecutionDenialKind = "authn"
	ExecutionDenyPolicy  ExecutionDenialKind = "policy"
	ExecutionDenyReplay  ExecutionDenialKind = "replay"
	ExecutionDenyRevoked ExecutionDenialKind = "revoked"
)

// ExecutionDecision is the outcome of AuthorizeExecution.
type ExecutionDecision struct {
	// Allow is true when the call may execute.
	Allow bool
	// PCActn and Grant are set on an allow.
	PCActn map[string]any
	Grant  map[string]any
	// Kind and Status describe a denial (Status is 401 or 403); Reason is the decisive reason in the verifier's words.
	Kind   ExecutionDenialKind
	Status int
	Reason string
	// Checks are the verifier's checks, when it ran; Verdict is its full result (including the assurance report).
	Checks  map[string]string
	Verdict *AuthorizeResult
	// Assurance is what each check rested on (see BuildAssuranceReport), when the verifier ran.
	Assurance *AssuranceReport
}

// ExecutionRequiredChecks are the checks a full-policy decision must PASS: the RequirePCA default profile (counter,
// revocation, plan root, audience, validity, grant_ref binding) plus the params digest and the policy itself (Authorize adds
// `operation`).
func ExecutionRequiredChecks() []string {
	return append(DefaultRequiredChecks(), "params_digest", "policy")
}

// MissingExecutionComponents lists the required components that opts lacks (empty when the configuration is complete).
func MissingExecutionComponents(opts AuthorizeExecutionOptions) []string {
	var missing []string
	if opts.Audience == "" {
		missing = append(missing, "audience")
	}
	if opts.Grant == nil && opts.ResolveGrant == nil {
		missing = append(missing, "grant or resolveGrant")
	}
	if opts.State == nil {
		missing = append(missing, "state")
	}
	if opts.IsRevoked == nil {
		missing = append(missing, "isRevoked")
	}
	return missing
}

// AmountRisk is the server's risk input for a money-moving operation: blastRadius = amount / kappa from the verified
// params[amountField] (default "amount") and the grant's own risk policy. Nil when there is no numeric amount (the verifier then
// prices the missing inputs at the worst case).
func AmountRisk(grant map[string]any, params map[string]any, amountField string) map[string]any {
	if amountField == "" {
		amountField = "amount"
	}
	amount, ok := jsNum(params[amountField])
	if !ok || math.IsInf(amount, 0) || math.IsNaN(amount) {
		return nil
	}
	env := ReadEnvelope(grant)
	if env == nil {
		return nil
	}
	rp, _ := env["risk_policy"].(map[string]any)
	kappa, ok := jsNum(rp["kappa"])
	if !ok || !finite(kappa) || !(kappa > 0) {
		return nil
	}
	return map[string]any{"blastRadius": math.Min(1, math.Max(0, amount/kappa))}
}

const (
	executionRiskNoise = "risk input(s) missing"
	// executionBudgetConflict is the reason the pipeline reports when an atomic claim lost its budget compare-and-set.
	executionBudgetConflict = "the trust budget changed while this action was decided (a concurrent spend)"
	// DefaultClaimRetries is the default of AuthorizeExecutionOptions.ClaimRetries.
	DefaultClaimRetries = 3
)

// executionCoreOrder is the order the verifier reports its core checks in; checks added after them follow in the order their
// reasons were reported (the reference walks the verdict's checks in that insertion order).
var executionCoreOrder = []string{"wire", "version", "audience", "validity", "cap_chain", "chain", "grant_ref_bound", "plan_inclusion",
	"plan_root_authorized", "leaf_signature", "counter_format", "intent", "taint_gate", "freshness", "attestation", "threshold", "revocation"}

// executionDecisiveReason is the reason of the first failing check (the verifier also lists context such as worst-case risk
// inputs). The verb and resource are bound before the verifier runs, so a failing `operation` check here is a params mismatch
// that `params_digest` already reports: it is ranked last so the reason stays the established `params_digest` one.
func executionDecisiveReason(r AuthorizeResult) string {
	hasPrefix := func(reason, name string) bool { return strings.HasPrefix(reason, name+":") }
	reported := func(n string) int {
		for i, x := range r.Reasons {
			if hasPrefix(x, n) {
				return i
			}
		}
		return math.MaxInt32
	}
	core := func(n string) int {
		for i, c := range executionCoreOrder {
			if c == n {
				return i
			}
		}
		return len(executionCoreOrder)
	}
	var failing []string
	for n, s := range r.Checks {
		if s == "fail" {
			failing = append(failing, n)
		}
	}
	sort.SliceStable(failing, func(i, j int) bool {
		a, b := failing[i], failing[j]
		if (a == "operation") != (b == "operation") {
			return b == "operation"
		}
		if core(a) != core(b) {
			return core(a) < core(b)
		}
		if reported(a) != reported(b) {
			return reported(a) < reported(b)
		}
		return a < b
	})
	for _, n := range failing {
		for _, x := range r.Reasons {
			if hasPrefix(x, n) && !strings.Contains(x, executionRiskNoise) {
				return x
			}
		}
	}
	for _, x := range r.Reasons {
		if !strings.Contains(x, executionRiskNoise) {
			return x
		}
	}
	if len(r.Reasons) > 0 {
		return r.Reasons[0]
	}
	return "denied"
}

func executionDeny(kind ExecutionDenialKind, status int, reason string) ExecutionDecision {
	return ExecutionDecision{Kind: kind, Status: status, Reason: reason}
}

func executionPlanOf(p map[string]any) map[string]any {
	plan, _ := p["plan"].(map[string]any)
	action, _ := p["action"].(map[string]any)
	return map[string]any{"id": plan["node_id"], "verb": action["verb"], "resource": action["resource"],
		"params_digest": action["params_digest"], "reversibility_class": action["reversibility_class"]}
}

// AuthorizeExecution authorizes one execution completely: configuration, binding to the operation, and the full verifier. pcactn
// is the presented PCActn (a parsed object, or its JSON text). It never panics: an internal error is a 403 denial.
func AuthorizeExecution(pcactn any, operation ExecutionOperation, opts AuthorizeExecutionOptions) (dec ExecutionDecision) {
	if missing := MissingExecutionComponents(opts); len(missing) > 0 {
		return executionDeny(ExecutionDenyConfig, 403, "full policy mode is missing "+strings.Join(missing, ", ")+" (fail closed)")
	}
	retries := DefaultClaimRetries
	if opts.ClaimRetries != nil {
		retries = *opts.ClaimRetries
	}
	if retries < 0 {
		return executionDeny(ExecutionDenyConfig, 403, "claimRetries must be a non-negative integer (fail closed)")
	}
	defer func() {
		if r := recover(); r != nil {
			dec = executionDeny(ExecutionDenyPolicy, 403, fmt.Sprintf("authorization error (fail closed): %v", r))
		}
	}()
	p, _ := coercePCActn(pcactn)
	action, _ := p["action"].(map[string]any)
	show := func(k string) string {
		v, ok := action[k]
		if !ok {
			return "undefined"
		}
		return jsValueString(v)
	}
	// binding: checked before any state is read or written, so a proof presented for another operation is not spent.
	verb, _ := action["verb"].(string)
	resource, _ := action["resource"].(string)
	if p == nil || verb != operation.Verb || (operation.Resource != "" && resource != operation.Resource) {
		want := operation.Verb
		if operation.Resource != "" {
			want = operation.Verb + " on " + operation.Resource
		}
		return executionDeny(ExecutionDenyBinding, 403, fmt.Sprintf("the proof is for %s on %s, but this call is %s", show("verb"), show("resource"), want))
	}
	grant := opts.Grant
	if grant == nil {
		ref, _ := p["grant_ref"].(string)
		g, err := opts.ResolveGrant(ref, p)
		if err != nil {
			return executionDeny(ExecutionDenyPolicy, 403, "authorization error (fail closed): "+err.Error())
		}
		grant = g
	}
	if grant == nil {
		return executionDeny(ExecutionDenyAuthn, 401, "unknown grant_ref")
	}
	now := time.Now().UnixMilli()
	if opts.Now != nil {
		now = opts.Now()
	}
	params := operation.Params
	suites := opts.AllowedSuites
	if suites == nil {
		suites = []string{"ed25519"}
	}
	opRes := operation.Resource
	if opRes == "" {
		opRes = resource
	}
	in := AuthorizeInput{
		Operation:        &Operation{Verb: operation.Verb, Resource: opRes, Params: params},
		Audience:         opts.Audience,
		AllowedSuites:    suites,
		PqPins:           opts.PqPins,
		Now:              now,
		RequireAssurance: opts.RequireAssurance,
		EnforceTaint:     opts.EnforceTaint,
		EnforceFreshness: opts.EnforceFreshness,
		MultiInstance:    opts.MultiInstance,
		UsesStore:        opts.UsesStore,
		ArgProvenance:    opts.Provenance,
		ProvenanceBundle: operation.Provenance,
		Threshold:        opts.Hooks.Threshold,
		ResolveGrant:     func(string) (map[string]any, error) { return grant, nil },
		StateStore:       opts.State,
		IsRevoked:        func(pc, g map[string]any) (bool, error) { return opts.IsRevoked(g, pc) },
		Require:          append(ExecutionRequiredChecks(), opts.Require...),
		Risk: func(_ *Operation, g, pc map[string]any) (map[string]any, error) {
			if opts.Risk != nil {
				return opts.Risk(g, params, pc), nil
			}
			return AmountRisk(g, params, ""), nil
		},
		Context: func(pc map[string]any) (*AuthorizeContext, error) {
			plan := []map[string]any{executionPlanOf(pc)}
			pl, _ := pc["plan"].(map[string]any)
			root, _ := pl["root"].(string)
			computed, ok := planRoot(plan)
			approved := true
			if opts.IsPlanAuthorized != nil {
				ref, _ := pc["grant_ref"].(string)
				approved = opts.IsPlanAuthorized(ref, root)
			}
			return &AuthorizeContext{Plan: plan, PlanAuthorized: ok && computed == root && approved}, nil
		},
	}
	in.AssuranceHooks = AssuranceHooks{Attestation: opts.Hooks.Attestation, Zk: opts.Hooks.Zk}
	in.Attestation, _ = opts.Hooks.Attestation.(AttestationVerifierHook)
	in.Zk, _ = opts.Hooks.Zk.(ZkVerifierHook)
	if opts.Hooks.Threshold != nil {
		in.AssuranceHooks.Threshold = opts.Hooks.Threshold
	}
	if opts.K1 != nil {
		k1 := opts.K1
		in.K1 = func(map[string]any) (*K1Input, error) { return k1, nil }
	}
	var r AuthorizeResult
	for attempt := 0; ; attempt++ {
		r = Authorize(p, in)
		if r.Allow || !executionHasBudgetConflict(r) {
			break
		}
		if attempt >= retries {
			why := "replay: concurrent state update for this holder kept conflicting (fail closed, retry the request)"
			r.Checks = map[string]string{"replay": "fail"}
			r.Reasons = []string{why}
			r.Reason = why
			break
		}
	}
	if r.Allow {
		pc := r.PCActn
		if pc == nil {
			pc = p
		}
		a := r.Assurance
		return ExecutionDecision{Allow: true, PCActn: pc, Grant: grant, Verdict: &r, Assurance: &a}
	}
	kind := ExecutionDenyPolicy
	switch {
	case r.Status == 401:
		kind = ExecutionDenyAuthn
	case r.Checks["revocation"] == "fail":
		kind = ExecutionDenyRevoked
	case r.Checks["replay"] == "fail":
		kind = ExecutionDenyReplay
	}
	a := r.Assurance
	return ExecutionDecision{Kind: kind, Status: r.Status, Reason: executionDecisiveReason(r), Checks: r.Checks, Verdict: &r, Assurance: &a}
}

func executionHasBudgetConflict(r AuthorizeResult) bool {
	for _, x := range r.Reasons {
		if strings.Contains(x, executionBudgetConflict) {
			return true
		}
	}
	return false
}
