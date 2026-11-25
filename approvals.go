package pca

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The approval and step-up model. It is the headless core an approval inbox (push, chat, web) renders: given an intended action it
// decides whether the action auto-admits, is a hard deny, or needs a human, and when a human is needed it builds the StepUpRequest
// with the goal lineage, the risk tier and a stable id. It also covers batching, standing "approve this class for N hours"
// approvals, the budget effect of a co-sign and time-boxing a grant. It composes the agent's non-authoritative DryRun with the
// budget algebra and signs nothing except where a grant is explicitly time-boxed. The resource server stays the authority.

// LineageNode is one hop of the "why is this action requested" chain, from the human goal down to the concrete action.
type LineageNode struct {
	// Kind is "goal", "authority" or "action".
	Kind string `json:"kind"`
	// Label is a one-line human label.
	Label string `json:"label"`
	// Detail is optional structured detail.
	Detail string `json:"detail,omitempty"`
}

// GoalLineage is the lineage carried on a pending approval: the goal the grant's goal_commit opens to, threaded through the
// delegated authority down to this action. GoalVerified says whether the revealed plaintext goal really opens the commitment.
type GoalLineage struct {
	Goal         *string       `json:"goal,omitempty"`
	GoalCommit   string        `json:"goalCommit"`
	GoalVerified bool          `json:"goalVerified"`
	Chain        []LineageNode `json:"chain"`
	Because      string        `json:"because"`
}

// StepUpRequest is a pending approval.
type StepUpRequest struct {
	// ID is the stable id: the hash of the action and the request time.
	ID       string         `json:"id"`
	Verb     string         `json:"verb"`
	Resource string         `json:"resource"`
	Params   map[string]any `json:"params,omitempty"`
	// Tier is the tier a human or guardian must satisfy (2 guardian, 3 human).
	Tier       int         `json:"tier"`
	Reason     string      `json:"reason"`
	GoalCommit string      `json:"goalCommit"`
	Goal       *string     `json:"goal,omitempty"`
	Lineage    GoalLineage `json:"lineage"`
	// R is the risk the action carries.
	R           float64 `json:"r"`
	RequestedAt int64   `json:"requestedAt"`
	// Render is the canonical approval render of this exact action and RenderDigest is H(R); both are set when a renderer was supplied.
	Render       map[string]any `json:"render,omitempty"`
	RenderDigest string         `json:"renderDigest,omitempty"`
}

// MarshalJSON emits params whenever the request carries them, even as an empty object.
func (r StepUpRequest) MarshalJSON() ([]byte, error) {
	type plain StepUpRequest
	aux := struct {
		plain
		Params *map[string]any `json:"params,omitempty"`
	}{plain: plain(r)}
	if r.Params != nil {
		aux.Params = &r.Params
	}
	return json.Marshal(aux)
}

// Review is the outcome of reviewing one intended action: Kind "auto", "deny" (with Reason) or "step_up" (with Request).
type Review struct {
	Kind    string         `json:"kind"`
	Reason  string         `json:"reason,omitempty"`
	Request *StepUpRequest `json:"request,omitempty"`
}

// ApprovalRenderer builds the canonical approval render of an action. An error or a panic makes the review a deny: an action that
// cannot be displayed completely is never put to a human.
type ApprovalRenderer func(verb, resource string, params map[string]any) (map[string]any, error)

// ReviewOptions are the options of ReviewAction.
type ReviewOptions struct {
	// Now is the clock in epoch ms (nil: the wall clock).
	Now *int64
	// Goal is the plaintext goal to carry on a step-up request.
	Goal *string
	// Standing are the standing class approvals that can downgrade a step-up to auto.
	Standing []ClassApproval
	// Renderer builds the approval render. A step-up request is created only together with its render.
	Renderer ApprovalRenderer
	// InsecureUnboundApproval is the documented insecure opt-out: without a Renderer the review is a deny unless this is true,
	// which keeps the unbound pre-render behaviour.
	InsecureUnboundApproval bool
}

// IntendedCall is one action of a batch.
type IntendedCall struct {
	Verb     string
	Resource string
	Params   map[string]any
}

// ClassApproval is a standing "approve this class for N hours" approval.
type ClassApproval struct {
	ID string `json:"id"`
	// Verbs are the verbs it covers.
	Verbs []string `json:"verbs"`
	// Resource is an optional matcher (exact, "*" or a trailing-"*" prefix); nil means any resource.
	Resource  *string `json:"resource,omitempty"`
	GrantedAt int64   `json:"grantedAt"`
	TTLMs     int64   `json:"ttlMs"`
	// By is who approved (for the audit trail).
	By string `json:"by"`
}

// ApprovalDecision is a human's decision on a request (data for the audit trail).
type ApprovalDecision struct {
	RequestID string `json:"requestId"`
	Decision  string `json:"decision"`
	By        string `json:"by"`
	At        int64  `json:"at"`
}

// approvalJSStringify is JSON.stringify of a JSON value, members in the order jsKeys reports.
func approvalJSStringify(v any) string {
	var sb strings.Builder
	var rec func(x any)
	rec = func(x any) {
		switch t := x.(type) {
		case nil:
			sb.WriteString("null")
		case bool:
			sb.WriteString(strconv.FormatBool(t))
		case string:
			lenientString(&sb, t)
		case []any:
			sb.WriteByte('[')
			for i, e := range t {
				if i > 0 {
					sb.WriteByte(',')
				}
				rec(e)
			}
			sb.WriteByte(']')
		case map[string]any:
			sb.WriteByte('{')
			for i, k := range jsKeys(t) {
				if i > 0 {
					sb.WriteByte(',')
				}
				lenientString(&sb, k)
				sb.WriteByte(':')
				rec(t[k])
			}
			sb.WriteByte('}')
		default:
			if f, ok := jsNum(x); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
				sb.WriteString(jsNumberString(f))
			} else {
				sb.WriteString("null")
			}
		}
	}
	rec(v)
	return sb.String()
}

// approvalJSString is String(v) for a primitive and JSON.stringify(v) for an object, an array or null.
func approvalJSString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case nil, map[string]any, []any:
		return approvalJSStringify(v)
	}
	if f, ok := jsNum(v); ok {
		return jsNumberString(f)
	}
	return fmt.Sprint(v)
}

func approvalFormatLimit(l ParsedLimit) string {
	base := jsNumberString(l.Amount)
	if l.Unit == "usd" {
		base = "$" + base
	}
	if l.PeriodMs == 0 {
		return base
	}
	hours := float64(l.PeriodMs) / 3_600_000
	var period string
	switch {
	case math.Mod(hours, 24) == 0 && hours >= 24:
		period = jsNumberString(hours/24) + "d"
	case hours >= 1:
		period = jsNumberString(hours) + "h"
	default:
		period = jsNumberString(math.Floor(float64(l.PeriodMs)/60_000+0.5)) + "m"
	}
	return base + "/" + period
}

func approvalSummarizeParams(params map[string]any, amountField string) string {
	if params == nil {
		return ""
	}
	if amountField != "" {
		if v, has := params[amountField]; has {
			return amountField + "=" + jsValueString(v) // String(v): an object is [object Object]
		}
	}
	keys := jsKeys(params)
	if len(keys) == 0 {
		return ""
	}
	if len(keys) > 4 {
		keys = keys[:4]
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + approvalJSString(params[k])
	}
	return strings.Join(parts, ", ")
}

func approvalSpec(agent *FacadeAgent, verb string) *CatalogAction {
	for i := range agent.Policy.Actions {
		if agent.Policy.Actions[i].Verb == verb {
			return &agent.Policy.Actions[i]
		}
	}
	return nil
}

// BuildGoalLineage derives the goal lineage of one intended action from data already present: the grant's goal_commit, the
// compiled policy (the delegated authority that admits the verb and its limit), the action and, when the caller reveals it, the
// plaintext goal, which is checked against the commitment with the agent's goal salt. Pure; signs nothing.
func BuildGoalLineage(agent *FacadeAgent, verb, resource string, params map[string]any, goal *string) GoalLineage {
	goalCommit := ""
	if env := ReadEnvelope(agent.Grant); env != nil {
		goalCommit, _ = env["goal_commit"].(string)
	}
	verified := false
	if goal != nil && goalCommit != "" && agent.GoalSalt != "" {
		if c, err := GoalCommitOf(*goal, agent.GoalSalt); err == nil && c == goalCommit {
			verified = true
		}
	}
	spec := approvalSpec(agent, verb)
	limit, hasLimit := agent.Policy.Limits[verb]

	goalLabel := "Pursue the grant’s committed goal"
	if goal != nil {
		goalLabel = "Pursue the goal: “" + *goal + "”"
	}
	goalDetail := ""
	switch {
	case goal != nil && verified:
		goalDetail = "verified: this goal opens the signed grant commitment"
	case goal != nil:
		goalDetail = "unverified: the revealed goal does not open the grant commitment"
	case goalCommit != "":
		goalDetail = "committed as " + goalCommit
	}
	authorityLabel := "Delegated authority to " + verb
	if hasLimit {
		authorityLabel += " (up to " + approvalFormatLimit(limit) + ")"
	}
	amountField, description := "", ""
	if spec != nil {
		amountField, description = spec.AmountField, spec.Description
	}
	chain := []LineageNode{
		{Kind: "goal", Label: goalLabel, Detail: goalDetail},
		{Kind: "authority", Label: authorityLabel, Detail: description},
		{Kind: "action", Label: verb + " " + resource, Detail: approvalSummarizeParams(params, amountField)},
	}
	because := "Approving " + verb + " on " + resource + ", authorized under the grant’s committed goal."
	if goal != nil {
		because = "Approving " + verb + " on " + resource + " because you asked to “" + *goal + "”."
	}
	return GoalLineage{Goal: goal, GoalCommit: goalCommit, GoalVerified: verified, Chain: chain, Because: because}
}

// DescribeGoalLineage flattens a lineage to plain text lines (for SMS, plain email, chat fallbacks).
func DescribeGoalLineage(l GoalLineage) []string {
	out := make([]string, len(l.Chain))
	for i, n := range l.Chain {
		if n.Detail != "" {
			out[i] = n.Label + " — " + n.Detail
		} else {
			out[i] = n.Label
		}
	}
	return out
}

func approvalRisk(agent *FacadeAgent, verb string, params map[string]any) float64 {
	clamp := func(x float64) float64 { return math.Max(0, math.Min(1, x)) }
	spec := approvalSpec(agent, verb)
	if agent.Policy.BudgetModel == "dollars" && spec != nil && spec.AmountField != "" {
		amt := jsToNumber(params[spec.AmountField])
		if kappa, _ := numOf(agent.Policy.RiskPolicy["kappa"]); !math.IsNaN(amt) && !math.IsInf(amt, 0) && kappa > 0 {
			return clamp(amt / kappa)
		}
	}
	if spec != nil {
		return clamp(spec.BlastRadius)
	}
	return 0.8
}

// ReviewAction reviews an intended action against the agent's grant. "auto" needs no human; "deny" means the grant's predicates
// or caveats forbid it (no approval can fix that offline); "step_up" is admissible but needs a tier-2 or tier-3 co-sign, unless a
// standing class approval covers it (then "auto").
func ReviewAction(agent *FacadeAgent, verb, resource string, params map[string]any, opts ReviewOptions) (rev Review) {
	now := time.Now().UnixMilli()
	if opts.Now != nil {
		now = *opts.Now
	}
	dr := agent.DryRunAt(verb, resource, params, now)
	if !dr.Allowed {
		reason := dr.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return Review{Kind: "deny", Reason: reason}
	}
	if dr.T <= 1 {
		return Review{Kind: "auto"}
	}
	if len(opts.Standing) > 0 && CoveredByAny(opts.Standing, verb, resource, now) {
		return Review{Kind: "auto"}
	}
	if opts.Renderer == nil && !opts.InsecureUnboundApproval {
		return Review{Kind: "deny", Reason: "approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true"}
	}
	var render map[string]any
	renderDigest := ""
	if opts.Renderer != nil {
		failed := func(msg string) Review {
			return Review{Kind: "deny", Reason: "approval render failed (fail closed): " + msg}
		}
		defer func() {
			if r := recover(); r != nil {
				rev = failed(clPanicText(r))
			}
		}()
		var err error
		if render, err = opts.Renderer(verb, resource, params); err != nil {
			return failed(err.Error())
		}
		if renderDigest, err = ApprovalRenderDigest(render); err != nil {
			return failed(err.Error())
		}
	}
	goalCommit := ""
	if env := ReadEnvelope(agent.Grant); env != nil {
		goalCommit, _ = env["goal_commit"].(string)
	}
	reason := dr.Reason
	if reason == "" {
		reason = "requires tier " + strconv.Itoa(dr.T) + " co-sign"
	}
	var nparams any
	if params != nil {
		n, err := normObj(params)
		if err != nil {
			return Review{Kind: "deny", Reason: "params are not JSON: " + err.Error()}
		}
		nparams = n
	}
	id, err := HashCanonical(map[string]any{"d": "atlas-pca/stepup/v1", "verb": verb, "resource": resource, "params": nparams, "at": int(now)})
	if err != nil {
		return Review{Kind: "deny", Reason: "approval request failed (fail closed): " + err.Error()}
	}
	req := &StepUpRequest{
		ID: id, Verb: verb, Resource: resource, Params: params, Tier: dr.T, Reason: reason, GoalCommit: goalCommit, Goal: opts.Goal,
		Lineage: BuildGoalLineage(agent, verb, resource, params, opts.Goal), R: approvalRisk(agent, verb, params), RequestedAt: now,
		Render: render, RenderDigest: renderDigest,
	}
	return Review{Kind: "step_up", Request: req}
}

// BatchReview reviews a batch of intended actions (the inbox's "N actions waiting").
func BatchReview(agent *FacadeAgent, calls []IntendedCall, opts ReviewOptions) []Review {
	out := make([]Review, len(calls))
	for i, c := range calls {
		out[i] = ReviewAction(agent, c.Verb, c.Resource, c.Params, opts)
	}
	return out
}

// PendingRequests is just the step-up requests of a batch of reviews (what the approver actually sees).
func PendingRequests(reviews []Review) []StepUpRequest {
	out := []StepUpRequest{}
	for _, r := range reviews {
		if r.Kind == "step_up" && r.Request != nil {
			out = append(out, *r.Request)
		}
	}
	return out
}

// ApproveClassOptions are the options of ApproveClass.
type ApproveClassOptions struct {
	TTLMs int64
	By    string
	// Now is the grant time in epoch ms (nil: the wall clock).
	Now      *int64
	Resource *string
}

// ApproveClass mints a standing class approval ("approve stripe.refund and gmail.send for the next 4 hours").
func ApproveClass(verbs []string, o ApproveClassOptions) (ClassApproval, error) {
	grantedAt := time.Now().UnixMilli()
	if o.Now != nil {
		grantedAt = *o.Now
	}
	sorted := append([]string(nil), verbs...)
	sort.Strings(sorted)
	vs := make([]any, len(sorted))
	for i, v := range sorted {
		vs[i] = v
	}
	var res any
	if o.Resource != nil {
		res = *o.Resource
	}
	id, err := HashCanonical(map[string]any{"d": "atlas-pca/class-approval/v1", "verbs": vs, "resource": res, "grantedAt": int(grantedAt), "by": o.By})
	if err != nil {
		return ClassApproval{}, err
	}
	return ClassApproval{ID: id, Verbs: append([]string{}, verbs...), Resource: o.Resource, GrantedAt: grantedAt, TTLMs: o.TTLMs, By: o.By}, nil
}

func approvalResourceMatches(pattern *string, resource string) bool {
	if pattern == nil || *pattern == "*" {
		return true
	}
	if strings.HasSuffix(*pattern, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(*pattern, "*"))
	}
	return *pattern == resource
}

// ClassApprovalCovers reports whether a standing approval still covers (verb, resource) at now.
func ClassApprovalCovers(a ClassApproval, verb, resource string, now int64) bool {
	if now < a.GrantedAt || now >= a.GrantedAt+a.TTLMs {
		return false
	}
	covered := false
	for _, v := range a.Verbs {
		if v == verb {
			covered = true
			break
		}
	}
	return covered && approvalResourceMatches(a.Resource, resource)
}

// CoveredByAny reports whether (verb, resource) is covered by any active standing approval.
func CoveredByAny(approvals []ClassApproval, verb, resource string, now int64) bool {
	for _, a := range approvals {
		if ClassApprovalCovers(a, verb, resource, now) {
			return true
		}
	}
	return false
}

// RecordDecision records a human's decision on a request (pure data for the audit trail). at nil is the wall clock.
func RecordDecision(request StepUpRequest, decision, by string, at *int64) ApprovalDecision {
	t := time.Now().UnixMilli()
	if at != nil {
		t = *at
	}
	return ApprovalDecision{RequestID: request.ID, Decision: decision, By: by, At: t}
}

// ApplyCosign applies a human co-sign to the trust budget: a partial recharge (rho per co-sign), or with full a recharge to bMax.
// It is the only thing that raises the budget, so the safety bound holds between two co-signs.
func ApplyCosign(budget TrustBudget, policy RiskPolicy, now float64, full bool) TrustBudget {
	if full {
		return RechargeFull(policy.BMax, now)
	}
	return budget.Recharge(policy.Rho, policy.BMax, now)
}

// TimeBox narrows a capability to expire ttlMs after now by appending an `expires` caveat signed by the holder: caveats are
// conjunctive and append-only, so this can only restrict. now nil is the wall clock.
func TimeBox(parent map[string]any, holder *KeyPair, ttlMs float64, now *float64) (map[string]any, error) {
	if holder == nil {
		return nil, errors.New("timeBox: a holder key is required")
	}
	t := float64(time.Now().UnixMilli())
	if now != nil {
		t = *now
	}
	// a fractional instant is kept as is (the strict canonicalizer decides what it accepts), never truncated
	return Attenuate(parent, []any{map[string]any{"type": "expires", "at": t + ttlMs}}, holder, nil)
}
