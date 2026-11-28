package pca

// OpenAI Agents guard for Proof-Carrying Authority: the SDK-independent policy, forwarding and step-up logic of the TypeScript
// @atlasauth/pca-openai-agents package over plain values. There is no Go OpenAI Agents SDK, so the tool and the run context are
// plain values here (a tool is an OATool; a run context is any JSON-shaped value or struct-free map).
//
//   - OAWithPcaTool / OAPcaTools: a tool call first REQUIRES a proof-carrying action (found in the run context), VERIFIES it
//     (fail closed: *OAToolDenied) and only then runs the original. Default mode "full": Authorize (an AuthorizeInput template) runs
//     the whole pipeline (the input must hash to the signed params, grant limits, revocation, single use). Mode "signature-only" with
//     Verify checks only the signature, chain, audience and window, which does NOT prove the grant permits the call.
//   - OAGuardrail (OAInputGuardrail, OAToolGuard): signature-only pre-filters that trip when the run or call carries no valid proof.
//   - step-up: OAReviewToolCall, OAPendingStepUps, OANeedsApproval, OAWithApproval.
//
// Differences from the reference: the grant-form verifier is OAGrantVerifier (openai_agents_grant.go), the agent-side wrapper is
// OAAttachPCA (openai_agents_attach.go), and there is no audience opt-out; the step-up review is the Review callback (the agent's review of an
// intended action).

import (
	"fmt"
	"strings"
)

// OAToolDenied is a guarded tool refusing to run. Kind: missing | malformed | verify | binding | policy | replay | revoked | config.
type OAToolDenied struct {
	Message string
	Verb    any
	Kind    string
	Checks  map[string]any
}

func (e *OAToolDenied) Error() string {
	return fmt.Sprintf("PCA tool denied (%s) for %s: %s", e.Kind, adapterJsString(e.Verb), e.Message)
}

// ---- proof sources ----

func oaIsRecord(v any) bool {
	switch v.(type) {
	case nil, string, bool, float64, int, int64:
		return false
	}
	if _, ok := jsNum(v); ok {
		return false
	}
	return true
}

func oaProofFromBag(bag any) any {
	if !oaIsRecord(bag) {
		return nil
	}
	if s, ok := adapterFirst(adapterGet(bag, "pca"), adapterGet(bag, "pcaProof"), adapterGet(bag, "pca_proof")).(string); ok {
		return s
	}
	return nil
}

// OAProofFromRunContext is the encoded PCActn from runContext.context (`pca` / `pcaProof` / `pca_proof`), then from runContext
// itself; nil when there is none.
func OAProofFromRunContext(_ any, runContext any) any {
	if p := oaProofFromBag(adapterGet(runContext, "context")); p != nil {
		return p
	}
	return oaProofFromBag(runContext)
}

// OAProvenanceFromRunContext is the call's provenance bundle: `pcaProvenance` / `pca_provenance` / `PCA-Provenance` on the
// context, then on the run context; nil when there is none.
func OAProvenanceFromRunContext(_ any, runContext any) any {
	for _, bag := range []any{adapterGet(runContext, "context"), runContext} {
		if !oaIsRecord(bag) {
			continue
		}
		if v := adapterFirst(adapterGet(bag, "pcaProvenance"), adapterGet(bag, "pca_provenance"), adapterGet(bag, "PCA-Provenance")); v != nil {
			return v
		}
	}
	return nil
}

// OAProofFromInputHeaders is a proof source reading a header value (default field "headers", header "PCA-Action") from the tool input.
func OAProofFromInputHeaders(field, header string) func(input, runContext any) any {
	if field == "" {
		field = "headers"
	}
	if header == "" {
		header = "PCA-Action"
	}
	return func(input, _ any) any {
		if !oaIsRecord(input) {
			return nil
		}
		bag := adapterGet(input, field)
		if !oaIsRecord(bag) {
			return nil
		}
		if s, ok := adapterGet(bag, header).(string); ok {
			return s
		}
		return nil
	}
}

// OAGuardrailProofFromContext is the guardrail default: the proof from the run context passed as args.context.
func OAGuardrailProofFromContext(args any) any {
	outer := adapterGet(args, "context")
	var inner any
	if oaIsRecord(outer) {
		inner = adapterGet(outer, "context")
	}
	if p := oaProofFromBag(inner); p != nil {
		return p
	}
	return oaProofFromBag(outer)
}

// OAProvenanceFrom is a provenance bundle from an object, a JSON text or a base64url header value; nil when it is none of them.
func OAProvenanceFrom(v any) any {
	if v == nil {
		return nil
	}
	if oaIsRecord(v) {
		return v
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	if b, err := StrictParse(s); err == nil {
		return b
	}
	text, err := gwDecodeHeader(s)
	if err != nil {
		return nil
	}
	if b, err := StrictParse(text); err == nil {
		return b
	}
	return nil
}

// ---- the proof pipeline ----

// OAVerdict is a signature-only verifier's answer.
type OAVerdict struct {
	Allow  bool
	Reason *string
	Checks map[string]any
}

type oaDecision struct {
	allow  bool
	kind   string
	reason string
	checks map[string]any
}

func oaToPCActn(raw any) (map[string]any, error) {
	switch t := raw.(type) {
	case map[string]any:
		return t, nil
	case string:
		if m, err := gwDecodePCActn(t); err == nil {
			return m, nil
		}
		text, err := gwDecodeHeader(t)
		if err != nil {
			return nil, err
		}
		return gwDecodePCActn(text)
	}
	return nil, fmt.Errorf("the proof is neither a PCActn object nor encoded text")
}

func oaVerbOf(p map[string]any) any { return adapterGet(adapterGet(p, "action"), "verb") }

func oaOr(v, fallback any) any {
	if v != nil {
		return v
	}
	return fallback
}

// oaAssertProof decodes, binds to verb (when non-empty), then verifies (or runs the full policy). A refusal is *OAToolDenied; any
// other error is the verifier's own failure and propagates.
func oaAssertProof(raw any, verify func(map[string]any) (OAVerdict, error), verb, label string, full func(map[string]any) oaDecision) (map[string]any, OAVerdict, error) {
	if raw == nil {
		return nil, OAVerdict{}, &OAToolDenied{Message: "no proof-carrying action present on the call", Verb: label, Kind: "missing"}
	}
	pcactn, err := oaToPCActn(raw)
	if err != nil {
		return nil, OAVerdict{}, &OAToolDenied{Message: "proof could not be decoded: " + err.Error(), Verb: label, Kind: "malformed"}
	}
	got := oaVerbOf(pcactn)
	if gs, _ := got.(string); verb != "" && (gs != verb || got == nil) {
		return nil, OAVerdict{}, &OAToolDenied{Message: fmt.Sprintf("proof is for '%s', not this tool's '%s'", adapterJsString(got), verb), Verb: oaOr(got, label), Kind: "binding"}
	}
	if full != nil {
		d := full(pcactn)
		if !d.allow {
			kind := d.kind
			if kind == "authn" {
				kind = "verify"
			}
			return nil, OAVerdict{}, &OAToolDenied{Message: d.reason, Verb: oaOr(got, label), Kind: kind, Checks: d.checks}
		}
		return pcactn, OAVerdict{Allow: true, Checks: d.checks}, nil
	}
	var res OAVerdict
	if verify == nil {
		reason := "no verifier configured"
		res = OAVerdict{Reason: &reason, Checks: map[string]any{}}
	} else if res, err = verify(pcactn); err != nil {
		return nil, OAVerdict{}, err
	}
	if !res.Allow {
		reason := "verification failed"
		if res.Reason != nil {
			reason = *res.Reason
		}
		return nil, OAVerdict{}, &OAToolDenied{Message: reason, Verb: oaOr(got, label), Kind: "verify", Checks: res.Checks}
	}
	return pcactn, res, nil
}

// oaDecisionOf maps an AuthorizeResult to the guard's kinds: config (missing components) | authn (401) | revoked | replay | policy.
func oaDecisionOf(r AuthorizeResult) oaDecision {
	checks := map[string]any{}
	for k, v := range r.Checks {
		checks[k] = v
	}
	if r.Allow {
		return oaDecision{allow: true, checks: checks}
	}
	kind := "policy"
	switch {
	case len(r.Missing) > 0:
		kind = "config"
	case r.Status == 401:
		kind = "authn"
	case r.Checks["revocation"] == "fail":
		kind = "revoked"
	case r.Checks["replay"] == "fail":
		kind = "replay"
	}
	reason := r.Reason
	if reason == "" {
		reason = "denied"
	}
	return oaDecision{kind: kind, reason: reason, checks: checks}
}

// ---- the execution guard ----

// OATool is a tool: a name, the call and any further fields (kept untouched).
type OATool struct {
	Name    string
	Execute func(input any, runContext any) (any, error)
	// OnInvokeTool is the SDK's text form: the model's arguments arrive as a raw JSON string (or bytes). When set it is the call that
	// is guarded (the proof source sees the parsed arguments, nil when they are not JSON); Execute is then ignored.
	OnInvokeTool  func(runContext any, raw any) (any, error)
	NeedsApproval func(runContext any, input any) (bool, error)
	Extra         map[string]any
}

// OARecorder records a tool result as untrusted tool output (a *ProvenanceRecorder is one).
type OARecorder interface {
	Tool(name string, output any) (map[string]any, error)
}

// OAToolOptions configures OAWithPcaTool. Mode is "full" (default) or "signature-only". Verify is the signature-only verifier; Authorize
// is the full-mode AuthorizeInput template (its Audience, Operation, Now and ProvenanceBundle are filled per call). Operation maps a call
// to the operation, or Verb + Resource name it. Audience (a string, used by the full mode) is required there. Require is the proof
// source (default OAProofFromRunContext); Provenance the provenance source. AudienceSet records that Audience was given at all.
type OAToolOptions struct {
	Mode        string
	Verify      func(pcactn map[string]any) (OAVerdict, error)
	Authorize   *AuthorizeInput
	Operation   func(input, runContext any) (*Operation, error)
	Verb        string
	Resource    string
	Audience    *string
	AudienceSet bool
	Require     func(input, runContext any) any
	Provenance  func(input, runContext any) any
	Recorder    OARecorder
	OnDeny      func(err *OAToolDenied, input any)
	OnVerified  func(result OAVerdict, pcactn map[string]any, input any)
	Now         func() int64
}

func oaFullPolicy(o *OAToolOptions) (func(pcactn map[string]any, input, runContext any) oaDecision, error) {
	mode := o.Mode
	if mode == "" {
		mode = "full"
	}
	if mode != "full" && mode != "signature-only" {
		return nil, fmt.Errorf("withPcaTool: unknown mode '%s'", mode)
	}
	if mode == "signature-only" {
		if o.Authorize != nil {
			return nil, fmt.Errorf("withPcaTool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'")
		}
		if o.Verify == nil {
			return nil, fmt.Errorf("withPcaTool: mode 'signature-only' needs `verify`")
		}
		return nil, nil
	}
	if o.Authorize == nil {
		return nil, fmt.Errorf("withPcaTool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only")
	}
	if o.Verify != nil {
		return nil, fmt.Errorf("withPcaTool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`")
	}
	audience := ""
	if o.Audience != nil {
		audience = *o.Audience
	}
	tmpl := *o.Authorize
	tmpl.Audience = audience
	missing := MissingAuthorizeComponents(tmpl)
	if o.Operation == nil && (o.Verb == "" || o.Resource == "") {
		missing = append(missing, "operation (or the guard's verb and resource)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("withPcaTool: full policy mode is missing %s", strings.Join(missing, ", "))
	}
	prov := o.Provenance
	if prov == nil {
		prov = OAProvenanceFromRunContext
	}
	return func(pcactn map[string]any, input, runContext any) oaDecision {
		var op Operation
		if o.Operation != nil {
			p, err := o.Operation(input, runContext)
			if err != nil || p == nil {
				return oaDecision{kind: "policy", reason: "authorization error (fail closed): operation"}
			}
			op = *p
		} else {
			params, _ := input.(map[string]any)
			if params == nil {
				params = map[string]any{}
			}
			op = Operation{Verb: o.Verb, Resource: o.Resource, Params: params}
		}
		a := adapterGet(pcactn, "action")
		verb, res := adapterGet(a, "verb"), adapterGet(a, "resource")
		if vs, _ := verb.(string); vs != op.Verb || verb == nil || (op.Resource != "" && res != any(op.Resource)) {
			want := op.Verb
			if op.Resource != "" {
				want = op.Verb + " on " + op.Resource
			}
			return oaDecision{kind: "binding", reason: fmt.Sprintf("the proof is for %s on %s, but this call is %s", adapterJsString(verb), adapterJsString(res), want)}
		}
		in := tmpl
		in.Operation = &op
		if o.Now != nil {
			in.Now = o.Now()
		}
		if b := OAProvenanceFrom(prov(input, runContext)); b != nil {
			in.ProvenanceBundle = b
		}
		return oaDecisionOf(Authorize(pcactn, in))
	}, nil
}

// OAWithPcaTool is a copy of tool whose every call first requires and verifies a proof (see the file doc); every other field is kept.
// A configuration error is returned here, not at call time.
func OAWithPcaTool(tool *OATool, o OAToolOptions) (*OATool, error) {
	source := o.Require
	if source == nil {
		source = OAProofFromRunContext
	}
	label := o.Verb
	if label == "" {
		label = tool.Name
	}
	if label == "" {
		label = "(tool)"
	}
	full, err := oaFullPolicy(&o)
	if err != nil {
		return nil, err
	}
	guarded := func(input any, rawContext any, call func() (any, error)) (any, error) {
		runContext := rawContext // a missing run context reads as {} for the proof source; the tool gets what it was given
		if runContext == nil {
			runContext = map[string]any{}
		}
		var fullFn func(map[string]any) oaDecision
		if full != nil {
			fullFn = func(p map[string]any) oaDecision { return full(p, input, runContext) }
		}
		pcactn, verified, err := oaAssertProof(source(input, runContext), o.Verify, o.Verb, label, fullFn)
		if err != nil {
			if d, ok := err.(*OAToolDenied); ok && o.OnDeny != nil {
				o.OnDeny(d, input)
			}
			return nil, err
		}
		if o.OnVerified != nil {
			o.OnVerified(verified, pcactn, input)
		}
		out, err := call()
		if err != nil {
			return nil, err
		}
		if o.Recorder != nil {
			name := label
			if v := oaVerbOf(pcactn); v != nil {
				name = adapterJsString(v)
			}
			if _, err := o.Recorder.Tool(name, out); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	cp := *tool
	if tool.OnInvokeTool != nil {
		cp.OnInvokeTool = func(rawContext any, raw any) (any, error) {
			return guarded(oaParseArgs(raw), rawContext, func() (any, error) { return tool.OnInvokeTool(rawContext, raw) })
		}
		return &cp, nil
	}
	cp.Execute = func(input any, rawContext any) (any, error) {
		return guarded(input, rawContext, func() (any, error) {
			if tool.Execute == nil {
				return nil, fmt.Errorf("withPcaTool: the wrapped tool has no execute()")
			}
			return tool.Execute(input, rawContext)
		})
	}
	return &cp, nil
}

// oaParseArgs reads the SDK's raw argument text as JSON (nil when it is not JSON); any other value is the input itself.
func oaParseArgs(raw any) any {
	var b []byte
	switch t := raw.(type) {
	case string:
		b = []byte(t)
	case []byte:
		b = t
	default:
		return raw
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil
	}
	return v
}

// oaMergeOptions applies a per-tool override over the shared options: a per-tool Authorize (or Verify) replaces the shared mode (the
// two are exclusive); the other members take the override when set, else the shared value.
func oaMergeOptions(base OAToolOptions, over *OAToolOptions) OAToolOptions {
	if over == nil {
		return base
	}
	ownMode := over.Authorize != nil
	var out OAToolOptions
	switch {
	case ownMode:
		out.Authorize, out.Operation = over.Authorize, over.Operation
		out.Verify = nil
	case over.Verify != nil:
		out.Verify = over.Verify
	default:
		out.Verify, out.Authorize, out.Operation = base.Verify, base.Authorize, base.Operation
	}
	out.Mode = over.Mode
	if out.Mode == "" && !ownMode {
		out.Mode = base.Mode
	}
	out.Require, out.Provenance = over.Require, over.Provenance
	if out.Require == nil {
		out.Require = base.Require
	}
	if out.Provenance == nil {
		out.Provenance = base.Provenance
	}
	if out.Verb = over.Verb; out.Verb == "" {
		out.Verb = base.Verb
	}
	if out.Resource = over.Resource; out.Resource == "" {
		out.Resource = base.Resource
	}
	if out.OnDeny = over.OnDeny; out.OnDeny == nil {
		out.OnDeny = base.OnDeny
	}
	if out.OnVerified = over.OnVerified; out.OnVerified == nil {
		out.OnVerified = base.OnVerified
	}
	if out.Recorder = over.Recorder; out.Recorder == nil {
		out.Recorder = base.Recorder
	}
	if out.Now = over.Now; out.Now == nil {
		out.Now = base.Now
	}
	if over.AudienceSet {
		out.Audience, out.AudienceSet = over.Audience, true
	} else {
		out.Audience, out.AudienceSet = base.Audience, base.AudienceSet
	}
	return out
}

// OAPcaTools guards tools (keyed by Name) with shared options. per[name] overrides them for one tool, only (nil = all) limits the
// guarded set; every other tool passes through unchanged (the same pointer).
func OAPcaTools(tools []*OATool, per map[string]*OAToolOptions, only []string, o OAToolOptions) ([]*OATool, error) {
	out := make([]*OATool, 0, len(tools))
	for _, t := range tools {
		if only != nil {
			listed := false
			for _, n := range only {
				listed = listed || n == t.Name
			}
			if !listed {
				out = append(out, t)
				continue
			}
		}
		g, err := OAWithPcaTool(t, oaMergeOptions(o, per[t.Name]))
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// ---- guardrails ----

// OAGuardrail is a signature-only proof gate.
type OAGuardrail struct {
	Name   string
	source func(args any) any
	verify func(map[string]any) (OAVerdict, error)
	verb   string
	label  string
}

// OAGuardrailResult is a guardrail's verdict.
type OAGuardrailResult struct {
	TripwireTriggered bool
	OutputInfo        map[string]any
}

func oaGuardrail(def, label string, verify func(map[string]any) (OAVerdict, error), require func(args any) any, verb, name string) *OAGuardrail {
	if name == "" {
		name = def
	}
	if require == nil {
		require = OAGuardrailProofFromContext
	}
	if verb != "" {
		label = verb
	}
	return &OAGuardrail{Name: name, source: require, verify: verify, verb: verb, label: label}
}

// OAInputGuardrail trips at the top of a run when the run context carries no valid proof.
func OAInputGuardrail(verify func(map[string]any) (OAVerdict, error), require func(args any) any, verb, name string) *OAGuardrail {
	return oaGuardrail("pca-input-guardrail", "(run)", verify, require, verb, name)
}

// OAToolGuard is the same gate scoped to a tool call; prefer OAWithPcaTool with Authorize for the real check.
func OAToolGuard(verify func(map[string]any) (OAVerdict, error), require func(args any) any, verb, name string) *OAGuardrail {
	return oaGuardrail("pca-tool-guard", "(run)", verify, require, verb, name)
}

// Execute runs the gate on args ({agent?, input?, context?}). A verifier failure is returned as an error (not a verdict).
func (g *OAGuardrail) Execute(args any) (OAGuardrailResult, error) {
	pcactn, _, err := oaAssertProof(g.source(args), g.verify, g.verb, g.label, nil)
	if err != nil {
		d, ok := err.(*OAToolDenied)
		if !ok {
			return OAGuardrailResult{}, err
		}
		info := map[string]any{"kind": d.Kind, "verb": d.Verb, "reason": d.Error()}
		if d.Checks != nil {
			info["checks"] = d.Checks
		}
		return OAGuardrailResult{TripwireTriggered: true, OutputInfo: info}, nil
	}
	return OAGuardrailResult{OutputInfo: map[string]any{"verb": oaVerbOf(pcactn)}}, nil
}

// ---- step-up ----

// OAReviewOptions configures OAReviewToolCall. Intent maps a call to {verb, resource, params?} (nil = unguarded, `auto`); Review
// returns {kind: auto} | {kind: deny, reason} | {kind: step_up, request} for an intended action; Opts (now, goal, standing,
// renderer, insecure_unbound_approval; nil members dropped) is handed to Review.
type OAReviewOptions struct {
	Intent func(tool string, input any) map[string]any
	Review func(agent any, verb, resource, params any, opts map[string]any) (map[string]any, error)
	Opts   map[string]any
}

// OAReviewToolCall reviews one intended tool call; the result is {tool, review}.
func OAReviewToolCall(agent any, tool string, input any, o OAReviewOptions) (map[string]any, error) {
	if o.Intent == nil {
		return nil, fmt.Errorf("reviewToolCall: pass `intent`")
	}
	mapped := o.Intent(tool, input)
	if mapped == nil {
		return map[string]any{"tool": tool, "review": map[string]any{"kind": "auto"}}, nil
	}
	if o.Review == nil {
		return nil, fmt.Errorf("reviewToolCall: pass `review`, the agent's review of an intended action")
	}
	params := mapped["params"]
	if params == nil {
		params = input
	}
	opts := map[string]any{}
	for k, v := range o.Opts {
		if v != nil {
			opts[k] = v
		}
	}
	r, err := o.Review(agent, mapped["verb"], mapped["resource"], params, opts)
	if err != nil {
		return nil, err
	}
	return map[string]any{"tool": tool, "review": r}, nil
}

// OAPendingStepUps are the step-up requests among OAReviewToolCall results (auto and deny filtered out).
func OAPendingStepUps(reviews []any) []any {
	out := []any{}
	for _, r := range reviews {
		if adapterGet(adapterGet(r, "review"), "kind") == "step_up" {
			out = append(out, map[string]any{"tool": adapterGet(r, "tool"), "request": adapterGet(adapterGet(r, "review"), "request")})
		}
	}
	return out
}

// OANeedsApprovalOptions configures OANeedsApproval: auto -> false; a step-up not yet co-signed -> OnStepUp and true (the run
// interrupts); an already approved step-up -> false; deny -> true unless DenyRejects (the approver then rejects it).
type OANeedsApprovalOptions struct {
	OAReviewOptions
	ToolName    string
	Approved    func(request any) bool
	OnStepUp    func(step map[string]any)
	DenyRejects bool
}

// OANeedsApproval is the `needs_approval` callback of a tool from risk review.
func OANeedsApproval(agent any, o OANeedsApprovalOptions) func(runContext, input any) (bool, error) {
	name := o.ToolName
	if name == "" {
		name = "(tool)"
	}
	return func(_, input any) (bool, error) {
		res, err := OAReviewToolCall(agent, name, input, o.OAReviewOptions)
		if err != nil {
			return false, err
		}
		r, _ := res["review"].(map[string]any)
		switch r["kind"] {
		case "auto":
			return false, nil
		case "deny":
			return !o.DenyRejects, nil
		}
		if o.Approved != nil && o.Approved(r["request"]) {
			return false, nil
		}
		if o.OnStepUp != nil {
			o.OnStepUp(map[string]any{"tool": name, "request": r["request"]})
		}
		return true, nil
	}
}

// OAWithApproval is a copy of tool with NeedsApproval from PCA risk review (the tool's name seeds the intent lookup unless
// o.ToolName is set).
func OAWithApproval(tool *OATool, agent any, o OANeedsApprovalOptions) *OATool {
	if o.ToolName == "" {
		o.ToolName = tool.Name
	}
	cp := *tool
	cp.NeedsApproval = OANeedsApproval(agent, o)
	return &cp
}
