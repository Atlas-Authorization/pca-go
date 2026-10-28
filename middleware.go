package pca

// net/http middleware for Proof-Carrying Authority. This layers transport concerns (where the
// PCActn comes from, how failures surface) on top of the existing offline verifier,
// VerifyPCActnCore; it does NOT re-implement any canonicalization, Ed25519 or chain logic.
//
// Note on types: this package models both the PCActn and a capability/grant as map[string]any
// (see ValidateWireV2 / VerifyChain), so the middleware mirrors that. RequirePCAOptions.ResolveGrant
// therefore returns a *grant capability* as map[string]any and FromContext returns the PCActn as
// map[string]any rather than a dedicated struct.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"
)

// PCAHeader is the request header carrying a base64url(JSON) PCActn.
const PCAHeader = "PCA-Action"

// ctxKey is the unexported context key under which a successful verification is stashed.
type ctxKey struct{}

// contextValue holds what a passing request carries to downstream handlers.
type contextValue struct {
	verdict *Verdict
	pcactn  map[string]any
	authz   *AuthorizeResult
}

// RequirePCAOptions configures the RequirePCA middleware.
//
//   - Audience is this resource server / instance id; it is checked against the PCActn's signed `aud`.
//   - ResolveGrant maps a PCActn's grant_ref to the root grant capability (the chain is rooted at it).
//     Returning an error or a nil grant is treated as an unknown grant (HTTP 401).
//   - Now returns the current time in epoch milliseconds; nil defaults to time.Now().UnixMilli().
//   - Intent is the optional Intent Layer M2 policy (nil = none; see IntentPolicy).
//   - IntentV2 optionally returns the Intent Layer v2 verifier state for this request (plaintext params, accepted
//     schemas, session root and grants, accumulator state, layers, W-B artifacts and policy); nil = none. See
//     IntentV2Context.
//   - Authorize configures the default guard (0.5): every request goes through Authorize, which binds the proof to the
//     executed operation and checks envelope predicates, root and delegated caveats, revocation and the replay counter,
//     all required. nil = an empty option set: every request is refused with 403 authorize_config naming what is
//     missing, never silently downgraded. See AuthorizeOptions.
//   - SignatureOnly (0.5) is the explicit opt-in to verify the signature, chain and freshness only (the core verifier):
//     no policy, no replay, no revocation, no operation binding. Giving it together with Authorize panics at construction.
type RequirePCAOptions struct {
	Audience      string
	ResolveGrant  func(grantRef string) (map[string]any, error)
	Now           func() int64
	Intent        *IntentPolicy
	IntentV2      func(r *http.Request, pcactn map[string]any) *IntentV2Context
	Authorize     *AuthorizeOptions
	SignatureOnly bool
	// FreshAt returns the consistency-token policy for this request (nil = none). When the PCActn has no `fresh_at` member and
	// the policy carries no side-carried token, the `pca-fresh-at` header (JSON) is read as one; an unparseable header is a
	// null token (bad_token), never a missing one.
	FreshAt func(r *http.Request, pcactn map[string]any) *FreshAtPolicy
}

func (o RequirePCAOptions) freshAt(r *http.Request, p map[string]any) *FreshAtPolicy {
	if o.FreshAt == nil {
		return nil
	}
	fp := o.FreshAt(r, p)
	if _, has := p["fresh_at"]; fp == nil || has || fp.HasSideCarried {
		return fp
	}
	if hs := r.Header.Values("pca-fresh-at"); len(hs) > 0 {
		c := *fp
		c.HasSideCarried = true
		if v, err := StrictParse(hs[0]); err == nil {
			c.SideCarried = v
		}
		return &c
	}
	return fp
}

// PlanFromContext is the AuthorizeOptions.Plan value that turns the single-step plan off: AuthorizeOptions.Context must
// then return the principal-authorized plan (Plan with PlanAuthorized true).
const PlanFromContext = "context"

// AuthorizeOptions are the Authorize components RequirePCA adds on top of its Audience / ResolveGrant / Now / Intent /
// IntentV2 when it runs in authorize mode.
//
//   - StateStore, IsRevoked: as in AuthorizeInput (both required: a missing one denies every request with 403).
//   - Plan: "" (default) = PlanSingleStep; PlanFromContext = the plan must come from Context.
//   - Context: the per-request AuthorizeContext (nil = none); an error denies.
//   - Require: extra check names that must pass.
//   - Operation maps the request to the operation the handler will execute (from your routing and the request body,
//     never from the PCActn). body is the request body (at most MaxJSONChars bytes; the handler still reads it). No
//     mapping, an error, a panic, a nil operation or a larger body denies (403) before the handler runs.
type AuthorizeOptions struct {
	StateStore StateStore
	IsRevoked  func(pcactn, grant map[string]any) (bool, error)
	Plan       string
	Context    func(r *http.Request, pcactn map[string]any) (*AuthorizeContext, error)
	Require    []string
	Operation  func(r *http.Request, body []byte) (*Operation, error)
	// EscalationPrincipals pins the Ed25519 keys whose EscalationAnswers count (header PCA-Escalation-Answer: strict
	// base64url JSON, or the JSON body member escalation_answer); EscalationPinned pins principals that sign with a
	// post-quantum / hybrid suite. Both empty: every escalate is refused (403, decision "escalate"). With any pinned,
	// StateStore must implement LastStore: RequirePCA panics at construction otherwise.
	EscalationPrincipals []string
	EscalationPinned     []PinnedSigner
	// EscalationRender (K7) recomputes H(R) of the approval render from the executed params and the verifier's own definition;
	// InsecureUnboundApproval is the documented INSECURE opt-out of the default rule that an answer is admitted only when it is
	// signed over a recomputed render (see AuthorizeInput).
	EscalationRender        func(pcactn map[string]any) string
	InsecureUnboundApproval bool
	// RevocationStaleness / RevocationState / GuardianPublic / GuardianPins: the revocation staleness policy (T9), as in
	// AuthorizeInput. Off unless RevocationStaleness is set; then RevocationState is required (a missing one denies).
	RevocationStaleness *RevocationStalenessPolicy
	// RevocationProof / RevocationIds: per-capability non-membership proofs (see AuthorizeInput).
	RevocationProof func(r *http.Request, id string, pcactn map[string]any) any
	RevocationIds   func(r *http.Request, pcactn map[string]any) []string
	// Plans is the plan registry (T10), as AuthorizeInput.Plans.
	Plans *PlanRegistry
	// Workflow (K5, C-308; nil = off) is the workflow admission gate of AuthorizeInput. The step this request is comes from
	// WorkflowStep when set, else from the JSON body member `workflow` {commitment, receipts, step, units, goal_digest}, else none
	// (refused when Workflow.Required). A present but malformed body member is a step that AdmitStep denies.
	Workflow     *WorkflowOption
	WorkflowStep func(r *http.Request, pcactn map[string]any) *WorkflowCall
	// RequireAssurance / AssuranceHooks: the high-assurance policy (T8), as in AuthorizeInput.
	RequireAssurance *AssuranceRequirement
	AssuranceHooks   AssuranceHooks
	RevocationState  func(r *http.Request, pcactn, grant map[string]any) (*RevocationState, error)
	GuardianPublic   string
	GuardianPins     map[string]string
	// K1 returns the caveat language v2 input for this request (the pins, the verified SPIFFE ID, the history, ...); nil = off,
	// K1 caveats stay refused. Discharges and a narrow block are read from the PCA-Discharges / PCA-Narrow headers (see
	// PresentedK1) and merged under what K1 returns: the members K1 sets win, unreadable headers are no discharges. UsesStore
	// spends max_uses. See AuthorizeInput.K1.
	K1        func(r *http.Request, pcactn map[string]any) (*K1Input, error)
	UsesStore StateStore
}

// FromContext returns the Verdict and the verified PCActn stashed by a passing RequirePCA
// middleware, and whether one was present.
func FromContext(ctx context.Context) (*Verdict, map[string]any, bool) {
	cv, ok := ctx.Value(ctxKey{}).(*contextValue)
	if !ok || cv == nil {
		return nil, nil, false
	}
	return cv.verdict, cv.pcactn, true
}

// AuthorizationFromContext returns the AuthorizeResult stashed by a passing RequirePCA in authorize mode (its
// Operation is the operation the request was authorized for), and whether one was present.
func AuthorizationFromContext(ctx context.Context) (*AuthorizeResult, bool) {
	cv, ok := ctx.Value(ctxKey{}).(*contextValue)
	if !ok || cv == nil || cv.authz == nil {
		return nil, false
	}
	return cv.authz, true
}

// ErrPCAHeader is returned by DecodePCAHeader for a value that is not strict unpadded base64url of UTF-8 text.
var ErrPCAHeader = errors.New("PCA-Action header is not strict unpadded base64url of UTF-8 text")

// DecodePCAHeader reverses the PCA-Action header encoding: header value -> the encoded PCActn JSON text.
//
// STRICT (0.4.1), exactly the profile's base64url rule: non-empty; unpadded RFC 4648 section 5 alphabet only
// (A-Z a-z 0-9 - _), no '=', no '+' or '/', no whitespace anywhere (nothing is trimmed), length mod 4 != 1,
// zero unused trailing bits; then the bytes must be valid UTF-8 (no overlong forms, surrogates or truncated
// sequences). A leading BOM is kept (the strict JSON parser then refuses it). Nothing is normalized, so one
// PCActn has exactly one header spelling. Any failure returns ("", ErrPCAHeader).
func DecodePCAHeader(value string) (string, error) {
	if value == "" {
		return "", ErrPCAHeader
	}
	b, ok := DecodeB64uStrict(value, -1)
	if !ok || !utf8.Valid(b) {
		return "", ErrPCAHeader
	}
	return string(b), nil
}

// extractPCActn pulls the PCActn from the PCA-Action header (strict base64url -> JSON, see DecodePCAHeader) or, failing a header,
// from a JSON request body of the shape {"pcactn": {...}}. Reading the body is non-destructive: it is
// buffered and restored so downstream handlers still see it. The returned reason is only meaningful
// when ok is false.
func extractPCActn(r *http.Request) (pcactn map[string]any, reason string, ok bool) {
	if h := r.Header.Get(PCAHeader); h != "" {
		raw, derr := DecodePCAHeader(h)
		if derr != nil {
			return nil, "PCA-Action header is not valid base64url", false
		}
		p, err := ParsePCActn(raw)
		if err != nil {
			return nil, "PCA-Action header is not a valid PCActn JSON object", false
		}
		return p, "", true
	}

	if r.Body == nil || r.Body == http.NoBody {
		return nil, "no PCActn presented (missing PCA-Action header and request body)", false
	}

	buf, err := io.ReadAll(io.LimitReader(r.Body, int64(MaxJSONChars)+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf)) // restore for downstream handlers
	if err != nil || len(buf) == 0 {
		return nil, "no PCActn presented (missing PCA-Action header and request body)", false
	}

	v, perr := StrictParse(string(buf))
	if perr != nil {
		return nil, "request body is not valid strict JSON", false
	}
	m, isObj := v.(map[string]any)
	if !isObj {
		return nil, "request body is not a JSON object", false
	}
	pv, has := m["pcactn"]
	if !has {
		return nil, "request body has no 'pcactn' field", false
	}
	p, isObj := pv.(map[string]any)
	if !isObj {
		return nil, "'pcactn' is not a JSON object", false
	}
	return p, "", true
}

// writePCAError writes a JSON error body plus an RFC-6750-shaped WWW-Authenticate challenge. desc MUST be one of the
// guard's own fixed strings: it is echoed into the challenge header. Request-derived text (a verdict reason, a verifier
// error) goes through writePCAErrorReason instead.
func writePCAError(w http.ResponseWriter, status int, code, desc string, verdict *Verdict) {
	writePCAErr(w, status, code, desc, desc, verdict)
}

// writePCAErrorReason is writePCAError for a request-derived reason: the reason is surfaced only in the JSON body
// (encoded), never in the WWW-Authenticate header (header injection; TS requirePCA puts no reason in its challenge).
func writePCAErrorReason(w http.ResponseWriter, status int, code, reason string, verdict *Verdict) {
	writePCAErr(w, status, code, "", reason, verdict)
}

func writePCAErr(w http.ResponseWriter, status int, code, headerDesc, desc string, verdict *Verdict) {
	challenge := fmt.Sprintf("PCA realm=%q, error=%q", "pca", code)
	if headerDesc != "" {
		challenge += fmt.Sprintf(", error_description=%q", headerDesc)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	body := map[string]any{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	if verdict != nil {
		if verdict.Reason != "" {
			body["reason"] = verdict.Reason
		}
		body["checks"] = verdict.Checks
	}
	_ = json.NewEncoder(w).Encode(body)
}

// RequirePCA returns standard net/http middleware that requires a valid Proof-Carrying Authority
// action on every request it guards.
//
// On success the Verdict and PCActn are placed in the request context (read them with FromContext)
// and the next handler runs. On failure it responds with a JSON body and a WWW-Authenticate: PCA
// challenge, using status:
//
//   - 401 when no PCActn is presented, it cannot be decoded, its grant_ref is not a non-empty string, or it is unknown;
//     (a resolver error is treated as unknown: fail closed);
//   - 403 when a well-formed PCActn resolves a grant but fails verification (the reason is in the JSON body only,
//     never in the WWW-Authenticate header).
//
// The default is the full Authorize path (see RequirePCAOptions.Authorize); SignatureOnly opts into the core verifier alone.
// It panics when both are given (a configuration error).
func RequirePCA(opts RequirePCAOptions) func(http.Handler) http.Handler {
	if opts.SignatureOnly && opts.Authorize != nil {
		panic("pca: RequirePCA: SignatureOnly and Authorize are mutually exclusive")
	}
	if az := opts.Authorize; az != nil && az.StateStore != nil && len(az.EscalationPrincipals)+len(az.EscalationPinned) > 0 {
		if _, ok := az.StateStore.(LastStore); !ok {
			panic("pca: RequirePCA: Authorize.EscalationPrincipals needs a StateStore that implements LastStore (an escalation answer is bound to the holder's history head)")
		}
	}
	now := opts.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return func(next http.Handler) http.Handler {
		if !opts.SignatureOnly {
			return authorizeHandler(opts, now, next)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pcactn, reason, ok := extractPCActn(r)
			if !ok {
				writePCAError(w, http.StatusUnauthorized, "invalid_request", reason, nil)
				return
			}

			grantRef, _ := pcactn["grant_ref"].(string)
			if grantRef == "" {
				writePCAError(w, http.StatusUnauthorized, "invalid_request", "PCActn has no grant_ref", nil)
				return
			}
			if opts.ResolveGrant == nil {
				writePCAError(w, http.StatusUnauthorized, "invalid_request", "no grant resolver configured", nil)
				return
			}
			grant, err := opts.ResolveGrant(grantRef)
			if err != nil || grant == nil {
				writePCAError(w, http.StatusUnauthorized, "unknown_grant", "grant_ref does not resolve to a known grant", nil)
				return
			}

			vopts := VerifyOptions{Intent: opts.Intent, FreshAt: opts.freshAt(r, pcactn)}
			if opts.IntentV2 != nil {
				vopts.IntentV2 = opts.IntentV2(r, pcactn)
			}
			verdict, verr := VerifyPCActnCoreWith(pcactn, grant, now(), opts.Audience, vopts)
			if verr != nil {
				writePCAErrorReason(w, http.StatusForbidden, "verification_error", verr.Error(), nil)
				return
			}
			if !verdict.Allow {
				writePCAErrorReason(w, http.StatusForbidden, "insufficient_authority", verdict.Reason, &verdict)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKey{}, &contextValue{verdict: &verdict, pcactn: pcactn})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authorizeHandler is RequirePCA in authorize mode: the PCActn is extracted as in the default mode (401 when absent or
// undecodable), the operation is mapped from the request, and Authorize decides before the handler runs.
func authorizeHandler(opts RequirePCAOptions, now func() int64, next http.Handler) http.Handler {
	az := opts.Authorize
	if az == nil {
		az = &AuthorizeOptions{}
	}
	plan := az.Plan
	switch plan {
	case "":
		plan = PlanSingleStep
	case PlanFromContext:
		plan = ""
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		bodyOK := true
		if r.Body != nil && r.Body != http.NoBody {
			buf, err := io.ReadAll(io.LimitReader(r.Body, int64(MaxJSONChars)+1))
			_ = r.Body.Close()
			body, bodyOK = buf, err == nil && len(buf) <= MaxJSONChars
		}
		restore := func() {
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
		restore()
		pcactn, reason, ok := extractPCActn(r)
		if !ok {
			writePCAError(w, http.StatusUnauthorized, "invalid_request", reason, nil)
			return
		}
		var op *Operation
		if az.Operation != nil && bodyOK {
			restore()
			op = mapOperation(az.Operation, r, body)
		}
		in := AuthorizeInput{Operation: op, Audience: opts.Audience, ResolveGrant: opts.ResolveGrant,
			StateStore: az.StateStore, IsRevoked: az.IsRevoked, Now: now(), Plan: plan, Intent: opts.Intent, FreshAt: opts.freshAt(r, pcactn),
			Require: az.Require, EscalationPrincipals: az.EscalationPrincipals, EscalationPinned: az.EscalationPinned,
			EscalationRender: az.EscalationRender, InsecureUnboundApproval: az.InsecureUnboundApproval}
		if len(in.escalationPins()) > 0 {
			in.EscalationAnswer = extractEscalationAnswer(r, body, bodyOK)
		}
		in.Plans, in.RequireAssurance, in.AssuranceHooks = az.Plans, az.RequireAssurance, az.AssuranceHooks
		in.RevocationStaleness, in.GuardianPublic, in.GuardianPins = az.RevocationStaleness, az.GuardianPublic, az.GuardianPins
		if az.RevocationProof != nil {
			in.RevocationProof = func(id string, p map[string]any) any { return az.RevocationProof(r, id, p) }
		}
		if az.RevocationIds != nil {
			in.RevocationIds = func(p map[string]any) []string { return az.RevocationIds(r, p) }
		}
		if az.RevocationState != nil {
			in.RevocationState = func(p, g map[string]any) (*RevocationState, error) { return az.RevocationState(r, p, g) }
		}
		if az.Context != nil {
			in.Context = func(p map[string]any) (*AuthorizeContext, error) { return az.Context(r, p) }
		}
		if opts.IntentV2 != nil {
			in.IntentV2 = func(p map[string]any) (*IntentV2Context, error) { return opts.IntentV2(r, p), nil }
		}
		if az.K1 != nil {
			in.K1 = func(p map[string]any) (*K1Input, error) {
				own, err := az.K1(r, p)
				if err != nil || own == nil {
					return nil, err
				}
				return mergePresentedK1(r.Header, own), nil
			}
			in.UsesStore = az.UsesStore
		}
		if az.Workflow != nil {
			in.Workflow = az.Workflow
			in.WorkflowStep = workflowStepOf(az, r, pcactn, body, bodyOK)
		}
		res := Authorize(pcactn, in)
		if !res.Allow {
			code := "insufficient_authority"
			if res.Status == http.StatusUnauthorized {
				code = "invalid_pcactn"
			}
			writeAuthorizeError(w, res, code)
			return
		}
		restore()
		ctx := context.WithValue(r.Context(), ctxKey{}, &contextValue{verdict: res.Verdict, pcactn: res.PCActn, authz: &res})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// workflowStepOf is the workflow step of a request: the callback, else the body member `workflow`, else nil. Never panics.
func workflowStepOf(az *AuthorizeOptions, r *http.Request, pcactn map[string]any, body []byte, bodyOK bool) (wc *WorkflowCall) {
	defer func() {
		if recover() != nil {
			wc = &WorkflowCall{} // a failing callback is a step AdmitStep denies, never "no step"
		}
	}()
	if az.WorkflowStep != nil {
		return az.WorkflowStep(r, pcactn)
	}
	if !bodyOK || len(body) == 0 {
		return nil
	}
	v, err := StrictParse(string(body))
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	raw, has := m["workflow"]
	if !has {
		return nil
	}
	w, isObj := raw.(map[string]any)
	step, isStr := w["step"].(string)
	if !isObj || !isStr {
		return &WorkflowCall{}
	}
	return &WorkflowCall{Commitment: w["commitment"], Receipts: w["receipts"], Step: step, Units: w["units"], GoalDigest: w["goal_digest"]}
}

func mapOperation(f func(*http.Request, []byte) (*Operation, error), r *http.Request, body []byte) (op *Operation) {
	defer func() {
		if recover() != nil {
			op = nil
		}
	}()
	op, err := f(r, body)
	if err != nil {
		return nil
	}
	return op
}

// writeAuthorizeError writes an authorize denial: the challenge carries only the error code (the reason is
// request-derived, so it stays in the JSON body: error_description, reason, checks, missing).
func writeAuthorizeError(w http.ResponseWriter, res AuthorizeResult, code string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("PCA realm=%q, error=%q", "pca", code))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.Status)
	body := map[string]any{"error": code, "error_description": res.Reason, "reason": res.Reason, "checks": res.Checks, "decision": res.Decision}
	if res.Escalation != nil {
		body["escalation"] = res.Escalation
	}
	if res.Missing != nil {
		body["missing"] = res.Missing
	}
	// a lone surrogate of a truncated escalation reason is written as \udXXXX, as JSON.stringify does
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	_, _ = w.Write(RestoreLoneSurrogates(buf.Bytes()))
}

// extractEscalationAnswer reads the principal's EscalationAnswer: header PCA-Escalation-Answer (strict unpadded base64url
// of the JSON), else the body member escalation_answer. nil when absent or unreadable (an unreadable answer is no answer).
func extractEscalationAnswer(r *http.Request, body []byte, bodyOK bool) any {
	if h := r.Header.Get("PCA-Escalation-Answer"); h != "" {
		raw, ok := DecodeB64uStrict(h, -1)
		if !ok {
			return nil
		}
		v, err := StrictParse(string(raw))
		if err != nil {
			return nil
		}
		return v
	}
	if !bodyOK || len(body) == 0 {
		return nil
	}
	v, err := StrictParse(string(body))
	if err != nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m["escalation_answer"]
	}
	return nil
}

// PresentedK1 reads the discharges and the narrow block presented with a request: header PCA-Discharges (strict unpadded
// base64url of a JSON array) and PCA-Narrow (the same encoding, any JSON value). An empty or absent header is absent; header
// names are case-insensitive; a header sent twice, text that is not strict base64url of UTF-8, JSON the strict parser refuses
// or a PCA-Discharges that is not an array returns an error. Only Discharges, Narrow and HasNarrow of the result are set.
func PresentedK1(h http.Header) (K1Input, error) {
	var out K1Input
	get := func(name string) (string, error) {
		vs := h.Values(name)
		switch len(vs) {
		case 0:
			return "", nil
		case 1:
			return vs[0], nil
		}
		return "", fmt.Errorf("%s is sent more than once", name)
	}
	if d, err := get("PCA-Discharges"); err != nil {
		return K1Input{}, err
	} else if d != "" {
		text, err := DecodePCAHeader(d)
		if err != nil {
			return K1Input{}, err
		}
		v, err := StrictParse(text)
		if err != nil {
			return K1Input{}, err
		}
		arr, isArr := v.([]any)
		if !isArr {
			return K1Input{}, errors.New("PCA-Discharges must be a JSON array")
		}
		out.Discharges = arr
	}
	if n, err := get("PCA-Narrow"); err != nil {
		return K1Input{}, err
	} else if n != "" {
		text, err := DecodePCAHeader(n)
		if err != nil {
			return K1Input{}, err
		}
		v, err := StrictParse(text)
		if err != nil {
			return K1Input{}, err
		}
		out.Narrow, out.HasNarrow = v, true
	}
	return out, nil
}

// mergePresentedK1 is {...presented, ...own} for a configured K1 input: the discharges and narrow block of the request headers
// fill in only what own leaves unset. Unreadable headers are no discharges (the K1 caveat then stays unsatisfied).
func mergePresentedK1(h http.Header, own *K1Input) *K1Input {
	out := *own
	presented, err := PresentedK1(h)
	if err != nil {
		return &out
	}
	if out.Discharges == nil {
		out.Discharges = presented.Discharges
	}
	if !out.HasNarrow {
		out.Narrow, out.HasNarrow = presented.Narrow, presented.HasNarrow
	}
	return &out
}
