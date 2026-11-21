package pca

// Authorize: the full authorization pipeline for a Go resource server or tool guard (0.5, additive), mirroring the
// TypeScript authorize() / verifyPCActn and the Python atlas_pca.authorize check by check.
//
// VerifyPCActnCore answers "is this a validly signed PCActn for this audience". Authorize answers "may THIS operation
// run now", in this order:
//
//  1. configuration: Audience, ResolveGrant, StateStore and IsRevoked are REQUIRED, and the call must name the
//     Operation it will execute (verb, resource, params). A missing one denies with its name; nothing is ever
//     downgraded to "not enforced".
//  2. the core checks (VerifyPCActnCoreWith: wire, version, audience, validity, chain, grant_ref_bound,
//     plan_inclusion, leaf_signature, counter format, intent), then `revocation` (IsRevoked), then `zk_compliance` (a
//     carried proof cannot be verified here: fail closed).
//  3. `operation`: the signed action.verb / action.resource equal the operation's, and the signed action.params_digest
//     opens to exactly the operation's params. Those params are what the predicates and caveats read, so a $400
//     operation is judged as $400 even when the agent signed $50 (and then refused for the mismatch).
//  4. `grant_ref`, `params_digest`, `plan_root_authorized` (Plan "single-step" or a Context plan), `attestation` (a
//     grant whose agent_binding pins the agent needs an attestation verifier this SDK does not have: fail closed),
//     `reversibility` (when the context names an authoritative class).
//  5. policy: the grant's envelope predicates (default deny), the envelope's caveats and the ROOT caveats outside the
//     envelope (`policy`), and the caveats delegation hops appended (`delegated_caveats`). `predicates` and
//     `tool_schema` caveats are enforced against the operation; unknown caveat types fail closed.
//  6. replay: only when everything above passes, the counter is consumed through StateStore.Claim(key, counter), one
//     atomic compare-and-set per action (key = "<grant id>:<leaf holder>"). A replayed or older counter denies.
//
// Revocation staleness and signed revocation epochs are ported (revocation_staleness.go: RevocationStaleness, with an automatic
// rollback pin in the StateStore). Not ported from the TypeScript policy VM: beacons, and (until the full risk port lands) the risk
// score, trust budget and threshold step-up. Never panics: any internal error is a denial.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// PlanSingleStep is the AuthorizeInput.Plan mode that accepts a one-node plan whose node is exactly the operation.
const PlanSingleStep = "single-step"

const envelopeCaveat = "envelope"

// defaultRequiredChecks must be "pass" (not merely "not failed"): the TypeScript DEFAULT_REQUIRED_CHECKS plus the
// operation binding and the policy. AuthorizeInput.Require can add names, never remove these.
var defaultRequiredChecks = []string{"counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity",
	"grant_ref_bound", "operation", "params_digest", "policy"}

// A failing one of these is an authentication failure (401), everything else is insufficient authority (403); the same
// split as the TypeScript requirePCA (Go names the chain check `chain`, TypeScript `cap_chain`).
var authnChecks = []string{"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature",
	"malformed", "grant_ref", "pq_pin"}

// DefaultRequiredChecks returns the check names Authorize always requires to pass.
func DefaultRequiredChecks() []string { return append([]string(nil), defaultRequiredChecks...) }

// ---- the replay store --------------------------------------------------------------------------------------------

// ClaimResult is what StateStore.Claim returns. OK is true only when THIS call consumed the counter; LastCounter is
// the stored counter that refused it, when known.
type ClaimResult struct {
	OK          bool
	LastCounter *int64
}

// StateStore is the replay store: Claim(key, counter) is ONE atomic operation of your backend. If a counter is stored
// for key and counter is not strictly greater, return ClaimResult{OK: false, LastCounter: &stored}; otherwise store
// counter and return ClaimResult{OK: true}. A claim that cannot decide must return OK false or an error (Authorize then
// denies).
type StateStore interface {
	Claim(key string, counter int64) (ClaimResult, error)
}

// OnceStore is the optional TTL'd consume-once side of a StateStore (max_uses use slots). ConsumeOnce(key, retainUntilMs, nowMs)
// is ONE atomic operation: true iff key has no live record (a live record has retainUntil >= now), in which case it
// records the key until retainUntilMs; a live record is never shortened (the later horizon wins). It returns an error,
// never true, when retainUntilMs < nowMs or key is empty, and a refused call leaves nothing behind. The store may forget a
// key once its horizon has passed. A StateStore without it is used through Claim(key, 1), which never expires.
type OnceStore interface {
	ConsumeOnce(key string, retainUntilMs, nowMs int64) (bool, error)
}

// ErrConsumeOnce is returned by ConsumeOnce for an empty key or a retention horizon before now.
var ErrConsumeOnce = errors.New("pca: ConsumeOnce needs a non-empty key and retainUntil >= now")

// MemoryStateStore is the in-process reference store (one mutex). Correct for ONE process only; use SQLStateStore or
// your database for several workers. The zero value is ready to use.
type MemoryStateStore struct {
	mu      sync.Mutex
	last    map[string]int64
	once    map[string]int64          // ConsumeOnce: key -> retain_until
	pins    map[string]float64        // PinStore: key -> highest raised value
	budgets map[string]map[string]any // BudgetStore: stream key -> stored trust budget
}

// ConsumeOnce implements OnceStore.
func (s *MemoryStateStore) ConsumeOnce(key string, retainUntilMs, nowMs int64) (bool, error) {
	if key == "" || retainUntilMs < nowMs {
		return false, ErrConsumeOnce
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.once == nil {
		s.once = map[string]int64{}
	}
	if len(s.once) >= 1024 { // prune expired records once the map is sizeable
		for k, r := range s.once {
			if r < nowMs {
				delete(s.once, k)
			}
		}
	}
	if r, has := s.once[key]; has && r >= nowMs {
		if retainUntilMs > r {
			s.once[key] = retainUntilMs
		}
		return false, nil
	}
	s.once[key] = retainUntilMs
	return true, nil
}

// StoreScope is the optional scope declaration of a StateStore: "process" (state lives in this process only) or "shared"
// (state is shared between instances). A store that does not implement it is taken as shared. MemoryStateStore declares
// "process"; SQLStateStore declares "shared".
type StoreScope interface{ Scope() string }

// ScopeProcess and ScopeShared are the values of StoreScope.Scope.
const (
	ScopeProcess = "process"
	ScopeShared  = "shared"
)

// Scope implements StoreScope: a MemoryStateStore is correct for ONE process only.
func (s *MemoryStateStore) Scope() string { return ScopeProcess }

// NewMemoryStateStore returns an empty MemoryStateStore.
func NewMemoryStateStore() *MemoryStateStore { return &MemoryStateStore{} }

// Claim implements StateStore.
func (s *MemoryStateStore) Claim(key string, counter int64) (ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, has := s.last[key]; has && !(counter > last) {
		return ClaimResult{OK: false, LastCounter: &last}, nil
	}
	if s.last == nil {
		s.last = map[string]int64{}
	}
	s.last[key] = counter
	return ClaimResult{OK: true}, nil
}

// StateKey is the store key of a holder's counter stream. It is the grant-holder key (the TypeScript 'grant-holder' scope, the 0.4
// default); the reference's 0.5 default adds the audience (`aud:<audience>:<grant>:<holder>`). The native key is NARROWER: two
// audiences sharing a grant collide on one counter stream, which denies (fails closed), so there is no weaker case.
func StateKey(grantID, leafHolder string) string { return grantID + ":" + leafHolder }

// ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) --------------------------------

func validateRiskPolicy(pv any) string {
	// an array is a JavaScript object without these members (the reference's typeof check): it fails on the first member
	objOf := func(v any) (map[string]any, bool) {
		if _, isArr := v.([]any); isArr {
			return map[string]any{}, true
		}
		m, ok := v.(map[string]any)
		return m, ok
	}
	p, ok := objOf(pv)
	if !ok {
		return "risk_policy must be an object"
	}
	w, ok := objOf(p["weights"])
	if !ok {
		return "risk_policy.weights missing"
	}
	for _, k := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"} {
		if v, ok := finNum(w[k]); !ok || v < 0 {
			return "risk_policy.weights." + k + " must be finite and >= 0"
		}
	}
	vals := map[string]float64{}
	for _, k := range []string{"theta1", "theta2", "kappa", "lambda", "rho", "bMax"} {
		v, ok := finNum(p[k])
		if !ok {
			return "risk_policy." + k + " must be finite"
		}
		vals[k] = v
	}
	if vals["theta1"] < 0 || vals["theta2"] < vals["theta1"] {
		return "risk_policy requires 0 <= theta1 <= theta2"
	}
	if vals["kappa"] <= 0 {
		return "risk_policy.kappa must be > 0"
	}
	if vals["lambda"] < 0 || vals["rho"] < 0 || vals["bMax"] < 0 {
		return "risk_policy lambda/rho/bMax must be >= 0"
	}
	return ""
}

// ReadEnvelope returns the grant's policy envelope: its FIRST `envelope` caveat without `type` (a new map), or nil when
// absent or malformed (goal_commit a string, predicates and caveats arrays, agent_binding an object or array, a valid
// risk_policy). Never panics (comma-ok assertions, nil-map reads and comparisons against a string constant only).
func ReadEnvelope(grant any) (env map[string]any) {
	g, _ := grant.(map[string]any)
	cs, ok := g["caveats"].([]any)
	if !ok {
		return nil
	}
	var cv map[string]any
	for _, c := range cs {
		if m, ok := c.(map[string]any); ok && m["type"] == envelopeCaveat {
			cv = m
			break
		}
	}
	e := make(map[string]any, len(cv)) // no envelope caveat: e stays empty and the goal_commit check below refuses it
	for k, v := range cv {
		if k != "type" {
			e[k] = v
		}
	}
	if _, ok := e["goal_commit"].(string); !ok {
		return nil
	}
	if _, ok := e["predicates"].([]any); !ok {
		return nil
	}
	if _, ok := e["caveats"].([]any); !ok {
		return nil
	}
	switch e["agent_binding"].(type) {
	case map[string]any, []any:
	default:
		return nil
	}
	if validateRiskPolicy(e["risk_policy"]) != "" {
		return nil
	}
	return e
}

// RootCaveats returns every root caveat except the first `envelope` one (TypeScript rootCaveats); a non-array
// grant.caveats is returned as is (the caveat evaluators refuse it).
func RootCaveats(grant any) any {
	g, _ := grant.(map[string]any)
	cs, ok := g["caveats"].([]any)
	if !ok {
		return g["caveats"]
	}
	out := make([]any, 0, len(cs))
	skipped := false
	for _, c := range cs {
		if m, ok := c.(map[string]any); ok && !skipped && m["type"] == envelopeCaveat {
			skipped = true
			continue
		}
		out = append(out, c)
	}
	return out
}

// requiresAttestation is the TypeScript requiresAttestation: any agent pin in agent_binding requires a bound
// attestation.
func requiresAttestation(binding any) bool {
	b, _ := binding.(map[string]any)
	ne := func(x any) bool { a, ok := x.([]any); return ok && len(a) > 0 }
	mm, hasMin := b["min_measurement"]
	op, _ := b["operator"].(string)
	return ne(b["model_allowlist"]) || (hasMin && mm != "") || op != "" || ne(b["weights_allowlist"]) ||
		ne(b["system_prompt_allowlist"]) || ne(b["tool_manifest_allowlist"]) || b["require_hardware"] == true ||
		b["require_measured_weights"] == true
}

// ---- authorize ---------------------------------------------------------------------------------------------------

var classRank = map[string]int{"reversible": 0, "rate_limited": 1, "costly": 1, "irreversible": 2}

func reversibilityRank(c any) int {
	if s, ok := c.(string); ok {
		if r, known := classRank[s]; known {
			return r
		}
	}
	return 2
}

// Operation is what the handler / tool WILL execute, from the server's own routing and parsed input, never from the
// PCActn. Params must be a non-nil map (use an empty map for no params); numbers may be json.Number (StrictParse /
// ParseJSON), float64 or Go integers.
type Operation struct {
	Verb     string
	Resource string
	Params   map[string]any
}

// AuthorizedOperation is the operation an allowing decision is bound to. ID is the digest of the presented PCActn.
type AuthorizedOperation struct {
	Verb         string
	Resource     string
	ParamsDigest string
	ID           string
}

// AuthorizeContext is the server-side context of one decision (every member optional).
//
//   - Plan / PlanAuthorized: the principal-authorized plan nodes ({id, verb, resource, params_digest,
//     reversibility_class, pre?, post?}); Plan nil = none. Required when AuthorizeInput.Plan is not "single-step".
//   - Subject / Env: the predicate context members `subject` and `env`.
//   - BlastRadius, RecentActionTimes: the caveat context members `blast_radius` (a number) and
//     `recent_action_times` (an array of epoch-ms numbers); nil = absent.
//   - ReversibilityClass: the server's authoritative class ("" = none); the agent may only declare a stricter one.
type AuthorizeContext struct {
	Plan               []map[string]any
	PlanAuthorized     bool
	Subject            any
	Env                any
	BlastRadius        any
	RecentActionTimes  any
	ReversibilityClass string
	// Risk holds the server's own risk inputs for this decision (semanticDistance, reversibility, blastRadius, taint, confidence, age,
	// each in [0, 1]); the members AuthorizeInput.Risk returns are merged over it. An input nobody supplies is the worst case.
	Risk map[string]any
	// Budget is the host's own trust budget for this stream (carried: it is not stored back). Nil: the budget stored with the replay
	// counter, else the grant's bMax at the decision time.
	Budget *TrustBudget
	// GoalNodeID is the plan goal node for the semantic distance (default: the last plan node). AgeHorizonMs is the horizon of the
	// age input derived from the budget's last human touch (default one hour).
	GoalNodeID   string
	AgeHorizonMs float64
}

// ThresholdResult is what a ThresholdHook reports: OK false is a rejected threshold proof; Enforced with T is the threshold the hook
// actually enforced (the guard compares it with the server-derived one).
type ThresholdResult struct {
	OK       bool
	Enforced bool
	T        int
}

// ThresholdHook verifies the threshold co-signature of a PCActn (the `threshold` member). The guard derives t from server-held data
// (risk inputs, budget, policy), never from the proof: a hook that enforced less than the derived t, or reported nothing, fails the
// `threshold` check. Without a hook, a release that needs t > 1 fails it.
type ThresholdHook func(pcactn, grant map[string]any) ThresholdResult

// AuthorizeInput configures one Authorize call.
//
//   - Operation: what will execute (required).
//   - Audience: this resource server's id (the PCActn's signed `aud` must equal it).
//   - ResolveGrant: grant_ref -> grant from your own store; (nil, nil) = unknown grant (401), an error denies (403).
//   - StateStore: the replay store (MemoryStateStore, SQLStateStore or your database).
//   - IsRevoked: only (false, nil) passes; true, an error or a panic denies.
//   - Now: epoch milliseconds (0 = the wall clock).
//   - Plan: PlanSingleStep, or "" (then Context must return the authorized plan with PlanAuthorized true; with neither,
//     `plan_root_authorized` denies: default-deny, no single-step fallback).
//   - Context: per-decision server context (nil = none); an error denies.
//   - Intent / IntentV2 / AllowedSuites: forwarded to VerifyPCActnCoreWith (IntentV2's `params` default to the
//     operation's); an IntentV2 error denies.
//   - Require: extra check names that must pass (the defaults always apply).
type AuthorizeInput struct {
	Operation    *Operation
	Audience     string
	ResolveGrant func(grantRef string) (map[string]any, error)
	StateStore   StateStore
	// ResolvePrincipal resolves the grant's issuer to an enrolled principal (its result is returned on AuthorizeResult.Principal); a
	// nil result is an unverified principal. RequireVerifiedPrincipal denies unless it yields a verified one (identity enforcement
	// at the resource server): without a resolver it denies too. The check is reported as `principal`.
	ResolvePrincipal         func(principalPub string, grant map[string]any) (*PrincipalInfo, error)
	RequireVerifiedPrincipal bool
	// EnforceFreshness switches the freshness-anchor gate on (check `freshness_anchor`, see VerifyOptions.EnforceFreshness).
	EnforceFreshness *FreshnessGate
	// Beacon is the dead-man liveness beacon of the grant (see BeaconInput). The `beacon` check is REQUIRED: the beacon must verify for
	// this grant, be newer than the last accepted one (kept in the state store, which then must implement PinStore) and be bound by the
	// PCActn's signed `freshness.beacon_ref`. No beacon (the hook returns nil) freezes the grant.
	Beacon func(grantRef string, pcactn map[string]any) *BeaconInput
	// EnforceTaint switches the information-flow taint gate on (check `taint_gate`, see VerifyOptions.EnforceTaint).
	EnforceTaint *TaintGate
	// RequirePassport demands a valid signed agent passport for the presenting agent (nil: behaviour unchanged). The call must carry
	// Passport, its `sub` must be the PCActn's leaf holder key, and Options.TrustedIssuers and Options.Revoked are required (missing:
	// denied). Hardware additionally demands a hardware-rooted passport whose evidence verified. A refusal is `passport: <reason>`.
	RequirePassport *PassportRequirement
	Passport        any
	// AdaptivePolicy returns a tightened risk policy (e.g. from an immune layer), re-read on every call. It can only NARROW: when it needs
	// a higher threshold for the decided risk than the grant's own policy does, the call is refused (`adaptive: ...`); a looser policy is
	// ignored and an invalid one refuses. nil result: none.
	AdaptivePolicy func(now int64) *RiskPolicy
	// RequireLinkedTemplate demands that the grant is the instantiation of its linked policy template: the registry (templates by version
	// digest, overlays, trusted organisation keys, params; see ResolveLink) is read on every call. A grant with no readable envelope or no
	// template_ref, or whose policy differs from the template's, is refused (`template: ...`).
	RequireLinkedTemplate func() map[string]any
	// Forbid is the forbid-wins gate (see ForbidPolicy), checked before the PCActn is read.
	Forbid *ForbidPolicy
	// ForbidCertificate is the certificate the call carries (checked when Forbid.RequireCertificate is set).
	ForbidCertificate any
	// Contracts enforces a signed behavioural contract: the action is peeked against it before the PCActn is read, and once the call
	// is admitted so far it is checked and the durable monitor state advanced (a real violation latches the enforcer).
	// Refusal: `contract: <reason>[ (<violated,...>)]`.
	Contracts *ContractEnforcer
	// RequireRiskInputs names the risk inputs the SERVER must supply (semanticDistance, reversibility, blastRadius, taint, confidence,
	// age): a missing one fails `risk_inputs` instead of being assumed worst case. semanticDistance counts as supplied when a plan is
	// given (the geodesic fills it).
	RequireRiskInputs []string
	// Risk supplies the server's own risk inputs for an operation (see AuthorizeContext.Risk); merged over Context.Risk. An error or a
	// panic denies. Without any risk input every input is the worst case and the action needs the highest threshold.
	Risk func(op *Operation, grant, pcactn map[string]any) (map[string]any, error)
	// Threshold verifies a threshold co-signature (see ThresholdHook); nil: none is enforced.
	Threshold ThresholdHook
	// PqPins pins the post-quantum key of each grant issuer on this server (issuer -> pq_pk; nil = unset, given even empty = enforced):
	// a PQ or hybrid grant whose issuer has no pin, or another one, is denied (`pq_pin`). Without it such a root is trusted from the
	// stored grant alone. Forwarded to the core verifier.
	PqPins map[string]string
	// MultiInstance (nil = on unless the StateStore declares Scope "process", as in the reference): the deployment runs several
	// instances. Set true with a process-scoped store it is a configuration error (one PCActn would replay once per instance).
	MultiInstance *bool
	IsRevoked     func(pcactn, grant map[string]any) (bool, error)
	Now           int64
	Plan          string
	Context       func(pcactn map[string]any) (*AuthorizeContext, error)
	Intent        *IntentPolicy
	IntentV2      func(pcactn map[string]any) (*IntentV2Context, error)
	// FreshAt is the consistency-token policy forwarded to the core verifier (nil = none: a PCActn carrying `fresh_at` is then
	// refused). A stale verifier is an escalation.
	FreshAt       *FreshAtPolicy
	AllowedSuites []string
	// AllowUnsupported lists the checks that may be `unsupported` without denying. A PCActn carrying a feature this verifier does
	// not implement (today: `bond_ref`, check `bond`) reports that check as `unsupported`, never `pass`, and is denied unless listed.
	AllowUnsupported []string
	Require          []string
	// RevocationStaleness (T9, off when nil or empty) caps how old the revocation state may be, by the action's effective
	// reversibility class (the stricter of Context.ReversibilityClass and the signed class; missing or unknown counts as
	// irreversible). It needs RevocationState (the state source) and, for a signed epoch, GuardianPublic (plus GuardianPins
	// for a post-quantum guardian). The result is the required `freshness` check; IsRevoked stays the revocation answer
	// and works unchanged.
	RevocationStaleness *RevocationStalenessPolicy
	// With RevocationStaleness on, per-capability revocation is ON by default: every id RevocationIds returns (default: every
	// id in the PCActn's cap_chain) needs a valid non-membership proof against the revocation root after the freshness step.
	// RevocationProof returns the parsed proof for an id (nil, or no RevocationProof at all = none supplied, denied). Both are
	// part of the `freshness` check. Return an empty list from RevocationIds to opt a deployment out explicitly.
	RevocationProof func(id string, pcactn map[string]any) any
	RevocationIds   func(pcactn map[string]any) []string
	// Plans (T10): the plan registry. When the context names no plan, the plan the PCActn commits to (plan.root) is looked
	// up for this grant: its nodes and whether it is executable now feed plan_root_authorized, and a plan that is not
	// executable (unknown, not yet authorized, expired, revoked) also fails `plan_state` with the registry's reason.
	Plans *PlanRegistry
	// RequireAssurance (T8) is a high-assurance policy: when the evidence behind the passing checks is weaker, missing,
	// unlabelled, awaiting-audit, degraded or unsupported, the `assurance` check fails and the request is denied before any replay
	// state is written. AssuranceHooks carries the labels of the verifier's hooks (the report never trusts presented
	// evidence). Every result carries the Assurance report whether or not a requirement is set.
	RequireAssurance *AssuranceRequirement
	AssuranceHooks   AssuranceHooks
	RevocationState  func(pcactn, grant map[string]any) (*RevocationState, error)
	GuardianPublic   string
	GuardianPins     map[string]string
	// EscalationPrincipals are the pinned b64u Ed25519 keys whose EscalationAnswers count; EscalationPinned pins principals
	// that sign with a post-quantum / hybrid suite (their Ed25519 identity plus the PQ key pinned for them). Both empty: every
	// escalate is refused. EscalationAnswer is the principal's signed answer for THIS action (parsed JSON). A verdict whose
	// every failing check is escalate-class is Decision "escalate", refused with the request in Escalation; it is admitted
	// only by a valid answer bound to this grant, this PCActn and the holder's history head; the replay claim spends it; an
	// answer never upgrades a deny. With any principal pinned the StateStore MUST implement LastStore (the history head an
	// answer is bound to): otherwise the call is refused as a configuration error (Missing names it).
	EscalationPrincipals []string
	EscalationPinned     []PinnedSigner
	EscalationAnswer     any
	// EscalationRequestTTLMs is how long an issued EscalationRequest is valid (0: one hour, DefaultEscalationRequestTTLMs).
	EscalationRequestTTLMs int64
	// EscalationRender (K7) recomputes H(R), the canonical approval render digest, from the executed params and the verifier's
	// own definition (RenderApproval + ApprovalRenderDigest). "" means none could be derived. With it the request carries the digest
	// and an answer must be signed over exactly it; an answer that carries a render when this is nil is refused.
	EscalationRender func(pcactn map[string]any) string
	// InsecureUnboundApproval is the documented INSECURE opt-out: by default (K7) an answer is admitted only when EscalationRender recomputed the approval render and the answer is signed over exactly it.
	InsecureUnboundApproval bool
	// K1 (caveat language v2, optional; nil = off) returns the verifier-side input of the K1 caveat types for this PCActn:
	// the discharge-issuer pins, the discharges and narrow block presented with the action, revoked discharge digests, the
	// verified SPIFFE ID of the presenting workload and the holder's history (see K1Input). Authorize computes the action
	// digest itself and ignores K1Input.ActionDigest. With K1 set, K1 caveat types are removed from the stock evaluator's
	// lists and evaluated by EvaluateK1 over the whole chain, and a verified narrow block's plain caveats join the delegated
	// list. Without K1 a chain that carries a K1 caveat is refused (EvaluateK1 with no input). An error or a panic
	// from the callback means no input, which fails closed for every K1 caveat.
	K1 func(pcactn map[string]any) (*K1Input, error)
	// UsesStore spends max_uses (one atomic claim per use slot, see ReserveMaxUses), only after the counter claim succeeded.
	// A chain that carries a max_uses caveat is refused when UsesStore is nil. It may be the same store as StateStore.
	UsesStore StateStore
	// Workflow (K5, C-308; nil = off) pins the keys of the committed-workflow admission gate; WorkflowStep is the step THIS call
	// is. A call with a WorkflowStep is decided by AdmitStep before the replay stage (a refusal never consumes the counter); a
	// call without one is refused when Workflow.Required.
	Workflow     *WorkflowOption
	WorkflowStep *WorkflowCall
	// ArgProvenance configures the provenance gate (check `provenance_flow`; see ArgProvenanceOptions), which is ALWAYS ON:
	// a sensitive action (anything its facts do not declare read-only; an unknown action is sensitive) whose choice or any
	// argument does not derive from the principal is `escalate` (only a principal's signed escalation answer admits it), and a
	// forged or malformed bundle is `deny`. nil = no pinned mediator and no action facts (every sensitive call escalates). The
	// ONLY opt-out is the grant envelope's signed `provenance: {mode: "insecure_off"}` (check `not-enforced`; DANGEROUS:
	// injected content can then steer the grant's sensitive actions). principal_plan holds for an executable,
	// principal-authorized plan from Plans; principal_control for an admitted Workflow step. A plan the request or Context
	// supplies is not a principal plan.
	ArgProvenance *ArgProvenanceOptions
	// ProvenanceBundle is the provenance bundle presented with THIS call (ProvenanceRecorder.ForAction, as parsed JSON); nil =
	// none (then ArgProvenance.Bundle, else the call is unlabelled). RequirePCA fills it from the PCA-Provenance header or the
	// JSON body member pca_provenance.
	ProvenanceBundle any
	// Undo (0.5, optional) is the undo admission hook: an escalated action (every failing check escalate-class, no escalation
	// answer presented, and NOT a provenance escalation: `provenance_flow` and Intent v2 rule 17 `provenance` must not fail) is
	// offered to it, and an admission makes the action run now under a veto window instead of waiting for approval (decision
	// allow, check `undo_window`, the result carries Undo and the `undo_window` obligation). See UndoAdmission for the contract:
	// return an admission only after the window's record is durably opened. An error or a panic is no admission.
	Undo func(a UndoAdmitInput) (*UndoAdmission, error)
}

// WorkflowOption: Principal and RsSigner are the keys this server pinned (the commitment's and the step receipts'); a key
// named inside either is never trusted.
type WorkflowOption struct {
	Principal string
	RsSigner  string
	Required  bool
}

// WorkflowCall is the workflow step one call claims to be: Commitment, Receipts, Units (nil = {}) and GoalDigest (nil = null)
// are decoded JSON values.
type WorkflowCall struct {
	Commitment any
	Receipts   any
	Step       string
	Units      any
	GoalDigest any
}

// escalationPins is every pinned principal: the Ed25519-only ones first, then the PQ-pinned ones.
func (in AuthorizeInput) escalationPins() []PinnedSigner {
	return append(Ed25519Pins(in.EscalationPrincipals...), in.EscalationPinned...)
}

// PinStore holds monotone pins next to the replay counters: Pin(key) is the highest value raised for key (nil: none), and
// RaisePin(key, v) sets it to max(old, v) atomically, never lowering. Authorize keeps the revocation-epoch rollback pin of each
// grant there (key `<grant id>:epoch`), so a replayed older signed epoch is refused without the host supplying the last accepted
// epoch. A StateStore used with RevocationStaleness MUST implement it (MemoryStateStore and SQLStateStore do).
type PinStore interface {
	Pin(key string) (*float64, error)
	RaisePin(key string, v float64) error
}

// Pin implements PinStore.
func (s *MemoryStateStore) Pin(key string) (*float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, has := s.pins[key]; has {
		return &v, nil
	}
	return nil, nil
}

// RaisePin implements PinStore: the pin only ever rises.
func (s *MemoryStateStore) RaisePin(key string, v float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins == nil {
		s.pins = map[string]float64{}
	}
	if old, has := s.pins[key]; !has || v > old {
		s.pins[key] = v
	}
	return nil
}

// LastStore is the read side of a StateStore: the last admitted counter of a stream (nil: none). It binds an escalation
// answer to the holder's history, so a StateStore used with escalation principals MUST implement it (MemoryStateStore and
// SQLStateStore do); Authorize refuses such a configuration without it.
type LastStore interface {
	Last(key string) (*int64, error)
}

// Last implements LastStore.
func (s *MemoryStateStore) Last(key string) (*int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, has := s.last[key]; has {
		return &last, nil
	}
	return nil, nil
}

// AuthorizeResult is the outcome of Authorize. Allow is the one thing a caller must branch on.
//
// Status is 200, 401 (no / undecodable / unauthenticated proof) or 403. Checks maps each check to "pass", "fail" or
// "not-enforced"; Reason is the decisive one (an `operation` failure first). Missing names configuration components
// that were absent (the call was refused before any verification).
// PassportRequirement configures AuthorizeInput.RequirePassport; Options.NowMs and Options.Subject are set per call.
type PassportRequirement struct {
	Options  PassportOptions
	Hardware bool
}

// PrincipalInfo is an enrolled principal as the host resolves it.
type PrincipalInfo struct {
	Pub         string
	SubjectType string // e.g. "unverified"
	SubjectID   *string
	Verified    bool
}

type AuthorizeResult struct {
	// Principal is the resolved principal of the grant's issuer (nil without ResolvePrincipal).
	Principal *PrincipalInfo
	Allow     bool
	Status    int
	Checks    map[string]string
	Reasons   []string
	Reason    string
	Operation *AuthorizedOperation
	PCActn    map[string]any
	Verdict   *Verdict
	Missing   []string
	// Decision is "allow" (and Allow is true), "escalate" (refused: Escalation is the request to put to the principal) or
	// "deny". Allow is exactly Decision == "allow": an escalate is never an allow. On an allow admitted by an answer,
	// Escalation is {"answered_by": <principal>}.
	Decision   string
	Escalation map[string]any
	// Degraded names the passing checks that rest on a compatibility mode (check name -> why): "tighten" under rule 21's
	// model_polarity "legacy". A caller with a high-assurance policy must not accept a degraded pass.
	Degraded map[string]string
	// Assurance is the per-check report: what each passing check rests on (see BuildAssuranceReport). The capability
	// chain check is reported as `cap_chain`.
	Assurance AssuranceReport
	// Undo is the veto-window admission when AuthorizeInput.Undo replaced an escalation (allow with undo); Obligations then
	// carries its `undo_window` obligation {kind, params: {id, window_end}, due: window_end}, which the enforcement point must
	// perform (report the effect, let the window run).
	Undo        *UndoAdmission
	Obligations []any
}

// orderedChecks keeps the insertion order of the check names (the decisive reason is chosen in that order).
type orderedChecks struct {
	order []string
	st    map[string]string
}

func (c *orderedChecks) set(name, status string) {
	if _, has := c.st[name]; !has {
		c.order = append(c.order, name)
	}
	c.st[name] = status
}

// liftFailed turns every failing check into a pass (an answer or an admitted undo window lifts exactly the failures; any other
// status, like not-enforced, stays).
func liftFailed(st map[string]string) {
	for n, s := range st {
		if s == "fail" {
			st[n] = "pass"
		}
	}
}

func refuse(status int, check, reason string, missing []string, p map[string]any) AuthorizeResult {
	return AuthorizeResult{Status: status, Checks: map[string]string{check: "fail"}, Reasons: []string{reason},
		Reason: reason, Missing: missing, PCActn: p, Decision: "deny"}
}

// ForbidPolicy is the forbid-wins clause policy: any forbid matched denies, else no permit matched denies, else an escalate escalates.
// Clauses supplies the clause list (see DecideClauses) for the operation and its grant (nil when the grant cannot be read); Context may add
// to the decision context (the `action` member is the operation's); Precedence ranks signers; PermitSigners (non-nil) drops permits from
// any other signer; RequireCertificate demands a certificate the verifier recomputes (`forbid: certificate refused (<reason>)`).
type ForbidPolicy struct {
	Clauses            func(op Operation, grant map[string]any) any
	Context            func(op Operation) map[string]any
	Precedence         []string
	PermitSigners      []string
	RequireCertificate bool
}

// BeaconInput is what the Beacon hook supplies for a grant: the beacon, the pinned issuer keys, the instance, the server's issuer ->
// pq_pk pins (post-quantum suites) and the host's own last accepted seq (nil: none; the stored pin also counts).
type BeaconInput struct {
	Beacon          map[string]any
	Issuers         []string
	Instance        string
	PqPins          map[string]string
	LastAcceptedSeq *int64
}

// MissingAuthorizeComponents names the required components of in that are absent (empty = complete), in the order
// Audience, ResolveGrant, StateStore, IsRevoked, then StateStore.Last when escalation principals are pinned.
func MissingAuthorizeComponents(in AuthorizeInput) []string {
	missing := []string{}
	if in.Audience == "" {
		missing = append(missing, "Audience")
	}
	if in.ResolveGrant == nil {
		missing = append(missing, "ResolveGrant")
	}
	if in.StateStore == nil {
		missing = append(missing, "StateStore")
	}
	if in.IsRevoked == nil {
		missing = append(missing, "IsRevoked")
	}
	if in.stalenessOn() {
		if in.RevocationState == nil {
			missing = append(missing, "RevocationState (required by RevocationStaleness)")
		}
		if err := in.RevocationStaleness.Validate(); err != nil {
			missing = append(missing, "RevocationStaleness (invalid: "+err.Error()+")")
		}
		if in.StateStore != nil {
			if _, ok := in.StateStore.(PinStore); !ok {
				missing = append(missing, "revocation staleness needs a state store that implements pins (rollback protection)")
			}
		}
	}
	if len(in.escalationPins()) > 0 && in.StateStore != nil {
		if _, ok := in.StateStore.(LastStore); !ok {
			missing = append(missing, "StateStore.Last (required by EscalationPrincipals)")
		}
	}
	if why := multiInstanceError(in.StateStore, in.MultiInstance); why != "" {
		missing = append(missing, why)
	}
	if in.Forbid != nil && in.Forbid.Clauses == nil {
		missing = append(missing, "Forbid.Clauses")
	}
	if in.Beacon != nil && in.StateStore != nil {
		if _, ok := in.StateStore.(PinStore); !ok {
			missing = append(missing, "beacon needs a state store that implements pins (replay protection)")
		}
	}
	return missing
}

// multiInstanceError is the construction rule of the reference: multiInstance set with a process-scoped store is refused.
func multiInstanceError(store StateStore, multiInstance *bool) string {
	if multiInstance == nil || !*multiInstance || store == nil {
		return ""
	}
	if sc, ok := store.(StoreScope); ok && sc.Scope() == ScopeProcess {
		return "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)"
	}
	return ""
}

func contractAction(op Operation) any {
	return map[string]any{"action": map[string]any{"verb": op.Verb, "resource": op.Resource, "params": op.Params}}
}

func contractRefusal(c map[string]any) *AuthorizeResult {
	if c["allow"] == true {
		return nil
	}
	reason := "contract: " + jsValueString(c["reason"])
	if v, _ := c["violated"].([]any); len(v) > 0 {
		reason += " (" + joinAny(v) + ")"
	}
	r := refuse(403, "contract", reason, nil, nil)
	return &r
}

// readableGrant best-effort resolves the grant a PCActn names: nil when the PCActn or the grant cannot be read (the clause source or the
// verification that follows decides).
func readableGrant(pcactn any, in AuthorizeInput) (p, grant map[string]any) {
	defer func() {
		if recover() != nil {
			p, grant = nil, nil
		}
	}()
	p, _ = coercePCActn(pcactn)
	if p == nil {
		return nil, nil
	}
	if ref, ok := p["grant_ref"].(string); ok {
		if g, err := in.ResolveGrant(ref); err == nil {
			grant = g
		}
	}
	return p, grant
}

func forbidRefusal(pcactn any, in AuthorizeInput, op Operation) (r *AuthorizeResult) {
	f := in.Forbid
	if f == nil {
		return nil
	}
	_, grant := readableGrant(pcactn, in)
	opMap, _ := pNorm(map[string]any{"verb": op.Verb, "resource": op.Resource, "params": op.Params})
	ctx := map[string]any{"action": opMap}
	if f.Context != nil {
		func() {
			defer func() { _ = recover() }()
			for k, v := range f.Context(op) {
				ctx[k] = v
			}
		}()
	}
	var clauses any
	func() {
		defer func() { _ = recover() }() // a clause source that fails is a policy with no clauses: malformed, a deny
		clauses = f.Clauses(op, grant)
	}()
	cn, _ := pNorm(clauses)
	xn, _ := pNorm(ctx)
	budget := &regexBudget{}
	d := decideClausesB(cn, xn, f.Precedence, f.PermitSigners, budget)
	deny := func(reason string) *AuthorizeResult {
		x := refuse(403, "forbid", reason, nil, nil)
		return &x
	}
	if d["decision"] != "allow" {
		w := d["witness"].(map[string]any)["winner"].(map[string]any)
		reason := "forbid: " + d["decision"].(string) + " by " + w["kind"].(string)
		if id, ok := w["id"].(string); ok && id != "" {
			reason += " " + id
		}
		return deny(reason)
	}
	if f.RequireCertificate {
		if in.ForbidCertificate == nil {
			return deny("forbid: the call carries no certificate (fail closed)")
		}
		if c := CheckForbidCertificate(in.ForbidCertificate, cn, xn, f.Precedence, f.PermitSigners); c["ok"] != true {
			why, _ := c["reason"].(string)
			if why == "" {
				why = "mismatch"
			}
			return deny("forbid: certificate refused (" + why + ")")
		}
	}
	return nil
}

// templateRefusal is the RequireLinkedTemplate gate: nil when the grant is the instantiation of its linked template. A PCActn or grant that
// cannot be read is left to the verification that follows (it denies it).
func templateRefusal(pcactn any, in AuthorizeInput) *AuthorizeResult {
	if in.RequireLinkedTemplate == nil {
		return nil
	}
	p, grant := readableGrant(pcactn, in)
	if p == nil {
		return nil
	}
	env := ReadEnvelope(grant)
	why := ""
	switch {
	case grant == nil || len(env) == 0:
		why = "the grant has no readable envelope"
	default:
		if _, has := env["template_ref"]; !has {
			why = "the grant carries no template_ref"
		} else {
			why = callLinkedPolicy(in.RequireLinkedTemplate, env)
		}
	}
	if why == "" {
		return nil
	}
	r := refuse(403, "template", "template: "+why, nil, nil)
	return &r
}

// beaconStep decides the `beacon` check; it returns the seq to pin once the action is admitted (nil: nothing to pin).
func beaconStep(in AuthorizeInput, p, grant map[string]any, grantRef string, now int64, mark func(string, string), fail func(string, string)) (pinSeq *int64) {
	var bc *BeaconInput
	func() {
		defer func() {
			if recover() != nil {
				bc = nil
			}
		}()
		bc = in.Beacon(grantRef, p)
	}()
	if bc != nil && bc.Beacon == nil {
		bc = nil
	}
	var verdict BeaconVerdict
	var last *int64
	id, _ := grant["id"].(string)
	if bc != nil {
		last = bc.LastAcceptedSeq
		if ps, ok := in.StateStore.(PinStore); ok && id != "" {
			if pin, failed := readPin(ps, id+":beacon"); failed {
				fail("beacon", "the beacon pin could not be read (fail closed)")
				return nil
			} else if pin != nil {
				if v := int64(*pin); last == nil || v > *last {
					last = &v
				}
			}
		}
		verdict = VerifyLivenessBeacon(bc.Beacon, bc.Issuers, now, bc.Instance, id, bc.PqPins)
	}
	var seq int64
	if bc != nil && verdict.OK {
		seq, _ = safeInt(bc.Beacon["seq"])
	}
	replayed := bc != nil && verdict.OK && last != nil && seq < *last
	binds := false
	if bc != nil && verdict.OK && !replayed {
		fr, _ := p["freshness"].(map[string]any)
		ref, err := BeaconRef(bc.Beacon)
		binds = err == nil && fr["beacon_ref"] == any(ref)
	}
	switch BeaconDecision(bc != nil, verdict.OK, replayed, binds) {
	case "rejected":
		why := verdict.Reason
		if why == "" {
			why = "beacon rejected"
		}
		fail("beacon", why)
	case "replayed":
		fail("beacon", fmt.Sprintf("beacon seq %d is older than the last accepted %d (replay)", seq, *last))
	case "unbound":
		fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon")
	case "pass":
		mark("beacon", "pass")
		if id != "" {
			return &seq
		}
	}
	return nil
}

// pinTarget is the rollback pin to raise once the action is allowed (key "" = none).
type pinTarget struct {
	key   string
	epoch *float64
}

// withRollbackPin returns state with LastAcceptedEpoch = max(the host's value, the stored pin of this grant), and the pin key.
// A pin that cannot be read denies (fail closed). Only a signed epoch carries an epoch number to pin.
func withRollbackPin(store StateStore, st *RevocationState, grant map[string]any) (*RevocationState, string, string) {
	if st == nil || st.Epoch == nil {
		return st, "", ""
	}
	id, ok := grant["id"].(string)
	if !ok || id == "" {
		return st, "", "the grant has no readable id for its revocation pin (fail closed)"
	}
	ps, ok := store.(PinStore)
	if !ok {
		return st, "", "the state store does not implement pins (fail closed)"
	}
	key := id + ":epoch"
	pin, err := readPin(ps, key)
	if err {
		return st, "", "the revocation pin store failed (fail closed)"
	}
	cp := *st
	if pin != nil && (cp.LastAcceptedEpoch == nil || *pin > *cp.LastAcceptedEpoch) {
		v := *pin
		cp.LastAcceptedEpoch = &v
	}
	return &cp, key, ""
}

func readPin(ps PinStore, key string) (pin *float64, failed bool) {
	defer func() {
		if recover() != nil {
			pin, failed = nil, true
		}
	}()
	v, err := ps.Pin(key)
	if err != nil {
		return nil, true
	}
	return v, false
}

func raisePin(ps PinStore, key string, v float64) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return ps.RaisePin(key, v) != nil
}

// verifiedEpoch is the epoch number of a signed epoch that just passed the gate.
func verifiedEpoch(st *RevocationState) *float64 {
	if st == nil || st.Epoch == nil {
		return nil
	}
	if e, ok := extSafeInt(st.Epoch["epoch"]); ok {
		return &e
	}
	return nil
}

func (in AuthorizeInput) stalenessOn() bool {
	return in.RevocationStaleness != nil && in.RevocationStaleness.On()
}

func callRevocationState(f func(pcactn, grant map[string]any) (*RevocationState, error), p, g map[string]any) (st *RevocationState, failed bool) {
	defer func() {
		if recover() != nil {
			st, failed = nil, true
		}
	}()
	st, err := f(p, g)
	return st, err != nil
}

func validOperation(op *Operation) bool {
	return op != nil && op.Verb != "" && op.Resource != "" && op.Params != nil
}

func decisive(c *orderedChecks, reasons []string) string {
	// stable: a binding failure first, then the plan state (as the reference), then insertion order; a name met again
	// later is a no-op (it could not return the first time)
	for _, n := range append([]string{"operation", "plan_state"}, c.order...) {
		if c.st[n] != "fail" {
			continue
		}
		for _, r := range reasons {
			if strings.HasPrefix(r, n+":") {
				return r
			}
		}
	}
	if len(reasons) > 0 {
		return reasons[0]
	}
	return "denied"
}

// jsonValue converts a Go value to the JSON value model of this package (map[string]any, []any, string, bool, nil,
// json.Number in the JavaScript number lexeme). Values of other types go through encoding/json. ok is false for a value
// JSON cannot carry (NaN, an integer outside the safe range, a channel, ...).
func jsonValue(v any, depth int) (any, bool) {
	if depth > MaxJSONDepth+1 {
		return nil, false
	}
	switch t := v.(type) {
	case nil, bool, string:
		return t, true
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			y, ok := jsonValue(x, depth+1)
			if !ok {
				return nil, false
			}
			m[k] = y
		}
		return m, true
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			y, ok := jsonValue(x, depth+1)
			if !ok {
				return nil, false
			}
			a[i] = y
		}
		return a, true
	case json.Number:
		f, ok := parseJSNumberLexeme(string(t))
		if !ok || math.IsInf(f, 0) {
			return nil, false
		}
		return jsNumber(f), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil, false
		}
		return jsNumber(t), true
	case float32:
		return jsonValue(float64(t), depth)
	case int:
		return safeIntNumber(int64(t))
	case int8:
		return safeIntNumber(int64(t))
	case int16:
		return safeIntNumber(int64(t))
	case int32:
		return safeIntNumber(int64(t))
	case int64:
		return safeIntNumber(t)
	case uint8:
		return safeIntNumber(int64(t))
	case uint16:
		return safeIntNumber(int64(t))
	case uint32:
		return safeIntNumber(int64(t))
	case uint:
		if uint64(t) > maxSafeInt {
			return nil, false
		}
		return safeIntNumber(int64(t))
	case uint64:
		if t > maxSafeInt {
			return nil, false
		}
		return safeIntNumber(int64(t))
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	x, err := ParseJSONLenient(b)
	if err != nil {
		return nil, false
	}
	return jsonValue(x, depth)
}

func safeIntNumber(i int64) (any, bool) {
	if i > maxSafeInt || i < -maxSafeInt {
		return nil, false
	}
	return json.Number(strconv.FormatInt(i, 10)), true
}

// copyParams is the private copy of the operation params (canonical round trip): the params that are verified cannot
// change under the verifier.
func copyParams(params map[string]any) (map[string]any, bool) {
	v, ok := jsonValue(params, 1)
	if !ok {
		return nil, false
	}
	text, err := Canonicalize(v)
	if err != nil {
		return nil, false
	}
	back, err := StrictParse(text)
	if err != nil {
		return nil, false
	}
	m, ok := back.(map[string]any)
	return m, ok
}

func coercePCActn(pcactn any) (map[string]any, string) {
	switch t := pcactn.(type) {
	case nil:
		return nil, "absent"
	case map[string]any:
		if t == nil {
			return nil, "absent"
		}
		return t, ""
	case string:
		p, err := ParsePCActn(t)
		if err != nil {
			return nil, "undecodable"
		}
		return p, ""
	case []byte:
		if len(t) > MaxArtifactBytes {
			return nil, "undecodable"
		}
		if !utf8.Valid(t) {
			return nil, "undecodable"
		}
		p, err := ParsePCActn(string(t))
		if err != nil {
			return nil, "undecodable"
		}
		return p, ""
	}
	return nil, "undecodable"
}

// Authorize authorizes ONE operation (see the file comment for the pipeline). pcactn is the presented PCActn: a parsed
// object (map[string]any), or its JSON text (string or []byte, strict profile); nil means none was presented.
// Never panics: an internal error is a 403 denial with check `authorize`.
func Authorize(pcactn any, in AuthorizeInput) (res AuthorizeResult) {
	defer func() {
		if r := recover(); r != nil {
			if af, ok := r.(adaptiveFault); ok {
				res = refuse(403, "authorize", "authorize error (fail closed): "+af.msg, nil, nil)
				return
			}
			res = refuse(403, "authorize", fmt.Sprintf("authorize: error (fail closed): %v", r), nil, nil)
		}
	}()
	return authorize(pcactn, in)
}

// Seams, identity in production, so a test can reach the fail-closed checks on their results that no real input trips: the
// core verifier and ParamsDigest never return an error here, the escalation digests were computed without error just
// above, and planLeaf refuses a nil node's missing id itself.
var (
	authorizeCoreVerify      = VerifyPCActnCoreWith
	authorizeParamsDigest    = ParamsDigest
	authorizeEscPolicyDigest = EscalationPolicyDigest
	authorizeEscActionDigest = EscalationActionDigest
	authorizeEscHistoryHead  = EscalationHistoryHead
	planRootLeaf             = planLeaf
	authorizeEscBuild        = BuildEscalationRequestWithRender
)

// authorizeCoreHook is a test seam: it may edit the core verdict (e.g. inject an escalate-class failure) before the
// pipeline reads it. Always nil in production.
var authorizeCoreHook func(core *Verdict)

func authorize(pcactn any, in AuthorizeInput) AuthorizeResult {
	missing := MissingAuthorizeComponents(in)
	if in.Plan != "" && in.Plan != PlanSingleStep {
		missing = append(missing, `Plan (only "single-step" or "")`)
	}
	if len(missing) > 0 {
		return refuse(403, "authorize_config", "authorize_config: missing required component(s): "+
			strings.Join(missing, ", ")+" (fail closed)", missing, nil)
	}
	if !validOperation(in.Operation) {
		return refuse(403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) "+
			"(fail closed)", nil, nil)
	}
	// a private copy: the params that are verified cannot change under the verifier
	params, ok := copyParams(in.Operation.Params)
	if !ok {
		return refuse(403, "operation", "operation: the operation params are not canonical JSON (fail closed)", nil, nil)
	}
	op := Operation{Verb: in.Operation.Verb, Resource: in.Operation.Resource, Params: params}

	if r := forbidRefusal(pcactn, in, op); r != nil {
		return *r
	}
	if r := templateRefusal(pcactn, in); r != nil {
		return *r
	}

	// workflow required and no step: refused before the PCActn is read (needs none); an undecodable PCActn with a step is refused
	// below by the pipeline's own 401, the gate does not judge it
	if in.Workflow != nil && in.Workflow.Required && in.WorkflowStep == nil {
		return refuse(403, "workflow", "workflow: this call carries no workflow step (fail closed)", nil, nil)
	}

	if in.Contracts != nil {
		if r := contractRefusal(in.Contracts.Peek(contractAction(op))); r != nil {
			return *r
		}
	}

	p, why := coercePCActn(pcactn)
	if p == nil {
		if why == "absent" {
			return refuse(401, "wire", "wire: no PCActn presented", nil, nil)
		}
		return refuse(401, "pcactn", "undecodable PCActn: not a strict-profile PCActn (fail closed)", nil, nil)
	}
	grantRef, isStr := p["grant_ref"].(string)
	if !isStr {
		return refuse(401, "malformed", "malformed: grant_ref is not a string", nil, p)
	}
	grant, gerr := callResolve(in.ResolveGrant, grantRef)
	if gerr {
		return refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", nil, p)
	}
	if grant == nil {
		return refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant", nil, p)
	}

	now := in.Now
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	ctx := &AuthorizeContext{}
	if in.Context != nil {
		c, cerr := callContext(in.Context, p)
		if cerr {
			return refuse(403, "context", "context: the context callback failed (fail closed)", nil, p)
		}
		if c != nil {
			ctx = c
		}
	}

	var planStatus *PlanStatus
	principalPlan, principalControl := false, false // the provenance gate's principal commitments
	if in.Plans != nil && ctx.Plan == nil {
		pl, _ := p["plan"].(map[string]any)
		root, _ := pl["root"].(string)
		if pc := authorizePlanContext(in.Plans, grantRef, root, now); pc != nil {
			cp := *ctx
			cp.Plan, cp.PlanAuthorized = pc.Plan, pc.PlanAuthorized
			ctx = &cp
			planStatus = &pc.Status
			// the principal authorized this plan (and with it every node's exact params), and only while it is executable:
			// a plan that is not executable never makes its arguments trusted, whatever PlanAuthorized says
			principalPlan = pc.PlanAuthorized && pc.Status.Executable
		} else if in.Plan != PlanSingleStep {
			planStatus = &PlanStatus{State: PlanUnknown, Reason: "plan " + root + " is unknown to the plan registry"}
		}
	}

	// ---- K5 workflow admission (C-308): decided before the replay stage, so a refusal never consumes the counter
	// (Required with no step was refused above, before the PCActn was read)
	if in.Workflow != nil {
		if in.WorkflowStep != nil {
			wc := in.WorkflowStep
			var root any
			if pl, isMap := p["plan"].(map[string]any); isMap {
				if rs, isS := pl["root"].(string); isS {
					root = rs
				}
			}
			units := wc.Units
			if units == nil {
				units = map[string]any{}
			}
			d := AdmitStep(AdmitInput{Workflow: wc.Commitment, Principal: in.Workflow.Principal, RsSigner: in.Workflow.RsSigner, Receipts: wc.Receipts, Now: now,
				Request: map[string]any{"step": wc.Step, "verb": op.Verb, "resource": op.Resource, "params": op.Params, "units": units, "goal_digest": wc.GoalDigest, "plan_root": root}})
			if d.Decision != "allow" {
				why := "workflow: " + d.Code // every deny / escalate of AdmitStep names its code
				if d.Step != "" {
					why += " (step " + d.Step + ")"
				}
				r := refuse(403, "workflow", why, nil, p)
				if d.Decision == "escalate" {
					r.Decision = "escalate"
				}
				return r
			}
			// an admitted step of the principal's signed workflow: the CHOICE of this action is the principal's (the values are not)
			principalControl = true
		}
	}

	var v2 *IntentV2Context
	if in.IntentV2 != nil {
		c, verr := callIntentV2(in.IntentV2, p)
		if verr {
			return refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", nil, p)
		}
		v2 = c
	}
	// Rules 20 / 21 read the signed envelope of the stored grant: when it carries units / tighten / model_polarity or a
	// grant-side where reads a model-derived path, the v2 pipeline needs the plaintext params and the host env even if the host
	// configured no v2 context (TypeScript needsModelRules).
	if v2 == nil && needsModelRules(grant) {
		v2 = &IntentV2Context{raw: map[string]any{}}
	}
	if v2 != nil && !v2.malformed {
		raw := make(map[string]any, len(v2.raw)+2)
		for k, x := range v2.raw {
			raw[k] = x
		}
		if raw["params"] == nil {
			raw["params"] = op.Params
		}
		if raw["env"] == nil { // `intentV2.env ?? ctx.env`: a null env is the authorize context's (a non-object one is malformed)
			delete(raw, "env")
			if ctx.Env != nil {
				raw["env"] = ctx.Env
			}
		}
		v2 = &IntentV2Context{raw: raw}
	}

	// ---- 1. the core checks
	core, cerr := authorizeCoreVerify(p, grant, now, in.Audience, VerifyOptions{AllowedSuites: in.AllowedSuites,
		Intent: in.Intent, IntentV2: v2, FreshAt: in.FreshAt, zkInAuthorize: true, InsecureSkipPlanRootCheck: true, PQPins: in.PqPins, EnforceFreshness: in.EnforceFreshness, EnforceTaint: in.EnforceTaint}) // Authorize decides the plan itself
	if cerr != nil {
		return refuse(403, "authorize", "authorize: error (fail closed): "+cerr.Error(), nil, p)
	}
	if authorizeCoreHook != nil {
		authorizeCoreHook(&core)
	}
	if ok, has := core.Checks["wire"]; has && !ok {
		r := core.Reason
		if r == "" {
			r = "wire: malformed PCActn"
		}
		return AuthorizeResult{Status: 401, Checks: map[string]string{"wire": "fail", "malformed": "fail"},
			Reasons: []string{r}, Reason: r, PCActn: p, Verdict: &core}
	}
	checks := &orderedChecks{st: map[string]string{}}
	for _, name := range coreCheckOrder(core.Checks) {
		if core.Checks[name] {
			checks.set(name, "pass")
		} else {
			checks.set(name, "fail")
		}
	}
	reasons := []string{}
	if !core.Allow {
		if len(core.Reasons) > 0 { // the first failure, then every further failing v2 check (the whole set decides escalate vs deny)
			reasons = append(reasons, core.Reasons...)
		} else if core.Reason != "" {
			reasons = append(reasons, core.Reason)
		}
	}
	mark := func(name, status string) { checks.set(name, status) }
	fail := func(name, why string) {
		checks.set(name, "fail")
		reasons = append(reasons, name+": "+why)
	}

	// ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
	switch revoked, rerr := callRevoked(in.IsRevoked, p, grant); {
	case !rerr && !revoked:
		mark("revocation", "pass")
	case !rerr && revoked:
		fail("revocation", "the grant is revoked")
	default:
		fail("revocation", "the revocation check failed (fail closed)")
	}
	var revEpochPin pinTarget
	if in.stalenessOn() {
		if st, serr := callRevocationState(in.RevocationState, p, grant); serr {
			fail("freshness", "the revocation state source failed (fail closed)")
		} else if st, pinKey, perr := withRollbackPin(in.StateStore, st, grant); perr != "" {
			fail("freshness", perr)
		} else if why := revocationFreshness(in, ctx, p, st, now); why != "" {
			fail("freshness", why)
		} else {
			mark("freshness", "pass")
			revEpochPin = pinTarget{key: pinKey, epoch: verifiedEpoch(st)}
		}
	}
	var beaconSeq *int64
	if in.Beacon != nil {
		beaconSeq = beaconStep(in, p, grant, grantRef, now, mark, fail)
	}
	if _, has := p["zk_compliance"]; has {
		fail("zk_compliance", zkNoVerifierReason)
	}

	action, _ := p["action"].(map[string]any)
	signedDigest := action["params_digest"]
	opDigest, derr := authorizeParamsDigest(op.Params)
	if derr != nil {
		return refuse(403, "authorize", "authorize: error (fail closed): "+derr.Error(), nil, p)
	}

	// ---- 3. the operation binding
	if action["verb"] != any(op.Verb) || action["resource"] != any(op.Resource) {
		fail("operation", fmt.Sprintf("the proof is for %s on %s, but this operation is %s on %s",
			jsMemberString(action, "verb"), jsMemberString(action, "resource"), op.Verb, op.Resource))
	} else if signedDigest != any(opDigest) {
		fail("operation", "the proof's params_digest does not match the params of this "+op.Verb+" operation")
	} else {
		mark("operation", "pass")
	}

	// ---- 4. grant_ref, params, plan, attestation, reversibility
	if any(grantRef) == grant["id"] {
		mark("grant_ref", "pass")
	} else {
		fail("grant_ref", "does not reference the supplied grant")
	}
	if signedDigest == any(opDigest) {
		mark("params_digest", "pass")
	} else {
		fail("params_digest", "supplied params do not hash to action.params_digest")
	}

	pl, _ := p["plan"].(map[string]any)
	nodeID := pl["node_id"]
	planNodes := ctx.Plan
	planAuthorized := ctx.PlanAuthorized
	if in.Plan == PlanSingleStep && planNodes == nil {
		planNodes = []map[string]any{{"id": jsMemberString(pl, "node_id"), "verb": op.Verb, "resource": op.Resource,
			"params_digest": opDigest, "reversibility_class": action["reversibility_class"]}}
		planAuthorized = true
	}
	if planNodes != nil {
		known, kok := planRoot(planNodes)
		if !kok || any(known) != pl["root"] {
			fail("plan_root_authorized", "known plan does not match plan.root")
		} else if !planAuthorized {
			fail("plan_root_authorized", "the plan root has not been authorized by the principal")
		} else {
			mark("plan_root_authorized", "pass")
		}
	} else {
		// default-deny (K5): no authorized plan configured. Authorize has no opt-out; it requires this check to pass.
		fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)")
	}

	if planStatus != nil {
		if planStatus.Executable {
			mark("plan_state", "pass")
		} else { // every non-executable status carries its reason (PlanRegistry.Status, the unknown-root status above)
			fail("plan_state", planStatus.Reason)
		}
	}

	env := ReadEnvelope(grant)
	if env != nil && requiresAttestation(env["agent_binding"]) {
		fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED "+
			"(no attestation verifier in this SDK: fail closed)")
	}

	declared, hasDeclared := action["reversibility_class"]
	var effective any
	if hasDeclared {
		effective = declared
	}
	if ctx.ReversibilityClass != "" {
		dr, sr := reversibilityRank(declared), reversibilityRank(ctx.ReversibilityClass)
		if dr < sr {
			fail("reversibility", fmt.Sprintf("declared class '%s' is less restrictive than the authoritative '%s'",
				jsMemberString(action, "reversibility_class"), ctx.ReversibilityClass))
		} else {
			mark("reversibility", "pass")
		}
		if dr > sr {
			effective = declared
		} else {
			effective = ctx.ReversibilityClass
		}
	}

	// ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
	chain, _ := p["cap_chain"].([]any)
	depth := len(chain) - 1
	if depth < 0 {
		depth = 0
	}
	inner := map[string]any{"params": op.Params}
	if v, has := action["verb"]; has {
		inner["verb"] = v
	}
	if v, has := action["resource"]; has {
		inner["resource"] = v
	}
	if effective != nil {
		inner["reversibility_class"] = effective
	}
	actionCtx := map[string]any{"action": inner}
	if ctx.Subject != nil {
		actionCtx["subject"] = ctx.Subject
	}
	if predEnv := v2Env(p, grant, v2, now, ctx.Env); predEnv != nil {
		actionCtx["env"] = predEnv
	}
	verb, _ := inner["verb"].(string)
	toolCall := &ToolCall{Tool: verb, Args: op.Params}
	if tb, ok := p["tool_binding"].(string); ok {
		toolCall.ToolSignatureDigest = &tb
	}
	revClass := effective
	if nid, ok := nodeID.(string); revClass == nil && ok && planNodes != nil {
		for _, n := range planNodes {
			if n != nil && n["id"] == any(nid) {
				revClass = n["reversibility_class"]
				break
			}
		}
	}
	cctx := map[string]any{"now": now, "action": inner, "delegation_depth": depth}
	if ctx.BlastRadius != nil {
		cctx["blast_radius"] = ctx.BlastRadius
	}
	if revClass != nil {
		cctx["reversibility_class"] = revClass
	}
	if ctx.RecentActionTimes != nil {
		cctx["recent_action_times"] = ctx.RecentActionTimes
	}

	var k1r *K1Result
	if in.K1 != nil || k1Present(grant, chain) { // no K1 option: a chain carrying a K1 caveat is refused by EvaluateK1 (nil input)
		var ki *K1Input
		if in.K1 != nil {
			ki = callK1(in.K1, p)
		}
		if ki != nil {
			ki.ActionDigest, _ = DischargeActionDigest(p) // "" when it cannot be computed
		}
		r := EvaluateK1(grant, chain, ki, K1Context{Now: float64(now), Action: inner})
		k1r = &r
	}

	if len(chain) > 0 {
		leaf, _ := chain[len(chain)-1].(map[string]any)
		gcs, _ := grant["caveats"].([]any)
		var extra any
		if lc, ok := leaf["caveats"].([]any); ok {
			if len(lc) > len(gcs) {
				extra = lc[len(gcs):]
			} else {
				extra = []any{}
			}
		}
		if k1r != nil {
			extra = k1StockList(extra, k1r.Plain)
		}
		ok, failed := evaluateAgentCaveats(extra, cctx, actionCtx, toolCall, &regexBudget{})
		why := ""
		if k1r != nil && !k1r.OK {
			failed = append(append([]string{}, failed...), k1r.Failed...)
			why = " (" + strings.Join(k1r.Reasons, "; ") + ")"
		}
		if ok && (k1r == nil || k1r.OK) {
			mark("delegated_caveats", "pass")
		} else {
			fail("delegated_caveats", "delegation caveat(s) not satisfied: "+strings.Join(failed, ", ")+why)
		}
	}

	policyWhy := policyStep(env, grant, cctx, actionCtx, toolCall, k1r != nil)
	if len(policyWhy) > 0 {
		checks.set("policy", "fail")
		for _, w := range policyWhy {
			reasons = append(reasons, "policy: "+w)
		}
	} else {
		mark("policy", "pass")
	}
	if k1r != nil && !k1r.OK && len(chain) == 0 { // no chain to report under delegated_caveats: the root grant's K1 caveats
		fail("policy", "k1 caveat(s) not satisfied: "+strings.Join(k1r.Failed, ", ")+" ("+strings.Join(k1r.Reasons, "; ")+")")
	}

	// ---- risk, trust budget and threshold (policy-vm.ts steps 3-5, server/verify.ts): the server's own risk inputs, the signed
	// `caution` as a floor on r, the budget leaked to now, then the band / admission / release decision. A release at t > 1 needs an
	// enforced threshold (ThresholdHook): without one it fails `threshold`. A metered release is debited in the SAME atomic step as
	// the replay claim (BudgetStore.ClaimBudgeted); a store that cannot persist the budget refuses it.
	var budgetWrite *budgetWriteT
	if env != nil {
		if rp, ok := RiskPolicyOf(env["risk_policy"]); ok {
			budgetWrite = riskStep(&in, &op, grant, p, chain, ctx, rp, now, policyWhy, planNodes, nodeID, effective, checks.st, mark, fail, &reasons)
		}
	}

	// ---- required checks (default-deny), then the replay claim. `replay` passes tentatively and flips to fail when the
	// store refuses the claim below. A counter the stream already passed fails here, before any escalation answer or undo
	// admission is consulted (a replayed proof never reaches the coordinator), as in the reference.
	if replayed := func() string {
		ls, ok := in.StateStore.(LastStore)
		if !ok || len(chain) == 0 {
			return ""
		}
		leaf, _ := chain[len(chain)-1].(map[string]any)
		h, okH := leaf["holder"].(string)
		gid, okG := grant["id"].(string)
		c, okC := safeInt(p["counter"])
		if !okH || !okG || !okC {
			return ""
		}
		if l, err := ls.Last(StateKey(gid, h)); err == nil && l != nil && !(c > *l) {
			return fmt.Sprintf("%d is not greater than last seen %d (replay)", c, *l)
		}
		return ""
	}(); replayed != "" {
		fail("replay", replayed)
	} else {
		mark("replay", "pass")
	}
	assuranceReport := func() AssuranceReport {
		src := AssuranceSources{PCActn: p, Hooks: in.AssuranceHooks}
		for _, n := range checks.order {
			name := n
			if name == "chain" {
				name = "cap_chain" // the reference's name for the capability chain check
			}
			src.Checks = append(src.Checks, NamedStatus{Name: name, Status: checks.st[n]})
		}
		if core.LegacyModelPolarity && checks.st["tighten"] == "pass" {
			src.Degraded = map[string]string{"tighten": LegacyPolarityDegraded}
		}
		return BuildAssuranceReport(src)
	}
	if in.RequireAssurance != nil {
		if why := UnmetAssurance(assuranceReport(), *in.RequireAssurance); why != "" {
			checks.set("assurance", "fail")
			reasons = append(reasons, why)
		}
	}
	required := append([]string(nil), defaultRequiredChecks...)
	if in.Beacon != nil {
		required = append(required, "beacon")
	}
	if in.stalenessOn() {
		required = append(required, "freshness")
	}
	for _, name := range in.Require {
		if name == "counter" { // the 0.4 name of the stateful check
			name = "replay"
		}
		required = append(required, name)
	}
	for _, name := range required {
		// every check set so far is "pass" or "fail": one that is neither is absent
		if st := checks.st[name]; st != "pass" && st != "fail" {
			checks.set(name, "fail")
			reasons = append(reasons, name+": required check is absent (default-deny: not enforced by this resource server)")
		}
	}

	// ---- provenance by default (its own check name: `provenance` is the Intent v2 rule 17 check, never overwritten)
	if st, why := argProvenanceGate(in, p, grant, op, principalPlan, principalControl); st == "fail" {
		fail("provenance_flow", why)
	} else if checks.st["provenance_flow"] != "fail" { // a required check's failure above is never overwritten
		mark("provenance_flow", st)
	}

	passportLeaf, passportHW := "", false
	if in.RequirePassport != nil {
		why := ""
		leafHolder := ""
		if len(chain) > 0 {
			leaf, _ := chain[len(chain)-1].(map[string]any)
			leafHolder, _ = leaf["holder"].(string)
		}
		switch {
		case leafHolder == "":
			why = "malformed"
		default:
			po := in.RequirePassport.Options
			po.NowMs, po.Subject = now, &leafHolder
			why = VerifyPassport(in.Passport, po)
			if why == "" && in.RequirePassport.Hardware {
				if sp, _ := in.Passport.(map[string]any); sp != nil {
					if pp, _ := sp["passport"].(map[string]any); pp["hardware_rooted"] != true {
						why = "hardware_evidence_missing"
					}
				}
			}
		}
		if why != "" {
			fail("passport", why)
		} else {
			mark("passport", "pass")
			passportLeaf = leafHolder
			if sp, _ := in.Passport.(map[string]any); sp != nil {
				pp, _ := sp["passport"].(map[string]any)
				passportHW = pp["hardware_rooted"] == true
			}
		}
	}

	var principal *PrincipalInfo
	if in.ResolvePrincipal != nil {
		issuer, _ := grant["issuer"].(string)
		resolved, rerr := callResolvePrincipal(in.ResolvePrincipal, issuer, grant)
		switch {
		case rerr:
			fail("principal", "the principal resolver failed (fail closed)")
		default:
			if resolved == nil {
				resolved = &PrincipalInfo{Pub: issuer, SubjectType: "unverified"}
			}
			principal = resolved
			switch {
			case in.RequireVerifiedPrincipal && !resolved.Verified:
				fail("principal", "the grant issuer is not an enrolled, verified principal")
			case resolved.Verified:
				mark("principal", "pass")
			default:
				mark("principal", "not-enforced")
			}
		}
	} else if in.RequireVerifiedPrincipal {
		fail("principal", "requireVerifiedPrincipal needs a resolvePrincipal resolver")
	}

	unsupportedRefused := false
	if _, has := p["bond_ref"]; has {
		if checks.st["bond"] != "fail" { // a required check's failure above is never overwritten
			mark("bond", "unsupported")
		}
		if !slices.Contains(in.AllowUnsupported, "bond") {
			unsupportedRefused = true
			reasons = append(reasons, "bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)")
		}
	}

	var escalation map[string]any
	answeredBy := ""
	var undoAdm *UndoAdmission
	var undoObligation map[string]any
	deny := func() AuthorizeResult {
		status := 403
		for _, c := range authnChecks {
			if checks.st[c] == "fail" {
				status = 401
				break
			}
		}
		dec := "deny"
		if escalation != nil {
			dec = "escalate"
		}
		return AuthorizeResult{Status: status, Checks: checks.st, Reasons: reasons, Reason: decisive(checks, reasons),
			PCActn: p, Verdict: &core, Decision: dec, Escalation: escalation, Assurance: assuranceReport()}
	}
	var holder string
	hasHolder := false
	if len(chain) > 0 {
		if leaf, ok := chain[len(chain)-1].(map[string]any); ok {
			holder, hasHolder = leaf["holder"].(string)
		}
	}
	grantID, hasID := grant["id"].(string)
	if unsupportedRefused {
		return deny()
	}
	anyFail := false
	for _, s := range checks.st {
		if s == "fail" {
			anyFail = true
		}
	}
	if anyFail {
		if !hasHolder || !hasID || !allEscalateClass(checks, reasons) {
			return deny()
		}
		// Ternary decision: every failing check is escalate-class. Never admitted by itself.
		var last *int64
		headKnown := false
		if ls, ok := in.StateStore.(LastStore); ok {
			if l, err := ls.Last(StateKey(grantID, holder)); err == nil {
				last, headKnown = l, true
			}
		}
		var rerr error
		renderDigest := ""
		if in.EscalationRender != nil {
			func() {
				defer func() { _ = recover() }() // a render that cannot be derived is no render (refused below when required)
				renderDigest = in.EscalationRender(p)
			}()
		}
		if escalation, rerr = authorizeEscBuild(in.Audience, grant, p, last, reasons, now, in.EscalationRequestTTLMs, renderDigest); rerr != nil {
			return deny()
		}
		// an answer with no pinned principal is still verified (and refused with its reason), as in the reference
		if !in.InsecureUnboundApproval && renderDigest == "" && in.EscalationAnswer != nil {
			reasons = append(reasons, "escalation: an approval render is required and none could be recomputed (set escalation.render, or insecureUnboundApproval)")
		} else if in.EscalationAnswer != nil && headKnown {
			pd, e1 := authorizeEscPolicyDigest(grant)
			ad, e2 := authorizeEscActionDigest(p)
			hh, e3 := authorizeEscHistoryHead(last)
			if e1 == nil && e2 == nil && e3 == nil { // an unbindable answer is never verified
				v := VerifyEscalationAnswer(in.EscalationAnswer, in.escalationPins(), EscalationBinding{PolicyDigest: pd, ActionDigest: ad, HistoryHead: hh, RenderDigest: renderDigest}, now)
				switch {
				case v.OK && v.Decision == "allow":
					liftFailed(checks.st)
					checks.set("escalation", "pass")
					// v.OK: the principal passed the answer shape check, canonical base64url of 32 bytes (43 characters)
					reasons = append(reasons, "escalation: answered allow by principal "+v.Principal[:8])
					answeredBy, escalation = v.Principal, nil
				case v.OK:
					reasons = append(reasons, "escalation: the principal answered deny")
				default:
					reasons = append(reasons, "escalation: "+v.Reason)
				}
			}
		}
		// Undo window: an unanswered escalation runs now under a veto window when the coordinator admits it. Only escalate-class
		// failures are lifted (exactly what an answer would lift). Never for a provenance escalation: reversibility does not
		// make an action injected content chose safe to run.
		provenanceEscalated := checks.st["provenance_flow"] == "fail" || checks.st["provenance"] == "fail"
		if escalation != nil && in.Undo != nil && in.EscalationAnswer == nil && !provenanceEscalated {
			if adm, ob := callUndoAdmit(in.Undo, UndoAdmitInput{PCActn: p, Grant: grant, Operation: op}); adm != nil {
				liftFailed(checks.st)
				checks.set("undo_window", "pass")
				reasons = append(reasons, fmt.Sprintf("undo_window: runs now under a veto window until %d (compensation %s)", adm.WindowEnd, adm.Compensation.Verb))
				undoAdm, undoObligation, escalation = adm, ob, nil
			}
		}
		if escalation != nil {
			return deny()
		}
	}

	counter, hasCounter := safeInt(p["counter"])
	if !hasHolder || !hasID || !hasCounter {
		fail("replay", "no counter stream for this proof (fail closed)")
		return deny()
	}
	// the rollback pin rises only for an action that is allowed so far and whose freshness check passed (monotone: raising it to
	// a value that just verified is safe even if the claim below then loses)
	if revEpochPin.key != "" && revEpochPin.epoch != nil {
		if raisePin(in.StateStore.(PinStore), revEpochPin.key, *revEpochPin.epoch) {
			fail("freshness", "the revocation pin store failed (fail closed)")
			return deny()
		}
	}
	if in.Contracts != nil {
		if cr := contractRefusal(in.Contracts.Check(contractAction(op), true)); cr != nil {
			fail("contract", strings.TrimPrefix(cr.Reason, "contract: "))
			return deny()
		}
	}
	if beaconSeq != nil {
		if raisePin(in.StateStore.(PinStore), grant["id"].(string)+":beacon", float64(*beaconSeq)) {
			fail("beacon", "the beacon pin could not be stored (fail closed)")
			return deny()
		}
	}
	var claimed ClaimResult
	var serr bool
	if budgetWrite != nil {
		bs, isBS := in.StateStore.(BudgetStore)
		if !isBS {
			fail("budget", "this store does not persist trust budgets (a metered action cannot be admitted)")
			return deny()
		}
		var outcome BudgetClaim
		outcome, claimed, serr = callClaimBudgeted(bs, StateKey(grantID, holder), counter, budgetWrite.before, budgetWrite.after)
		if !serr && outcome == BudgetConflict {
			fail("budget", "the trust budget changed while this action was decided (a concurrent spend): retry (fail closed)")
			return deny()
		}
	} else {
		claimed, serr = callClaim(in.StateStore, StateKey(grantID, holder), counter)
	}
	if serr || !claimed.OK {
		switch {
		case serr:
			fail("replay", "the replay store failed (fail closed)")
		case claimed.LastCounter != nil:
			fail("replay", fmt.Sprintf("%d is not greater than last seen %d (replay)", counter, *claimed.LastCounter))
		default:
			fail("replay", fmt.Sprintf("%d was already claimed (replay)", counter))
		}
		return deny()
	}
	if k1r != nil && k1HasMaxUses(k1r.Bound) { // spent only for an otherwise admitted action, after the counter claim
		if in.UsesStore == nil {
			fail("max_uses", "the chain carries a max_uses caveat and this guard has no UsesStore (fail closed)")
			return deny()
		}
		if r := ReserveMaxUses(in.UsesStore, k1r.Bound, float64(now)); !r.OK {
			fail("max_uses", r.Reason)
			return deny()
		}
	}
	// fail closed when the leaf could not be read up front, or the guard admitted a different leaf than the passport was checked for
	if in.RequirePassport != nil && (passportLeaf == "" || passportLeaf != holder) {
		fail("passport", "subject_mismatch")
		return deny()
	}
	id, herr := HashCanonical(p)
	if herr != nil {
		return refuse(403, "authorize", "authorize: error (fail closed): "+herr.Error(), nil, p)
	}
	sd, _ := signedDigest.(string)
	res := AuthorizeResult{Principal: principal, Allow: true, Status: 200, Checks: checks.st, Reasons: reasons, PCActn: p, Verdict: &core, Decision: "allow",
		Assurance: assuranceReport(),
		Operation: &AuthorizedOperation{Verb: op.Verb, Resource: op.Resource, ParamsDigest: sd, ID: id}}
	if in.RequirePassport != nil {
		pa := CheckAssurance{Outcome: "pass", Level: "software"}
		if passportHW {
			var hook any
			if in.RequirePassport.Options.Attest != nil {
				hook = in.RequirePassport.Options.Attest
			} else if in.RequirePassport.Options.DefaultHardware != nil {
				hook = in.RequirePassport.Options.DefaultHardware.Verifier // the vendor verifier carries the label (hardware, vendor)
			}
			l := labelOf(hook)
			pa.Level, pa.Vendor = l.Level, l.Vendor
			if pa.Level == "" {
				pa.Level = "unknown"
			}
		}
		res.Assurance.Set("passport", pa)
	}
	if answeredBy != "" {
		res.Escalation = map[string]any{"answered_by": answeredBy}
	}
	if undoAdm != nil {
		res.Undo, res.Obligations = undoAdm, []any{undoObligation}
	}
	if core.LegacyModelPolarity && checks.st["tighten"] == "pass" {
		res.Degraded = map[string]string{"tighten": LegacyPolarityDegraded}
	}
	return res
}

// LegacyPolarityDegraded is the Degraded["tighten"] text of a verdict that passed rule 21 under model_polarity "legacy".
const LegacyPolarityDegraded = "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"

// coreCheckOrder lists the core verdict's checks in the normative order (unknown names after, sorted).
func coreCheckOrder(m map[string]bool) []string {
	normative := []string{"wire", "version", "audience", "validity", "pq_pin", "freshness_anchor", "chain", "grant_ref_bound", "plan_inclusion",
		"plan_root_authorized", "leaf_signature", "counter_format", "intent", "schema", "intent_session", "layers", "accumulators", "map", "facts",
		"provenance", "classes", "fresh_at", "taint_gate"}
	out := make([]string, 0, len(m))
	seen := map[string]bool{}
	for _, n := range normative {
		if _, has := m[n]; has {
			out = append(out, n)
			seen[n] = true
		}
	}
	rest := []string{}
	for n := range m {
		if !seen[n] {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// planRoot never panics: canonicalization reports unsupported values as errors. A nil node is refused here, not left to planLeaf.
func planRoot(nodes []map[string]any) (root string, ok bool) {
	leaves := make([]any, len(nodes))
	for i, n := range nodes {
		if n == nil {
			return "", false
		}
		cond, err := conditionsDigest(n["pre"], n["post"])
		if err != nil {
			return "", false
		}
		leaf, err := planRootLeaf(n["id"], n, cond)
		if err != nil {
			return "", false
		}
		leaves[i] = leaf
	}
	r, err := MerkleRoot(leaves)
	return r, err == nil
}

// policyStep never panics: the predicate and caveat evaluators it calls recover their own errors (fail closed).
func policyStep(env, grant map[string]any, cctx, actionCtx map[string]any, tc *ToolCall, k1 bool) (why []string) {
	if env == nil {
		return []string{"grant carries no valid envelope"}
	}
	b := &regexBudget{} // one document budget for the whole policy step
	if ok, reason := envelopePredicates(env["predicates"], actionCtx, b); !ok {
		why = append(why, reason)
	}
	if ok, failed := evaluateAgentCaveats(env["caveats"], cctx, actionCtx, tc, b); !ok {
		why = append(why, "caveat(s) not satisfied: "+strings.Join(failed, ", "))
	}
	root := RootCaveats(grant)
	if k1 { // K1 caveat types are evaluated by EvaluateK1 over the whole chain
		root = k1StockList(root, nil)
	}
	if ok, failed := evaluateAgentCaveats(root, cctx, actionCtx, tc, b); !ok {
		why = append(why, "root caveat(s) not satisfied: "+strings.Join(failed, ", "))
	}
	return why
}

// envelopePredicates is evaluatePredicates with its refusal reason: the action must match at least one predicate
// (default deny: an empty list allows nothing).
func envelopePredicates(predicates any, actionCtx map[string]any, b *regexBudget) (ok bool, reason string) {
	defer func() {
		if recover() != nil {
			ok, reason = false, "predicate evaluation error (fail closed)"
		}
	}()
	arr, isArr := predicates.([]any)
	if !isArr || len(arr) == 0 {
		return false, "envelope grants no predicates"
	}
	for _, pr := range arr {
		if predicateMatches(pr, actionCtx, b) {
			return true, ""
		}
	}
	a, _ := actionCtx["action"].(map[string]any)
	if limit, found := firstUnmetLimit(arr, actionCtx, b); found {
		return false, limit + " not satisfied for " + jsMemberString(a, "verb") + " on " + jsMemberString(a, "resource")
	}
	return false, "no predicate permits " + jsMemberString(a, "verb") + " on " + jsMemberString(a, "resource")
}

// v2Env is the predicate `env`: the host's, with the verifier-computed Intent Layer v2 members (TypeScript v2Env).
func v2Env(p, grant map[string]any, v2 *IntentV2Context, now int64, env any) any {
	if _, has := p["intent_session"]; !has {
		return env
	}
	rest := map[string]any{}
	if m, ok := env.(map[string]any); ok {
		for k, v := range m {
			rest[k] = v
		}
	}
	for _, k := range []string{"acc", "mon", "canon", "world", "prov", "class"} {
		delete(rest, k)
	}
	for k, v := range decideIntentV2(p, grant, v2, float64(now)).env {
		if v != nil {
			rest[k] = v
		}
	}
	return rest
}

// ---- the host callbacks, each total (a panic is an error) -----------------------------------------------------------

func callResolve(f func(string) (map[string]any, error), ref string) (g map[string]any, failed bool) {
	defer func() {
		if recover() != nil {
			g, failed = nil, true
		}
	}()
	g, err := f(ref)
	if err != nil {
		return nil, true
	}
	return g, false
}

func callContext(f func(map[string]any) (*AuthorizeContext, error), p map[string]any) (c *AuthorizeContext, failed bool) {
	defer func() {
		if recover() != nil {
			c, failed = nil, true
		}
	}()
	c, err := f(p)
	return c, err != nil
}

func callIntentV2(f func(map[string]any) (*IntentV2Context, error), p map[string]any) (c *IntentV2Context, failed bool) {
	defer func() {
		if recover() != nil {
			c, failed = nil, true
		}
	}()
	c, err := f(p)
	return c, err != nil
}

func callLinkedPolicy(f func() map[string]any, env map[string]any) (why string) {
	defer func() {
		if recover() != nil {
			why = "link verification error (fail closed)"
		}
	}()
	return VerifyLinkedPolicy(env, f())
}

func callResolvePrincipal(f func(string, map[string]any) (*PrincipalInfo, error), issuer string, grant map[string]any) (pi *PrincipalInfo, failed bool) {
	defer func() {
		if recover() != nil {
			pi, failed = nil, true
		}
	}()
	pi, err := f(issuer, grant)
	return pi, err != nil
}

func callRevoked(f func(pcactn, grant map[string]any) (bool, error), p, g map[string]any) (revoked, failed bool) {
	defer func() {
		if recover() != nil {
			revoked, failed = false, true
		}
	}()
	revoked, err := f(p, g)
	return revoked, err != nil
}

func callClaimBudgeted(s BudgetStore, key string, counter int64, before, after map[string]any) (outcome BudgetClaim, r ClaimResult, failed bool) {
	defer func() {
		if recover() != nil {
			outcome, r, failed = 0, ClaimResult{}, true
		}
	}()
	o, r, err := s.ClaimBudgeted(key, counter, before, after)
	return o, r, err != nil
}

func callClaim(s StateStore, key string, counter int64) (r ClaimResult, failed bool) {
	defer func() {
		if recover() != nil {
			r, failed = ClaimResult{}, true
		}
	}()
	r, err := s.Claim(key, counter)
	if err != nil {
		return ClaimResult{}, true
	}
	return r, false
}

// isAuthorizedFault is a test seam (nil in production): it runs inside IsAuthorizedFor's recover scope, after the params copy
// succeeded, so a test can pin that a panic there is a refusal.
var isAuthorizedFault func()

// IsAuthorizedFor reports whether result allowed exactly this operation (verb, resource, params digest). Call it where
// the side effect runs, with the values it is about to use.
func IsAuthorizedFor(result AuthorizeResult, op *Operation) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	b := result.Operation
	if !result.Allow || b == nil || !validOperation(op) {
		return false
	}
	params, ok := copyParams(op.Params)
	if !ok {
		return false
	}
	if isAuthorizedFault != nil {
		isAuthorizedFault()
	}
	d, err := ParamsDigest(params)
	return err == nil && b.Verb == op.Verb && b.Resource == op.Resource && b.ParamsDigest == d
}

// allEscalateClass: at least one check failed and every failing check has at least one reason "<check>: <body>" and
// every such body starts with an escalate prefix (DecisionOf == "escalate" over the checks and reasons).
func allEscalateClass(c *orderedChecks, reasons []string) bool {
	rs := make([]any, len(reasons))
	for i, r := range reasons {
		rs[i] = r
	}
	checks := map[string]any{}
	for n, st := range c.st {
		checks[n] = st
	}
	return DecisionOf(map[string]any{"allow": false, "checks": checks, "reasons": rs}) == "escalate"
}

// callK1 reads the optional K1 input; an error, a nil result or a panic is nil = no input (every K1 caveat then fails closed).
func callK1(f func(map[string]any) (*K1Input, error), p map[string]any) (ki *K1Input) {
	defer func() {
		if recover() != nil {
			ki = nil
		}
	}()
	if got, err := f(p); err == nil && got != nil {
		c := *got
		ki = &c
	}
	return ki
}

// k1Present reports whether the chain carries a K1 caveat type anywhere (a malformed chain reports false: the stock path judges it).
func k1Present(grant, chain any) bool {
	bound, ok := BoundCaveats(grant, chain)
	return ok && len(clK1Only(bound)) > 0
}

// k1StockList is the part of a caveat list the stock evaluator keeps when K1 is on: the non-K1 caveats, then plain. A value that
// is not a list is returned unchanged (the stock evaluator refuses it).
func k1StockList(v any, plain []any) any {
	list, ok := v.([]any)
	if !ok {
		return v
	}
	out := make([]any, 0, len(list)+len(plain))
	for _, c := range list {
		if !IsK1Caveat(c) {
			out = append(out, c)
		}
	}
	return append(out, plain...)
}

func k1HasMaxUses(bound []BoundCaveat) bool {
	for _, b := range bound {
		if m, ok := b.Caveat.(map[string]any); ok && m["type"] == CaveatMaxUses {
			return true
		}
	}
	return false
}

// authorizePlanContext is PlanRegistry.Context; a test seam so the principal-plan guard above stays observable.
var authorizePlanContext = func(r *PlanRegistry, grantRef, root string, now int64) *PlanContext {
	return r.Context(grantRef, root, now)
}
