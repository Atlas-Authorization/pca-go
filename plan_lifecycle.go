package pca

// Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and
// the principal's plan authorization.
//
//	draft ──Validate──▶ validated ──Commit──▶ committed ──Authorize──▶ authorized
//	  └─────────────────────┴──────────────────────┴──────────Revoke──────┴──▶ revoked
//
//   - draft: the nodes are recorded; the root is computed from them (never taken from the caller).
//   - validated: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the
//     server's own Validator (for example every node inside the grant's predicates).
//   - committed: the root is fixed. A committed plan is NOT executable: it still needs the principal.
//   - authorized: the principal approved this root for this grant, optionally until ExpiresAt.
//   - revoked: terminal; every later action against the root is denied.
//
// "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is authorized, the
// approval has not expired, and its stored nodes still hash to the root. Check adds the per-action staleness rules a
// server applies immediately before execution: the node exists and the operation's verb, resource and params still match
// what the principal approved. The registry only feeds the plan into Authorize (AuthorizeInput.Plans) and names the state
// on a denial; the wire formats are unchanged. Mirrors the reference plan registry; plan-vectors.json pins it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"time"
)

// PlanState is a plan's lifecycle state.
type PlanState string

// The plan states.
const (
	PlanDraft      PlanState = "draft"
	PlanValidated  PlanState = "validated"
	PlanCommitted  PlanState = "committed"
	PlanAuthorized PlanState = "authorized"
	PlanRevoked    PlanState = "revoked"
	// PlanUnknown is the state reported for a root this grant does not have.
	PlanUnknown PlanState = "unknown"
)

// PlanApproval is the principal's approval of a plan.
type PlanApproval struct {
	// By is who approved (the principal's key or account id, for the record).
	By string `json:"by"`
	// ExpiresAt: the approval lapses at this time (epoch ms); nil: until revoked. It must be finite.
	ExpiresAt *float64 `json:"expiresAt,omitempty"`
}

// PlanRecord is the stored plan. Nodes are the plan nodes ({id, verb, resource, params_digest?, reversibility_class?,
// pre?, post?}); Root is their Merkle root, computed by the registry.
type PlanRecord struct {
	GrantRef      string           `json:"grantRef"`
	Root          string           `json:"root"`
	Nodes         []map[string]any `json:"nodes"`
	State         PlanState        `json:"state"`
	CreatedAt     int64            `json:"createdAt"`
	ValidatedAt   int64            `json:"validatedAt,omitempty"`
	CommittedAt   int64            `json:"committedAt,omitempty"`
	AuthorizedAt  int64            `json:"authorizedAt,omitempty"`
	Approval      *PlanApproval    `json:"approval,omitempty"`
	RevokedAt     int64            `json:"revokedAt,omitempty"`
	RevokedReason string           `json:"revokedReason,omitempty"`
}

// PlanTransition is the result of a lifecycle transition: OK with the new Record, or the State the plan is in and the
// Reason it refused.
type PlanTransition struct {
	OK     bool
	Record *PlanRecord
	State  PlanState
	Reason string
}

// PlanStatus is a plan's state at the moment of use.
type PlanStatus struct {
	State      PlanState `json:"state"`
	Executable bool      `json:"executable"`
	// Reason says why it is not executable.
	Reason string      `json:"reason,omitempty"`
	Record *PlanRecord `json:"record,omitempty"`
}

// PlanValidation is a Validator's answer.
type PlanValidation struct {
	OK     bool
	Reason string
}

// PlanContext is the verifier context for an action against a root: the stored plan and whether it is executable now.
type PlanContext struct {
	Plan           []map[string]any `json:"plan"`
	PlanAuthorized bool             `json:"planAuthorized"`
	Status         PlanStatus       `json:"status"`
}

// PlanCheckOptions configures PlanRegistry.Check.
type PlanCheckOptions struct {
	// NodeID is the plan node the action executes (the PCActn's plan.node_id); "" = not named.
	NodeID string
	// Operation is the operation about to execute: it must match the node (verb, resource, params digest).
	Operation *Operation
	// Now is the time of the check in epoch ms (0: the registry clock).
	Now int64
}

// PlanRegistryOptions configures NewPlanRegistry.
type PlanRegistryOptions struct {
	// KV is where the records live (nil: in memory, one process). Use NewSQLAtomicKV for a database.
	KV AtomicKV
	// Prefix is the key prefix in KV (default "pca-plan:").
	Prefix string
	// Now is the clock in epoch ms (nil: the wall clock).
	Now func() int64
	// Validator is the server's validation, run by Validate after the structural checks (for example each node is within
	// the grant's predicates). An error or panic refuses.
	Validator func(rec PlanRecord) (PlanValidation, error)
}

// PlanRegistry is the plan lifecycle store. Safe for concurrent use when the AtomicKV is: every transition is one atomic
// update, so of N concurrent claims of one transition exactly one succeeds.
type PlanRegistry struct {
	kv        AtomicKV
	prefix    string
	now       func() int64
	validator func(PlanRecord) (PlanValidation, error)
}

// NewPlanRegistry builds a registry.
func NewPlanRegistry(opts PlanRegistryOptions) *PlanRegistry {
	r := &PlanRegistry{kv: opts.KV, prefix: opts.Prefix, now: opts.Now, validator: opts.Validator}
	if r.kv == nil {
		r.kv = NewMemoryAtomicKV()
	}
	if r.prefix == "" {
		r.prefix = "pca-plan:"
	}
	if r.now == nil {
		r.now = func() int64 { return time.Now().UnixMilli() }
	}
	return r
}

func (r *PlanRegistry) key(grantRef, root string) string {
	return r.prefix + url.QueryEscape(grantRef) + ":" + root
}

func decodePlanRecord(b []byte) (PlanRecord, bool) {
	var rec PlanRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if len(b) == 0 || d.Decode(&rec) != nil || rec.Root == "" || rec.Nodes == nil {
		return PlanRecord{}, false
	}
	return rec, true
}

// Get returns the stored plan (nil: none for this grant).
func (r *PlanRegistry) Get(grantRef, root string) (*PlanRecord, error) {
	b, ok, err := r.kv.Get(r.key(grantRef, root))
	if err != nil || !ok {
		return nil, err
	}
	if rec, ok := decodePlanRecord(b); ok {
		return &rec, nil
	}
	return nil, nil
}

func unknownPlan(root string) PlanTransition {
	return PlanTransition{State: PlanUnknown, Reason: fmt.Sprintf("plan %s is unknown for this grant", root)}
}

func storeRefusal(err error) PlanTransition {
	return PlanTransition{State: PlanUnknown, Reason: "the plan store failed (fail closed): " + err.Error()}
}

// cloneNodes deep-copies plan nodes through JSON (numbers stay exact).
func cloneNodes(nodes []map[string]any) []map[string]any {
	b, err := json.Marshal(nodes)
	if err != nil {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out []map[string]any
	if d.Decode(&out) != nil {
		return nil
	}
	return out
}

// planRootOf is the Merkle root of the plan-node leaves.
func planRootOf(nodes []map[string]any) (string, error) {
	if len(nodes) == 0 {
		return "", fmt.Errorf("merkleRoot: empty leaf set")
	}
	root, ok := planRoot(nodes)
	if !ok {
		return "", fmt.Errorf("a plan node cannot be hashed")
	}
	return root, nil
}

// structuralProblem is the reason a plan's nodes are not well-formed ("" when valid).
func structuralProblem(nodes []map[string]any) string {
	if len(nodes) == 0 {
		return "a plan needs at least one node"
	}
	ids := map[string]bool{}
	for _, n := range nodes {
		id, ok := n["id"].(string)
		if n == nil || !ok || id == "" {
			return "every node needs an id"
		}
		if ids[id] {
			return fmt.Sprintf("duplicate node id '%s'", id)
		}
		ids[id] = true
		if v, ok := n["verb"].(string); !ok || v == "" {
			return fmt.Sprintf("node '%s' needs a verb and a resource", id)
		}
		if v, ok := n["resource"].(string); !ok || v == "" {
			return fmt.Sprintf("node '%s' needs a verb and a resource", id)
		}
		if rc, has := n["reversibility_class"]; has {
			s, isStr := rc.(string)
			if _, known := classRank[s]; !isStr || !known {
				return fmt.Sprintf("node '%s' has an unknown reversibility class '%s'", id, jsMemberString(n, "reversibility_class"))
			}
		}
	}
	return ""
}

// move atomically moves a plan from one of `from` to the state `to` (next computes the new record from the current one).
func (r *PlanRegistry) move(grantRef, root string, from []PlanState, to string, next func(PlanRecord) PlanRecord) PlanTransition {
	out := unknownPlan(root)
	err := r.kv.Update(r.key(grantRef, root), func(prev []byte) []byte {
		cur, ok := decodePlanRecord(prev)
		if !ok {
			out = unknownPlan(root)
			return nil
		}
		allowed := false
		for _, s := range from {
			allowed = allowed || cur.State == s
		}
		if !allowed {
			out = PlanTransition{State: cur.State, Reason: fmt.Sprintf("plan %s is %s: cannot %s", root, cur.State, to)}
			return nil
		}
		rec := next(cur)
		enc, merr := json.Marshal(rec)
		if merr != nil {
			out = storeRefusal(merr)
			return nil
		}
		out = PlanTransition{OK: true, Record: &rec}
		return enc
	})
	if err != nil {
		return storeRefusal(err)
	}
	return out
}

// Draft records a draft plan for a grant. The root is computed from nodes. Re-drafting an existing root is refused.
func (r *PlanRegistry) Draft(grantRef string, nodes []map[string]any) PlanTransition {
	if grantRef == "" {
		return PlanTransition{State: PlanUnknown, Reason: "a plan needs a grant"}
	}
	// structural problems are reported by Validate (a draft can be inspected first); an unhashable plan has no root
	root, err := planRootOf(nodes)
	if err != nil {
		return PlanTransition{State: PlanUnknown, Reason: "the plan cannot be committed: " + err.Error()}
	}
	rec := PlanRecord{GrantRef: grantRef, Root: root, Nodes: cloneNodes(nodes), State: PlanDraft, CreatedAt: r.now()}
	if rec.Nodes == nil {
		return PlanTransition{State: PlanUnknown, Reason: "the plan cannot be committed: the nodes are not JSON"}
	}
	enc, err := json.Marshal(rec)
	if err != nil {
		return storeRefusal(err)
	}
	out := PlanTransition{OK: true, Record: &rec}
	if err := r.kv.Update(r.key(grantRef, root), func(prev []byte) []byte {
		if cur, ok := decodePlanRecord(prev); ok {
			out = PlanTransition{State: cur.State, Reason: fmt.Sprintf("plan %s already exists (%s)", root, cur.State)}
			return nil
		}
		out = PlanTransition{OK: true, Record: &rec}
		return enc
	}); err != nil {
		return storeRefusal(err)
	}
	return out
}

func runValidator(f func(PlanRecord) (PlanValidation, error), rec PlanRecord) (v PlanValidation) {
	defer func() {
		if p := recover(); p != nil {
			v = PlanValidation{Reason: "validator error (fail closed): " + panicMessage(p)}
		}
	}()
	out, err := f(rec)
	if err != nil {
		return PlanValidation{Reason: "validator error (fail closed): " + err.Error()}
	}
	return out
}

// Validate moves draft -> validated (structural checks, then the server's Validator).
func (r *PlanRegistry) Validate(grantRef, root string) PlanTransition {
	cur, err := r.Get(grantRef, root)
	if err != nil {
		return storeRefusal(err)
	}
	if cur == nil {
		return unknownPlan(root)
	}
	if cur.State != PlanDraft {
		return PlanTransition{State: cur.State, Reason: fmt.Sprintf("plan %s is %s: cannot validate", root, cur.State)}
	}
	problem := structuralProblem(cur.Nodes)
	if problem == "" {
		if got, err := planRootOf(cur.Nodes); err != nil || got != root {
			problem = "the stored nodes no longer hash to the root"
		}
	}
	if problem != "" {
		return PlanTransition{State: cur.State, Reason: fmt.Sprintf("plan %s is invalid: %s", root, problem)}
	}
	if r.validator != nil {
		clone := *cur
		clone.Nodes = cloneNodes(cur.Nodes)
		v := runValidator(r.validator, clone)
		if !v.OK {
			why := v.Reason
			if why == "" {
				why = "refused by the validator"
			}
			return PlanTransition{State: cur.State, Reason: fmt.Sprintf("plan %s is invalid: %s", root, why)}
		}
	}
	return r.move(grantRef, root, []PlanState{PlanDraft}, "validate", func(p PlanRecord) PlanRecord {
		p.State, p.ValidatedAt = PlanValidated, r.now()
		return p
	})
}

// Commit moves validated -> committed: the root is fixed; it still needs the principal's authorization to execute.
func (r *PlanRegistry) Commit(grantRef, root string) PlanTransition {
	return r.move(grantRef, root, []PlanState{PlanValidated}, "commit", func(p PlanRecord) PlanRecord {
		p.State, p.CommittedAt = PlanCommitted, r.now()
		return p
	})
}

// Authorize moves committed -> authorized with the principal's approval (call it only after verifying the principal's
// consent). A nil approval, an empty By or a non-finite ExpiresAt is refused.
func (r *PlanRegistry) Authorize(grantRef, root string, approval *PlanApproval) PlanTransition {
	stateOf := func() PlanState {
		if cur, _ := r.Get(grantRef, root); cur != nil {
			return cur.State
		}
		return PlanUnknown
	}
	if approval == nil || approval.By == "" {
		return PlanTransition{State: stateOf(), Reason: "an approval names who approved (`by`)"}
	}
	if e := approval.ExpiresAt; e != nil && (math.IsNaN(*e) || math.IsInf(*e, 0)) {
		return PlanTransition{State: stateOf(), Reason: "approval.expiresAt must be a time (epoch ms)"}
	}
	ap := *approval
	return r.move(grantRef, root, []PlanState{PlanCommitted}, "authorize", func(p PlanRecord) PlanRecord {
		p.State, p.AuthorizedAt, p.Approval = PlanAuthorized, r.now(), &ap
		return p
	})
}

// Revoke moves any state except revoked to revoked (terminal).
func (r *PlanRegistry) Revoke(grantRef, root, reason string) PlanTransition {
	return r.move(grantRef, root, []PlanState{PlanDraft, PlanValidated, PlanCommitted, PlanAuthorized}, "revoke", func(p PlanRecord) PlanRecord {
		p.State, p.RevokedAt, p.RevokedReason = PlanRevoked, r.now(), reason
		return p
	})
}

// Status is the state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the
// root). now 0 is the registry clock. A store error is reported as not executable.
func (r *PlanRegistry) Status(grantRef, root string, now int64) PlanStatus {
	if now == 0 {
		now = r.now()
	}
	rec, err := r.Get(grantRef, root)
	if err != nil {
		return PlanStatus{State: PlanUnknown, Reason: "the plan store failed (fail closed): " + err.Error()}
	}
	if rec == nil {
		return PlanStatus{State: PlanUnknown, Reason: fmt.Sprintf("plan %s is unknown for this grant", root)}
	}
	if rec.State != PlanAuthorized {
		why := fmt.Sprintf("%s, not authorized", rec.State)
		switch rec.State {
		case PlanCommitted:
			why = "committed but not authorized by the principal"
		case PlanRevoked:
			reason := rec.RevokedReason
			if reason == "" {
				reason = "no reason given"
			}
			why = fmt.Sprintf("revoked (%s)", reason)
		}
		return PlanStatus{State: rec.State, Reason: fmt.Sprintf("plan %s is %s", root, why), Record: rec}
	}
	if rec.Approval != nil && rec.Approval.ExpiresAt != nil && !(float64(now) < *rec.Approval.ExpiresAt) {
		return PlanStatus{State: rec.State, Record: rec,
			Reason: fmt.Sprintf("plan %s: the principal's approval expired at %s", root, jsNumberString(*rec.Approval.ExpiresAt))}
	}
	if got, err := planRootOf(rec.Nodes); err != nil || got != root {
		return PlanStatus{State: rec.State, Record: rec, Reason: fmt.Sprintf("plan %s: the stored nodes no longer hash to the root", root)}
	}
	return PlanStatus{State: rec.State, Executable: true, Record: rec}
}

// Check is Status plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately
// before execution.
func (r *PlanRegistry) Check(grantRef, root string, o PlanCheckOptions) PlanStatus {
	s := r.Status(grantRef, root, o.Now)
	if !s.Executable || s.Record == nil || (o.NodeID == "" && o.Operation == nil) {
		return s
	}
	var node map[string]any
	if o.NodeID != "" {
		for _, n := range s.Record.Nodes {
			if n["id"] == any(o.NodeID) {
				node = n
				break
			}
		}
		if node == nil {
			s.Executable, s.Reason = false, fmt.Sprintf("plan %s has no node '%s'", root, o.NodeID)
			return s
		}
	}
	if op := o.Operation; op != nil {
		candidates := s.Record.Nodes
		if node != nil {
			candidates = []map[string]any{node}
		}
		digest, err := ParamsDigest(paramsAny(op.Params))
		if err != nil {
			s.Executable, s.Reason = false, fmt.Sprintf("plan %s: the operation's params cannot be hashed", root)
			return s
		}
		empty, _ := ParamsDigest(nil)
		same := false
		for _, n := range candidates {
			nd, has := n["params_digest"]
			if !has || nd == nil {
				nd = empty
			}
			if n["verb"] == any(op.Verb) && n["resource"] == any(op.Resource) && nd == any(digest) {
				same = true
			}
		}
		if !same {
			s.Executable = false
			s.Reason = fmt.Sprintf("plan %s: the operation (%s on %s with these params) is not what the principal approved", root, op.Verb, op.Resource)
		}
	}
	return s
}

// IsPlanAuthorized is true only when the plan is executable now (fail closed on any error).
func (r *PlanRegistry) IsPlanAuthorized(grantRef, planRoot string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return r.Status(grantRef, planRoot, 0).Executable
}

// Context is the verifier context for an action against root: the stored plan, and PlanAuthorized = executable. nil: the
// root is unknown for this grant.
func (r *PlanRegistry) Context(grantRef, root string, now int64) *PlanContext {
	s := r.Status(grantRef, root, now)
	if s.Record == nil {
		return nil
	}
	return &PlanContext{Plan: cloneNodes(s.Record.Nodes), PlanAuthorized: s.Executable, Status: s}
}
