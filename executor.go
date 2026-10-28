package pca

// Executor: Authorize + ExecuteAuthorized in one call, with retries answered from the record. A second presentation of
// the same PCActn is refused by Authorize as a replay; if that replay is the ONLY failing check (the proof, binding,
// policy and revocation all still pass now) and a record exists for its operation id and this operation, the record's
// outcome is returned (Replayed true) instead of the bare denial. No record means the first attempt never reached
// execution: the denial stands (the authorization was consumed; the agent signs a fresh PCActn).

import "time"

// ExecutorOptions configures NewExecutor.
type ExecutorOptions struct {
	// Operations is REQUIRED: the operation record store.
	Operations OperationStore
	// Authorize is the Authorize configuration (Audience, ResolveGrant, StateStore, IsRevoked, Plans, ...). Its Operation
	// is set per call. Before an irreversible operation the executor re-runs IsRevoked against the grant, checks the
	// PCActn's expiry, and with Authorize.Plans that the registered plan is still executable for the node.
	Authorize AuthorizeInput
	// Recheck is an extra re-check before an irreversible operation (for example a step-up approval still stands).
	Recheck func(h ExecutionHandle) (RecheckResult, error)
	// RecheckFor: "" or "irreversible" (default), or "always".
	RecheckFor string
	// ReversibilityClassOf is the server's reversibility class for an operation (catalog); nil: the signed class only.
	ReversibilityClassOf func(op Operation) string
	// PendingTimeoutMs: an open record older than this is settled (0: OperationPendingTimeoutMs).
	PendingTimeoutMs int64
	// Now is the clock in epoch ms (nil: the wall clock; Authorize.Now, when set, wins for the authorization).
	Now func() int64
}

// ExecutorOutcome is the executor's answer: the execution outcome, or (Status "denied") the authorization denial with
// nothing run.
type ExecutorOutcome struct {
	ExecuteOutcome
	Authorization *AuthorizeResult
}

// Executor runs authorized operations at most once. Safe for concurrent use.
type Executor struct{ o ExecutorOptions }

// NewExecutor builds an executor.
func NewExecutor(o ExecutorOptions) *Executor { return &Executor{o: o} }

func (e *Executor) clock() func() int64 {
	if e.o.Now != nil {
		return e.o.Now
	}
	return func() int64 { return time.Now().UnixMilli() }
}

func (e *Executor) timeout() int64 {
	if e.o.PendingTimeoutMs != 0 {
		return e.o.PendingTimeoutMs
	}
	return OperationPendingTimeoutMs
}

// recheck is the executor's own re-check: the grant is still known and not revoked, a registered plan is still executable,
// then the caller's extra re-check.
func (e *Executor) recheck(now func() int64) func(ExecutionHandle) (RecheckResult, error) {
	in := e.o.Authorize
	return func(h ExecutionHandle) (RecheckResult, error) {
		ref, _ := h.PCActn["grant_ref"].(string)
		grant, gerr := callResolve(in.ResolveGrant, ref)
		if gerr || grant == nil {
			return RecheckResult{Reason: "the grant is no longer known"}, nil
		}
		revoked, rerr := callRevoked(in.IsRevoked, h.PCActn, grant)
		if rerr {
			return RecheckResult{Reason: "revocation could not be checked"}, nil
		}
		if revoked {
			return RecheckResult{Reason: "the grant has been revoked"}, nil
		}
		// a registered plan must still be executable: not revoked, the principal's approval not expired
		if pl, ok := h.PCActn["plan"].(map[string]any); ok && in.Plans != nil {
			if root, ok := pl["root"].(string); ok {
				if rec, _ := in.Plans.Get(ref, root); rec != nil {
					nodeID, _ := pl["node_id"].(string)
					if ps := in.Plans.Check(ref, root, PlanCheckOptions{NodeID: nodeID, Now: now()}); !ps.Executable {
						why := ps.Reason
						if why == "" {
							why = "plan is " + string(ps.State)
						}
						return RecheckResult{Reason: why}, nil
					}
				}
			}
		}
		if e.o.Recheck != nil {
			return e.o.Recheck(h)
		}
		return RecheckResult{OK: true}, nil
	}
}

// Run authorizes pcactn for op and, when allowed, executes fn at most once (see the file comment). A missing record store
// is a refusal.
func (e *Executor) Run(pcactn any, op *Operation, fn func(ExecutionHandle) (any, error)) ExecutorOutcome {
	if e.o.Operations == nil {
		return ExecutorOutcome{ExecuteOutcome: refusedOutcome("NewExecutor: missing required component: Operations (fail closed)")}
	}
	now := e.clock()
	in := e.o.Authorize
	in.Operation = op
	if in.Now == 0 {
		in.Now = now()
	}
	r := Authorize(pcactn, in)
	cls := ""
	if op != nil && e.o.ReversibilityClassOf != nil {
		cls = e.o.ReversibilityClassOf(*op)
	}
	if r.Allow {
		return ExecutorOutcome{ExecuteOutcome: ExecuteAuthorized(r, fn, ExecuteOptions{Store: e.o.Operations, Operation: op,
			Recheck: e.recheck(now), RecheckFor: e.o.RecheckFor, ReversibilityClass: cls, PendingTimeoutMs: e.timeout(), Now: now})}
	}
	denied := ExecutorOutcome{ExecuteOutcome: ExecuteOutcome{Status: "denied"}, Authorization: &r}
	failed := 0
	onlyReplay := false
	for name, st := range r.Checks {
		if st == "fail" {
			failed++
			onlyReplay = name == "replay"
		}
	}
	if r.Status != 403 || failed != 1 || !onlyReplay || op == nil || r.PCActn == nil {
		return denied
	}
	// a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
	id, err := HashCanonical(r.PCActn)
	if err != nil {
		return denied
	}
	rec, err := e.o.Operations.Get(id)
	if err != nil || rec == nil {
		return denied
	}
	want, derr := ParamsDigest(paramsAny(op.Params))
	if derr != nil || rec.Verb != op.Verb || rec.Resource != op.Resource || rec.ParamsDigest != want {
		return denied
	}
	return ExecutorOutcome{ExecuteOutcome: fromRecord(e.o.Operations, *rec, now(), e.timeout())}
}
