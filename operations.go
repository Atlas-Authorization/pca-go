package pca

// Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
//
// Authorize decides and consumes the PCActn's replay counter. Between that decision and the end of the side effect the
// process can crash, the client can time out and retry, or two workers can pick up the same authorization. A record per
// operation id (AuthorizedOperation.ID, the digest of the presented PCActn) closes that gap:
//
//  1. ExecuteAuthorized creates the record in state `pending` BEFORE anything runs (one atomic create-if-absent: of N
//     concurrent executions of one authorization exactly one gets to run fn);
//  2. for an irreversible operation it re-checks revocation, expiry and approval immediately before fn (Recheck is
//     required, fail closed); a failed re-check records `aborted` and fn never runs;
//  3. it moves the record to `executing` and only then calls fn, with the operation id as the idempotency key;
//  4. the record becomes `committed` (with fn's result) or `failed` (with its error) afterwards.
//
// A second execution of the same id never runs fn again: it answers from the record. Once PendingTimeoutMs has passed, a
// record still `pending` is settled `aborted` (the side effect never started) and one still `executing` `uncertain` (it
// may or may not have happened: reconcile it with ResolveOperation using the idempotency key). Mirrors the reference
// operation-record module; the shared operation-vectors.json corpus pins the state machine and every message.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// OperationState is where an operation is in its execution.
type OperationState string

// The operation states.
const (
	// OpPending: claimed for execution, fn not started yet (re-check running), or the process crashed before starting it.
	OpPending OperationState = "pending"
	// OpExecuting: fn has been started; the side effect is running, or the process crashed during or after it.
	OpExecuting OperationState = "executing"
	// OpCommitted: the side effect completed; Result is what fn returned.
	OpCommitted OperationState = "committed"
	// OpFailed: fn returned an error (or panicked); not re-run.
	OpFailed OperationState = "failed"
	// OpAborted: the pre-execution re-check refused (revoked, expired, approval withdrawn); fn never ran.
	OpAborted OperationState = "aborted"
	// OpUncertain: found executing after PendingTimeoutMs; the outcome is unknown and must be reconciled, never re-run.
	OpUncertain OperationState = "uncertain"
)

// OperationPendingTimeoutMs is the default age after which an open record is settled.
const OperationPendingTimeoutMs int64 = 5 * 60_000

// OperationRecord is the durable record of one operation. Times are epoch milliseconds.
type OperationRecord struct {
	ID            string         `json:"id"`
	State         OperationState `json:"state"`
	Verb          string         `json:"verb"`
	Resource      string         `json:"resource"`
	ParamsDigest  string         `json:"params_digest"`
	Reversibility string         `json:"reversibility"`
	StartedAt     int64          `json:"startedAt"`
	ExecutingAt   int64          `json:"executingAt,omitempty"`
	FinishedAt    int64          `json:"finishedAt,omitempty"`
	// Result: what fn returned when committed (keep it JSON-serialisable for a durable store).
	Result any `json:"result,omitempty"`
	// Error: why a record is failed, aborted or uncertain.
	Error string `json:"error,omitempty"`
}

// OperationStore is the durable, shared storage of operation records. Create and Transition MUST be atomic across every
// process and node that shares the store. A call that cannot decide MUST return an error: the executor then refuses.
type OperationStore interface {
	// Create inserts rec if no record with its id exists (created true); otherwise it returns the existing record.
	Create(rec OperationRecord) (created bool, existing OperationRecord, err error)
	// Get returns the record (nil: none).
	Get(id string) (*OperationRecord, error)
	// Transition atomically replaces the record with next only if its current state is from. It reports whether it did.
	Transition(id string, from OperationState, next OperationRecord) (bool, error)
}

// OpenLister is the optional OperationStore capability RecoverOperations needs: the records still pending or executing.
type OpenLister interface {
	ListOpen() ([]OperationRecord, error)
}

// MemoryOperationStore is the in-process OperationStore (tests, one worker). Its records die with the process.
type MemoryOperationStore struct {
	mu sync.Mutex
	m  map[string]OperationRecord
}

// NewMemoryOperationStore returns an empty in-memory store.
func NewMemoryOperationStore() *MemoryOperationStore {
	return &MemoryOperationStore{m: map[string]OperationRecord{}}
}

// Create implements OperationStore.
func (s *MemoryOperationStore) Create(rec OperationRecord) (bool, OperationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[rec.ID]; ok {
		return false, cur, nil
	}
	s.m[rec.ID] = rec
	return true, OperationRecord{}, nil
}

// Get implements OperationStore.
func (s *MemoryOperationStore) Get(id string) (*OperationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.m[id]; ok {
		return &r, nil
	}
	return nil, nil
}

// Transition implements OperationStore.
func (s *MemoryOperationStore) Transition(id string, from OperationState, next OperationRecord) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[id]; !ok || cur.State != from {
		return false, nil
	}
	next.ID = id
	s.m[id] = next
	return true, nil
}

// ListOpen implements OpenLister, ordered by id.
func (s *MemoryOperationStore) ListOpen() ([]OperationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []OperationRecord
	for _, r := range s.m {
		if r.State == OpPending || r.State == OpExecuting {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// KVOperationStore is an OperationStore over any AtomicKV (use NewSQLAtomicKV for a database). It has no ListOpen:
// recover a known id with RecoverOperation.
type KVOperationStore struct {
	kv     AtomicKV
	prefix string
}

// DefaultOperationPrefix is the key prefix of KVOperationStore.
const DefaultOperationPrefix = "pca-op:"

// NewKVOperationStore builds the store; prefix "" is DefaultOperationPrefix.
func NewKVOperationStore(kv AtomicKV, prefix string) *KVOperationStore {
	if prefix == "" {
		prefix = DefaultOperationPrefix
	}
	return &KVOperationStore{kv: kv, prefix: prefix}
}

func decodeOperationRecord(b []byte) (OperationRecord, bool) {
	var r OperationRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if len(b) == 0 || d.Decode(&r) != nil || r.ID == "" || r.State == "" {
		return OperationRecord{}, false
	}
	return r, true
}

// Create implements OperationStore with one atomic KV update.
func (s *KVOperationStore) Create(rec OperationRecord) (bool, OperationRecord, error) {
	enc, err := json.Marshal(rec)
	if err != nil {
		return false, OperationRecord{}, err
	}
	var existing OperationRecord
	found := false
	err = s.kv.Update(s.prefix+rec.ID, func(prev []byte) []byte {
		existing, found = decodeOperationRecord(prev)
		if found {
			return nil
		}
		return enc
	})
	if err != nil {
		return false, OperationRecord{}, err
	}
	return !found, existing, nil
}

// Get implements OperationStore.
func (s *KVOperationStore) Get(id string) (*OperationRecord, error) {
	b, ok, err := s.kv.Get(s.prefix + id)
	if err != nil || !ok {
		return nil, err
	}
	if r, ok := decodeOperationRecord(b); ok {
		return &r, nil
	}
	return nil, nil
}

// Transition implements OperationStore with one atomic KV update.
func (s *KVOperationStore) Transition(id string, from OperationState, next OperationRecord) (bool, error) {
	next.ID = id
	enc, err := json.Marshal(next)
	if err != nil {
		return false, err
	}
	done := false
	err = s.kv.Update(s.prefix+id, func(prev []byte) []byte {
		cur, ok := decodeOperationRecord(prev)
		done = ok && cur.State == from
		if !done {
			return nil
		}
		return enc
	})
	return done && err == nil, err
}

// RecheckResult is what a pre-execution re-check answered.
type RecheckResult struct {
	OK     bool
	Reason string
}

// ExecutionHandle is what the executed function receives.
type ExecutionHandle struct {
	// IdempotencyKey is the operation id: pass it as the idempotency key of the downstream call.
	IdempotencyKey string
	Operation      AuthorizedOperation
	PCActn         map[string]any
}

// ExecuteOptions configures ExecuteAuthorized.
type ExecuteOptions struct {
	// Store is REQUIRED (shared and durable in production).
	Store OperationStore
	// Operation, when set, is the operation about to execute: the authorization must be for exactly it.
	Operation *Operation
	// Recheck re-checks, immediately before fn, that the authorization still stands (grant not revoked, approval not
	// expired or withdrawn). REQUIRED for an irreversible operation (fail closed), and for the others with
	// RecheckFor "always". The PCActn's own expiry (`exp`) is always checked with it. An error or panic is a refusal.
	Recheck func(h ExecutionHandle) (RecheckResult, error)
	// RecheckFor: "" or "irreversible" (default), or "always".
	RecheckFor string
	// ReversibilityClass is the server's authoritative class; the stricter of it and the signed class applies
	// (missing or unknown = irreversible).
	ReversibilityClass string
	// PendingTimeoutMs: an open record older than this is settled (0: OperationPendingTimeoutMs).
	PendingTimeoutMs int64
	// Now is the clock in epoch ms (nil: the wall clock).
	Now func() int64
}

func (o ExecuteOptions) clock() func() int64 {
	if o.Now != nil {
		return o.Now
	}
	return func() int64 { return time.Now().UnixMilli() }
}

func (o ExecuteOptions) timeout() int64 {
	if o.PendingTimeoutMs != 0 {
		return o.PendingTimeoutMs
	}
	return OperationPendingTimeoutMs
}

// ExecuteOutcome is the outcome of an execution attempt. Replayed means it was answered from an existing record.
//
// Status: "committed" (Result, Recorded: false means fn ran but the record could not be written), "failed" (Error),
// "aborted" (Reason), "pending" (another execution of this id is in flight; fn did not run here), "uncertain" (Reason:
// the earlier outcome is unknown; fn did not run here), or "refused" (Reason: nothing ran and nothing was recorded).
type ExecuteOutcome struct {
	Status      string
	OperationID string
	Result      any
	Error       string
	Reason      string
	Replayed    bool
	Recorded    bool
}

func refusedOutcome(reason string) ExecuteOutcome {
	return ExecuteOutcome{Status: "refused", Reason: reason}
}

func storeFailed(err error) ExecuteOutcome {
	return refusedOutcome("executeAuthorized: the operation store failed (fail closed): " + err.Error())
}

// settleStale settles an open record older than timeoutMs: pending -> aborted, executing -> uncertain.
func settleStale(store OperationStore, rec OperationRecord, now, timeoutMs int64) (OperationRecord, error) {
	if rec.State != OpPending && rec.State != OpExecuting {
		return rec, nil
	}
	// executing is aged from the moment fn was started (a slow re-check does not count against it)
	start := rec.StartedAt
	if rec.State == OpExecuting && rec.ExecutingAt != 0 {
		start = rec.ExecutingAt
	}
	if !(now-start > timeoutMs) {
		return rec, nil
	}
	next := rec
	next.FinishedAt = now
	if rec.State == OpPending {
		next.State = OpAborted
		next.Error = fmt.Sprintf("not started within %d ms of the claim: the side effect never ran", timeoutMs)
	} else {
		next.State = OpUncertain
		next.Error = fmt.Sprintf("no outcome recorded within %d ms of the start: the side effect may or may not have happened", timeoutMs)
	}
	if _, err := store.Transition(rec.ID, rec.State, next); err != nil {
		return rec, err
	}
	// whatever is stored now (the original execution may have finished in between)
	cur, err := store.Get(rec.ID)
	if err != nil {
		return rec, err
	}
	if cur != nil {
		return *cur, nil
	}
	return next, nil
}

// fromRecord answers an execution attempt from an existing record (never runs anything).
func fromRecord(store OperationStore, rec0 OperationRecord, now, timeoutMs int64) ExecuteOutcome {
	rec, err := settleStale(store, rec0, now, timeoutMs)
	if err != nil {
		return storeFailed(err)
	}
	orDefault := func(s, d string) string {
		if s == "" {
			return d
		}
		return s
	}
	switch rec.State {
	case OpCommitted:
		return ExecuteOutcome{Status: "committed", OperationID: rec.ID, Result: rec.Result, Replayed: true, Recorded: true}
	case OpFailed:
		return ExecuteOutcome{Status: "failed", OperationID: rec.ID, Error: orDefault(rec.Error, "failed"), Replayed: true}
	case OpAborted:
		return ExecuteOutcome{Status: "aborted", OperationID: rec.ID, Reason: orDefault(rec.Error, "aborted"), Replayed: true}
	case OpUncertain:
		return ExecuteOutcome{Status: "uncertain", OperationID: rec.ID, Reason: orDefault(rec.Error, "outcome unknown"), Replayed: true}
	case OpPending, OpExecuting:
		return ExecuteOutcome{Status: "pending", OperationID: rec.ID, Replayed: true}
	}
	return ExecuteOutcome{Status: "uncertain", OperationID: rec.ID, Reason: fmt.Sprintf("unknown record state '%s'", rec.State), Replayed: true}
}

// finish leaves executing (or uncertain, when recovery settled a slow execution) for the final state.
func finish(store OperationStore, rec OperationRecord, mut func(*OperationRecord)) (bool, error) {
	out := rec
	mut(&out)
	ok, err := store.Transition(rec.ID, rec.State, out)
	if err != nil || ok {
		return ok, err
	}
	if rec.State == OpExecuting {
		return store.Transition(rec.ID, OpUncertain, out)
	}
	return false, nil
}

// answerCurrent answers from the record as it is stored now (a concurrent recovery or execution changed it).
func answerCurrent(store OperationStore, id string, now, timeoutMs int64) ExecuteOutcome {
	cur, err := store.Get(id)
	if err != nil {
		return storeFailed(err)
	}
	if cur == nil {
		return ExecuteOutcome{Status: "uncertain", OperationID: id, Reason: "the operation record disappeared", Replayed: true}
	}
	return fromRecord(store, *cur, now, timeoutMs)
}

func panicMessage(r any) string {
	if e, ok := r.(error); ok {
		return e.Error()
	}
	return fmt.Sprint(r)
}

func runRecheck(f func(ExecutionHandle) (RecheckResult, error), h ExecutionHandle) (rc RecheckResult) {
	defer func() {
		if r := recover(); r != nil {
			rc = RecheckResult{Reason: "recheck error (fail closed): " + panicMessage(r)}
		}
	}()
	r, err := f(h)
	if err != nil {
		return RecheckResult{Reason: "recheck error (fail closed): " + err.Error()}
	}
	return r
}

func runExecution(fn func(ExecutionHandle) (any, error), h ExecutionHandle) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("%s", panicMessage(r))
		}
	}()
	return fn(h)
}

// ExecuteAuthorized executes an allowed Authorize result at most once, with a durable record (see the file comment). fn
// runs only if this call created the pending record and the re-check (when required) passed; every other outcome is
// answered from the record. An error or panic from fn is recorded as failed and returned in the outcome.
func ExecuteAuthorized(az AuthorizeResult, fn func(ExecutionHandle) (any, error), opts ExecuteOptions) ExecuteOutcome {
	store := opts.Store
	if store == nil {
		return refusedOutcome("executeAuthorized: missing required component: store (fail closed)")
	}
	if !az.Allow || az.Operation == nil || az.Operation.ID == "" || az.PCActn == nil {
		return refusedOutcome("executeAuthorized: the authorization did not allow an operation")
	}
	op := *az.Operation
	if opts.Operation != nil {
		d, err := ParamsDigest(paramsAny(opts.Operation.Params))
		if err != nil || opts.Operation.Verb != op.Verb || opts.Operation.Resource != op.Resource || d != op.ParamsDigest {
			return refusedOutcome("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)")
		}
	}
	now := opts.clock()
	timeoutMs := opts.timeout()
	var signed any
	if action, ok := az.PCActn["action"].(map[string]any); ok {
		signed = action["reversibility_class"]
	}
	reversibility := EffectiveReversibility(opts.ReversibilityClass, signed)
	mustRecheck := reversibility == "irreversible" || opts.RecheckFor == "always"
	if mustRecheck && opts.Recheck == nil {
		return refusedOutcome(fmt.Sprintf("executeAuthorized: a %s operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)", reversibility))
	}

	handle := ExecutionHandle{IdempotencyKey: op.ID, Operation: op, PCActn: az.PCActn}
	rec := OperationRecord{ID: op.ID, State: OpPending, Verb: op.Verb, Resource: op.Resource, ParamsDigest: op.ParamsDigest,
		Reversibility: reversibility, StartedAt: now()}
	created, existing, err := store.Create(rec)
	if err != nil {
		return storeFailed(err)
	}
	if !created {
		return fromRecord(store, existing, now(), timeoutMs)
	}

	if mustRecheck {
		var rc RecheckResult
		if exp, ok := jsNum(az.PCActn["exp"]); ok && float64(now()) > exp {
			rc = RecheckResult{Reason: "the PCActn expired at " + jsNumberString(exp)}
		} else {
			rc = runRecheck(opts.Recheck, handle)
		}
		if !rc.OK {
			why := rc.Reason
			if why == "" {
				why = "refused"
			}
			reason := "recheck: " + why
			if ok, ferr := finish(store, rec, func(r *OperationRecord) { r.State, r.Error, r.FinishedAt = OpAborted, reason, now() }); ferr != nil {
				return storeFailed(ferr)
			} else if ok {
				return ExecuteOutcome{Status: "aborted", OperationID: rec.ID, Reason: reason}
			}
			return answerCurrent(store, rec.ID, now(), timeoutMs)
		}
	}

	// the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
	running := rec
	running.State, running.ExecutingAt = OpExecuting, now()
	switch ok, terr := store.Transition(rec.ID, OpPending, running); {
	case terr != nil:
		return storeFailed(terr)
	case !ok:
		return answerCurrent(store, rec.ID, now(), timeoutMs)
	}

	result, ferr := runExecution(fn, handle)
	if ferr != nil {
		msg := ferr.Error()
		_, _ = finish(store, running, func(r *OperationRecord) { r.State, r.Error, r.FinishedAt = OpFailed, msg, now() })
		return ExecuteOutcome{Status: "failed", OperationID: rec.ID, Error: msg}
	}
	recorded, _ := finish(store, running, func(r *OperationRecord) { r.State, r.Result, r.FinishedAt = OpCommitted, result, now() })
	return ExecuteOutcome{Status: "committed", OperationID: rec.ID, Result: result, Recorded: recorded}
}

// paramsAny keeps a nil Params an untyped nil (ParamsDigest treats it as {}).
func paramsAny(p map[string]any) any {
	if p == nil {
		return nil
	}
	return p
}

// RecoverOptions configures RecoverOperations / RecoverOperation.
type RecoverOptions struct {
	// OlderThanMs: records older than this are settled (0: OperationPendingTimeoutMs).
	OlderThanMs int64
	// Now is the clock in epoch ms (nil: the wall clock).
	Now func() int64
}

func (o RecoverOptions) now() int64 {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UnixMilli()
}

func (o RecoverOptions) olderThan() int64 {
	if o.OlderThanMs != 0 {
		return o.OlderThanMs
	}
	return OperationPendingTimeoutMs
}

// RecoverOperations settles every open record older than OlderThanMs (run it at startup and periodically): pending ->
// aborted (the side effect never started), executing -> uncertain. It returns the records it settled and needs a store
// that implements OpenLister. Nothing is re-run: reconcile each uncertain one with ResolveOperation.
func RecoverOperations(store OperationStore, opts RecoverOptions) ([]OperationRecord, error) {
	l, ok := store.(OpenLister)
	if !ok {
		return nil, fmt.Errorf("RecoverOperations: the store has no ListOpen (recover by id with RecoverOperation)")
	}
	open, err := l.ListOpen()
	if err != nil {
		return nil, err
	}
	out := []OperationRecord{}
	for _, r := range open {
		u, err := RecoverOperation(store, r.ID, opts)
		if err != nil {
			return out, err
		}
		if u != nil && u.State != r.State {
			out = append(out, *u)
		}
	}
	return out, nil
}

// RecoverOperation is RecoverOperations for one id. It returns the record as it now stands (nil: no record, the
// operation never started).
func RecoverOperation(store OperationStore, id string, opts RecoverOptions) (*OperationRecord, error) {
	r, err := store.Get(id)
	if err != nil || r == nil {
		return nil, err
	}
	settled, err := settleStale(store, *r, opts.now(), opts.olderThan())
	if err != nil {
		return nil, err
	}
	return &settled, nil
}

// OperationResolution is the reconciled outcome of an uncertain operation: State OpCommitted (with the Result the
// downstream system reports) or OpFailed (with an Error: it never applied).
type OperationResolution struct {
	State  OperationState
	Result any
	Error  string
}

// ResolveOperation settles an uncertain record after reconciling with the downstream system (look the idempotency key up
// there). It returns false when the record is not uncertain (or unknown) or the resolution is not committed / failed.
func ResolveOperation(store OperationStore, id string, outcome OperationResolution, now func() int64) (bool, error) {
	r, err := store.Get(id)
	if err != nil || r == nil || r.State != OpUncertain {
		return false, err
	}
	at := time.Now().UnixMilli()
	if now != nil {
		at = now()
	}
	next := *r
	next.FinishedAt = at
	switch outcome.State {
	case OpCommitted:
		next.State, next.Result = OpCommitted, outcome.Result
	case OpFailed:
		next.State, next.Error = OpFailed, outcome.Error
	default:
		return false, fmt.Errorf("ResolveOperation: the outcome state must be committed or failed")
	}
	return store.Transition(id, OpUncertain, next)
}
