package pca

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// Operation records (T3): replays operation-vectors.json scenario by scenario, then concurrency, the key/value store and
// the executor. A missing vector file fails the test.

// jsonOf round-trips a Go value through encoding/json into the package's lenient JSON model.
func jsonOf(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseJSONLenient(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func canonOf(t *testing.T, v any) string {
	t.Helper()
	s, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("canonicalize %v: %v", v, err)
	}
	return s
}

func recordOf(t *testing.T, v any) OperationRecord {
	t.Helper()
	b, _ := json.Marshal(v)
	r, ok := decodeOperationRecord(b)
	if !ok {
		t.Fatalf("not an operation record: %v", v)
	}
	return r
}

func recordJSON(t *testing.T, r *OperationRecord) any {
	if r == nil {
		return nil
	}
	return jsonOf(t, r)
}

func outcomeJSON(o ExecuteOutcome) map[string]any {
	switch o.Status {
	case "committed":
		m := map[string]any{"status": o.Status, "operationId": o.OperationID, "replayed": o.Replayed, "recorded": o.Recorded}
		if o.Result != nil {
			m["result"] = o.Result
		}
		return m
	case "failed":
		return map[string]any{"status": o.Status, "operationId": o.OperationID, "error": o.Error, "replayed": o.Replayed}
	case "aborted", "uncertain":
		return map[string]any{"status": o.Status, "operationId": o.OperationID, "reason": o.Reason, "replayed": o.Replayed}
	case "pending":
		return map[string]any{"status": o.Status, "operationId": o.OperationID, "replayed": o.Replayed}
	}
	return map[string]any{"status": o.Status, "reason": o.Reason}
}

func runOperationStep(t *testing.T, store *MemoryOperationStore, s map[string]any) any {
	t.Helper()
	at := func() int64 { return num(s["at"]) }
	switch s["op"] {
	case "seed":
		if created, _, err := store.Create(recordOf(t, s["record"])); err != nil || !created {
			t.Fatalf("seed: %v %v", created, err)
		}
		return nil
	case "get":
		r, _ := store.Get(s["id"].(string))
		return recordJSON(t, r)
	case "recover":
		rs, err := RecoverOperations(store, RecoverOptions{Now: at, OlderThanMs: num(s["older_than_ms"])})
		if err != nil {
			t.Fatal(err)
		}
		out := []any{}
		for _, r := range rs {
			out = append(out, map[string]any{"id": r.ID, "state": string(r.State)})
		}
		return out
	case "recover_one":
		r, err := RecoverOperation(store, s["id"].(string), RecoverOptions{Now: at, OlderThanMs: num(s["older_than_ms"])})
		if err != nil {
			t.Fatal(err)
		}
		return recordJSON(t, r)
	case "resolve":
		o := s["outcome"].(map[string]any)
		res := OperationResolution{State: OperationState(o["state"].(string)), Result: o["result"]}
		res.Error, _ = o["error"].(string)
		ok, err := ResolveOperation(store, s["id"].(string), res, at)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// execute
	str := func(k, def string) string {
		if v, ok := s[k].(string); ok {
			return v
		}
		return def
	}
	empty, _ := ParamsDigest(nil)
	id := s["id"].(string)
	action := map[string]any{}
	if c, ok := s["signed_class"]; ok {
		action["reversibility_class"] = c
	}
	pcactn := map[string]any{"action": action}
	if e, ok := s["exp"]; ok {
		pcactn["exp"] = e
	}
	az := AuthorizeResult{Allow: !(s["not_allowed"] == true), PCActn: pcactn,
		Operation: &AuthorizedOperation{ID: id, Verb: str("verb", "payments.refund"), Resource: str("resource", "/orders/1"), ParamsDigest: str("params_digest", empty)}}
	opts := ExecuteOptions{Store: store, Now: at, ReversibilityClass: str("server_class", ""), RecheckFor: str("recheck_for", ""), PendingTimeoutMs: num(s["timeout_ms"])}
	if s["no_store"] == true {
		opts.Store = nil
	}
	switch rc := s["recheck"].(type) {
	case string:
		opts.Recheck = func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{OK: true}, nil }
	case map[string]any:
		if msg, ok := rc["refuse"].(string); ok {
			opts.Recheck = func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{Reason: msg}, nil }
		} else {
			msg, _ := rc["throw"].(string)
			opts.Recheck = func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{}, errors.New(msg) }
		}
	}
	fnSpec := s["fn"].(map[string]any)
	calls := 0
	out := ExecuteAuthorized(az, func(h ExecutionHandle) (any, error) {
		calls++
		switch fnSpec["kind"] {
		case "throw":
			return nil, errors.New(fnSpec["message"].(string))
		case "reenter":
			inner := ExecuteAuthorized(az, func(ExecutionHandle) (any, error) { return nil, errors.New("inner must not run") }, opts)
			return inner.Status, nil
		}
		if r, has := fnSpec["result"]; has {
			return r, nil
		}
		return h.IdempotencyKey, nil
	}, opts)
	var rec any
	if s["no_store"] != true && s["not_allowed"] != true {
		r, _ := store.Get(id)
		rec = recordJSON(t, r)
	}
	return map[string]any{"outcome": outcomeJSON(out), "fn_calls": jsNumber(float64(calls)), "record": rec}
}

func TestOperationVectors(t *testing.T) {
	doc := load(t, "operation-vectors.json")
	if num(doc["constants"].(map[string]any)["pending_timeout_ms"]) != OperationPendingTimeoutMs {
		t.Fatal("default pending timeout differs from the corpus")
	}
	scs := grows(t, doc, "scenarios")
	if len(scs) != 19 {
		t.Fatalf("scenarios: %d", len(scs))
	}
	for _, sc := range scs {
		t.Run(sc["name"].(string), func(t *testing.T) {
			store := NewMemoryOperationStore()
			steps, expect := sc["steps"].([]any), sc["expect"].([]any)
			if len(steps) != len(expect) {
				t.Fatalf("steps %d expect %d", len(steps), len(expect))
			}
			for i, st := range steps {
				got := canonOf(t, runOperationStep(t, store, st.(map[string]any)))
				if want := canonOf(t, expect[i]); got != want {
					t.Fatalf("step %d (%v):\n got %s\nwant %s", i, st.(map[string]any)["op"], got, want)
				}
			}
		})
	}
}

func allowedFixture(id string, class string) AuthorizeResult {
	d, _ := ParamsDigest(nil)
	return AuthorizeResult{Allow: true, PCActn: map[string]any{"action": map[string]any{"reversibility_class": class}},
		Operation: &AuthorizedOperation{ID: id, Verb: "v", Resource: "/r", ParamsDigest: d}}
}

// Of N concurrent executions of one authorization exactly one runs fn; every other is answered from the record.
func TestExecuteAuthorizedConcurrentRunsOnce(t *testing.T) {
	for name, store := range map[string]OperationStore{
		"memory": NewMemoryOperationStore(),
		"kv":     NewKVOperationStore(NewMemoryAtomicKV(), ""),
	} {
		t.Run(name, func(t *testing.T) {
			var calls, firsts int32
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < 64; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					o := ExecuteAuthorized(allowedFixture("op-c", "reversible"), func(h ExecutionHandle) (any, error) {
						atomic.AddInt32(&calls, 1)
						return "done", nil
					}, ExecuteOptions{Store: store})
					if !o.Replayed && o.Status == "committed" {
						atomic.AddInt32(&firsts, 1)
					}
					if o.Status == "refused" {
						t.Errorf("refused: %s", o.Reason)
					}
				}()
			}
			close(start)
			wg.Wait()
			if calls != 1 || firsts != 1 {
				t.Fatalf("fn ran %d times, %d first executions (want 1 and 1)", calls, firsts)
			}
			if r, _ := store.Get("op-c"); r == nil || r.State != OpCommitted || r.Result != "done" {
				t.Fatalf("record: %+v", r)
			}
		})
	}
}

func TestExecuteAuthorizedRefusesWithoutCheckedAuthorization(t *testing.T) {
	store := NewMemoryOperationStore()
	az := allowedFixture("op-x", "reversible")
	ran := false
	fn := func(ExecutionHandle) (any, error) { ran = true; return nil, nil }
	other := &Operation{Verb: "v", Resource: "/other", Params: map[string]any{}}
	if o := ExecuteAuthorized(az, fn, ExecuteOptions{Store: store, Operation: other}); o.Status != "refused" || ran {
		t.Fatalf("an authorization for another operation must be refused: %+v", o)
	}
	az.Operation.ID = ""
	if o := ExecuteAuthorized(az, fn, ExecuteOptions{Store: store}); o.Status != "refused" || ran {
		t.Fatalf("an authorization without an operation id must be refused: %+v", o)
	}
	// a panicking fn is a recorded failure, not a crash
	o := ExecuteAuthorized(allowedFixture("op-p", "reversible"), func(ExecutionHandle) (any, error) { panic("kaboom") }, ExecuteOptions{Store: store})
	if o.Status != "failed" || o.Error != "kaboom" {
		t.Fatalf("panic: %+v", o)
	}
}

// A store that cannot decide refuses; nothing runs.
type brokenOperationStore struct{ OperationStore }

func (brokenOperationStore) Create(OperationRecord) (bool, OperationRecord, error) {
	return false, OperationRecord{}, errors.New("db down")
}

func TestExecuteAuthorizedStoreFailureFailsClosed(t *testing.T) {
	ran := false
	o := ExecuteAuthorized(allowedFixture("op-b", "reversible"), func(ExecutionHandle) (any, error) { ran = true; return nil, nil },
		ExecuteOptions{Store: brokenOperationStore{NewMemoryOperationStore()}})
	if o.Status != "refused" || ran || o.Reason != "executeAuthorized: the operation store failed (fail closed): db down" {
		t.Fatalf("%+v ran=%v", o, ran)
	}
}

func TestKVOperationStoreRoundTrip(t *testing.T) {
	var s OperationStore = NewKVOperationStore(NewMemoryAtomicKV(), "")
	rec := OperationRecord{ID: "a", State: OpPending, Verb: "v", Resource: "/r", ParamsDigest: "d", Reversibility: "costly", StartedAt: 7}
	if created, _, err := s.Create(rec); err != nil || !created {
		t.Fatal(created, err)
	}
	if created, ex, _ := s.Create(rec); created || ex.ID != "a" {
		t.Fatalf("second create: %v %+v", created, ex)
	}
	next := rec
	next.State, next.Result = OpCommitted, map[string]any{"n": json.Number("5")}
	if ok, _ := s.Transition("a", OpExecuting, next); ok {
		t.Fatal("a transition from the wrong state must not apply")
	}
	if ok, err := s.Transition("a", OpPending, next); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if r, _ := s.Get("a"); r == nil || r.State != OpCommitted || canonOf(t, jsonOf(t, r.Result)) != `{"n":5}` {
		t.Fatalf("%+v", r)
	}
	if _, err := RecoverOperations(s, RecoverOptions{}); err == nil {
		t.Fatal("a store without ListOpen cannot recover all")
	}
	if r, err := RecoverOperation(s, "zzz", RecoverOptions{}); r != nil || err != nil {
		t.Fatal("unknown id")
	}
}

// ---- the executor (Authorize + ExecuteAuthorized)

func executorFixture(t *testing.T, revokedAfter int32) (*Executor, any, *Operation, *int32) {
	t.Helper()
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[0].(map[string]any) // signed class irreversible
	s := c["steps"].([]any)[0].(map[string]any)
	grant := c["grant"].(map[string]any)
	var revCalls int32
	in := AuthorizeInput{Audience: d["audience"].(string), Now: fixNum(d["now"]), Plan: PlanSingleStep, StateStore: NewMemoryStateStore(),
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		IsRevoked: func(_, _ map[string]any) (bool, error) {
			return revokedAfter >= 0 && atomic.AddInt32(&revCalls, 1) > revokedAfter, nil
		}, ArgProvenance: harnessProv()}
	return NewExecutor(ExecutorOptions{Operations: NewMemoryOperationStore(), Authorize: in, Now: func() int64 { return in.Now }}), s["pcactn"], fixOp(s["operation"].(map[string]any)), &revCalls
}

func TestExecutorRunsOnceAndAnswersRetryFromRecord(t *testing.T) {
	ex, pcactn, op, _ := executorFixture(t, -1)
	calls := 0
	fn := func(h ExecutionHandle) (any, error) { calls++; return "sent:" + h.IdempotencyKey[:4], nil }
	first := ex.Run(pcactn, op, fn)
	if first.Status != "committed" || first.Replayed || calls != 1 {
		t.Fatalf("first: %+v calls=%d", first, calls)
	}
	retry := ex.Run(pcactn, op, fn)
	if retry.Status != "committed" || !retry.Replayed || calls != 1 || retry.Result != first.Result {
		t.Fatalf("retry must be answered from the record: %+v calls=%d", retry, calls)
	}
	// the same proof for a DIFFERENT operation is a plain denial, never the record
	other := &Operation{Verb: op.Verb, Resource: op.Resource, Params: map[string]any{"amount": json.Number("999")}}
	if o := ex.Run(pcactn, other, fn); o.Status != "denied" || o.Authorization == nil || calls != 1 {
		t.Fatalf("another operation: %+v", o)
	}
}

func TestExecutorRecheckSeesRevocationAfterAuthorize(t *testing.T) {
	ex, pcactn, op, _ := executorFixture(t, 1) // authorize sees "not revoked", the pre-execution re-check sees "revoked"
	ran := false
	o := ex.Run(pcactn, op, func(ExecutionHandle) (any, error) { ran = true; return nil, nil })
	if o.Status != "aborted" || ran || o.Reason != "recheck: the grant has been revoked" {
		t.Fatalf("%+v ran=%v", o, ran)
	}
	// the grant is revoked now, so the retry is a plain denial (a revocation failure, not only a replay)
	if again := ex.Run(pcactn, op, func(ExecutionHandle) (any, error) { ran = true; return nil, nil }); again.Status != "denied" || ran {
		t.Fatalf("retry after revocation: %+v", again)
	}
}

func TestExecutorWithoutOperationsRefuses(t *testing.T) {
	ex, pcactn, op, _ := executorFixture(t, -1)
	ex.o.Operations = nil
	if o := ex.Run(pcactn, op, nil); o.Status != "refused" {
		t.Fatalf("%+v", o)
	}
}

func TestOperationRecordJSONIsStable(t *testing.T) {
	r := OperationRecord{ID: "i", State: OpCommitted, Verb: "v", Resource: "r", ParamsDigest: "p", Reversibility: "reversible", StartedAt: 1, Result: "x"}
	b, _ := json.Marshal(r)
	if string(b) != `{"id":"i","state":"committed","verb":"v","resource":"r","params_digest":"p","reversibility":"reversible","startedAt":1,"result":"x"}` {
		t.Fatalf("%s", b)
	}
}
