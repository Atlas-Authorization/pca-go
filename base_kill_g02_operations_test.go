package pca

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Operation records (operations.go): store failures, settle / finish edges and option defaults, each pinned exactly.

var g02boom = errors.New("boom")

// g02kv is an AtomicKV with scripted answers; its Update never calls fn.
type g02kv struct {
	getB   []byte
	getOK  bool
	getErr error
	updErr error
}

func (k *g02kv) Get(string) ([]byte, bool, error) { return k.getB, k.getOK, k.getErr }

func (k *g02kv) Update(string, func([]byte) []byte) error { return k.updErr }

// g02store is an OperationStore with scripted answers (nil func: Create created, Get none, Transition done).
type g02store struct {
	create func(OperationRecord) (bool, OperationRecord, error)
	get    func(string) (*OperationRecord, error)
	trans  func(string, OperationState, OperationRecord) (bool, error)
}

func (s *g02store) Create(r OperationRecord) (bool, OperationRecord, error) {
	if s.create == nil {
		return true, OperationRecord{}, nil
	}
	return s.create(r)
}

func (s *g02store) Get(id string) (*OperationRecord, error) {
	if s.get == nil {
		return nil, nil
	}
	return s.get(id)
}

func (s *g02store) Transition(id string, from OperationState, next OperationRecord) (bool, error) {
	if s.trans == nil {
		return true, nil
	}
	return s.trans(id, from, next)
}

type g02lister struct {
	g02store
	list func() ([]OperationRecord, error)
}

func (l *g02lister) ListOpen() ([]OperationRecord, error) { return l.list() }

func g02boomGet(string) (*OperationRecord, error) { return nil, g02boom }

func g02boomTrans(string, OperationState, OperationRecord) (bool, error) { return false, g02boom }

const g02storeFailed = "executeAuthorized: the operation store failed (fail closed): boom"

func TestG02KVOperationStoreEdges(t *testing.T) {
	if s := NewKVOperationStore(nil, ""); s.prefix != DefaultOperationPrefix {
		t.Errorf("default prefix %q", s.prefix)
	}
	if s := NewKVOperationStore(nil, "x:"); s.prefix != "x:" {
		t.Errorf("custom prefix %q", s.prefix)
	}

	if r, ok := decodeOperationRecord([]byte(`{"id":"a","state":"committed","result":1.5}`)); !ok || r.Result != json.Number("1.5") {
		t.Errorf("numbers decode as json.Number: %#v %v", r.Result, ok)
	}
	if _, ok := decodeOperationRecord([]byte(`{"id":"a","state":"pending","verb":5}`)); ok {
		t.Error("a record with a mistyped field decoded")
	}

	mem := NewKVOperationStore(NewMemoryAtomicKV(), "")
	if created, _, err := mem.Create(OperationRecord{ID: "a", State: OpPending, Result: make(chan int)}); created || err == nil {
		t.Errorf("unencodable record: created %v err %v", created, err)
	}
	if created, existing, err := NewKVOperationStore(&g02kv{}, "").Create(OperationRecord{ID: "a", State: OpPending}); !created || err != nil || existing.ID != "" {
		t.Errorf("Update without a call: created %v existing %+v err %v", created, existing, err)
	}
	if created, _, err := NewKVOperationStore(&g02kv{updErr: g02boom}, "").Create(OperationRecord{ID: "a", State: OpPending}); created || err != g02boom {
		t.Errorf("Update failure: created %v err %v", created, err)
	}
	if rec, err := NewKVOperationStore(&g02kv{getB: []byte(`{"id":"a","state":"pending"}`), getOK: true, getErr: g02boom}, "").Get("a"); rec != nil || err != g02boom {
		t.Errorf("Get failure: %+v %v", rec, err)
	}

	if _, _, err := mem.Create(OperationRecord{ID: "b", State: OpPending}); err != nil {
		t.Fatal(err)
	}
	if done, err := mem.Transition("b", OpPending, OperationRecord{State: OpCommitted, Result: make(chan int)}); done || err == nil {
		t.Errorf("unencodable next: done %v err %v", done, err)
	}
	if cur, err := mem.Get("b"); err != nil || cur == nil || cur.State != OpPending {
		t.Errorf("record after a refused transition: %+v %v", cur, err)
	}
	if done, err := NewKVOperationStore(&g02kv{}, "").Transition("a", OpPending, OperationRecord{State: OpCommitted}); done || err != nil {
		t.Errorf("Transition without a call: done %v err %v", done, err)
	}
}

func TestG02SettleStale(t *testing.T) {
	st := NewMemoryOperationStore()
	p := OperationRecord{ID: "p", State: OpPending, StartedAt: 0, ExecutingAt: 1000}
	e := OperationRecord{ID: "e", State: OpExecuting, StartedAt: 0, ExecutingAt: 1}
	for _, r := range []OperationRecord{p, e} {
		if _, _, err := st.Create(r); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := settleStale(st, p, 1500, 1000); err != nil || got.State != OpAborted {
		t.Errorf("pending is aged from StartedAt: %+v %v", got, err)
	}
	if got, err := settleStale(st, e, 1001, 1000); err != nil || got.State != OpExecuting {
		t.Errorf("executing is aged from ExecutingAt: %+v %v", got, err)
	}

	stale := OperationRecord{ID: "s", State: OpPending}
	if got, err := settleStale(&g02store{trans: g02boomTrans}, stale, 10, 5); err != g02boom || got.State != OpPending {
		t.Errorf("Transition failure: %+v %v", got, err)
	}
	if got, err := settleStale(&g02store{get: g02boomGet}, stale, 10, 5); err != g02boom || got.State != OpPending {
		t.Errorf("Get failure: %+v %v", got, err)
	}
	got, err := settleStale(&g02store{}, stale, 10, 5)
	if err != nil || got.State != OpAborted || got.FinishedAt != 10 || got.Error != "not started within 5 ms of the claim: the side effect never ran" {
		t.Errorf("nothing stored: %+v %v", got, err)
	}
	committed := func(string) (*OperationRecord, error) {
		return &OperationRecord{ID: "s", State: OpCommitted, Result: "r"}, nil
	}
	if got, err := settleStale(&g02store{get: committed}, stale, 10, 5); err != nil || got.State != OpCommitted || got.Result != "r" {
		t.Errorf("stored record wins: %+v %v", got, err)
	}
}

func TestG02FromRecordFinishAnswer(t *testing.T) {
	if out := fromRecord(&g02store{trans: g02boomTrans}, OperationRecord{ID: "s", State: OpPending}, 10, 5); out != (ExecuteOutcome{Status: "refused", Reason: g02storeFailed}) {
		t.Errorf("settle failure: %+v", out)
	}
	if out := fromRecord(NewMemoryOperationStore(), OperationRecord{ID: "f", State: OpFailed}, 10, 5); out != (ExecuteOutcome{Status: "failed", OperationID: "f", Error: "failed", Replayed: true}) {
		t.Errorf("failed without an error: %+v", out)
	}

	st := NewMemoryOperationStore()
	for _, r := range []OperationRecord{{ID: "u", State: OpUncertain}, {ID: "v", State: OpUncertain}, {ID: "c", State: OpCommitted, Result: "r"}} {
		if _, _, err := st.Create(r); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := finish(st, OperationRecord{ID: "u", State: OpExecuting}, func(r *OperationRecord) { r.State = OpCommitted }); !ok || err != nil {
		t.Errorf("executing settled uncertain meanwhile: %v %v", ok, err)
	}
	if cur, _ := st.Get("u"); cur == nil || cur.State != OpCommitted {
		t.Errorf("u: %+v", cur)
	}
	if ok, err := finish(st, OperationRecord{ID: "v", State: OpPending}, func(r *OperationRecord) { r.State = OpAborted }); ok || err != nil {
		t.Errorf("pending moved meanwhile: %v %v", ok, err)
	}
	if cur, _ := st.Get("v"); cur == nil || cur.State != OpUncertain {
		t.Errorf("v: %+v", cur)
	}

	if out := answerCurrent(&g02store{get: g02boomGet}, "x", 10, 5); out != (ExecuteOutcome{Status: "refused", Reason: g02storeFailed}) {
		t.Errorf("answerCurrent Get failure: %+v", out)
	}
	if out := answerCurrent(NewMemoryOperationStore(), "x", 10, 5); out != (ExecuteOutcome{Status: "uncertain", OperationID: "x", Reason: "the operation record disappeared", Replayed: true}) {
		t.Errorf("answerCurrent no record: %+v", out)
	}
	if out := answerCurrent(st, "c", 10, 5); out != (ExecuteOutcome{Status: "committed", OperationID: "c", Result: "r", Replayed: true, Recorded: true}) {
		t.Errorf("answerCurrent committed: %+v", out)
	}

	rc := runRecheck(func(ExecutionHandle) (RecheckResult, error) { panic("boom") }, ExecutionHandle{})
	if rc != (RecheckResult{Reason: "recheck error (fail closed): boom"}) {
		t.Errorf("recheck panic: %+v", rc)
	}
}

func TestG02ExecuteAuthorizedEdges(t *testing.T) {
	d, err := ParamsDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	az := func(id string) AuthorizeResult {
		return AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "read", Resource: "doc", ParamsDigest: d, ID: id}, PCActn: map[string]any{}}
	}
	clock := func() int64 { return 1000 }
	never := func(ExecutionHandle) (any, error) {
		t.Error("fn ran")
		return nil, nil
	}
	refuse := func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{}, nil }

	out := ExecuteAuthorized(az("op1"), never, ExecuteOptions{Store: NewMemoryOperationStore(), Operation: &Operation{Verb: "write", Resource: "doc"}, Now: clock})
	if out != (ExecuteOutcome{Status: "refused", Reason: "executeAuthorized: the authorization is not for this operation (verb, resource or params differ)"}) {
		t.Errorf("other verb: %+v", out)
	}
	out = ExecuteAuthorized(az("op2"), never, ExecuteOptions{Store: NewMemoryOperationStore(), RecheckFor: "always", Recheck: refuse, Now: clock})
	if out != (ExecuteOutcome{Status: "aborted", OperationID: "op2", Reason: "recheck: refused"}) {
		t.Errorf("recheck without a reason: %+v", out)
	}
	out = ExecuteAuthorized(az("op3"), never, ExecuteOptions{Store: &g02store{trans: g02boomTrans}, RecheckFor: "always", Recheck: refuse, Now: clock})
	if out != (ExecuteOutcome{Status: "refused", Reason: g02storeFailed}) {
		t.Errorf("abort not recordable: %+v", out)
	}

	if paramsAny(nil) != nil {
		t.Error("paramsAny(nil) is not an untyped nil")
	}
	if m, ok := paramsAny(map[string]any{"a": 1}).(map[string]any); !ok || m["a"] != 1 {
		t.Errorf("paramsAny(map) = %#v", m)
	}
}

func TestG02RecoverAndResolve(t *testing.T) {
	before := time.Now().UnixMilli()
	if n := (RecoverOptions{}).now(); n < before || n > time.Now().UnixMilli() {
		t.Errorf("wall clock %d", n)
	}
	if n := (RecoverOptions{Now: func() int64 { return 42 }}).now(); n != 42 {
		t.Errorf("clock %d", n)
	}
	if n := (RecoverOptions{}).olderThan(); n != OperationPendingTimeoutMs {
		t.Errorf("default olderThan %d", n)
	}
	if n := (RecoverOptions{OlderThanMs: 1}).olderThan(); n != 1 {
		t.Errorf("olderThan 1 = %d", n)
	}

	opts := RecoverOptions{Now: func() int64 { return 10 }, OlderThanMs: 5}
	if out, err := RecoverOperations(&g02lister{list: func() ([]OperationRecord, error) { return nil, g02boom }}, opts); out != nil || err != g02boom {
		t.Errorf("ListOpen failure: %+v %v", out, err)
	}
	l := &g02lister{g02store: g02store{get: g02boomGet}, list: func() ([]OperationRecord, error) {
		return []OperationRecord{{ID: "a", State: OpPending}}, nil
	}}
	if out, err := RecoverOperations(l, opts); len(out) != 0 || err != g02boom {
		t.Errorf("RecoverOperation failure: %+v %v", out, err)
	}
	rs := &g02store{get: func(string) (*OperationRecord, error) { return &OperationRecord{ID: "a", State: OpPending}, nil }, trans: g02boomTrans}
	if r, err := RecoverOperation(rs, "a", opts); r != nil || err != g02boom {
		t.Errorf("settle failure: %+v %v", r, err)
	}

	st := NewMemoryOperationStore()
	for _, r := range []OperationRecord{{ID: "u", State: OpUncertain}, {ID: "c", State: OpExecuting}, {ID: "a", State: OpCommitted}, {ID: "b", State: OpPending}} {
		if _, _, err := st.Create(r); err != nil {
			t.Fatal(err)
		}
	}
	if open, err := st.ListOpen(); err != nil || len(open) != 2 || open[0].ID != "b" || open[1].ID != "c" {
		t.Errorf("ListOpen: %+v %v", open, err)
	}
	if ok, err := ResolveOperation(st, "u", OperationResolution{State: OpPending}, nil); ok || err == nil || err.Error() != "ResolveOperation: the outcome state must be committed or failed" {
		t.Errorf("resolve to pending: %v %v", ok, err)
	}
	if ok, err := ResolveOperation(st, "u", OperationResolution{State: OpCommitted, Result: "r"}, nil); !ok || err != nil {
		t.Errorf("resolve committed: %v %v", ok, err)
	}
	if cur, _ := st.Get("u"); cur == nil || cur.State != OpCommitted || cur.Result != "r" || cur.FinishedAt < before {
		t.Errorf("resolved record: %+v", cur)
	}
}
