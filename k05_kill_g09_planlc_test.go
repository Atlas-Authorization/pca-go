package pca

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

// g09 mutation kills for plan_lifecycle.go: store failures, record decoding, the structural checks, the validator
// outcomes, the expiry edge and Check's early return.

type g09pKV struct {
	getVal   []byte
	getOK    bool
	getErr   error
	updErr   error
	panicGet bool
}

func (k *g09pKV) Get(string) ([]byte, bool, error) {
	if k.panicGet {
		panic("kv boom")
	}
	return k.getVal, k.getOK, k.getErr
}

func (k *g09pKV) Update(string, func([]byte) []byte) error { return k.updErr }

func g09pNodes() []map[string]any {
	return []map[string]any{{"id": "a", "verb": "v", "resource": "r"}}
}

func g09pTamper(t *testing.T, kv *MemoryAtomicKV, key string, f func(n map[string]any)) {
	t.Helper()
	if err := kv.Update(key, func(prev []byte) []byte {
		rec, ok := decodePlanRecord(prev)
		if !ok {
			t.Fatal("no stored record")
		}
		f(rec.Nodes[0])
		b, _ := json.Marshal(rec)
		return b
	}); err != nil {
		t.Fatal(err)
	}
}

func TestG09PlanStoreFailures(t *testing.T) {
	boom := errors.New("boom")
	refused := "the plan store failed (fail closed): boom"
	getFail := NewPlanRegistry(PlanRegistryOptions{KV: &g09pKV{getErr: boom}, Now: func() int64 { return 1 }})
	if s := getFail.Status("g", "R", 1); s.State != PlanUnknown || s.Reason != refused || s.Executable {
		t.Errorf("Status: %+v", s)
	}
	if tr := getFail.Validate("g", "R"); tr.OK || tr.State != PlanUnknown || tr.Reason != refused {
		t.Errorf("Validate: %+v", tr)
	}
	stored, _ := json.Marshal(PlanRecord{GrantRef: "g", Root: "R", Nodes: g09pNodes(), State: PlanDraft})
	both := NewPlanRegistry(PlanRegistryOptions{KV: &g09pKV{getVal: stored, getOK: true, getErr: boom}})
	if rec, err := both.Get("g", "R"); rec != nil || err != boom {
		t.Errorf("Get with a value and an error: %v %v", rec, err)
	}
	updFail := NewPlanRegistry(PlanRegistryOptions{KV: &g09pKV{updErr: boom}, Now: func() int64 { return 1 }})
	if tr := updFail.Commit("g", "R"); tr.OK || tr.State != PlanUnknown || tr.Reason != refused {
		t.Errorf("Commit: %+v", tr)
	}
	if tr := updFail.Draft("g", g09pNodes()); tr.OK || tr.State != PlanUnknown || tr.Reason != refused {
		t.Errorf("Draft: %+v", tr)
	}
	panicky := NewPlanRegistry(PlanRegistryOptions{KV: &g09pKV{panicGet: true}, Now: func() int64 { return 1 }})
	if panicky.IsPlanAuthorized("g", "R") {
		t.Error("a panicking store must not authorize")
	}
}

func TestG09PlanRecordDecoding(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{``, false}, {`x`, false}, {`{"root":"","nodes":[]}`, false}, {`{"root":"r"}`, false}, {`{"root":"r","nodes":[]}`, true},
	} {
		if _, ok := decodePlanRecord([]byte(c.in)); ok != c.ok {
			t.Errorf("%q: %v", c.in, ok)
		}
	}
	rec, ok := decodePlanRecord([]byte(`{"root":"r","nodes":[{"n":1}]}`))
	if !ok {
		t.Fatal("decode")
	}
	if _, isNum := rec.Nodes[0]["n"].(json.Number); !isNum {
		t.Errorf("decoded numbers must stay json.Number: %T", rec.Nodes[0]["n"])
	}
	if _, isNum := cloneNodes([]map[string]any{{"n": json.Number("1")}})[0]["n"].(json.Number); !isNum {
		t.Error("cloned numbers must stay json.Number")
	}
	if got := structuralProblem(nil); got != "a plan needs at least one node" {
		t.Errorf("no nodes: %q", got)
	}
	if got := structuralProblem([]map[string]any{{"id": "", "verb": "v", "resource": "r"}}); got != "every node needs an id" {
		t.Errorf("empty id: %q", got)
	}
	if got := structuralProblem([]map[string]any{{"id": "a", "verb": "v", "resource": ""}}); got != "node 'a' needs a verb and a resource" {
		t.Errorf("empty resource: %q", got)
	}
	if got := NewPlanRegistry(PlanRegistryOptions{}).key("g", "r"); got != "pca-plan:g:r" {
		t.Errorf("default prefix: %q", got)
	}
	if got := NewPlanRegistry(PlanRegistryOptions{Prefix: "x:"}).key("g", "r"); got != "x:g:r" {
		t.Errorf("custom prefix: %q", got)
	}
	r := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 1 }})
	nodes := g09pNodes()
	nodes[0]["x"] = func() {} // not part of the plan leaf, so the root exists, but the nodes are not JSON
	if tr := r.Draft("g", nodes); tr.OK || tr.Reason != "the plan cannot be committed: the nodes are not JSON" {
		t.Errorf("unencodable nodes: %+v", tr)
	}
}

func TestG09PlanLifecycleEdges(t *testing.T) {
	kv := NewMemoryAtomicKV()
	calls := 0
	r := NewPlanRegistry(PlanRegistryOptions{KV: kv, Now: func() int64 { return 1000 }, Validator: func(PlanRecord) (PlanValidation, error) {
		calls++
		return PlanValidation{OK: calls == 1}, nil
	}})
	root := r.Draft("g", g09pNodes()).Record.Root
	if tr := r.Validate("g", root); !tr.OK {
		t.Fatalf("validate: %+v", tr)
	}
	// validating again is refused on the state, before the validator runs
	if tr := r.Validate("g", root); tr.OK || tr.Reason != "plan "+root+" is validated: cannot validate" || calls != 1 {
		t.Errorf("re-validate: %+v (validator calls %d)", tr, calls)
	}
	nan := math.NaN()
	tr := r.move("g", root, []PlanState{PlanValidated}, "x", func(p PlanRecord) PlanRecord {
		p.Approval = &PlanApproval{By: "x", ExpiresAt: &nan}
		return p
	})
	if tr.OK || tr.State != PlanUnknown || tr.Reason != "the plan store failed (fail closed): json: unsupported value: NaN" {
		t.Errorf("unencodable record: %+v", tr)
	}
	if tr := r.Commit("g", root); !tr.OK {
		t.Fatalf("commit: %+v", tr)
	}
	if s := r.Check("g", root, PlanCheckOptions{NodeID: "zz", Now: 1000}); s.Executable || s.Reason != "plan "+root+" is committed but not authorized by the principal" {
		t.Errorf("check on a committed plan: %+v", s)
	}
	if s := r.Check("g", "nope", PlanCheckOptions{NodeID: "a", Now: 1000}); s.Executable || s.Reason != "plan nope is unknown for this grant" {
		t.Errorf("check on an unknown plan: %+v", s)
	}
	if tr := r.Authorize("g", "nope", nil); tr.State != PlanUnknown || tr.Reason != "an approval names who approved (`by`)" {
		t.Errorf("nil approval: %+v", tr)
	}
	neg := math.Inf(-1)
	if tr := r.Authorize("g", root, &PlanApproval{By: "p", ExpiresAt: &neg}); tr.OK || tr.State != PlanCommitted || tr.Reason != "approval.expiresAt must be a time (epoch ms)" {
		t.Errorf("-Inf expiry: %+v", tr)
	}
	exp := 5000.0
	if tr := r.Authorize("g", root, &PlanApproval{By: "p", ExpiresAt: &exp}); !tr.OK {
		t.Fatalf("authorize: %+v", tr)
	}
	if s := r.Status("g", root, 4999); !s.Executable {
		t.Errorf("before expiry: %+v", s)
	}
	expired := "plan " + root + ": the principal's approval expired at 5000"
	if s := r.Status("g", root, 5000); s.Executable || s.Reason != expired {
		t.Errorf("at expiry: %+v", s)
	}
	// an explicit now wins over the registry clock (1000)
	if s := r.Status("g", root, 6000); s.Executable || s.Reason != expired {
		t.Errorf("explicit now: %+v", s)
	}
	if tr := r.Revoke("g", root, ""); !tr.OK {
		t.Fatalf("revoke: %+v", tr)
	}
	if s := r.Status("g", root, 1000); s.Reason != "plan "+root+" is revoked (no reason given)" {
		t.Errorf("revoked: %+v", s)
	}
}

func TestG09PlanValidateOutcomes(t *testing.T) {
	kv := NewMemoryAtomicKV()
	r := NewPlanRegistry(PlanRegistryOptions{KV: kv, Now: func() int64 { return 1 }})
	// a structural problem is reported as such even when the tampered nodes no longer hash to the root
	root := r.Draft("g", g09pNodes()).Record.Root
	g09pTamper(t, kv, r.key("g", root), func(n map[string]any) { n["verb"] = "" })
	if tr := r.Validate("g", root); tr.OK || tr.Reason != "plan "+root+" is invalid: node 'a' needs a verb and a resource" {
		t.Errorf("structural: %+v", tr)
	}
	r2 := NewPlanRegistry(PlanRegistryOptions{KV: NewMemoryAtomicKV(), Now: func() int64 { return 1 }})
	root2 := r2.Draft("g", g09pNodes()).Record.Root
	g09pTamper(t, r2.kv.(*MemoryAtomicKV), r2.key("g", root2), func(n map[string]any) { n["resource"] = "r2" })
	if tr := r2.Validate("g", root2); tr.OK || tr.Reason != "plan "+root2+" is invalid: the stored nodes no longer hash to the root" {
		t.Errorf("tampered: %+v", tr)
	}
	for _, c := range []struct {
		name string
		f    func(PlanRecord) (PlanValidation, error)
		want string
	}{
		{"silent refusal", func(PlanRecord) (PlanValidation, error) { return PlanValidation{}, nil }, "refused by the validator"},
		{"panic", func(PlanRecord) (PlanValidation, error) { panic("boom") }, "validator error (fail closed): boom"},
	} {
		rv := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 1 }, Validator: c.f})
		rt := rv.Draft("g", g09pNodes()).Record.Root
		if tr := rv.Validate("g", rt); tr.OK || tr.Reason != "plan "+rt+" is invalid: "+c.want {
			t.Errorf("%s: %+v", c.name, tr)
		}
	}
}
