package pca

import (
	"fmt"
	"testing"
	"time"
)

func TestG10ExecutorClockAndTimeout(t *testing.T) {
	before := time.Now().UnixMilli()
	got := NewExecutor(ExecutorOptions{}).clock()()
	if got < before || got > time.Now().UnixMilli() {
		t.Fatalf("default clock: %d", got)
	}
	if got := NewExecutor(ExecutorOptions{Now: func() int64 { return 42 }}).clock()(); got != 42 {
		t.Fatalf("set clock: %d", got)
	}
	for in, want := range map[int64]int64{0: OperationPendingTimeoutMs, 1: 1, 7: 7} {
		if got := NewExecutor(ExecutorOptions{PendingTimeoutMs: in}).timeout(); got != want {
			t.Fatalf("timeout(%d) = %d, want %d", in, got, want)
		}
	}
}

func g10exPlanNodes() []map[string]any {
	return []map[string]any{{"id": "n1", "verb": "v", "resource": "/r"}}
}

func g10exRecheck(plans *PlanRegistry, extra func(ExecutionHandle) (RecheckResult, error), grant map[string]any) func(ExecutionHandle) (RecheckResult, error) {
	in := AuthorizeInput{Risk: InsecureCalmRisk,
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		IsRevoked:    func(_, _ map[string]any) (bool, error) { return false, nil },
		Plans:        plans,
	}
	return NewExecutor(ExecutorOptions{Authorize: in, Recheck: extra}).recheck(func() int64 { return 1000 })
}

func g10exHandle(plan any) ExecutionHandle {
	p := map[string]any{"grant_ref": "g"}
	if plan != nil {
		p["plan"] = plan
	}
	return ExecutionHandle{PCActn: p}
}

func TestG10ExecutorRecheckPlans(t *testing.T) {
	grant := map[string]any{"id": "g"}
	// the grant resolves to nothing (no error): no longer known
	if rc, err := g10exRecheck(nil, nil, nil)(g10exHandle(nil)); err != nil || rc.OK || rc.Reason != "the grant is no longer known" {
		t.Fatalf("nil grant: %+v %v", rc, err)
	}
	// no plan, the caller's extra re-check decides
	extra := func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{Reason: "extra says no"}, nil }
	if rc, _ := g10exRecheck(nil, extra, grant)(g10exHandle(nil)); rc.OK || rc.Reason != "extra says no" {
		t.Fatalf("extra: %+v", rc)
	}
	if rc, _ := g10exRecheck(nil, nil, grant)(g10exHandle(nil)); !rc.OK || rc.Reason != "" {
		t.Fatalf("no plan: %+v", rc)
	}

	// an authorized plan: executable for its node
	reg := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 500 }})
	d := reg.Draft("g", g10exPlanNodes())
	if !d.OK {
		t.Fatalf("draft: %+v", d)
	}
	root := d.Record.Root
	if v := reg.Validate("g", root); !v.OK {
		t.Fatalf("validate: %+v", v)
	}
	if c := reg.Commit("g", root); !c.OK {
		t.Fatalf("commit: %+v", c)
	}
	if a := reg.Authorize("g", root, &PlanApproval{By: "alice"}); !a.OK {
		t.Fatalf("authorize: %+v", a)
	}
	if rc, _ := g10exRecheck(reg, nil, grant)(g10exHandle(map[string]any{"root": root, "node_id": "n1"})); !rc.OK || rc.Reason != "" {
		t.Fatalf("authorized plan: %+v", rc)
	}
	// a registered plan that is not executable (still a draft)
	reg2 := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 500 }})
	if d2 := reg2.Draft("g", g10exPlanNodes()); !d2.OK || d2.Record.Root != root {
		t.Fatalf("draft2: %+v", d2)
	}
	want := fmt.Sprintf("plan %s is draft, not authorized", root)
	if rc, _ := g10exRecheck(reg2, nil, grant)(g10exHandle(map[string]any{"root": root, "node_id": "n1"})); rc.OK || rc.Reason != want {
		t.Fatalf("draft plan: %+v", rc)
	}
	// a plan root the registry does not know: not looked at
	if rc, _ := g10exRecheck(reg2, nil, grant)(g10exHandle(map[string]any{"root": "unregistered", "node_id": "n1"})); !rc.OK {
		t.Fatalf("unregistered root: %+v", rc)
	}
	// a non-string root is not looked up, even when a record sits under the empty root's key
	kv := NewMemoryAtomicKV()
	if err := kv.Update("pca-plan:g:", func([]byte) []byte {
		return []byte(`{"grantRef":"g","root":"x","nodes":[{"id":"n1","verb":"v","resource":"/r"}],"state":"revoked","createdAt":1}`)
	}); err != nil {
		t.Fatal(err)
	}
	reg3 := NewPlanRegistry(PlanRegistryOptions{KV: kv})
	if rec, _ := reg3.Get("g", ""); rec == nil || rec.State != PlanRevoked {
		t.Fatalf("seeded record: %+v", rec)
	}
	if rc, _ := g10exRecheck(reg3, nil, grant)(g10exHandle(map[string]any{"root": 5, "node_id": "n1"})); !rc.OK {
		t.Fatalf("non-string root: %+v", rc)
	}
}

func TestG10ExecutorRunBranches(t *testing.T) {
	// a missing record store: the executor's own refusal
	ex, pcactn, op, _ := executorFixture(t, -1)
	ex.o.Operations = nil
	if o := ex.Run(pcactn, op, nil); o.Status != "refused" || o.Reason != "NewExecutor: missing required component: Operations (fail closed)" {
		t.Fatalf("no store: %+v", o)
	}

	// Authorize.Now unset: the executor's clock is the authorization time
	ex, pcactn, op, _ = executorFixture(t, -1)
	fixedNow := ex.o.Authorize.Now
	ex.o.Authorize.Now = 0
	ex.o.Now = func() int64 { return fixedNow }
	var seen []string
	ex.o.ReversibilityClassOf = func(o Operation) string { seen = append(seen, o.Verb); return "reversible" }
	if o := ex.Run(pcactn, op, func(ExecutionHandle) (any, error) { return "ok", nil }); o.Status != "committed" || o.Result != "ok" {
		t.Fatalf("executor clock: %+v", o)
	}
	if len(seen) != 1 || seen[0] != op.Verb {
		t.Fatalf("ReversibilityClassOf calls: %v", seen)
	}

	// Authorize.Now set wins for the authorization; the executor's clock still runs the expiry re-check
	ex, pcactn, op, _ = executorFixture(t, -1)
	later := ex.o.Authorize.Now + 10*365*24*3600*1000
	ex.o.Now = func() int64 { return later }
	ran := false
	o := ex.Run(pcactn, op, func(ExecutionHandle) (any, error) { ran = true; return nil, nil })
	if o.Status != "aborted" || ran || o.Reason != "recheck: the PCActn expired at 1792930800000" {
		t.Fatalf("authorize clock: %+v ran=%v", o, ran)
	}

	// a replay whose first presentation never reached execution (no record): the denial stands
	ex, pcactn, op, _ = executorFixture(t, -1)
	in := ex.o.Authorize
	in.Operation = op
	if r := Authorize(pcactn, in); !r.Allow {
		t.Fatalf("first presentation: %+v", r)
	}
	o = ex.Run(pcactn, op, func(ExecutionHandle) (any, error) { ran = true; return nil, nil })
	if o.Status != "denied" || ran || o.Authorization == nil || o.Authorization.Checks["replay"] != "fail" {
		t.Fatalf("replay without record: %+v", o)
	}
}
