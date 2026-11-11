package pca

import (
	"encoding/json"
	"testing"
)

// r5n3RetryKV runs fn twice, as an optimistic store does after a lost race: the first answer is thrown away, the second is kept.
type r5n3RetryKV struct{ first, second []byte }

func (k *r5n3RetryKV) Get(string) ([]byte, bool, error) { return nil, false, nil }
func (k *r5n3RetryKV) Update(_ string, fn func([]byte) []byte) error {
	_ = fn(k.first)
	_ = fn(k.second)
	return nil
}

type r5n3PanicKV struct{}

func (r5n3PanicKV) Get(string) ([]byte, bool, error)         { panic("store fault") }
func (r5n3PanicKV) Update(string, func([]byte) []byte) error { panic("store fault") }

func r5n3Record(t *testing.T, state PlanState) []byte {
	t.Helper()
	enc, err := json.Marshal(PlanRecord{GrantRef: "g", Root: "x", Nodes: []map[string]any{{"id": "a"}}, State: state})
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestR5N3PlanRootOfRefusals(t *testing.T) {
	root, err := planRootOf(nil)
	if root != "" || err == nil || err.Error() != "merkleRoot: empty leaf set" {
		t.Errorf("empty: %q %v", root, err)
	}
	root, err = planRootOf([]map[string]any{nil})
	if root != "" || err == nil || err.Error() != "a plan node cannot be hashed" {
		t.Errorf("nil node: %q %v", root, err)
	}
	if got := cloneNodes([]map[string]any{{"c": make(chan int)}}); got != nil {
		t.Errorf("cloneNodes of an unencodable node: %v", got)
	}
}

func TestR5N3PlanGetIgnoresAnUndecodableRecord(t *testing.T) {
	kv := NewMemoryAtomicKV()
	reg := NewPlanRegistry(PlanRegistryOptions{KV: kv})
	_ = kv.Update(reg.key("g", "R"), func([]byte) []byte { return []byte("not json") })
	if rec, err := reg.Get("g", "R"); rec != nil || err != nil {
		t.Errorf("Get: %v %v", rec, err)
	}
}

func TestR5N3PlanTransitionsResetOnAStoreRetry(t *testing.T) {
	nodes := []map[string]any{{"id": "a", "verb": "v", "resource": "r"}}
	// Draft: the first attempt saw an existing plan, the retry sees none and stores
	reg := NewPlanRegistry(PlanRegistryOptions{KV: &r5n3RetryKV{first: r5n3Record(t, PlanDraft)}})
	if got := reg.Draft("g", nodes); !got.OK || got.Record == nil {
		t.Errorf("Draft after a retry: %+v", got)
	}
	// move: the first attempt saw a draft (not committable), the retry sees nothing
	reg = NewPlanRegistry(PlanRegistryOptions{KV: &r5n3RetryKV{first: r5n3Record(t, PlanDraft)}})
	got := reg.Commit("g", "R")
	if got.OK || got.State != PlanUnknown || got.Reason != "plan R is unknown for this grant" {
		t.Errorf("Commit after a retry: %+v", got)
	}
}

func TestR5N3IsPlanAuthorizedFailsClosedOnAStoreFault(t *testing.T) {
	reg := NewPlanRegistry(PlanRegistryOptions{KV: r5n3PanicKV{}})
	r5n3Recover(t, "IsPlanAuthorized", func() {
		if reg.IsPlanAuthorized("g", "R") {
			t.Error("a faulting store authorized a plan")
		}
	})
}

func r5n3Authorized(t *testing.T, reg *PlanRegistry, nodes []map[string]any) string {
	t.Helper()
	d := reg.Draft("g", nodes)
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
	if a := reg.Authorize("g", root, &PlanApproval{By: "p"}); !a.OK {
		t.Fatalf("authorize: %+v", a)
	}
	return root
}

func TestR5N3PlanCheckOperationAndNodeRules(t *testing.T) {
	reg := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 10 }})
	root := r5n3Authorized(t, reg, []map[string]any{{"id": "a", "verb": "v", "resource": "r"}})
	// params that cannot be hashed
	s := reg.Check("g", root, PlanCheckOptions{NodeID: "a", Operation: &Operation{Verb: "v", Resource: "r", Params: map[string]any{"c": make(chan int)}}})
	if s.Executable || s.Reason != "plan "+root+": the operation's params cannot be hashed" {
		t.Errorf("unhashable params: %+v", s)
	}
	// the matching operation passes, a different one does not
	if s := reg.Check("g", root, PlanCheckOptions{NodeID: "a", Operation: &Operation{Verb: "v", Resource: "r"}}); !s.Executable {
		t.Errorf("matching operation: %+v", s)
	}
	if s := reg.Check("g", root, PlanCheckOptions{NodeID: "zz"}); s.Executable || s.Reason != "plan "+root+" has no node 'zz'" {
		t.Errorf("unknown node: %+v", s)
	}
}

func TestR5N3PlanCheckUsesTheFirstNodeOfADuplicateId(t *testing.T) {
	kv := NewMemoryAtomicKV()
	reg := NewPlanRegistry(PlanRegistryOptions{KV: kv, Now: func() int64 { return 10 }})
	nodes := []map[string]any{{"id": "a", "verb": "v", "resource": "r"}, {"id": "a", "verb": "w", "resource": "s"}}
	root, err := planRootOf(nodes)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := json.Marshal(PlanRecord{GrantRef: "g", Root: root, Nodes: nodes, State: PlanAuthorized, Approval: &PlanApproval{By: "p"}})
	_ = kv.Update(reg.key("g", root), func([]byte) []byte { return enc })
	if s := reg.Check("g", root, PlanCheckOptions{NodeID: "a", Operation: &Operation{Verb: "v", Resource: "r"}}); !s.Executable {
		t.Errorf("the first node of the id must be the one checked: %+v", s)
	}
}
