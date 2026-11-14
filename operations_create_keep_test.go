package pca

import "testing"

// A second claim of the same operation id must leave the first record untouched (the store never overwrites a claim).
func TestKVOperationStoreCreateKeepsTheFirstRecord(t *testing.T) {
	s := NewKVOperationStore(NewMemoryAtomicKV(), "")
	first := OperationRecord{ID: "a", State: OpPending, Verb: "first", Resource: "/r", StartedAt: 7}
	if created, _, err := s.Create(first); err != nil || !created {
		t.Fatal(created, err)
	}
	second := OperationRecord{ID: "a", State: OpExecuting, Verb: "second", Resource: "/other", StartedAt: 9}
	if created, ex, err := s.Create(second); err != nil || created || ex.Verb != "first" {
		t.Fatalf("second create: %v %+v %v", created, ex, err)
	}
	r, err := s.Get("a")
	if err != nil || r == nil || r.Verb != "first" || r.State != OpPending || r.Resource != "/r" || r.StartedAt != 7 {
		t.Fatalf("the first record was overwritten: %+v %v", r, err)
	}
}
