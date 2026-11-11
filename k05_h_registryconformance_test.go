package pca

import "testing"

// The in-memory stores pass their own kits.
func TestF11_MemoryStoresPassTheKits(t *testing.T) {
	shared := NewMemoryAtomicKV()
	if rep := (RegistryKvConformance{Name: "memory kv", Open: func() (AtomicKV, error) { return shared, nil }}).KvConformance(); !rep.OK() {
		t.Error(rep)
	}
	mem := NewMemoryStateStore()
	if rep := (BudgetStoreConformance{Name: "memory budget", Open: func() (StateStore, error) { return mem, nil }}).Run(); !rep.OK() {
		t.Error(rep)
	}
	// a store without the budget seam fails the kit
	if rep := (BudgetStoreConformance{Name: "no budgets", Open: func() (StateStore, error) { return unscopedStore{}, nil }}).Run(); rep.OK() {
		t.Error("a store without BudgetStore passed")
	}
}
