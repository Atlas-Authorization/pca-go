package pca

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func memoryStateConformance(shared, durable bool) StateStoreConformance {
	st := NewMemoryStateStore()
	return StateStoreConformance{Name: "memory", Open: func() (StateStore, error) { return st, nil }, Shared: shared, Durable: durable}
}

func checkStatus(r ConformanceReport, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "absent"
}

func TestStateStoreConformanceMemoryStorePasses(t *testing.T) {
	// one process, state dies with it: the durability checks are skipped, never passed
	r := RunStateStoreConformance(memoryStateConformance(true, false))
	if !r.OK() {
		t.Fatal(r)
	}
	for name, want := range map[string]string{"claim-burst": "pass", "claim-concurrent": "pass", "retry-after-timeout": "pass",
		"claim-durability": "skip", "crash-after-claim": "skip"} {
		if got := checkStatus(r, name); got != want {
			t.Errorf("%s: %s want %s\n%s", name, got, want, r)
		}
	}
	// the process-local store, reopened against itself, also keeps its state: durability holds within the process
	if r := RunStateStoreConformance(memoryStateConformance(true, true)); !r.OK() {
		t.Fatal(r)
	}
}

// A claim that reads, waits and then writes admits many copies of one counter: the harness must see it.
type racyStore struct {
	mu   sync.Mutex
	last map[string]int64
}

func (s *racyStore) Claim(key string, n int64) (ClaimResult, error) {
	s.mu.Lock()
	last, has := s.last[key]
	s.mu.Unlock()
	if has && n <= last {
		return ClaimResult{LastCounter: &last}, nil
	}
	time.Sleep(time.Millisecond)
	s.mu.Lock()
	if s.last == nil {
		s.last = map[string]int64{}
	}
	s.last[key] = n
	s.mu.Unlock()
	return ClaimResult{OK: true}, nil
}

func TestStateStoreConformanceCatchesANonAtomicClaim(t *testing.T) {
	st := &racyStore{}
	r := RunStateStoreConformance(StateStoreConformance{Name: "racy", Open: func() (StateStore, error) { return st, nil }, Shared: true})
	if r.OK() || checkStatus(r, "claim-concurrent") != "fail" {
		t.Fatalf("a read-wait-write claim must fail claim-concurrent:\n%s", r)
	}
	if checkStatus(r, "claim-burst") != "pass" {
		t.Fatalf("sequentially the racy store is correct, the burst must pass:\n%s", r)
	}
	if !strings.Contains(r.String(), "FAIL") {
		t.Fatal("the rendered report must say FAIL")
	}
}

func TestStateStoreConformanceCatchesAStoreThatForgets(t *testing.T) {
	// every Open is a fresh empty store, yet it claims durability and sharing
	forgetful := StateStoreConformance{Name: "forgetful", Open: func() (StateStore, error) { return NewMemoryStateStore(), nil }, Shared: true, Durable: true}
	r := RunStateStoreConformance(forgetful)
	for _, name := range []string{"claim-durability", "crash-after-claim", "retry-after-timeout"} {
		if checkStatus(r, name) != "fail" {
			t.Errorf("%s must fail for a store that forgets:\n%s", name, r)
		}
	}
	if (RunStateStoreConformance(StateStoreConformance{Name: "no open"})).OK() {
		t.Fatal("a configuration without Open must fail")
	}
}

func TestOperationStoreConformance(t *testing.T) {
	mem := NewMemoryOperationStore()
	if r := RunOperationStoreConformance(OperationStoreConformance{Name: "memory", Open: func() (OperationStore, error) { return mem, nil }, Shared: true, Durable: true}); !r.OK() {
		t.Fatal(r)
	}
	kv := NewMemoryAtomicKV()
	if r := RunOperationStoreConformance(OperationStoreConformance{Name: "kv", Open: func() (OperationStore, error) { return NewKVOperationStore(kv, ""), nil }, Shared: true, Durable: true}); !r.OK() {
		t.Fatal(r)
	}
}

// A create that checks and then writes is not create-if-absent.
type racyOperationStore struct {
	*MemoryOperationStore
}

func (s racyOperationStore) Create(rec OperationRecord) (bool, OperationRecord, error) {
	if cur, _ := s.Get(rec.ID); cur != nil {
		return false, *cur, nil
	}
	time.Sleep(time.Millisecond)
	s.MemoryOperationStore.mu.Lock()
	s.MemoryOperationStore.m[rec.ID] = rec
	s.MemoryOperationStore.mu.Unlock()
	return true, OperationRecord{}, nil
}

func TestOperationStoreConformanceCatchesANonAtomicCreate(t *testing.T) {
	store := racyOperationStore{NewMemoryOperationStore()}
	r := RunOperationStoreConformance(OperationStoreConformance{Name: "racy", Open: func() (OperationStore, error) { return store, nil }, Shared: true})
	if r.OK() || checkStatus(r, "create-once") != "fail" {
		t.Fatalf("a check-then-write create must fail create-once:\n%s", r)
	}
	// a store that forgets between handles fails the shared and durability checks
	r = RunOperationStoreConformance(OperationStoreConformance{Name: "forgetful", Open: func() (OperationStore, error) { return NewMemoryOperationStore(), nil }, Shared: true, Durable: true})
	if checkStatus(r, "shared") != "fail" || checkStatus(r, "durability") != "fail" {
		t.Fatalf("%s", r)
	}
}
