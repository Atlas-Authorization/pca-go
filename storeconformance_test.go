package pca

import (
	"fmt"
	"runtime"
	"strconv"
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

// goroutineID is the id of the calling goroutine (parsed from its stack header); the racy doubles below use it to tell the goroutine
// that built them (serial setup, which must never wait) from the racers.
func goroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	h := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	id, _ := strconv.ParseUint(h[:strings.IndexByte(h, ' ')], 10, 64)
	return id
}

// rendezvous makes the racers on one key meet between their read and their write: every racer reads, then waits until a partner on
// the same key has read too (racers pair off in arrival order: the harness's retry race has two racers and its bursts sixteen, so a
// barrier of a fixed size would not fit both), and only then do the two write, so a pair always loses an update whatever the scheduler
// or the machine speed does (a wall-clock sleep let a late racer run alone and the race go unseen). A call from the goroutine that
// built the double is serial setup and never waits. A racer left without a partner for 30 s fails: it is recorded in `broken` (the
// test asserts it is nil) and the call errors.
type rendezvous struct {
	owner   uint64
	mu      sync.Mutex
	pending map[string]chan struct{}
	broken  error
}

func newRendezvous() *rendezvous {
	return &rendezvous{owner: goroutineID(), pending: map[string]chan struct{}{}}
}

// wait blocks the first racer of a pair on key until its partner arrives; it returns an error when no partner comes.
func (r *rendezvous) wait(key string) error {
	if goroutineID() == r.owner {
		return nil
	}
	r.mu.Lock()
	partner := r.pending[key]
	if partner != nil {
		delete(r.pending, key)
		close(partner)
		r.mu.Unlock()
		return nil
	}
	mine := make(chan struct{})
	r.pending[key] = mine
	r.mu.Unlock()
	select {
	case <-mine:
		return nil
	case <-time.After(30 * time.Second):
		err := fmt.Errorf("no partner reached the rendezvous on %q", key)
		r.mu.Lock()
		if r.pending[key] == mine {
			delete(r.pending, key)
		}
		if r.broken == nil {
			r.broken = err
		}
		r.mu.Unlock()
		return err
	}
}

func (r *rendezvous) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.broken
}

// A claim that reads, waits for a partner to have read, and then writes admits many copies of one counter: the harness must see it.
type racyStore struct {
	mu   sync.Mutex
	last map[string]int64
	meet *rendezvous
}

func (s *racyStore) Claim(key string, n int64) (ClaimResult, error) {
	s.mu.Lock()
	last, has := s.last[key]
	s.mu.Unlock()
	if err := s.meet.wait(key); err != nil {
		return ClaimResult{}, err
	}
	if has && n <= last {
		return ClaimResult{LastCounter: &last}, nil
	}
	s.mu.Lock()
	if s.last == nil {
		s.last = map[string]int64{}
	}
	s.last[key] = n
	s.mu.Unlock()
	return ClaimResult{OK: true}, nil
}

func TestStateStoreConformanceCatchesANonAtomicClaim(t *testing.T) {
	st := &racyStore{meet: newRendezvous()}
	r := RunStateStoreConformance(StateStoreConformance{Name: "racy", Open: func() (StateStore, error) { return st, nil }, Shared: true})
	if err := st.meet.err(); err != nil {
		t.Fatalf("the racers failed to rendezvous: %v", err)
	}
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

// A create that checks, waits for a partner to have checked, and then writes is not create-if-absent.
type racyOperationStore struct {
	*MemoryOperationStore
	meet *rendezvous
}

func (s racyOperationStore) Create(rec OperationRecord) (bool, OperationRecord, error) {
	cur, _ := s.Get(rec.ID)
	if err := s.meet.wait(rec.ID); err != nil {
		return false, OperationRecord{}, err
	}
	if cur != nil {
		return false, *cur, nil
	}
	s.MemoryOperationStore.mu.Lock()
	s.MemoryOperationStore.m[rec.ID] = rec
	s.MemoryOperationStore.mu.Unlock()
	return true, OperationRecord{}, nil
}

func TestOperationStoreConformanceCatchesANonAtomicCreate(t *testing.T) {
	store := racyOperationStore{NewMemoryOperationStore(), newRendezvous()}
	r := RunOperationStoreConformance(OperationStoreConformance{Name: "racy", Open: func() (OperationStore, error) { return store, nil }, Shared: true})
	if err := store.meet.err(); err != nil {
		t.Fatalf("the racers failed to rendezvous: %v", err)
	}
	if r.OK() || checkStatus(r, "create-once") != "fail" {
		t.Fatalf("a check-then-write create must fail create-once:\n%s", r)
	}
	// a store that forgets between handles fails the shared and durability checks
	r = RunOperationStoreConformance(OperationStoreConformance{Name: "forgetful", Open: func() (OperationStore, error) { return NewMemoryOperationStore(), nil }, Shared: true, Durable: true})
	if checkStatus(r, "shared") != "fail" || checkStatus(r, "durability") != "fail" {
		t.Fatalf("%s", r)
	}
}
