package pca

// Mutants whose wrong behaviour used to surface only as a panic in a goroutine a test started, or as a loop that never ends.
// Each test here reaches the same code on the test's own goroutine, or stops the goroutines before they can crash, so the mutant
// fails a test. This file sorts before every other test file, and the order inside it matters: a test whose goroutines would
// crash under a mutant comes after the test that fails first under that mutant.

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const reKillSomeTimeMs = 1_700_000_000_000

// First of all: a table with a stale nil slot would crash the goroutines of every test below, and a loop that never ends would
// open handles until memory runs out, when an Open that works every time is all it meets.
func TestREOpenNOpensExactlyN(t *testing.T) {
	opens := 0
	c := StateStoreConformance{Open: func() (StateStore, error) {
		opens++
		if opens > 1 {
			return nil, errors.New("opened more handles than asked for")
		}
		return NewMemoryStateStore(), nil
	}}
	hs, err := c.openN(1)
	if err != nil || len(hs) != 1 || opens != 1 {
		t.Fatalf("handles %d, opens %d, err %v", len(hs), opens, err)
	}
}

// r3: the distinct-counter race with the highest counter refused, every claim parked behind a gate. Without wg.Add in either loop the
// check moves on while its claimers are parked and reports an error that the test sees before any gate opens (nothing is released
// then, so no wg.Done can panic). A table one slot short panics at the read on this goroutine: no claimer writes it. The call runs
// under a recover and a deadline, so a loop that never ends fails here as an ordinary test failure. It sits after the OpenN test
// (a stale nil slot would crash every goroutine below) and before the gated test, where the same short table would panic in a worker.
type reStageStore struct {
	StateStore
	roundsGo, distinctGo chan struct{}
	finished             *atomic.Int32
}

func (s reStageStore) Claim(key string, counter int64) (ClaimResult, error) {
	if strings.Contains(key, "concurrent-distinct") {
		<-s.distinctGo
		defer s.finished.Add(1)
		return ClaimResult{}, nil
	}
	if strings.Contains(key, "concurrent") {
		<-s.roundsGo
	}
	return s.StateStore.Claim(key, counter)
}

func TestRE3ClaimConcurrentStagedAndHighestRefused(t *testing.T) {
	var finished atomic.Int32
	var gaveUp atomic.Bool
	roundsGo, distinctGo := make(chan struct{}), make(chan struct{})
	go func() {
		time.Sleep(500 * time.Millisecond)
		if !gaveUp.Load() {
			close(roundsGo)
		}
		time.Sleep(500 * time.Millisecond)
		if !gaveUp.Load() {
			close(distinctGo)
		}
	}()
	shared := NewMemoryStateStore()
	c := StateStoreConformance{Rounds: 1, Copies: 2, Handles: 2, Open: func() (StateStore, error) {
		return reStageStore{StateStore: shared, roundsGo: roundsGo, distinctGo: distinctGo, finished: &finished}, nil
	}}
	res := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				res <- fmt.Errorf("panicked: %v", p)
			}
		}()
		res <- c.claimConcurrent()
	}()
	var err error
	select {
	case err = <-res:
	case <-time.After(5 * time.Second):
		gaveUp.Store(true)
		t.Fatal("claimConcurrent did not return")
	}
	if err == nil || err.Error() != "the highest of 2 racing counters was not admitted" || finished.Load() != 2 {
		gaveUp.Store(true)
		t.Fatalf("got %v with %d of 2 distinct claimers finished", err, finished.Load())
	}
}

// re2GatedStore parks every racing Claim until release closes, and admits counters below the racing ones (with Rounds 1 they
// are 2 and 3, and the check after the race asks only for those).
type re2GatedStore struct {
	StateStore
	release chan struct{}
}

func (s re2GatedStore) Claim(key string, counter int64) (ClaimResult, error) {
	if strings.Contains(key, "concurrent-distinct") {
		<-s.release
		if counter < 2 {
			return ClaimResult{OK: true}, nil
		}
	}
	return s.StateStore.Claim(key, counter)
}

// The distinct-counter race waits for its claimers, starts each once and re-checks only the counters that raced. A race that does
// not wait returns "not admitted" while the claimers are parked, before their wg.Done can panic. Two handles: a start index that
// runs below zero panics on this goroutine at hs[i%len(hs)], where one handle would spawn for ever. A re-check that runs downward
// reaches counter 1, which this store admits, instead of looping for ever.
func TestRE2ClaimConcurrentWaitsAndStopsAtBase(t *testing.T) {
	release := make(chan struct{})
	var gaveUp atomic.Bool
	go func() {
		time.Sleep(500 * time.Millisecond)
		if !gaveUp.Load() {
			close(release)
		}
	}()
	store := re2GatedStore{StateStore: NewMemoryStateStore(), release: release}
	c := StateStoreConformance{Rounds: 1, Copies: 2, Handles: 2, Open: func() (StateStore, error) { return store, nil }}
	if err := c.claimConcurrent(); err != nil {
		gaveUp.Store(true)
		t.Fatal(err)
	}
}

// reKillRefuseDistinct is a store that admits the identical-counter rounds and refuses every distinct racing counter.
type reKillRefuseDistinct struct{ StateStore }

func (s reKillRefuseDistinct) Claim(key string, counter int64) (ClaimResult, error) {
	if strings.Contains(key, "concurrent-distinct") {
		return ClaimResult{}, nil
	}
	return s.StateStore.Claim(key, counter)
}

// No goroutine writes admitted here, so a table one slot short panics at the read on the caller's goroutine.
func TestREClaimConcurrentHighestRefused(t *testing.T) {
	shared := NewMemoryStateStore()
	c := StateStoreConformance{Rounds: 1, Copies: 2, Handles: 1, Open: func() (StateStore, error) {
		return reKillRefuseDistinct{StateStore: shared}, nil
	}}
	err := c.claimConcurrent()
	if err == nil || err.Error() != "the highest of 2 racing counters was not admitted" {
		t.Fatalf("got %v", err)
	}
}

func reKillCheck(t *testing.T, rep ConformanceReport, name string) ConformanceCheck {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %s", name, rep)
	return ConformanceCheck{}
}

// An Open error fails the check even when a store came with it. Only the second Open hands both stores back with its error, so a
// check that ignores the error runs on real stores and passes. Before the first-Open test: open2 answers a first error with nil
// stores, and the same mutants then crash the goroutines.
func TestREOpConformanceSecondOpenError(t *testing.T) {
	store := NewMemoryOperationStore()
	opens := 0
	rep := RunOperationStoreConformance(OperationStoreConformance{Copies: 1, Shared: true, Open: func() (OperationStore, error) {
		opens++
		if opens%2 == 0 {
			return store, errors.New("boom")
		}
		return store, nil
	}})
	if c := reKillCheck(t, rep, "create-once"); c.Status != "fail" || c.Note != "boom" {
		t.Fatalf("create-once: %+v", c)
	}
}

func TestREOpConformanceFirstOpenError(t *testing.T) {
	store := NewMemoryOperationStore()
	rep := RunOperationStoreConformance(OperationStoreConformance{Copies: 1, Open: func() (OperationStore, error) {
		return store, errors.New("boom")
	}})
	if c := reKillCheck(t, rep, "create-once"); c.Status != "fail" || c.Note != "boom" {
		t.Fatalf("create-once: %+v", c)
	}
}

// reKillSlowOps holds every Create until release closes.
type reKillSlowOps struct {
	OperationStore
	release chan struct{}
	done    *atomic.Int32
}

func (s reKillSlowOps) Create(rec OperationRecord) (bool, OperationRecord, error) {
	<-s.release
	defer s.done.Add(1)
	return s.OperationStore.Create(rec)
}

// r3: create-once and transition-once each wait for their workers. A check that lost its wg.Add moves on at once, so the Open of
// the NEXT check finds the workers still parked and fails here, before anything is released (a worker that finished meanwhile
// would panic on a negative WaitGroup counter, which no test can catch). One test covers both checks, in this order, so neither
// mutant meets the other's race first; it comes after the open-error tests, before the create-once test below.
type reOpSlow struct {
	OperationStore
	createGo, moveGo chan struct{}
	done             *atomic.Int32
}

func (s reOpSlow) Create(rec OperationRecord) (bool, OperationRecord, error) {
	<-s.createGo
	defer s.done.Add(1)
	return s.OperationStore.Create(rec)
}

func (s reOpSlow) Transition(id string, from OperationState, next OperationRecord) (bool, error) {
	<-s.moveGo
	defer s.done.Add(1)
	return s.OperationStore.Transition(id, from, next)
}

func TestRE3OpConformanceChecksWaitForTheirWorkers(t *testing.T) {
	const copies = 2
	var done atomic.Int32
	var gaveUp atomic.Bool
	createGo, moveGo := make(chan struct{}), make(chan struct{})
	release := func(c chan struct{}) {
		time.Sleep(500 * time.Millisecond)
		if !gaveUp.Load() {
			close(c)
		}
	}
	go release(createGo)
	store := reOpSlow{OperationStore: NewMemoryOperationStore(), createGo: createGo, moveGo: moveGo, done: &done}
	opens := 0
	rep := RunOperationStoreConformance(OperationStoreConformance{Copies: copies, Open: func() (OperationStore, error) {
		opens++
		// create-once finishes copies Creates; transition-once adds its own setup Create plus copies Transitions
		want := map[int]int{2: copies, 3: 2*copies + 1}[opens]
		if want != 0 && int(done.Load()) != want {
			gaveUp.Store(true)
			t.Fatalf("the check before open %d returned with %d operations finished, want %d", opens, done.Load(), want)
		}
		if opens == 2 {
			go release(moveGo)
		}
		return store, nil
	}})
	if !rep.OK() {
		t.Fatal(rep)
	}
}

// create-once must wait for its creators. Without wg.Add it moves on at once; the next Open sees that and fails the test while
// the creators are still parked, before their wg.Done can panic.
func TestREOpConformanceCreateOnceWaits(t *testing.T) {
	const copies = 2
	var done atomic.Int32
	var gaveUp atomic.Bool
	release := make(chan struct{})
	go func() {
		time.Sleep(500 * time.Millisecond)
		if !gaveUp.Load() {
			close(release)
		}
	}()
	store := reKillSlowOps{OperationStore: NewMemoryOperationStore(), release: release, done: &done}
	opens := 0
	rep := RunOperationStoreConformance(OperationStoreConformance{Copies: copies, Open: func() (OperationStore, error) {
		opens++
		if opens == 2 && done.Load() != copies {
			gaveUp.Store(true)
			t.Fatalf("create-once returned with %d of %d creates finished", done.Load(), copies)
		}
		return store, nil
	}})
	if !rep.OK() {
		t.Fatal(rep)
	}
}

func TestREPlanRegistryDefaultClock(t *testing.T) {
	r := NewPlanRegistry(PlanRegistryOptions{})
	if r.now == nil {
		t.Fatal("no default clock")
	}
	if got := r.now(); got < reKillSomeTimeMs {
		t.Fatalf("default clock: %d", got)
	}
}

func TestREExecuteOptionsDefaultClock(t *testing.T) {
	clock := ExecuteOptions{}.clock()
	if clock == nil {
		t.Fatal("no default clock")
	}
	if got := clock(); got < reKillSomeTimeMs {
		t.Fatalf("default clock: %d", got)
	}
}
