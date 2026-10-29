package pca

// Store conformance: run your StateStore (the replay store behind Authorize) and your OperationStore through the
// invariants the guards rely on, from a test in your own repository:
//
//	rep := pca.RunStateStoreConformance(pca.StateStoreConformance{Name: "postgres", Open: openStore, Shared: true, Durable: true})
//	if !rep.OK() { t.Fatal(rep) }
//
// StateStore checks: claim-burst (strictly increasing counters admitted once each, repeats and older counters refused),
// claim-concurrent (N copies of one counter on several handles: exactly one admitted, every round; distinct counters in a
// race never admit the same one twice and always admit the highest), claim-durability (state survives closing every handle
// and a restart), crash-after-claim (admitted, then the instance dies without closing: the same counter stays refused),
// retry-after-timeout (the claim commits but its answer is lost: the retry is refused, the next counter admitted).
// OperationStore checks: create-once, transition-once, wrong-state, get-missing, shared, durability. A check the store
// declares it cannot meet (not Durable, not Shared) is skipped, never passed.

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConformanceCheck is the outcome of one check. Status is "pass", "fail" or "skip".
type ConformanceCheck struct {
	Name   string
	Status string
	Note   string
}

// ConformanceReport is the outcome of a conformance run.
type ConformanceReport struct {
	Name   string
	Checks []ConformanceCheck
}

// OK reports whether no check failed.
func (r ConformanceReport) OK() bool {
	for _, c := range r.Checks {
		if c.Status == "fail" {
			return false
		}
	}
	return true
}

// String renders the report, one line per check.
func (r ConformanceReport) String() string {
	var b strings.Builder
	verdict := "PASS"
	if !r.OK() {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "store conformance: %s -> %s\n", r.Name, verdict)
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  [%s] %-20s %s\n", strings.ToUpper(c.Status), c.Name, c.Note)
	}
	return b.String()
}

func (r *ConformanceReport) add(name string, err error, note string) {
	if err != nil {
		r.Checks = append(r.Checks, ConformanceCheck{Name: name, Status: "fail", Note: err.Error()})
		return
	}
	r.Checks = append(r.Checks, ConformanceCheck{Name: name, Status: "pass", Note: note})
}

func (r *ConformanceReport) skip(name, why string) {
	r.Checks = append(r.Checks, ConformanceCheck{Name: name, Status: "skip", Note: why})
}

func closeStore(s any) {
	if c, ok := s.(io.Closer); ok {
		_ = c.Close()
	}
}

// StateStoreConformance configures RunStateStoreConformance.
type StateStoreConformance struct {
	Name string
	// Open returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection). A store
	// that implements io.Closer is closed after use.
	Open func() (StateStore, error)
	// Restart, when set, crashes and restarts the backend; it runs between closing the handles and reopening.
	Restart func() error
	// Durable: state survives closing every handle (and Restart). False skips the durability checks.
	Durable bool
	// Shared: several handles can share the backend. False runs the race checks on one handle.
	Shared bool
	// Rounds (default 10), Copies (default 16) and Handles (default 4) size the race checks.
	Rounds, Copies, Handles int
}

func (c *StateStoreConformance) defaults() {
	if c.Rounds <= 0 {
		c.Rounds = 10
	}
	if c.Copies <= 0 {
		c.Copies = 16
	}
	if c.Handles <= 0 {
		c.Handles = 4
	}
	if !c.Shared {
		c.Handles = 1
	}
}

var confSeq atomic.Uint64

func confKey(prefix string) string {
	return fmt.Sprintf("conf:%d:%d:%s", time.Now().UnixNano(), confSeq.Add(1), prefix)
}

func (c StateStoreConformance) openN(n int) ([]StateStore, error) {
	out := make([]StateStore, 0, n)
	for i := 0; i < n; i++ {
		s, err := c.Open()
		if err != nil {
			for _, o := range out {
				closeStore(o)
			}
			return nil, fmt.Errorf("Open: %w", err)
		}
		out = append(out, s)
	}
	return out, nil
}

func closeBoth(a, b OperationStore) {
	closeStore(a)
	if b != a {
		closeStore(b)
	}
}

func closeAll(ss []StateStore) {
	for _, s := range ss {
		closeStore(s)
	}
}

// RunStateStoreConformance runs the StateStore checks. Open is required (a missing one is a failed report).
func RunStateStoreConformance(c StateStoreConformance) ConformanceReport {
	rep := ConformanceReport{Name: c.Name}
	if c.Open == nil {
		rep.add("configuration", errors.New("Open is required"), "")
		return rep
	}
	c.defaults()
	rep.add("claim-burst", c.claimBurst(), "")
	rep.add("claim-concurrent", c.claimConcurrent(), fmt.Sprintf("%d rounds x %d copies over %d handle(s)", c.Rounds, c.Copies, c.Handles))
	if c.Durable {
		rep.add("claim-durability", c.claimDurability(), "")
		rep.add("crash-after-claim", c.crashAfterClaim(), "")
	} else {
		rep.skip("claim-durability", "Durable is false (state dies with the process)")
		rep.skip("crash-after-claim", "Durable is false (state dies with the process)")
	}
	rep.add("retry-after-timeout", c.retryAfterTimeout(), "")
	return rep
}

func claim(s StateStore, key string, n int64) (bool, error) {
	r, err := s.Claim(key, n)
	return r.OK && err == nil, err
}

func (c StateStoreConformance) claimBurst() error {
	hs, err := c.openN(1)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	s, key := hs[0], confKey("burst")
	const n = 25
	for i := int64(1); i <= n; i++ {
		if ok, err := claim(s, key, i); err != nil || !ok {
			return fmt.Errorf("counter %d was not admitted on first use (err %v)", i, err)
		}
	}
	for i := int64(n); i >= 1; i-- {
		if ok, err := claim(s, key, i); err != nil {
			return fmt.Errorf("replay of counter %d errored: %v", i, err)
		} else if ok {
			return fmt.Errorf("counter %d was admitted twice (or an older counter was admitted after a newer one)", i)
		}
	}
	if ok, err := claim(s, key, n+1); err != nil || !ok {
		return fmt.Errorf("the next counter after refusals was not admitted (err %v)", err)
	}
	// keys are independent streams
	if ok, err := claim(s, confKey("burst-other"), 1); err != nil || !ok {
		return fmt.Errorf("a fresh key refused counter 1 (err %v)", err)
	}
	return nil
}

func (c StateStoreConformance) claimConcurrent() error {
	hs, err := c.openN(c.Handles)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	key := confKey("concurrent")
	for round := int64(1); round <= int64(c.Rounds); round++ {
		var wins, errs int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < c.Copies; i++ {
			wg.Add(1)
			go func(h StateStore) {
				defer wg.Done()
				<-start
				ok, err := claim(h, key, round)
				if err != nil {
					atomic.AddInt32(&errs, 1)
				} else if ok {
					atomic.AddInt32(&wins, 1)
				}
			}(hs[i%len(hs)])
		}
		close(start)
		wg.Wait()
		if wins != 1 {
			return fmt.Errorf("round %d: %d of %d copies of one counter were admitted (want exactly 1; %d errors)", round, wins, c.Copies, errs)
		}
	}
	// distinct counters racing on one key: the highest is always admitted and nothing is admitted twice
	base := int64(c.Rounds)
	key2 := confKey("concurrent-distinct")
	var wg sync.WaitGroup
	start := make(chan struct{})
	admitted := make([]int32, c.Copies+1)
	for i := 1; i <= c.Copies; i++ {
		wg.Add(1)
		go func(n int64, h StateStore) {
			defer wg.Done()
			<-start
			if ok, _ := claim(h, key2, base+n); ok {
				atomic.StoreInt32(&admitted[n], 1)
			}
		}(int64(i), hs[i%len(hs)])
	}
	close(start)
	wg.Wait()
	if admitted[c.Copies] != 1 {
		return fmt.Errorf("the highest of %d racing counters was not admitted", c.Copies)
	}
	for i := int64(1); i <= int64(c.Copies); i++ {
		if ok, err := claim(hs[0], key2, base+i); ok || err != nil {
			return fmt.Errorf("counter %d is admitted again after the race (err %v)", base+i, err)
		}
	}
	return nil
}

func (c StateStoreConformance) claimDurability() error {
	hs, err := c.openN(1)
	if err != nil {
		return err
	}
	key := confKey("durability")
	for i := int64(1); i <= 3; i++ {
		if ok, err := claim(hs[0], key, i); err != nil || !ok {
			closeAll(hs)
			return fmt.Errorf("counter %d was not admitted (err %v)", i, err)
		}
	}
	closeAll(hs)
	if c.Restart != nil {
		if err := c.Restart(); err != nil {
			return fmt.Errorf("Restart: %w", err)
		}
	}
	return c.afterReopen(key, 3, 4, "closing every handle")
}

func (c StateStoreConformance) afterReopen(key string, used, next int64, what string) error {
	hs, err := c.openN(1)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	if ok, err := claim(hs[0], key, used); err != nil || ok {
		return fmt.Errorf("counter %d was admitted again after %s (err %v)", used, what, err)
	}
	if ok, err := claim(hs[0], key, next); err != nil || !ok {
		return fmt.Errorf("counter %d was not admitted after %s (err %v)", next, what, err)
	}
	return nil
}

func (c StateStoreConformance) crashAfterClaim() error {
	hs, err := c.openN(1)
	if err != nil {
		return err
	}
	// the instance dies after the claim and before its handler ran: its handle is abandoned, never closed
	key := confKey("crash")
	if ok, err := claim(hs[0], key, 1); err != nil || !ok {
		return fmt.Errorf("counter 1 was not admitted (err %v)", err)
	}
	if c.Restart != nil {
		if err := c.Restart(); err != nil {
			return fmt.Errorf("Restart: %w", err)
		}
	}
	err = c.afterReopen(key, 1, 2, "the instance died")
	closeAll(hs)
	return err
}

// lossyStore commits the claim and then loses the answer once.
type lossyStore struct {
	StateStore
	lose atomic.Bool
}

func (l *lossyStore) Claim(key string, counter int64) (ClaimResult, error) {
	r, err := l.StateStore.Claim(key, counter)
	if l.lose.CompareAndSwap(true, false) {
		return ClaimResult{}, errors.New("timeout (answer lost after commit)")
	}
	return r, err
}

func (c StateStoreConformance) retryAfterTimeout() error {
	hs, err := c.openN(2)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	first, other := hs[0], hs[len(hs)-1]
	if !c.Shared {
		other = first
	}
	lossy := &lossyStore{StateStore: first}
	lossy.lose.Store(true)
	key := confKey("retry")
	if ok, err := claim(lossy, key, 1); ok || err == nil {
		return errors.New("the lossy wrapper must lose the first answer")
	}
	if ok, err := claim(other, key, 1); err != nil || ok {
		return fmt.Errorf("the retry of a claim whose answer was lost was admitted (err %v): the commit had already landed", err)
	}
	if ok, err := claim(other, key, 2); err != nil || !ok {
		return fmt.Errorf("the next counter after the retry was not admitted (err %v)", err)
	}
	return nil
}

// OperationStoreConformance configures RunOperationStoreConformance.
type OperationStoreConformance struct {
	Name string
	// Open returns a NEW handle onto the SAME backend each call.
	Open    func() (OperationStore, error)
	Restart func() error
	// Durable: records survive closing every handle (and Restart). Shared: handles share the backend.
	Durable, Shared bool
	// Copies (default 16) concurrent callers per race.
	Copies int
}

func opRecord(id string) OperationRecord {
	return OperationRecord{ID: id, State: OpPending, Verb: "v", Resource: "/r", ParamsDigest: "d", Reversibility: "reversible", StartedAt: 1}
}

// RunOperationStoreConformance runs the OperationStore checks.
func RunOperationStoreConformance(c OperationStoreConformance) ConformanceReport {
	rep := ConformanceReport{Name: c.Name}
	if c.Open == nil {
		rep.add("configuration", errors.New("Open is required"), "")
		return rep
	}
	if c.Copies <= 0 {
		c.Copies = 16
	}
	open2 := func() (OperationStore, OperationStore, error) {
		a, err := c.Open()
		if err != nil {
			return nil, nil, err
		}
		if !c.Shared {
			return a, a, nil
		}
		b, err := c.Open()
		return a, b, err
	}
	rep.add("create-once", func() error {
		a, b, err := open2()
		if err != nil {
			return err
		}
		defer closeBoth(a, b)
		id := confKey("create")
		var created int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < c.Copies; i++ {
			wg.Add(1)
			go func(s OperationStore) {
				defer wg.Done()
				<-start
				ok, existing, err := s.Create(opRecord(id))
				if err == nil && ok {
					atomic.AddInt32(&created, 1)
				} else if err == nil && existing.ID != id {
					atomic.AddInt32(&created, 100)
				}
			}([]OperationStore{a, b}[i%2])
		}
		close(start)
		wg.Wait()
		if created != 1 {
			return fmt.Errorf("%d concurrent creates of one id reported created (want exactly 1; >=100 means a loser got no existing record)", created)
		}
		return nil
	}(), "")
	rep.add("transition-once", func() error {
		a, b, err := open2()
		if err != nil {
			return err
		}
		defer closeBoth(a, b)
		id := confKey("transition")
		if ok, _, err := a.Create(opRecord(id)); err != nil || !ok {
			return fmt.Errorf("create failed (err %v)", err)
		}
		var won int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < c.Copies; i++ {
			wg.Add(1)
			go func(s OperationStore) {
				defer wg.Done()
				<-start
				next := opRecord(id)
				next.State = OpExecuting
				if ok, err := s.Transition(id, OpPending, next); err == nil && ok {
					atomic.AddInt32(&won, 1)
				}
			}([]OperationStore{a, b}[i%2])
		}
		close(start)
		wg.Wait()
		if won != 1 {
			return fmt.Errorf("%d concurrent transitions out of pending won (want exactly 1)", won)
		}
		return nil
	}(), "")
	rep.add("wrong-state", func() error {
		s, err := c.Open()
		if err != nil {
			return err
		}
		defer closeStore(s)
		id := confKey("wrong")
		if ok, _, err := s.Create(opRecord(id)); err != nil || !ok {
			return fmt.Errorf("create failed (err %v)", err)
		}
		next := opRecord(id)
		next.State = OpCommitted
		if ok, err := s.Transition(id, OpExecuting, next); err != nil || ok {
			return fmt.Errorf("a transition from the wrong state applied (err %v)", err)
		}
		if got, err := s.Get(id); err != nil || got == nil || got.State != OpPending {
			return fmt.Errorf("the record changed after a refused transition: %+v (err %v)", got, err)
		}
		if ok, err := s.Transition(confKey("missing"), OpPending, next); err != nil || ok {
			return fmt.Errorf("a transition of an unknown id applied (err %v)", err)
		}
		return nil
	}(), "")
	rep.add("get-missing", func() error {
		s, err := c.Open()
		if err != nil {
			return err
		}
		defer closeStore(s)
		if got, err := s.Get(confKey("never")); err != nil || got != nil {
			return fmt.Errorf("an unknown id returned %+v (err %v)", got, err)
		}
		return nil
	}(), "")
	if c.Shared {
		rep.add("shared", func() error {
			a, b, err := open2()
			if err != nil {
				return err
			}
			defer closeBoth(a, b)
			id := confKey("shared")
			if ok, _, err := a.Create(opRecord(id)); err != nil || !ok {
				return fmt.Errorf("create failed (err %v)", err)
			}
			if got, err := b.Get(id); err != nil || got == nil || got.ID != id {
				return fmt.Errorf("another handle does not see the record: %+v (err %v)", got, err)
			}
			return nil
		}(), "")
	} else {
		rep.skip("shared", "Shared is false")
	}
	if c.Durable {
		rep.add("durability", func() error {
			a, err := c.Open()
			if err != nil {
				return err
			}
			id := confKey("durable")
			if ok, _, err := a.Create(opRecord(id)); err != nil || !ok {
				closeStore(a)
				return fmt.Errorf("create failed (err %v)", err)
			}
			closeStore(a)
			if c.Restart != nil {
				if err := c.Restart(); err != nil {
					return fmt.Errorf("Restart: %w", err)
				}
			}
			b, err := c.Open()
			if err != nil {
				return err
			}
			defer closeStore(b)
			if got, err := b.Get(id); err != nil || got == nil || got.State != OpPending {
				return fmt.Errorf("the record did not survive closing every handle: %+v (err %v)", got, err)
			}
			return nil
		}(), "")
	} else {
		rep.skip("durability", "Durable is false")
	}
	return rep
}
