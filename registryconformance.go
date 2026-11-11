package pca

import (
	"errors"
	"fmt"
	"sync"
)

// Store conformance kits for the registries that keep their state in an AtomicKV (lease, break-glass, blueprint) and for the trust
// budget seam of a state store. Each kit is run by the author of a store (a SQL, Redis or file kv) against it: a failing check names
// the guarantee the store breaks. They use throw-away keys and need no signing key of their own beyond the one the caller passes.

// RegistryKvConformance configures the kv kits. Open returns a NEW handle onto the SAME backend each call (a restart or a second
// instance); a handle that implements io.Closer is closed after use. Sign produces a signed record for the kit: the kit asks for what
// it needs by name, so the caller owns the keys.
type RegistryKvConformance struct {
	Name string
	Open func() (AtomicKV, error)
}

// KvConformance checks the AtomicKV contract itself, the base of every registry: Update is atomic (concurrent increments lose
// none), an Update that returns nil leaves the key unchanged, and a second handle sees what the first wrote.
func (c RegistryKvConformance) KvConformance() ConformanceReport {
	rep := ConformanceReport{Name: c.Name}
	if c.Open == nil {
		rep.add("configuration", errors.New("Open is required"), "")
		return rep
	}
	rep.add("shared-state", func() error {
		a, err := c.Open()
		if err != nil {
			return err
		}
		defer closeStore(a)
		b, err := c.Open()
		if err != nil {
			return err
		}
		defer closeStore(b)
		key := confKey("kv-shared")
		if err := a.Update(key, func([]byte) []byte { return []byte(`1`) }); err != nil {
			return err
		}
		v, ok, err := b.Get(key)
		if err != nil || !ok || string(v) != "1" {
			return fmt.Errorf("a second handle read %q (found %v, err %v), want the first handle's write", v, ok, err)
		}
		return nil
	}(), "")
	rep.add("nil-leaves-the-key", func() error {
		a, err := c.Open()
		if err != nil {
			return err
		}
		defer closeStore(a)
		key := confKey("kv-nil")
		if err := a.Update(key, func([]byte) []byte { return []byte(`7`) }); err != nil {
			return err
		}
		if err := a.Update(key, func([]byte) []byte { return nil }); err != nil {
			return err
		}
		v, _, err := a.Get(key)
		if err != nil || string(v) != "7" {
			return fmt.Errorf("an Update that returned nil changed the key to %q (err %v)", v, err)
		}
		return nil
	}(), "")
	rep.add("atomic-update", func() error {
		const writers, each = 8, 25
		key := confKey("kv-atomic")
		var wg sync.WaitGroup
		var mu sync.Mutex
		var first error
		for i := 0; i < writers; i++ {
			h, err := c.Open()
			if err != nil {
				return err
			}
			wg.Add(1)
			go func(h AtomicKV) {
				defer wg.Done()
				defer closeStore(h)
				for j := 0; j < each; j++ {
					if err := h.Update(key, func(prev []byte) []byte {
						n := 0
						if prev != nil {
							fmt.Sscanf(string(prev), "%d", &n)
						}
						return []byte(fmt.Sprint(n + 1))
					}); err != nil {
						mu.Lock()
						if first == nil {
							first = err
						}
						mu.Unlock()
						return
					}
				}
			}(h)
		}
		wg.Wait()
		if first != nil {
			return first
		}
		a, err := c.Open()
		if err != nil {
			return err
		}
		defer closeStore(a)
		v, _, err := a.Get(key)
		if err != nil || string(v) != fmt.Sprint(writers*each) {
			return fmt.Errorf("%d concurrent increments ended at %q (err %v): an update was lost", writers*each, v, err)
		}
		return nil
	}(), fmt.Sprintf("%d handles x 25 increments", 8))
	return rep
}

// BudgetStoreConformance configures the budget kit: Open returns a NEW handle onto the SAME backend; the handle must implement
// BudgetStore (the kit fails otherwise).
type BudgetStoreConformance struct {
	Name string
	Open func() (StateStore, error)
}

// Run checks BudgetStore: the counter and the budget move together, a replay writes nothing, a budget that changed since it was read is
// a conflict that writes nothing, and concurrent debits of one stream have exactly one winner.
func (c BudgetStoreConformance) Run() ConformanceReport {
	rep := ConformanceReport{Name: c.Name}
	if c.Open == nil {
		rep.add("configuration", errors.New("Open is required"), "")
		return rep
	}
	open := func() (BudgetStore, func(), error) {
		s, err := c.Open()
		if err != nil {
			return nil, nil, err
		}
		bs, ok := s.(BudgetStore)
		if !ok {
			closeStore(s)
			return nil, nil, errors.New("the store does not implement BudgetStore")
		}
		return bs, func() { closeStore(s) }, nil
	}
	budget := func(b float64) map[string]any { return map[string]any{"B": b, "tau": 1000.0, "asOf": 1000.0} }
	val := func(m map[string]any) float64 { f, _ := jsNum(m["B"]); return f }
	rep.add("claim-and-store", func() error {
		s, done, err := open()
		if err != nil {
			return err
		}
		defer done()
		key := confKey("budget-claim")
		if b, err := s.Budget(key); err != nil || b != nil {
			return fmt.Errorf("a fresh stream has a budget %v (err %v)", b, err)
		}
		out, res, err := s.ClaimBudgeted(key, 1, nil, budget(0.5))
		if err != nil || out != BudgetClaimed || !res.OK {
			return fmt.Errorf("first claim: %v %+v err %v", out, res, err)
		}
		b, err := s.Budget(key)
		if err != nil || b == nil || val(b) != 0.5 {
			return fmt.Errorf("stored budget %v (err %v), want B 0.5", b, err)
		}
		return nil
	}(), "")
	rep.add("shared-between-handles", func() error {
		a, doneA, err := open()
		if err != nil {
			return err
		}
		defer doneA()
		b, doneB, err := open()
		if err != nil {
			return err
		}
		defer doneB()
		key := confKey("budget-shared")
		if _, _, err := a.ClaimBudgeted(key, 1, nil, budget(0.9)); err != nil {
			return err
		}
		got, err := b.Budget(key)
		if err != nil || got == nil || val(got) != 0.9 {
			return fmt.Errorf("a second handle read %v (err %v), want B 0.9", got, err)
		}
		return nil
	}(), "")
	rep.add("replay-writes-nothing", func() error {
		s, done, err := open()
		if err != nil {
			return err
		}
		defer done()
		key := confKey("budget-replay")
		if _, _, err := s.ClaimBudgeted(key, 5, nil, budget(0.8)); err != nil {
			return err
		}
		out, res, err := s.ClaimBudgeted(key, 5, budget(0.8), budget(0.1))
		if err != nil || out != BudgetReplay || res.OK {
			return fmt.Errorf("the same counter again: %v %+v err %v, want a replay", out, res, err)
		}
		if b, _ := s.Budget(key); b == nil || val(b) != 0.8 {
			return fmt.Errorf("a replayed claim changed the budget to %v", b)
		}
		return nil
	}(), "")
	rep.add("conflict-writes-nothing", func() error {
		s, done, err := open()
		if err != nil {
			return err
		}
		defer done()
		key := confKey("budget-conflict")
		if _, _, err := s.ClaimBudgeted(key, 1, nil, budget(0.8)); err != nil {
			return err
		}
		out, _, err := s.ClaimBudgeted(key, 2, budget(0.7), budget(0.2)) // read 0.7, but 0.8 is stored
		if err != nil || out != BudgetConflict {
			return fmt.Errorf("a stale read: %v err %v, want a conflict", out, err)
		}
		if b, _ := s.Budget(key); b == nil || val(b) != 0.8 {
			return fmt.Errorf("a conflicting claim changed the budget to %v", b)
		}
		// and the counter was not consumed: counter 2 is still free
		if out, _, err := s.ClaimBudgeted(key, 2, budget(0.8), budget(0.2)); err != nil || out != BudgetClaimed {
			return fmt.Errorf("the counter of a conflicting claim was consumed: %v err %v", out, err)
		}
		return nil
	}(), "")
	rep.add("concurrent-debits-one-winner", func() error {
		const copies = 8
		key := confKey("budget-race")
		s0, done0, err := open()
		if err != nil {
			return err
		}
		defer done0()
		if _, _, err := s0.ClaimBudgeted(key, 1, nil, budget(1)); err != nil {
			return err
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		claimed := 0
		var first error
		for i := 0; i < copies; i++ {
			h, done, err := open()
			if err != nil {
				return err
			}
			wg.Add(1)
			go func(h BudgetStore, done func()) {
				defer wg.Done()
				defer done()
				// every copy read the same budget (1) and tries the same next counter with its own debit
				out, _, err := h.ClaimBudgeted(key, 2, budget(1), budget(0.5))
				mu.Lock()
				defer mu.Unlock()
				if err != nil && first == nil {
					first = err
				}
				if err == nil && out == BudgetClaimed {
					claimed++
				}
			}(h, done)
		}
		wg.Wait()
		if first != nil {
			return first
		}
		if claimed != 1 {
			return fmt.Errorf("%d of %d concurrent debits of one stream were admitted (want exactly 1)", claimed, copies)
		}
		return nil
	}(), "")
	return rep
}
