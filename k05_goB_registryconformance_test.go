package pca

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- an AtomicKV whose every call can be counted, failed or bent ------------------------------------------------------

type goBKvEnv struct {
	mem                  *MemoryAtomicKV
	opens, gets, updates atomic.Int64
	mu                   sync.Mutex
	handles              []*goBKvH
	failOpen             func(n int64) error
	getHook              func(n int64, v []byte, ok bool, err error) ([]byte, bool, error)
	updHook              func(n int64, h *goBKvH) error // non-nil: this update fails without being applied
	lose                 bool                           // Update reports success and applies nothing
	onClose              func(h *goBKvH)
}

type goBKvH struct {
	env    *goBKvEnv
	closes atomic.Int32
}

func goBNewKvEnv() *goBKvEnv { return &goBKvEnv{mem: NewMemoryAtomicKV()} }

func (e *goBKvEnv) open() (AtomicKV, error) {
	n := e.opens.Add(1)
	if e.failOpen != nil {
		if err := e.failOpen(n); err != nil {
			return nil, err
		}
	}
	h := &goBKvH{env: e}
	e.mu.Lock()
	e.handles = append(e.handles, h)
	e.mu.Unlock()
	return h, nil
}

func (h *goBKvH) Get(key string) ([]byte, bool, error) {
	n := h.env.gets.Add(1)
	v, ok, err := h.env.mem.Get(key)
	if h.env.getHook != nil {
		return h.env.getHook(n, v, ok, err)
	}
	return v, ok, err
}

func (h *goBKvH) Update(key string, fn func([]byte) []byte) error {
	n := h.env.updates.Add(1)
	if h.env.updHook != nil {
		if err := h.env.updHook(n, h); err != nil {
			return err
		}
	}
	if h.env.lose {
		return nil
	}
	return h.env.mem.Update(key, fn)
}

func (h *goBKvH) Close() error {
	h.closes.Add(1)
	if h.env.onClose != nil {
		h.env.onClose(h)
	}
	return nil
}

func (e *goBKvEnv) run() ConformanceReport {
	return RegistryKvConformance{Name: "goB kv", Open: e.open}.KvConformance()
}

func goBFails(rep ConformanceReport) []ConformanceCheck {
	var out []ConformanceCheck
	for _, c := range rep.Checks {
		if c.Status == "fail" {
			out = append(out, c)
		}
	}
	return out
}

func goBCheck(rep ConformanceReport, name string) (ConformanceCheck, bool) {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return ConformanceCheck{}, false
}

func TestGoB_KvConformanceCleanRun(t *testing.T) {
	env := goBNewKvEnv()
	rep := env.run()
	want := []ConformanceCheck{{Name: "shared-state", Status: "pass"}, {Name: "nil-leaves-the-key", Status: "pass"},
		{Name: "atomic-update", Status: "pass", Note: "8 handles x 25 increments"}}
	if !reflect.DeepEqual(rep.Checks, want) || rep.Name != "goB kv" {
		t.Fatalf("report: %+v", rep)
	}
	// the kit's footprint: 2+1+(8+1) handles, 3 reads, 1+2+8*25 updates, every handle closed once
	if env.opens.Load() != 12 || env.gets.Load() != 3 || env.updates.Load() != 203 {
		t.Errorf("opens %d gets %d updates %d", env.opens.Load(), env.gets.Load(), env.updates.Load())
	}
	if len(env.handles) != 12 {
		t.Fatalf("handles: %d", len(env.handles))
	}
	for i, h := range env.handles {
		if h.closes.Load() != 1 {
			t.Errorf("handle %d closed %d times", i, h.closes.Load())
		}
	}
	// the real in-memory kv passes its own kit
	shared := NewMemoryAtomicKV()
	if rep := (RegistryKvConformance{Name: "memory", Open: func() (AtomicKV, error) { return shared, nil }}).KvConformance(); !rep.OK() {
		t.Error(rep)
	}
}

func TestGoB_KvConformanceNeedsOpen(t *testing.T) {
	rep := RegistryKvConformance{Name: "none"}.KvConformance()
	want := []ConformanceCheck{{Name: "configuration", Status: "fail", Note: "Open is required"}}
	if !reflect.DeepEqual(rep.Checks, want) || rep.Name != "none" {
		t.Errorf("%+v", rep)
	}
}

func TestGoB_KvConformanceOpenFailures(t *testing.T) {
	for n := int64(1); n <= 12; n++ {
		want := fmt.Sprintf("inject-open-%d", n)
		env := goBNewKvEnv()
		env.failOpen = func(m int64) error {
			if m == n {
				return errors.New(want)
			}
			return nil
		}
		f := goBFails(env.run())
		if len(f) != 1 || f[0].Note != want {
			t.Errorf("open %d: %+v", n, f)
		}
	}
}

func TestGoB_KvConformanceUpdateFailures(t *testing.T) {
	for _, n := range []int64{1, 2, 3, 4, 5, 50, 203} {
		want := fmt.Sprintf("inject-upd-%d", n)
		env := goBNewKvEnv()
		env.updHook = func(m int64, _ *goBKvH) error {
			if m == n {
				return errors.New(want)
			}
			return nil
		}
		f := goBFails(env.run())
		if len(f) != 1 || f[0].Note != want {
			t.Errorf("update %d: %+v", n, f)
		}
	}
}

func TestGoB_KvConformanceFirstUpdateErrorWins(t *testing.T) {
	env := goBNewKvEnv()
	var mu sync.Mutex
	var firstH *goBKvH
	released := make(chan struct{})
	var once sync.Once
	env.updHook = func(n int64, h *goBKvH) error {
		if n < 4 {
			return nil
		}
		err := fmt.Errorf("inject-upd-%d", n)
		if n == 4 {
			mu.Lock()
			firstH = h
			mu.Unlock()
			return err
		}
		// every other writer fails after the first one has reported (its handle is closed once it is done)
		select {
		case <-released:
		case <-time.After(10 * time.Second):
		}
		return err
	}
	env.onClose = func(h *goBKvH) {
		mu.Lock()
		f := firstH
		mu.Unlock()
		if f != nil && h == f {
			once.Do(func() { close(released) })
		}
	}
	f := goBFails(env.run())
	if len(f) != 1 || f[0].Name != "atomic-update" || f[0].Note != "inject-upd-4" {
		t.Errorf("the first writer's error is the one reported: %+v", f)
	}
}

func TestGoB_KvConformanceReadFailures(t *testing.T) {
	cases := []struct {
		name, check, marker string
		n                   int64
		mut                 func(v []byte, ok bool) ([]byte, bool, error)
	}{
		{"shared err only", "shared-state", "inject-get", 1, func(v []byte, ok bool) ([]byte, bool, error) { return v, ok, errors.New("inject-get") }},
		{"shared value only", "shared-state", "", 1, func(v []byte, ok bool) ([]byte, bool, error) { return []byte("2"), ok, nil }},
		{"shared missing only", "shared-state", "", 1, func(v []byte, ok bool) ([]byte, bool, error) { return v, false, nil }},
		{"nil err only", "nil-leaves-the-key", "inject-get", 2, func(v []byte, ok bool) ([]byte, bool, error) { return v, ok, errors.New("inject-get") }},
		{"nil value only", "nil-leaves-the-key", "", 2, func(v []byte, ok bool) ([]byte, bool, error) { return []byte("8"), ok, nil }},
		{"atomic err only", "atomic-update", "inject-get", 3, func(v []byte, ok bool) ([]byte, bool, error) { return v, ok, errors.New("inject-get") }},
		{"atomic value only", "atomic-update", "", 3, func(v []byte, ok bool) ([]byte, bool, error) { return []byte("199"), ok, nil }},
	}
	for _, c := range cases {
		env := goBNewKvEnv()
		env.getHook = func(n int64, v []byte, ok bool, err error) ([]byte, bool, error) {
			if n == c.n {
				return c.mut(v, ok)
			}
			return v, ok, err
		}
		f := goBFails(env.run())
		if len(f) != 1 || f[0].Name != c.check || !strings.Contains(f[0].Note, c.marker) || f[0].Note == "" {
			t.Errorf("%s: %+v", c.name, f)
		}
	}
}

func TestGoB_KvConformanceLostUpdates(t *testing.T) {
	env := goBNewKvEnv()
	env.lose = true
	rep := env.run()
	c, ok := goBCheck(rep, "atomic-update")
	if !ok || c.Status != "fail" || c.Note != `200 concurrent increments ended at "" (err <nil>): an update was lost` {
		t.Errorf("%+v", c)
	}
	if c, _ := goBCheck(rep, "shared-state"); c.Status != "fail" {
		t.Errorf("shared state: %+v", c)
	}
	if c, _ := goBCheck(rep, "nil-leaves-the-key"); c.Status != "fail" {
		t.Errorf("nil leaves the key: %+v", c)
	}
}

// ---- the budget kit ---------------------------------------------------------------------------------------------------

type goBBsEnv struct {
	mem                   *MemoryStateStore
	opens, budgets, claim atomic.Int64
	mu                    sync.Mutex
	handles               []*goBBs
	log                   []string
	failOpen              func(n int64) error
	budgetFn              func(n int64, b map[string]any, err error) (map[string]any, error)
	claimFn               func(n int64, h *goBBs, out BudgetClaim, res ClaimResult, err error) (BudgetClaim, ClaimResult, error)
	onClose               func(h *goBBs)
	plain                 bool // Open returns a store without the budget seam
}

type goBBs struct {
	*MemoryStateStore
	env    *goBBsEnv
	closes atomic.Int32
}

func goBNewBsEnv() *goBBsEnv { return &goBBsEnv{mem: NewMemoryStateStore()} }

func (e *goBBsEnv) open() (StateStore, error) {
	n := e.opens.Add(1)
	if e.failOpen != nil {
		if err := e.failOpen(n); err != nil {
			return nil, err
		}
	}
	if e.plain {
		return unscopedStore{}, nil
	}
	h := &goBBs{MemoryStateStore: e.mem, env: e}
	e.mu.Lock()
	e.handles = append(e.handles, h)
	e.mu.Unlock()
	return h, nil
}

func (h *goBBs) Budget(key string) (map[string]any, error) {
	n := h.env.budgets.Add(1)
	b, err := h.MemoryStateStore.Budget(key)
	if h.env.budgetFn != nil {
		return h.env.budgetFn(n, b, err)
	}
	return b, err
}

func goBFmtBudget(b map[string]any) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprint(b["B"])
}

func (h *goBBs) ClaimBudgeted(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error) {
	n := h.env.claim.Add(1)
	out, res, err := h.MemoryStateStore.ClaimBudgeted(key, counter, before, after)
	h.env.mu.Lock()
	h.env.log = append(h.env.log, fmt.Sprintf("c=%d before=%s after=%s", counter, goBFmtBudget(before), goBFmtBudget(after)))
	h.env.mu.Unlock()
	if h.env.claimFn != nil {
		return h.env.claimFn(n, h, out, res, err)
	}
	return out, res, err
}

func (h *goBBs) Close() error {
	h.closes.Add(1)
	if h.env.onClose != nil {
		h.env.onClose(h)
	}
	return nil
}

func (e *goBBsEnv) run() ConformanceReport {
	return BudgetStoreConformance{Name: "goB budget", Open: e.open}.Run()
}

func TestGoB_BudgetConformanceCleanRun(t *testing.T) {
	env := goBNewBsEnv()
	rep := env.run()
	var names []string
	for _, c := range rep.Checks {
		names = append(names, c.Name)
		if c.Status != "pass" || c.Note != "" {
			t.Errorf("check %s: %+v", c.Name, c)
		}
	}
	if !reflect.DeepEqual(names, []string{"claim-and-store", "shared-between-handles", "replay-writes-nothing", "conflict-writes-nothing", "concurrent-debits-one-winner"}) {
		t.Errorf("checks: %v", names)
	}
	if env.opens.Load() != 14 || env.budgets.Load() != 5 || env.claim.Load() != 16 || len(env.handles) != 14 {
		t.Errorf("opens %d budgets %d claims %d handles %d", env.opens.Load(), env.budgets.Load(), env.claim.Load(), len(env.handles))
	}
	for i, h := range env.handles {
		if h.closes.Load() != 1 {
			t.Errorf("handle %d closed %d times", i, h.closes.Load())
		}
	}
	// every claim, in order: the counter and the budget it read and wants to write
	want := []string{
		"c=1 before=nil after=0.5",
		"c=1 before=nil after=0.9",
		"c=5 before=nil after=0.8",
		"c=5 before=0.8 after=0.1",
		"c=1 before=nil after=0.8",
		"c=2 before=0.7 after=0.2",
		"c=2 before=0.8 after=0.2",
		"c=1 before=nil after=1",
	}
	for i := 0; i < 8; i++ {
		want = append(want, "c=2 before=1 after=0.5")
	}
	if !reflect.DeepEqual(env.log, want) {
		t.Errorf("claims:\n got  %q\n want %q", env.log, want)
	}
	// the real in-memory store passes its own kit
	mem := NewMemoryStateStore()
	if rep := (BudgetStoreConformance{Name: "memory", Open: func() (StateStore, error) { return mem, nil }}).Run(); !rep.OK() {
		t.Error(rep)
	}
}

func TestGoB_BudgetConformanceConfiguration(t *testing.T) {
	rep := BudgetStoreConformance{Name: "none"}.Run()
	want := []ConformanceCheck{{Name: "configuration", Status: "fail", Note: "Open is required"}}
	if !reflect.DeepEqual(rep.Checks, want) || rep.Name != "none" {
		t.Errorf("%+v", rep)
	}
	env := goBNewBsEnv()
	env.plain = true
	rep = env.run()
	if len(rep.Checks) != 5 {
		t.Fatalf("%+v", rep)
	}
	for _, c := range rep.Checks {
		if c.Status != "fail" || c.Note != "the store does not implement BudgetStore" {
			t.Errorf("%+v", c)
		}
	}
}

func TestGoB_BudgetConformanceOpenFailures(t *testing.T) {
	for n := int64(1); n <= 14; n++ {
		want := fmt.Sprintf("inject-open-%d", n)
		env := goBNewBsEnv()
		env.failOpen = func(m int64) error {
			if m == n {
				return errors.New(want)
			}
			return nil
		}
		f := goBFails(env.run())
		if len(f) != 1 || f[0].Note != want {
			t.Errorf("open %d: %+v", n, f)
		}
	}
}

func TestGoB_BudgetConformanceClaimFailures(t *testing.T) {
	// an error from the n-th claim (the claim itself applied): the check that made it fails and names the error
	for n := int64(1); n <= 8; n++ {
		marker := fmt.Sprintf("inject-claim-%d", n)
		env := goBNewBsEnv()
		env.claimFn = func(m int64, _ *goBBs, out BudgetClaim, res ClaimResult, err error) (BudgetClaim, ClaimResult, error) {
			if m == n {
				return out, res, errors.New(marker)
			}
			return out, res, err
		}
		f := goBFails(env.run())
		if len(f) != 1 || !strings.Contains(f[0].Note, marker) {
			t.Errorf("claim %d: %+v", n, f)
		}
	}
	// a wrong outcome, one operand at a time
	claimed, replay, conflict := BudgetClaimed, BudgetReplay, BudgetConflict
	cases := []struct {
		name  string
		n     int64
		check string
		out   *BudgetClaim
		ok    *bool
	}{
		{"first claim: wrong outcome", 1, "claim-and-store", &conflict, nil},
		{"first claim: not ok", 1, "claim-and-store", nil, goBBool(false)},
		{"replay: claimed again", 4, "replay-writes-nothing", &claimed, nil},
		{"replay: conflict", 4, "replay-writes-nothing", &conflict, nil},
		{"replay: ok", 4, "replay-writes-nothing", nil, goBBool(true)},
		{"stale read: claimed", 6, "conflict-writes-nothing", &claimed, nil},
		{"stale read: replay", 6, "conflict-writes-nothing", &replay, nil},
		{"freed counter: conflict", 7, "conflict-writes-nothing", &conflict, nil},
	}
	for _, c := range cases {
		env := goBNewBsEnv()
		env.claimFn = func(m int64, _ *goBBs, out BudgetClaim, res ClaimResult, err error) (BudgetClaim, ClaimResult, error) {
			if m == c.n {
				if c.out != nil {
					out = *c.out
				}
				if c.ok != nil {
					res.OK = *c.ok
				}
			}
			return out, res, err
		}
		f := goBFails(env.run())
		if len(f) != 1 || f[0].Name != c.check || f[0].Note == "" {
			t.Errorf("%s: %+v", c.name, f)
		}
	}
}

func goBBool(b bool) *bool { return &b }

func TestGoB_BudgetConformanceReadFailures(t *testing.T) {
	nilB := func(map[string]any) map[string]any { return nil }
	val := func(v float64) func(map[string]any) map[string]any {
		return func(map[string]any) map[string]any { return map[string]any{"B": v, "tau": 1000.0, "asOf": 1000.0} }
	}
	cases := []struct {
		name  string
		n     int64
		check string
		mut   func(b map[string]any, err error) (map[string]any, error)
	}{
		{"fresh: error", 1, "claim-and-store", func(b map[string]any, _ error) (map[string]any, error) { return b, errors.New("inject-read") }},
		{"fresh: a budget", 1, "claim-and-store", func(map[string]any, error) (map[string]any, error) { return val(1)(nil), nil }},
		{"stored: error", 2, "claim-and-store", func(b map[string]any, _ error) (map[string]any, error) { return b, errors.New("inject-read") }},
		{"stored: wrong value", 2, "claim-and-store", func(map[string]any, error) (map[string]any, error) { return val(0.4)(nil), nil }},
		{"stored: none", 2, "claim-and-store", func(map[string]any, error) (map[string]any, error) { return nilB(nil), nil }},
		{"shared: error", 3, "shared-between-handles", func(b map[string]any, _ error) (map[string]any, error) { return b, errors.New("inject-read") }},
		{"shared: wrong value", 3, "shared-between-handles", func(map[string]any, error) (map[string]any, error) { return val(0.4)(nil), nil }},
		{"shared: none", 3, "shared-between-handles", func(map[string]any, error) (map[string]any, error) { return nilB(nil), nil }},
		{"replay: wrong value", 4, "replay-writes-nothing", func(map[string]any, error) (map[string]any, error) { return val(0.1)(nil), nil }},
		{"replay: none", 4, "replay-writes-nothing", func(map[string]any, error) (map[string]any, error) { return nilB(nil), nil }},
		{"conflict: wrong value", 5, "conflict-writes-nothing", func(map[string]any, error) (map[string]any, error) { return val(0.2)(nil), nil }},
		{"conflict: none", 5, "conflict-writes-nothing", func(map[string]any, error) (map[string]any, error) { return nilB(nil), nil }},
	}
	for _, c := range cases {
		env := goBNewBsEnv()
		env.budgetFn = func(n int64, b map[string]any, err error) (map[string]any, error) {
			if n == c.n {
				return c.mut(b, err)
			}
			return b, err
		}
		f := goBFails(env.run())
		if len(f) != 1 || f[0].Name != c.check || f[0].Note == "" {
			t.Errorf("%s: %+v", c.name, f)
		}
	}
}

func TestGoB_BudgetConformanceRace(t *testing.T) {
	// a store that admits every debit: all 8 copies are counted
	env := goBNewBsEnv()
	env.claimFn = func(n int64, _ *goBBs, out BudgetClaim, res ClaimResult, err error) (BudgetClaim, ClaimResult, error) {
		if n >= 9 {
			return BudgetClaimed, ClaimResult{OK: true}, nil
		}
		return out, res, err
	}
	c, ok := goBCheck(env.run(), "concurrent-debits-one-winner")
	if !ok || c.Status != "fail" || c.Note != "8 of 8 concurrent debits of one stream were admitted (want exactly 1)" {
		t.Errorf("%+v", c)
	}
	// the first error is the one reported, whatever the others say
	env = goBNewBsEnv()
	var mu sync.Mutex
	var firstH *goBBs
	released := make(chan struct{})
	var once sync.Once
	env.claimFn = func(n int64, h *goBBs, out BudgetClaim, res ClaimResult, err error) (BudgetClaim, ClaimResult, error) {
		if n < 9 {
			return out, res, err
		}
		e := fmt.Errorf("inject-claim-%d", n)
		if n == 9 {
			mu.Lock()
			firstH = h
			mu.Unlock()
			return out, res, e
		}
		select {
		case <-released:
		case <-time.After(10 * time.Second):
		}
		return out, res, e
	}
	env.onClose = func(h *goBBs) {
		mu.Lock()
		f := firstH
		mu.Unlock()
		if f != nil && h == f {
			once.Do(func() { close(released) })
		}
	}
	c, ok = goBCheck(env.run(), "concurrent-debits-one-winner")
	if !ok || c.Status != "fail" || c.Note != "inject-claim-9" {
		t.Errorf("first error: %+v", c)
	}
}
