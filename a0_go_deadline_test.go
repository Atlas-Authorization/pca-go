package pca

// Calls whose broken variants spin, hang, run away in memory or panic. Each runs on a goroutine with a recover and a short
// deadline, so a broken variant becomes an ordinary FAIL instead of ending the test binary; the unbroken code finishes in
// microseconds. These sort first (a0_) so the failure is reported before any other test is reached.

import (
	"errors"
	"math"
	"testing"
	"time"
)

func goDlRun(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case p := <-done:
		if p != nil {
			t.Fatalf("%s panicked: %v", what, p)
		}
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

// prohibitions.go: the overflow merge of a full ledger drops the two oldest entries for one merged entry.
func TestGoDlAdvanceLedgerMergeTerminates(t *testing.T) {
	capC := `{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":99999999}`
	st := goAStateJ("20000", "0", "null", goABigLedger(10000, func(i int) string { return "1" }), "{}")
	var r map[string]any
	goDlRun(t, "AdvanceStateStrict", 2*time.Second, func() { r = AdvanceStateStrict(goAAct("pay", `"n":7`), goAC(capC), st) })
	if r["ok"] != true {
		t.Fatalf("advance refused: %v", r)
	}
	if n := len(r["state"].(map[string]any)["ledger"].(map[string]any)["c"].([]any)); n != 10000 {
		t.Errorf("ledger length %d", n)
	}
}

// taint.go: the allowed-rank scan runs rank 0 .. 4.
func TestGoDlTaintRankScanTerminates(t *testing.T) {
	reg := MapTrustedInputRegistry{"o": "tool"}
	var why string
	goDlRun(t, "taintGateReason", 2*time.Second, func() {
		g := TaintGate{Registry: reg, MaxTaint: 0.5}
		why = taintGateReason(&g, map[string]any{"trusted_refs": []any{"o"}})
	})
	if why != "" {
		t.Errorf("tool within 0.5: %q", why)
	}
}

// risk.go: the breadth-first search over the undirected plan graph visits each node once.
func TestGoDlPlanGeodesicTerminates(t *testing.T) {
	plan := []map[string]any{{"id": "a", "post": []any{"b"}}, {"id": "b", "post": "c"}, {"id": "c"}, {"id": "d"}}
	var got float64
	goDlRun(t, "PlanGeodesic", 500*time.Millisecond, func() { got = PlanGeodesic(plan, "a", "c") })
	if math.Abs(got-2.0/3) > 1e-9 {
		t.Errorf("a to c over two hops: %v", got)
	}
}

// lease.go: a prefix revocation covers every shard exactly once.
func TestGoDlLeasePrefixRevokeTerminates(t *testing.T) {
	k := newKey(t)
	reg := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}}, goCNewKV())
	if r := reg.Accept(g04SignLease(t, k, g04Lease()), nil); !r.Ok {
		t.Fatal(r)
	}
	rev := g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "prefix", "value": "db", "revoked_at": jnum(600)})
	var code string
	var n int
	goDlRun(t, "Revoke", 500*time.Millisecond, func() { code, n = reg.Revoke(rev) })
	if code != "" || n != 1 {
		t.Errorf("prefix revoke: %q %d", code, n)
	}
}

// attest_nvidia_rim.go: with the default coverage policy the chain check reads no requireFor entry and stays inside the chain.
func TestGoDlChainRevocationDefaultPolicyNoPanic(t *testing.T) {
	r := r11NewRig(t, true, true)
	rootCrl, icaCrl := r.crl(t, r.root, r.rootK), r.crl(t, r.ica, r.icaK)
	var got, missing string
	goDlRun(t, "checkNvidiaChainRevocation", 2*time.Second, func() {
		got = checkNvidiaChainRevocation(r.chain, [][]byte{icaCrl, rootCrl}, g12Now, nil)
		missing = checkNvidiaChainRevocation(r.chain, [][]byte{rootCrl}, g12Now, nil)
	})
	if got != "" {
		t.Errorf("both CRLs: %q", got)
	}
	if want := "no verified CRL from the issuer of chain certificate '" + subjectLine(r.chain[0]) + "'"; missing != want {
		t.Errorf("root CRL only: %q", missing)
	}
}

// budgetstore.go: the store's lock is released on every return.
func TestGoDlMemoryBudgetStoreUnlocks(t *testing.T) {
	s := NewMemoryStateStore()
	bud := map[string]any{"B": 1.0, "tau": 1000.0, "asOf": 1000.0}
	goDlRun(t, "MemoryStateStore budget calls", time.Second, func() {
		for i := int64(1); i <= 3; i++ {
			if _, err := s.Budget("k"); err != nil {
				panic(err)
			}
			if _, _, err := s.ClaimBudgeted("k", i, nil, bud); err != nil {
				panic(err)
			}
		}
	})
}

// registryconformance.go: the kits finish, with healthy stores and with a store whose every update fails.
func TestGoDlKvConformanceTerminates(t *testing.T) {
	var rep ConformanceReport
	goDlRun(t, "KvConformance", time.Second, func() { rep = goBNewKvEnv().run() })
	if !rep.OK() {
		t.Errorf("a healthy store must pass: %+v", rep)
	}
}

func TestGoDlKvConformanceFailingUpdatesTerminate(t *testing.T) {
	e := goBNewKvEnv()
	e.updHook = func(int64, *goBKvH) error { return errors.New("update failed") }
	var rep ConformanceReport
	goDlRun(t, "KvConformance with failing updates", time.Second, func() { rep = e.run() })
	if rep.OK() {
		t.Error("a store whose every update fails must not pass")
	}
}

func TestGoDlBudgetConformanceTerminates(t *testing.T) {
	mem := NewMemoryStateStore()
	var rep ConformanceReport
	goDlRun(t, "BudgetStoreConformance", time.Second, func() {
		rep = BudgetStoreConformance{Name: "memory", Open: func() (StateStore, error) { return mem, nil }}.Run()
	})
	if !rep.OK() {
		t.Errorf("the memory store must pass: %+v", rep)
	}
}
