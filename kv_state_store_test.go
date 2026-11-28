package pca

import "testing"

func TestKvStateStore(t *testing.T) {
	s, err := NewKvStateStore(NewMemoryAtomicKV(), "", ScopeProcess)
	if err != nil {
		t.Fatal(err)
	}
	if s.Scope() != ScopeProcess || !IsAtomicPcaStateStore(s) || IsAtomicPcaStateStore(struct{}{}) {
		t.Fatal("scope / atomic")
	}
	if r, _ := s.Claim("k", 5); !r.OK {
		t.Fatal("first claim")
	}
	if r, _ := s.Claim("k", 5); r.OK || r.LastCounter == nil || *r.LastCounter != 5 {
		t.Fatal("replay of the same counter")
	}
	if r, _ := s.Claim("k", 4); r.OK {
		t.Fatal("a lower counter")
	}
	if r, _ := s.Claim("k", 6); !r.OK {
		t.Fatal("a higher counter")
	}
	if l, _ := s.Last("k"); l == nil || *l != 6 {
		t.Fatal("last")
	}
	if l, _ := s.Last("none"); l != nil {
		t.Fatal("last of nothing")
	}
	// budget compare-and-set moves with the counter
	b1 := map[string]any{"B": jsNumber(10), "tau": jsNumber(1), "asOf": jsNumber(2)}
	if c, r, _ := s.ClaimBudgeted("b", 1, nil, b1); c != BudgetClaimed || !r.OK {
		t.Fatal("budgeted claim")
	}
	if got, _ := s.Budget("b"); got == nil || !budgetEqual(got, true, b1) {
		t.Fatal("stored budget")
	}
	if c, _, _ := s.ClaimBudgeted("b", 2, nil, b1); c != BudgetConflict {
		t.Fatal("a stale before must conflict")
	}
	if l, _ := s.Last("b"); l == nil || *l != 1 {
		t.Fatal("a conflict must not consume the counter")
	}
	if c, _, _ := s.ClaimBudgeted("b", 1, b1, b1); c != BudgetReplay {
		t.Fatal("budgeted replay")
	}
	// pins only rise
	_ = s.RaisePin("p", 3)
	_ = s.RaisePin("p", 2)
	if v, _ := s.Pin("p"); v == nil || *v != 3 {
		t.Fatal("pin")
	}
	// consume once
	if ok, _ := s.ConsumeOnce("u", 100, 50); !ok {
		t.Fatal("first use")
	}
	if ok, _ := s.ConsumeOnce("u", 100, 60); ok {
		t.Fatal("second use while live")
	}
	if ok, _ := s.ConsumeOnce("u", 300, 150); !ok {
		t.Fatal("use after the horizon")
	}
	if _, err := s.ConsumeOnce("", 1, 0); err == nil {
		t.Fatal("empty key")
	}
	if _, err := s.ConsumeOnce("x", 1, 2); err == nil {
		t.Fatal("past horizon")
	}
}
