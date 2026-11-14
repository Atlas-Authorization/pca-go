package pca

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

type goCBudgetStub struct {
	m      map[string]any
	err    error
	panics bool
	keys   []string
}

func (s *goCBudgetStub) Claim(string, int64) (ClaimResult, error) { return ClaimResult{OK: true}, nil }
func (s *goCBudgetStub) Budget(key string) (map[string]any, error) {
	s.keys = append(s.keys, key)
	if s.panics {
		panic("store down")
	}
	return s.m, s.err
}
func (s *goCBudgetStub) ClaimBudgeted(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error) {
	return BudgetClaimed, ClaimResult{OK: true}, nil
}

func goCCalm(sd any) map[string]any {
	m := map[string]any{"reversibility": 1.0, "blastRadius": 0.0, "taint": 0.0, "confidence": 1.0, "age": 0.0}
	if sd != nil {
		m["semanticDistance"] = sd
	}
	return m
}

type goCRiskOut struct {
	w            *budgetWriteT
	marks, fails []string
}

func goCRiskRun(in *AuthorizeInput, ctx *AuthorizeContext, chain []any, grant, p map[string]any, plan []map[string]any, nodeID any) goCRiskOut {
	var o goCRiskOut
	var reasons []string
	rp := RiskPolicy{Weights: RiskWeights{Alpha: 1}, Theta1: 0.3, Theta2: 0.7, Kappa: 1, BMax: 10}
	if p == nil {
		p = map[string]any{}
	}
	o.w = riskStep(in, &Operation{Verb: "v", Resource: "/r"}, grant, p, chain, ctx, rp, 1000, nil, plan, nodeID, nil, map[string]string{},
		func(n, s string) { o.marks = append(o.marks, n+":"+s) }, func(n, w string) { o.fails = append(o.fails, n+":"+w) }, &reasons)
	return o
}

func goCNear(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestGoCParseBudget(t *testing.T) {
	good, ok := parseBudget(map[string]any{"B": 1.0, "tau": 2.0})
	if !ok || good.B != 1 || good.Tau != 2 || good.HasAsOf {
		t.Errorf("plain: %+v %v", good, ok)
	}
	nilAsOf, ok := parseBudget(map[string]any{"B": 1.0, "tau": 2.0, "asOf": nil})
	if !ok || nilAsOf.HasAsOf {
		t.Errorf("null asOf is absent: %+v %v", nilAsOf, ok)
	}
	withAsOf, ok := parseBudget(map[string]any{"B": 1.0, "tau": 2.0, "asOf": 5.0})
	if !ok || !withAsOf.HasAsOf || withAsOf.AsOf != 5 {
		t.Errorf("asOf: %+v %v", withAsOf, ok)
	}
	inf := jn("Infinity")
	for name, m := range map[string]map[string]any{
		"B missing":       {"tau": 2.0},
		"tau missing":     {"B": 1.0},
		"B not a number":  {"B": "x", "tau": 2.0},
		"B infinite":      {"B": inf, "tau": 2.0},
		"tau infinite":    {"B": 1.0, "tau": inf},
		"asOf not number": {"B": 1.0, "tau": 2.0, "asOf": "x"},
		"asOf infinite":   {"B": 1.0, "tau": 2.0, "asOf": inf},
	} {
		if b, ok := parseBudget(m); ok || b != (TrustBudget{}) {
			t.Errorf("%s: %+v %v", name, b, ok)
		}
	}
}

func TestGoCBudgetMap(t *testing.T) {
	if got := budgetMap(TrustBudget{B: 1, Tau: 2, AsOf: 9, HasAsOf: true}); !reflect.DeepEqual(got, map[string]any{"B": 1.0, "tau": 2.0, "asOf": 9.0}) {
		t.Errorf("with asOf: %v", got)
	}
	if got := budgetMap(TrustBudget{B: 1, Tau: 2, AsOf: 9}); !reflect.DeepEqual(got, map[string]any{"B": 1.0, "tau": 2.0, "asOf": 2.0}) {
		t.Errorf("without asOf: %v", got)
	}
}

func TestGoCRiskCallGuards(t *testing.T) {
	op := &Operation{}
	if m, failed := callRisk(func(*Operation, map[string]any, map[string]any) (map[string]any, error) { panic("x") }, op, nil, nil); m != nil || !failed {
		t.Errorf("risk panic: %v %v", m, failed)
	}
	if _, failed := callRisk(func(*Operation, map[string]any, map[string]any) (map[string]any, error) { return nil, errors.New("x") }, op, nil, nil); !failed {
		t.Error("risk error")
	}
	if m, failed := callRisk(func(*Operation, map[string]any, map[string]any) (map[string]any, error) {
		return map[string]any{"a": 1.0}, nil
	}, op, nil, nil); failed || m["a"] != 1.0 {
		t.Errorf("risk ok: %v %v", m, failed)
	}
	if m, failed := callBudgetRead(&goCBudgetStub{panics: true}, "k"); m != nil || !failed {
		t.Errorf("budget panic: %v %v", m, failed)
	}
	if _, failed := callBudgetRead(&goCBudgetStub{err: errors.New("x"), m: map[string]any{"B": 1.0}}, "k"); !failed {
		t.Errorf("budget error: %v", failed)
	}
	if m, failed := callBudgetRead(&goCBudgetStub{m: map[string]any{"B": 1.0}}, "k"); failed || m["B"] != 1.0 {
		t.Errorf("budget ok: %v %v", m, failed)
	}
	if r := callThreshold(func(map[string]any, map[string]any) ThresholdResult { panic("x") }, nil, nil); r != (ThresholdResult{}) {
		t.Errorf("hook panic: %+v", r)
	}
	want := ThresholdResult{OK: true, Enforced: true, T: 2}
	if r := callThreshold(func(map[string]any, map[string]any) ThresholdResult { return want }, nil, nil); r != want {
		t.Errorf("hook result: %+v", r)
	}
}

func TestGoCRiskStepRiskProvider(t *testing.T) {
	// no provider: the context's inputs decide and the spend is stored
	o := goCRiskRun(&AuthorizeInput{}, &AuthorizeContext{Risk: goCCalm(0.1)}, nil, map[string]any{}, nil, nil, nil)
	if o.w == nil || len(o.fails) != 0 || len(o.marks) != 0 || o.w.before != nil || !goCNear(o.w.after["B"].(float64), 9.9) || o.w.after["tau"] != 1000.0 || o.w.after["asOf"] != 1000.0 {
		t.Errorf("baseline: %+v %v %v", o.w, o.marks, o.fails)
	}
	// a provider's members are merged over the context's
	in := &AuthorizeInput{Risk: func(*Operation, map[string]any, map[string]any) (map[string]any, error) {
		return map[string]any{"semanticDistance": 0.2}, nil
	}}
	o = goCRiskRun(in, &AuthorizeContext{Risk: goCCalm(0.9)}, nil, map[string]any{}, nil, nil, nil)
	if o.w == nil || !goCNear(o.w.after["B"].(float64), 9.8) || len(o.fails) != 0 {
		t.Errorf("merged: %+v %v", o.w, o.fails)
	}
	// a failing provider refuses and stores nothing
	for name, f := range map[string]func(*Operation, map[string]any, map[string]any) (map[string]any, error){
		"error": func(*Operation, map[string]any, map[string]any) (map[string]any, error) { return nil, errors.New("x") },
		"panic": func(*Operation, map[string]any, map[string]any) (map[string]any, error) { panic("x") },
	} {
		o = goCRiskRun(&AuthorizeInput{Risk: f}, &AuthorizeContext{Risk: goCCalm(0.1)}, nil, map[string]any{}, nil, nil, nil)
		if o.w != nil || !reflect.DeepEqual(o.fails, []string{"risk:the server risk provider failed (fail closed)"}) {
			t.Errorf("%s: %+v %v", name, o.w, o.fails)
		}
	}
}

func TestGoCRiskStepRequiredInputs(t *testing.T) {
	ctx := func() *AuthorizeContext { return &AuthorizeContext{Risk: goCCalm(0.1)} }
	o := goCRiskRun(&AuthorizeInput{RequireRiskInputs: []string{"semanticDistance", "taint"}}, ctx(), nil, map[string]any{}, nil, nil, nil)
	if !reflect.DeepEqual(o.marks, []string{"risk_inputs:pass"}) || len(o.fails) != 0 {
		t.Errorf("present: %v %v", o.marks, o.fails)
	}
	c := ctx()
	delete(c.Risk, "taint")
	c.Risk["blastRadius"] = jn("Infinity")
	o = goCRiskRun(&AuthorizeInput{RequireRiskInputs: []string{"semanticDistance", "taint", "blastRadius", "nope"}}, c, nil, map[string]any{}, nil, nil, nil)
	if len(o.marks) != 0 || len(o.fails) != 1 || o.fails[0] != "risk_inputs:required risk input(s) not supplied by the server: taint, blastRadius, nope" {
		t.Errorf("missing: %v %v", o.marks, o.fails)
	}
	// none required: no verdict on required inputs at all
	o = goCRiskRun(&AuthorizeInput{}, ctx(), nil, map[string]any{}, nil, nil, nil)
	for _, m := range o.marks {
		if strings.HasPrefix(m, "risk_inputs") {
			t.Errorf("unexpected %s", m)
		}
	}
	// the plan supplies semanticDistance
	c = ctx()
	delete(c.Risk, "semanticDistance")
	plan := []map[string]any{{"id": "a"}, {"id": "b"}}
	o = goCRiskRun(&AuthorizeInput{RequireRiskInputs: []string{"semanticDistance"}}, c, nil, map[string]any{}, nil, plan, "a")
	if !reflect.DeepEqual(o.marks, []string{"risk_inputs:pass"}) {
		t.Errorf("plan supplies it: %v %v", o.marks, o.fails)
	}
	o = goCRiskRun(&AuthorizeInput{RequireRiskInputs: []string{"semanticDistance"}}, c, nil, map[string]any{}, nil, nil, nil)
	if len(o.fails) < 1 || !strings.HasPrefix(o.fails[0], "risk_inputs:") {
		t.Errorf("no plan: %v", o.fails)
	}
}

func TestGoCRiskStepStoredBudget(t *testing.T) {
	chain := []any{map[string]any{"holder": "H"}}
	grant := map[string]any{"id": "G"}
	run := func(stub *goCBudgetStub, chain []any, grant map[string]any) goCRiskOut {
		return goCRiskRun(&AuthorizeInput{StateStore: stub}, &AuthorizeContext{Risk: goCCalm(0.1)}, chain, grant, nil, nil, nil)
	}
	stored := map[string]any{"B": 3.0, "tau": 0.0, "asOf": 0.0}
	stub := &goCBudgetStub{m: stored}
	o := run(stub, chain, grant)
	if !reflect.DeepEqual(stub.keys, []string{"G:H"}) || o.w == nil || !goCNear(o.w.after["B"].(float64), 2.9) || !reflect.DeepEqual(o.w.before, stored) || len(o.fails) != 0 {
		t.Errorf("stored: keys=%v %+v %v", stub.keys, o.w, o.fails)
	}
	// nothing stored: the grant's bMax seeds the budget and nothing was read from the row
	stub = &goCBudgetStub{}
	o = run(stub, chain, grant)
	if o.w == nil || o.w.before != nil || !goCNear(o.w.after["B"].(float64), 9.9) {
		t.Errorf("none stored: %+v", o.w)
	}
	// no leaf holder or no grant id: no stream key, no read
	for name, c := range map[string]struct {
		chain []any
		grant map[string]any
	}{
		"empty chain":     {nil, grant},
		"holder missing":  {[]any{map[string]any{}}, grant},
		"holder not text": {[]any{map[string]any{"holder": 5}}, grant},
		"grant id absent": {chain, map[string]any{}},
		"grant id number": {chain, map[string]any{"id": 5}},
	} {
		stub = &goCBudgetStub{m: stored}
		if o := run(stub, c.chain, c.grant); len(stub.keys) != 0 || o.w == nil {
			t.Errorf("%s: keys=%v", name, stub.keys)
		}
	}
	// a one-element chain is enough
	stub = &goCBudgetStub{m: stored}
	run(stub, chain, grant)
	if len(stub.keys) != 1 {
		t.Errorf("one-element chain: %v", stub.keys)
	}
	// unreadable store
	for name, s := range map[string]*goCBudgetStub{"error": {err: errors.New("x")}, "panic": {panics: true}} {
		o = run(s, chain, grant)
		if o.w != nil || !reflect.DeepEqual(o.fails, []string{"budget:the trust budget could not be read (fail closed)"}) {
			t.Errorf("%s: %+v %v", name, o.w, o.fails)
		}
	}
	// malformed stored budget
	o = run(&goCBudgetStub{m: map[string]any{"B": "x", "tau": 0.0}}, chain, grant)
	if o.w != nil || !reflect.DeepEqual(o.fails, []string{"budget:the stored trust budget is malformed (fail closed)"}) {
		t.Errorf("malformed: %+v %v", o.w, o.fails)
	}
	// a carried budget is used and not stored back
	ctx := &AuthorizeContext{Risk: goCCalm(0.1), Budget: &TrustBudget{B: 0.05, Tau: 1000, AsOf: 1000, HasAsOf: true}}
	stub = &goCBudgetStub{m: stored}
	o = goCRiskRun(&AuthorizeInput{StateStore: stub}, ctx, chain, grant, nil, nil, nil)
	if o.w != nil || len(stub.keys) != 0 {
		t.Errorf("carried: %+v keys=%v", o.w, stub.keys)
	}
}

func TestGoCRiskStepPlanNode(t *testing.T) {
	plan := []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}}
	c := goCCalm(nil)
	o := goCRiskRun(&AuthorizeInput{}, &AuthorizeContext{Risk: c}, nil, map[string]any{}, nil, plan, "b")
	if o.w == nil || !goCNear(o.w.after["B"].(float64), 9.5) {
		t.Errorf("node b is half way to the goal: %+v", o.w)
	}
	o = goCRiskRun(&AuthorizeInput{}, &AuthorizeContext{Risk: c}, nil, map[string]any{}, nil, plan, nil)
	if o.w != nil {
		t.Errorf("no node id: worst-case distance, a human step-up, no debit: %+v", o.w)
	}
	o = goCRiskRun(&AuthorizeInput{}, &AuthorizeContext{Risk: c}, nil, map[string]any{}, nil, plan, 5)
	if o.w != nil {
		t.Errorf("non-text node id: %+v", o.w)
	}
	// a node without an id must not be taken for the node the action is at
	anon := []map[string]any{{"id": "b"}, {"verb": "x"}, {"id": "c"}}
	o = goCRiskRun(&AuthorizeInput{}, &AuthorizeContext{Risk: c}, nil, map[string]any{}, nil, anon, nil)
	if o.w != nil {
		t.Errorf("no node id with an anonymous plan node: %+v", o.w)
	}
}

func TestGoCRiskStepCautionFloor(t *testing.T) {
	o := goCRiskRun(&AuthorizeInput{}, &AuthorizeContext{Risk: goCCalm(0.1)}, nil, map[string]any{}, map[string]any{"caution": 0.5}, nil, nil)
	if o.w == nil || !goCNear(o.w.after["B"].(float64), 9.5) {
		t.Errorf("caution raises the risk to its floor: %+v", o.w)
	}
}

func TestGoCRiskStepThresholdVerdict(t *testing.T) {
	run := func(h ThresholdHook) goCRiskOut {
		return goCRiskRun(&AuthorizeInput{Threshold: h}, &AuthorizeContext{Risk: goCCalm(0.1)}, nil, map[string]any{}, nil, nil, nil)
	}
	o := run(func(map[string]any, map[string]any) ThresholdResult { return ThresholdResult{OK: true} })
	if !reflect.DeepEqual(o.marks, []string{"threshold:pass"}) || len(o.fails) != 0 {
		t.Errorf("accepted: %v %v", o.marks, o.fails)
	}
	o = run(func(map[string]any, map[string]any) ThresholdResult { return ThresholdResult{} })
	if len(o.marks) != 0 || !reflect.DeepEqual(o.fails, []string{"threshold:the threshold proof was rejected"}) {
		t.Errorf("rejected: %v %v", o.marks, o.fails)
	}
	o = run(nil)
	if len(o.marks) != 0 || len(o.fails) != 0 {
		t.Errorf("no hook at t=1: %v %v", o.marks, o.fails)
	}
}
