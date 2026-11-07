package pca

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// g09 mutation kills for workflow.go: exact admission results (At, Pending), validator boundaries and every
// single-term failure of the shape checks.

func g09wAnys(l ...string) []any {
	out := []any{}
	for _, s := range l {
		out = append(out, s)
	}
	return out
}

func g09wSeq(prefix string, n int) []any {
	out := []any{}
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s%02d", prefix, i))
	}
	return out
}

func g09wStep(id string, deps ...string) map[string]any {
	return map[string]any{"id": id, "verb": "v." + id, "resource": "r/" + id, "params_digest": nil, "deps": g09wAnys(deps...), "sink": nil,
		"deny_labels": []any{}, "escalate_labels": []any{}, "fresh_ms": nil, "cost": map[string]any{}}
}

func g09wEdge(from, field, to, param, op string, promise any) map[string]any {
	return map[string]any{"from": map[string]any{"step": from, "field": field}, "to": map[string]any{"step": to, "param": param}, "op": op,
		"unit": nil, "deny_labels": []any{}, "promise": promise}
}

func g09wBody(principal string, steps []any, edges []any) map[string]any {
	return map[string]any{"v": jnum(1), "id": "wf1", "principal": principal, "goal_digest": nil, "plan_root": nil, "issued_at": jnum(1000),
		"expires_at": jnum(2000), "steps": steps, "edges": edges, "budget": map[string]any{"max_steps": jnum(10), "caps": map[string]any{}}}
}

func g09wSign(t *testing.T, pr fxKey, body map[string]any) map[string]any {
	t.Helper()
	return map[string]any{"body": body, "sig": signDomain(t, pr, k5WorkflowDomain, body)}
}

func g09wRef(r map[string]any) string { ref, _ := WorkflowReceiptRef(r); return ref }

func g09wOut(num any, labels ...string) map[string]any {
	return map[string]any{"digest": dg("out"), "num": num, "unit": nil, "labels": g09wAnys(labels...)}
}

// g09wRcpt signs a step receipt; prev is nil or the cited ref.
func g09wRcpt(t *testing.T, rs fxKey, body map[string]any, step string, seq int64, prev any, params map[string]any, outputs map[string]any, iat int64, outcome string) map[string]any {
	t.Helper()
	wd, _ := WorkflowDigest(body)
	pd, err := HashCanonical(params)
	if err != nil {
		t.Fatal(err)
	}
	r := map[string]any{"v": jnum(1), "wf": wd, "step": step, "seq": jnum(seq), "prev": prev, "outcome": outcome, "params_digest": pd,
		"outputs": outputs, "issued_at": jnum(iat), "signer": rs.id}
	r["sig"] = signDomain(t, rs, k5WfReceiptDomain, r)
	return r
}

func g09wReq(step string, params map[string]any) map[string]any {
	return map[string]any{"step": step, "verb": "v." + step, "resource": "r/" + step, "params": params, "units": map[string]any{}, "goal_digest": nil, "plan_root": nil}
}

func g09wIs(t *testing.T, name string, r WfResult, dec, code, step string, at int, pending ...int) {
	t.Helper()
	if pending == nil {
		pending = []int{}
	}
	if r.Decision != dec || r.Code != code || r.Step != step || r.At != at || r.Pending == nil || !reflect.DeepEqual(r.Pending, pending) {
		t.Errorf("%s: got %+v (pending nil=%v), want %s/%s/%s/%d/%v", name, r, r.Pending == nil, dec, code, step, at, pending)
	}
}

// The conformance vectors, with At compared exactly (the shared mapper folds every negative At to null).
func TestG09WorkflowVectorsExactAt(t *testing.T) {
	W := load(t, "workflow-vectors.json")
	for _, k := range []string{"admit", "bind"} {
		f := AdmitStep
		if k == "bind" {
			f = BindPromises
		}
		for _, x := range W[k].([]any) {
			c := x.(map[string]any)
			exp := c["expect"].(map[string]any)
			want := -1
			if exp["at"] != nil {
				want = int(num(exp["at"]))
			}
			r := f(k5Admit(W, c))
			if r.At != want || r.Pending == nil {
				t.Errorf("%s/%v: at %d (pending nil=%v), want %d", k, c["name"], r.At, r.Pending == nil, want)
			}
		}
	}
}

func TestG09WorkflowAdmitPaths(t *testing.T) {
	pr, rs, other := newKey(t), newKey(t), newKey(t)
	in := func(sw map[string]any, receipts []any, now int64, req map[string]any) AdmitInput {
		return AdmitInput{Workflow: sw, Principal: pr.id, RsSigner: rs.id, Receipts: receipts, Now: now, Request: req}
	}
	empty := map[string]any{}
	one := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	swOne := g09wSign(t, pr, one)

	g09wIs(t, "allow", AdmitStep(in(swOne, []any{}, 1500, g09wReq("a", empty))), "allow", "", "a", -1)
	g09wIs(t, "allow at issued_at", AdmitStep(in(swOne, []any{}, 1000, g09wReq("a", empty))), "allow", "", "a", -1)
	g09wIs(t, "not_yet", AdmitStep(in(swOne, []any{}, 999, g09wReq("a", empty))), "deny", "not_yet", "a", -1)
	g09wIs(t, "expired", AdmitStep(in(swOne, []any{}, 2000, g09wReq("a", empty))), "deny", "expired", "a", -1)
	g09wIs(t, "unplanned", AdmitStep(in(swOne, []any{}, 1500, g09wReq("zz", empty))), "deny", "unplanned_step", "zz", -1)
	rq := g09wReq("a", empty)
	rq["verb"] = "v.other"
	g09wIs(t, "step_mismatch", AdmitStep(in(swOne, []any{}, 1500, rq)), "deny", "step_mismatch", "a", -1)
	rq = g09wReq("a", empty)
	rq["goal_digest"] = dg("goal")
	g09wIs(t, "goal_mismatch", AdmitStep(in(swOne, []any{}, 1500, rq)), "deny", "goal_mismatch", "a", -1)
	rq = g09wReq("a", empty)
	rq["plan_root"] = dg("root")
	g09wIs(t, "plan_root_mismatch", AdmitStep(in(swOne, []any{}, 1500, rq)), "deny", "plan_root_mismatch", "a", -1)
	g09wIs(t, "bad_signature", AdmitStep(AdmitInput{Workflow: swOne, Principal: other.id, RsSigner: rs.id, Receipts: []any{}, Now: 1500, Request: g09wReq("a", empty)}),
		"deny", "bad_signature", "a", -1)
	g09wIs(t, "bind without receipt", BindPromises(in(swOne, []any{}, 1500, g09wReq("a", empty))), "deny", "params_mismatch", "a", -1)
	// a lone surrogate passes the scalar check but has no canonical form: k5Hash panics, the total wrapper denies
	g09wIs(t, "panic", AdmitStep(in(swOne, []any{}, 1500, g09wReq("a", map[string]any{"x": "\xed\xa0\x80"}))), "deny", "bad_workflow", "", -1)

	dup := g09wSign(t, pr, g09wBody(pr.id, []any{g09wStep("a"), g09wStep("a")}, []any{}))
	g09wIs(t, "bad_dag", AdmitStep(in(dup, []any{}, 1500, g09wReq("a", empty))), "deny", "bad_dag", "a", -1)

	pdBody := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	pd, _ := HashCanonical(map[string]any{"x": jnum(1)})
	pdBody["steps"].([]any)[0].(map[string]any)["params_digest"] = pd
	g09wIs(t, "params_mismatch", AdmitStep(in(g09wSign(t, pr, pdBody), []any{}, 1500, g09wReq("a", map[string]any{"x": jnum(2)}))), "deny", "params_mismatch", "a", -1)

	ra := g09wRcpt(t, rs, one, "a", 0, nil, empty, empty, 1100, "ok")
	g09wIs(t, "already_done", AdmitStep(in(swOne, []any{ra}, 1500, g09wReq("a", empty))), "deny", "already_done", "a", -1)

	zero := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	zero["budget"].(map[string]any)["max_steps"] = jnum(0)
	g09wIs(t, "max_steps", AdmitStep(in(g09wSign(t, pr, zero), []any{}, 1500, g09wReq("a", empty))), "deny", "budget_exceeded", "a", -1)

	// caps: 2 already spent + 2 for this step > 3 (spent += on the receipts, not -=)
	cb := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{})
	cb["steps"].([]any)[0].(map[string]any)["cost"] = map[string]any{"c": jnum(2)}
	cb["steps"].([]any)[1].(map[string]any)["cost"] = map[string]any{"c": jnum(2)}
	cb["budget"].(map[string]any)["caps"] = map[string]any{"c": jnum(3)}
	rca := g09wRcpt(t, rs, cb, "a", 0, nil, empty, empty, 1100, "ok")
	g09wIs(t, "caps", AdmitStep(in(g09wSign(t, pr, cb), []any{rca}, 1500, g09wReq("b", empty))), "deny", "budget_exceeded", "b", -1)

	ab := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{})
	swAB := g09wSign(t, pr, ab)
	g09wIs(t, "deps_unmet", AdmitStep(in(swAB, []any{}, 1500, g09wReq("b", empty))), "deny", "deps_unmet", "b", -1)
	rf := g09wRcpt(t, rs, ab, "a", 0, nil, empty, empty, 1100, "failed")
	g09wIs(t, "dep_failed", AdmitStep(in(swAB, []any{rf}, 1500, g09wReq("b", empty))), "deny", "dep_failed", "b", -1)
	// a receipt issued exactly at now is not in the future
	rnow := g09wRcpt(t, rs, ab, "a", 0, nil, empty, empty, 1500, "ok")
	g09wIs(t, "receipt at now", AdmitStep(in(swAB, []any{rnow}, 1500, g09wReq("b", empty))), "allow", "", "b", -1)
	// receipt for b before a, with no edge a->b at all (n == 0)
	rb0 := g09wRcpt(t, rs, ab, "b", 0, nil, empty, empty, 1100, "ok")
	g09wIs(t, "precede no edge", AdmitStep(in(swAB, []any{rb0}, 1500, g09wReq("a", empty))), "deny", "bad_receipt", "a", 0)
	if got := k5ReceiptError(ab, rs.id, []any{rnow}, 1500); got != -1 {
		t.Errorf("k5ReceiptError sound chain = %d, want -1", got)
	}
	if got := k5ReceiptError(ab, rs.id, []any{rb0}, 1500); got != 0 {
		t.Errorf("k5ReceiptError precede = %d, want 0", got)
	}
	// wrong prev on the second receipt
	ra2 := g09wRcpt(t, rs, ab, "a", 0, nil, empty, empty, 1100, "ok")
	rbBad := g09wRcpt(t, rs, ab, "b", 1, dg("not-the-ref"), empty, empty, 1100, "ok")
	g09wIs(t, "wrong prev", AdmitStep(in(swAB, []any{ra2, rbBad}, 1500, g09wReq("b", empty))), "deny", "bad_receipt", "b", 1)
	rbGood := g09wRcpt(t, rs, ab, "b", 1, g09wRef(ra2), empty, empty, 1100, "ok")
	g09wIs(t, "right prev", AdmitStep(in(swAB, []any{ra2, rbGood}, 1500, g09wReq("b", empty))), "deny", "already_done", "b", -1)

	stale := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{})
	stale["steps"].([]any)[1].(map[string]any)["fresh_ms"] = jnum(10)
	rs1 := g09wRcpt(t, rs, stale, "a", 0, nil, empty, empty, 1100, "ok")
	g09wIs(t, "stale_dep", AdmitStep(in(g09wSign(t, pr, stale), []any{rs1}, 1500, g09wReq("b", empty))), "deny", "stale_dep", "b", -1)

	taint := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{})
	taint["steps"].([]any)[1].(map[string]any)["deny_labels"] = g09wAnys("secret")
	rt := g09wRcpt(t, rs, taint, "a", 0, nil, empty, map[string]any{"o": g09wOut(nil, "secret")}, 1100, "ok")
	g09wIs(t, "taint_flow", AdmitStep(in(g09wSign(t, pr, taint), []any{rt}, 1500, g09wReq("b", empty))), "deny", "taint_flow", "b", -1)

	esc := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{})
	esc["steps"].([]any)[1].(map[string]any)["escalate_labels"] = g09wAnys("pii")
	re := g09wRcpt(t, rs, esc, "a", 0, nil, empty, map[string]any{"o": g09wOut(nil, "pii")}, 1100, "ok")
	g09wIs(t, "taint_escalate", AdmitStep(in(g09wSign(t, pr, esc), []any{re}, 1500, g09wReq("b", empty))), "escalate", "taint_escalate", "b", -1)

	// a missing dependency with a non-promise edge: escalate; with a promise edge: allow with the edge pending
	unc := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{g09wEdge("a", "o", "b", "p", "eq", nil)})
	g09wIs(t, "unconstrained", AdmitStep(in(g09wSign(t, pr, unc), []any{}, 1500, g09wReq("b", map[string]any{"p": jnum(1)}))), "escalate", "pipeline_unconstrained", "b", -1)
	pro := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{g09wEdge("a", "o", "b", "p", "eq", "pr")})
	g09wIs(t, "promised", AdmitStep(in(g09wSign(t, pr, pro), []any{}, 1500, g09wReq("b", map[string]any{"p": jnum(1)}))), "allow", "", "b", -1, 0)
	// receipt for b before a over a non-promise edge
	rbu := g09wRcpt(t, rs, unc, "b", 0, nil, map[string]any{"p": jnum(1)}, empty, 1100, "ok")
	g09wIs(t, "precede non-promise", AdmitStep(in(g09wSign(t, pr, unc), []any{rbu}, 1500, g09wReq("a", empty))), "deny", "bad_receipt", "a", 0)

	// bind: c's edge from grandparent a is still pending (b ran on a promise), so binding c is deps_unmet
	abc := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a"), g09wStep("c", "b")},
		[]any{g09wEdge("a", "o", "b", "p", "eq", "p1"), g09wEdge("a", "o", "c", "q", "eq", nil)})
	qp := map[string]any{"q": jnum(1)}
	rb := g09wRcpt(t, rs, abc, "b", 0, nil, map[string]any{"p": jnum(1)}, empty, 1100, "ok")
	rc := g09wRcpt(t, rs, abc, "c", 1, g09wRef(rb), qp, empty, 1100, "ok")
	g09wIs(t, "bind pending", BindPromises(in(g09wSign(t, pr, abc), []any{rb, rc}, 1500, g09wReq("c", qp))), "deny", "deps_unmet", "c", -1)

	// relational edges at equality: ge holds, lt and gt do not
	for _, c := range []struct {
		op   string
		dec  string
		code string
		at   int
	}{{"ge", "allow", "", -1}, {"le", "allow", "", -1}, {"lt", "deny", "edge_relation", 0}, {"gt", "deny", "edge_relation", 0}} {
		body := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{g09wEdge("a", "o", "b", "p", c.op, nil)})
		r := g09wRcpt(t, rs, body, "a", 0, nil, empty, map[string]any{"o": g09wOut(jnum(5))}, 1100, "ok")
		g09wIs(t, "op "+c.op, AdmitStep(in(g09wSign(t, pr, body), []any{r}, 1500, g09wReq("b", map[string]any{"p": jnum(5)}))), c.dec, c.code, "b", c.at)
	}
}

// Each term of the entry guard alone denies bad_workflow.
func TestG09WorkflowEntryGuard(t *testing.T) {
	pr, rs := newKey(t), newKey(t)
	empty := map[string]any{}
	body := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	sw := g09wSign(t, pr, body)
	base := func() AdmitInput {
		return AdmitInput{Workflow: sw, Principal: pr.id, RsSigner: rs.id, Receipts: []any{}, Now: 1500, Request: g09wReq("a", empty)}
	}
	g09wIs(t, "base", AdmitStep(base()), "allow", "", "a", -1)
	bad := func(name string, mut func(*AdmitInput)) {
		in := base()
		mut(&in)
		g09wIs(t, name, AdmitStep(in), "deny", "bad_workflow", "", -1)
	}
	bad("workflow not an object", func(in *AdmitInput) { in.Workflow = "x" })
	bad("missing sig member", func(in *AdmitInput) { in.Workflow = map[string]any{"body": body} })
	bad("extra member", func(in *AdmitInput) { in.Workflow = map[string]any{"body": body, "sig": sw["sig"], "x": true} })
	extra := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	extra["x"] = true
	bad("signed body with an extra member", func(in *AdmitInput) { in.Workflow = g09wSign(t, pr, extra) })
	bad("request extra member", func(in *AdmitInput) { q := g09wReq("a", empty); q["x"] = true; in.Request = q })
	bad("receipts not an array", func(in *AdmitInput) { in.Receipts = nil })
	bad("principal not b32", func(in *AdmitInput) { in.Principal = "x" })
	bad("rs not b32", func(in *AdmitInput) { in.RsSigner = "x" })
	bad("negative now", func(in *AdmitInput) { in.Now = -1 })
	// now == 0 is a valid clock
	z := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	z["issued_at"] = jnum(0)
	in := base()
	in.Workflow = g09wSign(t, pr, z)
	in.Now = 0
	g09wIs(t, "now zero", AdmitStep(in), "allow", "", "a", -1)
}

func TestG09WorkflowPlanRoot(t *testing.T) {
	pr := newKey(t)
	root := dg("root")
	body := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	body["plan_root"] = root
	sw := g09wSign(t, pr, body)
	if !PlanRootAuthorized(sw, pr.id, 1000, root) {
		t.Error("plan root at issued_at must be authorized")
	}
	if PlanRootAuthorized(sw, pr.id, 999, root) {
		t.Error("before issued_at")
	}
	extra := g09wBody(pr.id, []any{g09wStep("a")}, []any{})
	extra["plan_root"] = root
	extra["x"] = true
	if PlanRootAuthorized(g09wSign(t, pr, extra), pr.id, 1500, root) {
		t.Error("a signed body with an extra member must not authorize")
	}
	if k5NoPanic(func() bool { panic("boom") }) {
		t.Error("k5NoPanic must fail closed on a panic")
	}
	if !k5NoPanic(func() bool { return true }) || k5NoPanic(func() bool { return false }) {
		t.Error("k5NoPanic must return f's result")
	}
}

func TestG09WorkflowHelpers(t *testing.T) {
	if k5IsB32(1) || !k5IsB32(dg("x")) {
		t.Error("k5IsB32")
	}
	if k5OnlyKeys(map[string]any{"a": 1, "x": 1}, "a", "b") || !k5OnlyKeys(map[string]any{"a": 1, "b": 1}, "a", "b") {
		t.Error("k5OnlyKeys")
	}
	if k5SortedUnique("x", k5Label, 4) || !k5SortedUnique(g09wSeq("l", 4), k5Label, 4) || k5SortedUnique(g09wSeq("l", 5), k5Label, 4) {
		t.Error("k5SortedUnique")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("k5Hash of a non-canonical value must panic")
			}
		}()
		_ = k5Hash("\xed\xa0\x80")
	}()
	pr := newKey(t)
	body := map[string]any{"a": jnum(1)}
	if !k5VerifyBody("d", body, pr.id, signDomain(t, pr, "d", body)) || k5VerifyBody("d", body, pr.id, "AAAA") || k5VerifyBody("d", body, 1, 2) {
		t.Error("k5VerifyBody")
	}
	sm := func(n int) map[string]any {
		m := map[string]any{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("k%02d", i)] = jnum(int64(i))
		}
		return m
	}
	if k5IsScalarMap("x") || !k5IsScalarMap(sm(32)) || k5IsScalarMap(sm(33)) || k5IsScalarMap(map[string]any{"a b": "x"}) || k5IsScalarMap(map[string]any{"a": nil}) {
		t.Error("k5IsScalarMap")
	}
	if k5UintMap("x", 8) || !k5UintMap(sm(8), 8) || k5UintMap(sm(9), 8) || k5UintMap(map[string]any{"a b": jnum(1)}, 8) || k5UintMap(map[string]any{"a": jnum(-1)}, 8) {
		t.Error("k5UintMap")
	}
	if r := k5Deny("c", "s", -1); r.Pending == nil || len(r.Pending) != 0 {
		t.Errorf("k5Deny pending %#v", r.Pending)
	}
}

func TestG09WorkflowAncestors(t *testing.T) {
	if _, ok := k5Ancestors(map[string]any{"steps": []any{g09wStep("a", "a")}}); ok {
		t.Error("a self-dependency is a cycle")
	}
	// s_i depends on s_{i-1} and s_{i-2}: linear with memoisation, exponential without it
	steps := []any{}
	for i := 0; i < 64; i++ {
		deps := []string{}
		for _, j := range []int{i - 2, i - 1} {
			if j >= 0 {
				deps = append(deps, fmt.Sprintf("s%02d", j))
			}
		}
		steps = append(steps, g09wStep(fmt.Sprintf("s%02d", i), deps...))
	}
	type res struct {
		anc map[string]map[string]bool
		ok  bool
	}
	done := make(chan res, 1)
	go func() { a, ok := k5Ancestors(map[string]any{"steps": steps}); done <- res{a, ok} }()
	select {
	case r := <-done:
		if !r.ok || !r.anc["s05"]["s00"] || !r.anc["s63"]["s00"] || len(r.anc["s63"]) != 63 {
			t.Errorf("ancestors ok=%v s05=%v len63=%d", r.ok, r.anc["s05"], len(r.anc["s63"]))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("k5Ancestors did not memoise visited steps")
	}
}

func TestG09WorkflowValidStep(t *testing.T) {
	if !k5ValidStep(g09wStep("a")) {
		t.Fatal("base step")
	}
	cases := []struct {
		name string
		k    string
		v    any
		ok   bool
	}{
		{"verb 128", "verb", strings.Repeat("v", 128), true},
		{"verb 129", "verb", strings.Repeat("v", 129), false},
		{"resource 512", "resource", strings.Repeat("r", 512), true},
		{"resource 513", "resource", strings.Repeat("r", 513), false},
		{"deps 16", "deps", g09wSeq("d", 16), true},
		{"deps 17", "deps", g09wSeq("d", 17), false},
		{"deny 16", "deny_labels", g09wSeq("l", 16), true},
		{"deny 17", "deny_labels", g09wSeq("l", 17), false},
		{"esc 16", "escalate_labels", g09wSeq("l", 16), true},
		{"esc 17", "escalate_labels", g09wSeq("l", 17), false},
		{"cost 8", "cost", map[string]any{"c0": jnum(0), "c1": jnum(1), "c2": jnum(2), "c3": jnum(3), "c4": jnum(4), "c5": jnum(5), "c6": jnum(6), "c7": jnum(7)}, true},
		{"cost 9", "cost", map[string]any{"c0": jnum(0), "c1": jnum(1), "c2": jnum(2), "c3": jnum(3), "c4": jnum(4), "c5": jnum(5), "c6": jnum(6), "c7": jnum(7), "c8": jnum(8)}, false},
		{"bad id", "id", "a b", false},
		{"bad sink", "sink", "a b", false},
		{"bad fresh", "fresh_ms", jnum(-1), false},
		{"bad params_digest", "params_digest", "x", false},
	}
	for _, c := range cases {
		s := g09wStep("a")
		s[c.k] = c.v
		if k5ValidStep(s) != c.ok {
			t.Errorf("%s: want %v", c.name, c.ok)
		}
	}
	s := g09wStep("a")
	s["x"] = true
	if k5ValidStep(s) || k5ValidStep("x") {
		t.Error("extra member / non-object step")
	}
}

func TestG09WorkflowValidEdge(t *testing.T) {
	base := func() map[string]any { return g09wEdge("a", "o", "b", "p", "eq", nil) }
	for _, op := range []string{"eq", "le", "ge", "lt", "gt"} {
		e := base()
		e["op"] = op
		if !k5ValidEdge(e) {
			t.Errorf("op %s must be valid", op)
		}
	}
	e := base()
	e["promise"] = "pr"
	e["unit"] = "usd"
	e["deny_labels"] = g09wSeq("l", 16)
	if !k5ValidEdge(e) {
		t.Error("full edge must be valid")
	}
	bad := map[string]func(map[string]any){
		"op ne":         func(e map[string]any) { e["op"] = "ne" },
		"from not obj":  func(e map[string]any) { e["from"] = "x" },
		"to not obj":    func(e map[string]any) { e["to"] = "x" },
		"from extra":    func(e map[string]any) { e["from"] = map[string]any{"step": "a", "field": "o", "x": 1} },
		"from step bad": func(e map[string]any) { e["from"] = map[string]any{"step": "a b", "field": "o"} },
		"from field":    func(e map[string]any) { e["from"] = map[string]any{"step": "a", "field": "a:b"} },
		"to extra":      func(e map[string]any) { e["to"] = map[string]any{"step": "b", "param": "p", "x": 1} },
		"to step bad":   func(e map[string]any) { e["to"] = map[string]any{"step": "a b", "param": "p"} },
		"to param bad":  func(e map[string]any) { e["to"] = map[string]any{"step": "b", "param": "a:b"} },
		"unit bad":      func(e map[string]any) { e["unit"] = "a b" },
		"deny bad":      func(e map[string]any) { e["deny_labels"] = "x" },
		"deny 17":       func(e map[string]any) { e["deny_labels"] = g09wSeq("l", 17) },
		"promise bad":   func(e map[string]any) { e["promise"] = "a b" },
		"extra member":  func(e map[string]any) { e["x"] = true },
	}
	for name, mut := range bad {
		e := base()
		mut(e)
		if k5ValidEdge(e) {
			t.Errorf("%s must be invalid", name)
		}
	}
	if k5ValidEdge("x") {
		t.Error("non-object edge")
	}
}

func TestG09WorkflowValidBody(t *testing.T) {
	p := dg("principal")
	base := func() map[string]any { return g09wBody(p, []any{g09wStep("a")}, []any{}) }
	if !k5ValidWorkflowBody(base()) {
		t.Fatal("base body")
	}
	rep := func(x any, n int) []any {
		out := []any{}
		for i := 0; i < n; i++ {
			out = append(out, x)
		}
		return out
	}
	caps := func(n int) map[string]any {
		m := map[string]any{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("c%d", i)] = jnum(1)
		}
		return m
	}
	edge := g09wEdge("a", "o", "a", "p", "eq", nil)
	cases := []struct {
		name string
		mut  func(map[string]any)
		ok   bool
	}{
		{"v string", func(b map[string]any) { b["v"] = "1" }, false},
		{"v 2", func(b map[string]any) { b["v"] = jnum(2) }, false},
		{"id", func(b map[string]any) { b["id"] = "a b" }, false},
		{"principal", func(b map[string]any) { b["principal"] = "x" }, false},
		{"goal", func(b map[string]any) { b["goal_digest"] = "x" }, false},
		{"plan_root", func(b map[string]any) { b["plan_root"] = "x" }, false},
		{"issued_at", func(b map[string]any) { b["issued_at"] = jnum(-1) }, false},
		{"expires_at", func(b map[string]any) { b["expires_at"] = "x" }, false},
		{"steps not array", func(b map[string]any) { b["steps"] = "x" }, false},
		{"steps empty", func(b map[string]any) { b["steps"] = []any{} }, false},
		{"steps 64", func(b map[string]any) { b["steps"] = rep(g09wStep("a"), 64) }, true},
		{"steps 65", func(b map[string]any) { b["steps"] = rep(g09wStep("a"), 65) }, false},
		{"bad step", func(b map[string]any) { b["steps"] = []any{"x"} }, false},
		{"edges not array", func(b map[string]any) { b["edges"] = "x" }, false},
		{"edges 256", func(b map[string]any) { b["edges"] = rep(edge, 256) }, true},
		{"edges 257", func(b map[string]any) { b["edges"] = rep(edge, 257) }, false},
		{"bad edge", func(b map[string]any) { b["edges"] = []any{"x"} }, false},
		{"budget not obj", func(b map[string]any) { b["budget"] = "x" }, false},
		{"budget extra", func(b map[string]any) {
			b["budget"] = map[string]any{"max_steps": jnum(1), "caps": map[string]any{}, "x": 1}
		}, false},
		{"max_steps", func(b map[string]any) { b["budget"] = map[string]any{"max_steps": "x", "caps": map[string]any{}} }, false},
		{"caps 8", func(b map[string]any) { b["budget"] = map[string]any{"max_steps": jnum(1), "caps": caps(8)} }, true},
		{"caps 9", func(b map[string]any) { b["budget"] = map[string]any{"max_steps": jnum(1), "caps": caps(9)} }, false},
		{"extra member", func(b map[string]any) { b["x"] = true }, false},
	}
	for _, c := range cases {
		b := base()
		c.mut(b)
		if k5ValidWorkflowBody(b) != c.ok {
			t.Errorf("%s: want %v", c.name, c.ok)
		}
	}
}

func TestG09WorkflowValidReceiptShape(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"v": jnum(1), "wf": dg("w"), "step": "a", "seq": jnum(0), "prev": nil, "outcome": "ok", "params_digest": dg("pd"),
			"outputs": map[string]any{}, "issued_at": jnum(5), "signer": dg("s"), "sig": "x"}
	}
	if !k5ValidReceiptShape(base()) {
		t.Fatal("base receipt")
	}
	outs := func(n int) map[string]any {
		m := map[string]any{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("o%02d", i)] = g09wOut(nil)
		}
		return m
	}
	out := func(mut func(map[string]any)) map[string]any {
		o := g09wOut(nil)
		mut(o)
		return map[string]any{"o": o}
	}
	cases := []struct {
		name string
		mut  func(map[string]any)
		ok   bool
	}{
		{"seq 1 with prev", func(r map[string]any) { r["seq"] = jnum(1); r["prev"] = dg("p") }, true},
		{"failed outcome", func(r map[string]any) { r["outcome"] = "failed" }, true},
		{"extra member", func(r map[string]any) { r["x"] = true }, false},
		{"v string", func(r map[string]any) { r["v"] = "1" }, false},
		{"v 2", func(r map[string]any) { r["v"] = jnum(2) }, false},
		{"wf", func(r map[string]any) { r["wf"] = "x" }, false},
		{"step", func(r map[string]any) { r["step"] = "a b" }, false},
		{"seq", func(r map[string]any) { r["seq"] = "x" }, false},
		{"prev bad", func(r map[string]any) { r["seq"] = jnum(1); r["prev"] = "x" }, false},
		{"seq 1 no prev", func(r map[string]any) { r["seq"] = jnum(1) }, false},
		{"seq 0 with prev", func(r map[string]any) { r["prev"] = dg("p") }, false},
		{"outcome", func(r map[string]any) { r["outcome"] = "nope" }, false},
		{"sig", func(r map[string]any) { r["sig"] = jnum(1) }, false},
		{"params_digest", func(r map[string]any) { r["params_digest"] = "x" }, false},
		{"issued_at", func(r map[string]any) { r["issued_at"] = jnum(-1) }, false},
		{"signer", func(r map[string]any) { r["signer"] = "x" }, false},
		{"outputs not obj", func(r map[string]any) { r["outputs"] = "x" }, false},
		{"outputs 32", func(r map[string]any) { r["outputs"] = outs(32) }, true},
		{"outputs 33", func(r map[string]any) { r["outputs"] = outs(33) }, false},
		{"output name", func(r map[string]any) { r["outputs"] = map[string]any{"a b": g09wOut(nil)} }, false},
		{"output not obj", func(r map[string]any) { r["outputs"] = map[string]any{"o": "x"} }, false},
		{"output extra", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["x"] = 1 }) }, false},
		{"output digest", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["digest"] = "x" }) }, false},
		{"output num", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["num"] = "x" }) }, false},
		{"output unit", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["unit"] = "a b" }) }, false},
		{"output labels", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["labels"] = "x" }) }, false},
		{"output labels 16", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["labels"] = g09wSeq("l", 16) }) }, true},
		{"output labels 17", func(r map[string]any) { r["outputs"] = out(func(o map[string]any) { o["labels"] = g09wSeq("l", 17) }) }, false},
		{"output full", func(r map[string]any) {
			r["outputs"] = out(func(o map[string]any) { o["num"] = jnum(3); o["unit"] = "usd" })
		}, true},
	}
	for _, c := range cases {
		r := base()
		c.mut(r)
		if k5ValidReceiptShape(r) != c.ok {
			t.Errorf("%s: want %v", c.name, c.ok)
		}
	}
	if k5ValidReceiptShape("x") {
		t.Error("non-object receipt")
	}
}

func TestG09WorkflowValidRequest(t *testing.T) {
	base := func() map[string]any { return g09wReq("a", map[string]any{}) }
	if !k5ValidRequest(base()) {
		t.Fatal("base request")
	}
	cases := []struct {
		name string
		k    string
		v    any
		ok   bool
	}{
		{"verb 128", "verb", strings.Repeat("v", 128), true},
		{"verb 129", "verb", strings.Repeat("v", 129), false},
		{"resource 512", "resource", strings.Repeat("r", 512), true},
		{"resource 513", "resource", strings.Repeat("r", 513), false},
		{"step", "step", "a b", false},
		{"params", "params", "x", false},
		{"units not obj", "units", "x", false},
		{"units name", "units", map[string]any{"a b": "usd"}, false},
		{"units value", "units", map[string]any{"p": "a b"}, false},
		{"units ok", "units", map[string]any{"p": "usd"}, true},
		{"goal", "goal_digest", "x", false},
		{"goal ok", "goal_digest", dg("g"), true},
		{"plan_root", "plan_root", "x", false},
	}
	for _, c := range cases {
		r := base()
		r[c.k] = c.v
		if k5ValidRequest(r) != c.ok {
			t.Errorf("%s: want %v", c.name, c.ok)
		}
	}
}
