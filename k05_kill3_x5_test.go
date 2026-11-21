package pca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

// A lone surrogate reaches the canonicalizer (jsonValue passes strings through), which refuses it as hashCanonical throws in the
// reference: the params are refused, never admitted as nil.
func TestK05Kill3X5CopyParamsRefusesWhatCannotCanonicalize(t *testing.T) {
	for _, params := range []map[string]any{{"x": "\xed\xa0\x80"}, {"\xed\xa0\x80": json.Number("1")}} {
		if m, ok := copyParams(params); ok || m != nil {
			t.Fatalf("copyParams(%v) = %v, %v", params, m, ok)
		}
	}
	in, _, p := g01Fix(t)
	in.Operation = &Operation{Verb: in.Operation.Verb, Resource: in.Operation.Resource, Params: map[string]any{"x": "\xed\xa0\x80"}}
	g01Refused(t, Authorize(p, in), 403, "operation", "operation: the operation params are not canonical JSON (fail closed)")
}

// The replay stage needs a holder AND a counter: either one missing alone refuses, before any claim.
func TestK05Kill3X5NoCounterStream(t *testing.T) {
	defer func() { authorizeCoreHook = nil }()
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), g01DynIn(g)); !r.Allow {
		t.Fatalf("baseline: %v %q", r.Checks, r.Reasons)
	}
	for name, edit := range map[string]func(map[string]any){
		"counter absent":       func(p map[string]any) { delete(p, "counter") },
		"counter out of range": func(p map[string]any) { p["counter"] = json.Number("99999999999999999999") },
		"holder not a string": func(p map[string]any) {
			p["cap_chain"] = []any{map[string]any{"holder": json.Number("5"), "caveats": []any{}}}
		},
	} {
		p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
		authorizeCoreHook = func(*Verdict) { edit(p) } // after the core checks, which pass on the signed proof
		r := Authorize(p, g01DynIn(g))
		if r.Allow || r.Checks["replay"] != "fail" || r.Reason != "replay: no counter stream for this proof (fail closed)" {
			t.Fatalf("%s: %v %q", name, r.Checks, r.Reason)
		}
	}
}

type x5CountingStore struct {
	OperationStore
	gets int
}

func (s *x5CountingStore) Get(id string) (*OperationRecord, error) {
	s.gets++
	return s.OperationStore.Get(id)
}

// x5Executed: an executor that has committed the proof, so a record exists for it.
func x5Executed(t *testing.T) (*Executor, *x5CountingStore, map[string]any, *Operation, func(ExecutionHandle) (any, error)) {
	t.Helper()
	ex, pc, op, _ := executorFixture(t, -1)
	store := &x5CountingStore{OperationStore: ex.o.Operations}
	ex.o.Operations = store
	p := deepCopy(pc).(map[string]any)
	fn := func(ExecutionHandle) (any, error) { return "ok", nil }
	if o := ex.Run(p, op, fn); o.Status != "committed" {
		t.Fatalf("first run: %+v", o)
	}
	store.gets = 0
	return ex, store, p, op, fn
}

// operations.ts semantics: only a replay as the ONLY failing check is answered from the record. A single failure that is not the
// replay, with a record present, stays a plain denial.
func TestK05Kill3X5ExecutorOtherFailureIsNotAnsweredFromTheRecord(t *testing.T) {
	defer func() { authorizeCoreHook = nil }()
	ex, store, p, op, fn := x5Executed(t)
	ex.o.Authorize.StateStore = NewMemoryStateStore() // the counter is fresh here: replay passes
	authorizeCoreHook = func(core *Verdict) {
		core.Checks["x5other"] = false
		core.Allow, core.Reasons = false, []string{"x5other: no"}
	}
	o := ex.Run(p, op, fn)
	if o.Status != "denied" || o.Replayed || o.Authorization == nil || o.Authorization.Status != 403 ||
		o.Authorization.Checks["x5other"] != "fail" || o.Authorization.Checks["replay"] != "pass" || store.gets != 0 {
		t.Fatalf("%+v gets=%d", o, store.gets)
	}
}

// A replayed proof whose operation id cannot be computed is denied without reading the store.
func TestK05Kill3X5ExecutorUnhashableReplayNeverReadsTheStore(t *testing.T) {
	defer func() { authorizeCoreHook = nil }()
	ex, store, p, op, fn := x5Executed(t)
	authorizeCoreHook = func(*Verdict) { p["x5_bad"] = "\xed\xa0\x80" } // after the core checks
	o := ex.Run(p, op, fn)
	if o.Status != "denied" || o.Authorization == nil || o.Authorization.Status != 403 || store.gets != 0 {
		t.Fatalf("%+v gets=%d", o, store.gets)
	}
	failing := []string{}
	for name, st := range o.Authorization.Checks {
		if st == "fail" {
			failing = append(failing, name)
		}
	}
	if len(failing) != 1 || failing[0] != "replay" {
		t.Fatalf("failing checks: %v", failing)
	}
}

func x5AuthorizedPlan(t *testing.T, nodes []map[string]any) (*PlanRegistry, string) {
	t.Helper()
	reg := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 500 }})
	d := reg.Draft("g", nodes)
	if !d.OK {
		t.Fatalf("draft: %+v", d)
	}
	root := d.Record.Root
	if v := reg.Validate("g", root); !v.OK {
		t.Fatalf("validate: %+v", v)
	}
	if c := reg.Commit("g", root); !c.OK {
		t.Fatalf("commit: %+v", c)
	}
	if a := reg.Authorize("g", root, &PlanApproval{By: "alice"}); !a.OK {
		t.Fatalf("authorize: %+v", a)
	}
	return reg, root
}

// plan-lifecycle.ts: `n.params_digest ?? paramsDigest(undefined)`: a null digest reads as the digest of no params, as an absent one.
func TestK05Kill3X5PlanNullParamsDigest(t *testing.T) {
	reg, root := x5AuthorizedPlan(t, []map[string]any{{"id": "n1", "verb": "v", "resource": "/r", "params_digest": nil}})
	if s := reg.Check("g", root, PlanCheckOptions{Operation: &Operation{Verb: "v", Resource: "/r"}}); !s.Executable || s.Reason != "" {
		t.Fatalf("no params: %+v", s)
	}
	s := reg.Check("g", root, PlanCheckOptions{Operation: &Operation{Verb: "v", Resource: "/r", Params: map[string]any{"a": "b"}}})
	if want := fmt.Sprintf("plan %s: the operation (v on /r with these params) is not what the principal approved", root); s.Executable || s.Reason != want {
		t.Fatalf("other params: %+v", s)
	}
}

// plan-lifecycle.ts: `if (!s.executable || !s.record) return s`: a plan that is not executable keeps its own reason, whatever
// node the caller names.
func TestK05Kill3X5PlanCheckKeepsTheStatusReason(t *testing.T) {
	reg := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 500 }})
	d := reg.Draft("g", []map[string]any{{"id": "n1", "verb": "v", "resource": "/r"}})
	if !d.OK {
		t.Fatalf("draft: %+v", d)
	}
	root := d.Record.Root
	s := reg.Check("g", root, PlanCheckOptions{NodeID: "nope"})
	if want := fmt.Sprintf("plan %s is draft, not authorized", root); s.Executable || s.Reason != want || s.Record == nil {
		t.Fatalf("draft: %+v", s)
	}
	s = reg.Check("g", "no-such", PlanCheckOptions{NodeID: "n1"})
	if s.Executable || s.Reason != "plan no-such is unknown for this grant" || s.Record != nil {
		t.Fatalf("unknown: %+v", s)
	}
}

func x5Passport() map[string]any {
	return map[string]any{"typ": "atlas-pca/passport", "ver": json.Number("1"), "iss": "i", "sub": "s", "sig": "x",
		"nbf": json.Number("1"), "exp": json.Number("2"), "iat": json.Number("1"),
		"passport": map[string]any{"id": "a", "model_id": "m", "operator": "o", "hardware_rooted": false}}
}

// passport.ts: each malformed condition alone is "malformed", decided before the issuer is looked at.
func TestK05Kill3X5PassportMalformedConditionsAlone(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(map[string]any)
		now  int64
		want string
	}{
		{"baseline", func(map[string]any) {}, 0, "unknown_issuer"},
		{"now at the safe maximum", func(map[string]any) {}, maxSafeInt, "unknown_issuer"},
		{"now at the safe minimum", func(map[string]any) {}, -maxSafeInt, "unknown_issuer"},
		{"iat absent", func(s map[string]any) { delete(s, "iat") }, 0, "malformed"},
		{"nbf absent", func(s map[string]any) { delete(s, "nbf") }, 0, "malformed"},
		{"exp out of range", func(s map[string]any) { s["exp"] = json.Number("99999999999999999999") }, 0, "malformed"},
		{"exp equals nbf", func(s map[string]any) { s["exp"] = json.Number("1") }, 0, "malformed"},
		{"now above the safe range", func(map[string]any) {}, maxSafeInt + 1, "malformed"},
		{"now below the safe range", func(map[string]any) {}, -maxSafeInt - 1, "malformed"},
	} {
		s := x5Passport()
		c.edit(s)
		if got := VerifyPassport(s, PassportOptions{NowMs: c.now}); got != c.want {
			t.Fatalf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A panicking attestation hook reports failed, as one that errors (the reference catches a throwing hook at this call).
func TestK05Kill3X5PassportAttestPanicIsFailed(t *testing.T) {
	_, failed := callPassportAttest(func(map[string]any, PassportBinding) (PassportAttestation, error) { panic("x5") }, nil, PassportBinding{})
	if !failed {
		t.Fatal("a panicking attest hook must report failed")
	}
}

// RFC 9162 needs a 32-byte leaf hash: a shorter one that would otherwise fold to the root is refused up front.
func TestK05Kill3X5InclusionRefusesAShortLeafAlone(t *testing.T) {
	leaf, sibling := bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{2}, 32)
	root := rfc9162Node(sibling, leaf)
	if VerifyRFC9162Inclusion(leaf, 1, 2, [][]byte{sibling}, root) {
		t.Fatal("a 31-byte leaf hash must be refused")
	}
	full := bytes.Repeat([]byte{1}, 32)
	if !VerifyRFC9162Inclusion(full, 1, 2, [][]byte{sibling}, rfc9162Node(sibling, full)) {
		t.Fatal("baseline proof")
	}
}

// escalation.ts: the catch of verifyEscalationAnswer turns any internal error into this exact refusal.
func TestK05Kill3X5EscalationPanicIsARefusal(t *testing.T) {
	escalationVerifyHook = func() { panic("x5 boom") }
	defer func() { escalationVerifyHook = nil }()
	r := VerifyEscalationAnswer(nil, nil, EscalationBinding{}, 1)
	if r.OK || r.Reason != "escalation answer error (fail closed): x5 boom" {
		t.Fatalf("%+v", r)
	}
}
