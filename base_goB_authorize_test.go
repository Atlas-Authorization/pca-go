package pca

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// ---- stores that fail on demand ---------------------------------------------------------------------------------------

type goBPins struct {
	*MemoryStateStore
	pinErr, raiseErr     error
	pinPanic, raisePanic bool
}

func (p goBPins) Pin(k string) (*float64, error) {
	if p.pinPanic {
		panic("pin")
	}
	if p.pinErr != nil {
		return nil, p.pinErr
	}
	return p.MemoryStateStore.Pin(k)
}

func (p goBPins) RaisePin(k string, v float64) error {
	if p.raisePanic {
		panic("raise")
	}
	if p.raiseErr != nil {
		return p.raiseErr
	}
	return p.MemoryStateStore.RaisePin(k, v)
}

// goBClaimOnly is a replay store with nothing else: no budgets, no pins, no last-seen reads.
type goBClaimOnly struct{ s *MemoryStateStore }

func (c goBClaimOnly) Claim(k string, n int64) (ClaimResult, error) { return c.s.Claim(k, n) }

type goBBudgetHook struct {
	*MemoryStateStore
	claim func(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error)
}

func (b goBBudgetHook) ClaimBudgeted(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error) {
	return b.claim(key, counter, before, after)
}

type goBFailUpdateKv struct{ AtomicKV }

func (goBFailUpdateKv) Update(string, func([]byte) []byte) error { return errors.New("down") }

// goBAuth runs one dynamic Authorize (counter 1) against the g01 grant; mod edits the input before the call.
func goBAuth(t *testing.T, extra map[string]any, mod func(in *AuthorizeInput, store *MemoryStateStore, grant map[string]any)) AuthorizeResult {
	t.Helper()
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	in := g01DynIn(g)
	store := NewMemoryStateStore()
	in.StateStore = store
	if mod != nil {
		mod(&in, store, g)
	}
	return Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, extra), in)
}

func goBReasonHas(r AuthorizeResult, want string) bool { return slices.Contains(r.Reasons, want) }

// ---- configuration --------------------------------------------------------------------------------------------------

func TestGoB_MissingAuthorizeComponents(t *testing.T) {
	resolve := func(string) (map[string]any, error) { return nil, nil }
	revoked := func(_, _ map[string]any) (bool, error) { return false, nil }
	base := func(store StateStore) AuthorizeInput {
		return AuthorizeInput{Audience: "a", ResolveGrant: resolve, IsRevoked: revoked, StateStore: store}
	}
	same := func(name string, in AuthorizeInput, want ...string) {
		t.Helper()
		got := MissingAuthorizeComponents(in)
		if len(got) != len(want) || (len(want) > 0 && !slices.Equal(got, want)) {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
	same("complete", base(NewMemoryStateStore()))
	// staleness needs pins only when there is a store to ask
	ms := 60000.0
	stale := base(nil)
	stale.RevocationStaleness = &RevocationStalenessPolicy{MaxRevocationAgeMs: &ms}
	stale.RevocationState = func(_, _ map[string]any) (*RevocationState, error) { return nil, nil }
	same("staleness, no store", stale, "StateStore")
	stale.StateStore = unscopedStore{}
	same("staleness, store without pins", stale, "revocation staleness needs a state store that implements pins (rollback protection)")
	stale.StateStore = NewMemoryStateStore()
	same("staleness, pins", stale)
	// Forbid needs its clause source
	f := base(NewMemoryStateStore())
	f.Forbid = &ForbidPolicy{}
	same("forbid without clauses", f, "Forbid.Clauses")
	f.Forbid = &ForbidPolicy{Clauses: func(Operation, map[string]any) any { return nil }}
	same("forbid with clauses", f)
	// a beacon needs pins (replay protection) when there is a store
	hook := func(string, map[string]any) *BeaconInput { return nil }
	b := base(unscopedStore{})
	b.Beacon = hook
	same("beacon, store without pins", b, "beacon needs a state store that implements pins (replay protection)")
	b.StateStore = NewMemoryStateStore()
	same("beacon, pins", b)
	b.Beacon = nil
	b.StateStore = unscopedStore{}
	same("no beacon, store without pins", b)
	b.Beacon = hook
	b.StateStore = nil
	same("beacon, no store", b, "StateStore")
}

// ---- the contract / forbid / template gates -------------------------------------------------------------------------

func TestGoB_ContractRefusalViolatedSuffix(t *testing.T) {
	r := contractRefusal(map[string]any{"allow": false, "reason": "violated", "violated": []any{"a"}})
	if r == nil || r.Reason != "contract: violated (a)" || r.Status != 403 || r.Checks["contract"] != "fail" || r.Decision != "deny" {
		t.Errorf("one violated: %+v", r)
	}
	r = contractRefusal(map[string]any{"allow": false, "reason": "store-error", "violated": []any{}})
	if r == nil || r.Reason != "contract: store-error" {
		t.Errorf("none violated: %+v", r)
	}
	r = contractRefusal(map[string]any{"allow": false, "reason": "x"})
	if r == nil || r.Reason != "contract: x" {
		t.Errorf("no violated key: %+v", r)
	}
	if contractRefusal(map[string]any{"allow": true, "reason": "ok"}) != nil || contractRefusal(map[string]any{"allow": "true"}) == nil {
		t.Error("only allow == true is an allow")
	}
}

func TestGoB_ReadableGrant(t *testing.T) {
	grant := map[string]any{"id": "g1"}
	other := map[string]any{"id": "other"}
	resolver := func(g map[string]any, err error) func(string) (map[string]any, error) {
		return func(string) (map[string]any, error) { return g, err }
	}
	p, g := readableGrant(map[string]any{"grant_ref": "g1"}, AuthorizeInput{ResolveGrant: resolver(grant, nil)})
	if p == nil || g == nil || g["id"] != "g1" {
		t.Errorf("readable: %v %v", p, g)
	}
	// no grant_ref: the resolver is not asked
	asked := false
	p, g = readableGrant(map[string]any{"x": 1}, AuthorizeInput{ResolveGrant: func(string) (map[string]any, error) { asked = true; return other, nil }})
	if p == nil || g != nil || asked {
		t.Errorf("no grant_ref: %v %v asked=%v", p, g, asked)
	}
	// a resolver error leaves no grant, even when it returned one
	p, g = readableGrant(map[string]any{"grant_ref": "g1"}, AuthorizeInput{ResolveGrant: resolver(other, errors.New("down"))})
	if p == nil || g != nil {
		t.Errorf("resolver error: %v %v", p, g)
	}
	// a panicking resolver leaves nothing at all
	p, g = readableGrant(map[string]any{"grant_ref": "g1"}, AuthorizeInput{ResolveGrant: func(string) (map[string]any, error) { panic("x") }})
	if p != nil || g != nil {
		t.Errorf("resolver panic: %v %v", p, g)
	}
	// an unreadable PCActn
	if p, g := readableGrant(nil, AuthorizeInput{ResolveGrant: resolver(grant, nil)}); p != nil || g != nil {
		t.Errorf("nil PCActn: %v %v", p, g)
	}
	if p, g := readableGrant("not json", AuthorizeInput{ResolveGrant: resolver(grant, nil)}); p != nil || g != nil {
		t.Errorf("undecodable PCActn: %v %v", p, g)
	}
}

func goBForbidClauses(clauses ...any) *ForbidPolicy {
	list := append([]any{}, clauses...)
	return &ForbidPolicy{Clauses: func(Operation, map[string]any) any { return list }}
}

func TestGoB_ForbidRefusal(t *testing.T) {
	op := Operation{Verb: "pay", Resource: "/r", Params: map[string]any{}}
	permit := map[string]any{"id": "ok", "kind": "permit", "when": map[string]any{"verb": "pay"}}
	in := func(f *ForbidPolicy) AuthorizeInput { return AuthorizeInput{Forbid: f} }
	r := forbidRefusal(nil, in(goBForbidClauses(map[string]any{"id": "no", "kind": "forbid", "when": map[string]any{"verb": "pay"}}, permit)), op)
	if r == nil || r.Status != 403 || r.Reason != "forbid: deny by forbid no" || !strings.HasPrefix(r.Reason, "forbid:") ||
		r.Checks["forbid"] != "fail" || len(r.Checks) != 1 || r.Decision != "deny" {
		t.Errorf("forbid wins: %+v", r)
	}
	r = forbidRefusal(nil, in(goBForbidClauses(map[string]any{"id": "esc", "kind": "escalate", "when": map[string]any{"verb": "pay"}}, permit)), op)
	if r == nil || r.Status != 403 || r.Reason != "forbid: escalate by escalate esc" {
		t.Errorf("escalate: %+v", r)
	}
	r = forbidRefusal(nil, in(goBForbidClauses()), op)
	if r == nil || r.Reason != "forbid: deny by none" {
		t.Errorf("no permit: %+v", r)
	}
	if r := forbidRefusal(nil, in(goBForbidClauses(permit)), op); r != nil {
		t.Errorf("permitted: %+v", r)
	}
	if forbidRefusal(nil, AuthorizeInput{}, op) != nil {
		t.Error("no policy, no refusal")
	}
	// the decision context: the operation's, plus what Context adds
	gold := map[string]any{"id": "gold", "kind": "permit",
		"when": map[string]any{"verb": "pay", "where": []any{map[string]any{"field": "env.tier", "op": "eq", "value": "gold"}}}}
	withCtx := goBForbidClauses(gold)
	if r := forbidRefusal(nil, in(withCtx), op); r == nil || r.Reason != "forbid: deny by none" {
		t.Errorf("no context: %+v", r)
	}
	withCtx.Context = func(Operation) map[string]any { return map[string]any{"env": map[string]any{"tier": "gold"}} }
	if r := forbidRefusal(nil, in(withCtx), op); r != nil {
		t.Errorf("context applied: %+v", r)
	}
	// a Context that panics adds nothing and does not fail the call
	withCtx.Context = func(Operation) map[string]any { panic("x") }
	if r := forbidRefusal(nil, in(withCtx), op); r == nil || r.Reason != "forbid: deny by none" {
		t.Errorf("panicking context: %+v", r)
	}
	// a Context cannot replace the operation's own action
	withCtx.Context = func(Operation) map[string]any { return map[string]any{"env": map[string]any{"tier": "gold"}} }
	// the grant is handed to the clause source
	var seen map[string]any
	gp := &ForbidPolicy{Clauses: func(_ Operation, g map[string]any) any { seen = g; return []any{permit} }}
	gin := AuthorizeInput{Forbid: gp, ResolveGrant: func(string) (map[string]any, error) { return map[string]any{"id": "g9"}, nil }}
	if r := forbidRefusal(map[string]any{"grant_ref": "g9"}, gin, op); r != nil || seen == nil || seen["id"] != "g9" {
		t.Errorf("grant handed over: %v %v", r, seen)
	}
}

func TestGoB_ForbidCertificateReason(t *testing.T) {
	op := Operation{Verb: "pay", Resource: "/r", Params: map[string]any{}}
	clauses := []any{map[string]any{"id": "ok", "kind": "permit", "when": map[string]any{"verb": "pay"}}}
	ctx := map[string]any{"action": map[string]any{"verb": "pay", "resource": "/r", "params": map[string]any{}}}
	cert, err := Certify(clauses, ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := copyObj(cert)
	bad["decision"] = "deny"
	f := &ForbidPolicy{Clauses: func(Operation, map[string]any) any { return clauses }, RequireCertificate: true}
	c := CheckForbidCertificate(bad, clauses, ctx, nil, nil)
	if c["ok"] == true {
		t.Fatal("the tampered certificate must not check")
	}
	why, _ := c["reason"].(string)
	if why == "" {
		t.Fatal("a refused certificate carries its reason")
	}
	r := forbidRefusal(nil, AuthorizeInput{Forbid: f, ForbidCertificate: bad}, op)
	if r == nil || r.Reason != "forbid: certificate refused ("+why+")" || r.Status != 403 {
		t.Errorf("%+v want reason %q", r, why)
	}
}

func goBEnv(extra map[string]any) map[string]any {
	e := map[string]any{"type": envelopeCaveat, "goal_commit": "g", "predicates": []any{}, "caveats": []any{}, "agent_binding": map[string]any{}, "risk_policy": g01Risk()}
	for k, v := range extra {
		e[k] = v
	}
	return e
}

func TestGoB_TemplateRefusal(t *testing.T) {
	reg := map[string]any{}
	pc := map[string]any{"grant_ref": "g1"}
	mk := func(g map[string]any, err error) AuthorizeInput {
		return AuthorizeInput{RequireLinkedTemplate: func() map[string]any { return reg },
			ResolveGrant: func(string) (map[string]any, error) { return g, err }}
	}
	grantOf := func(env map[string]any) map[string]any {
		return map[string]any{"id": "g1", "caveats": []any{env}}
	}
	check := func(name string, got *AuthorizeResult, want string) {
		t.Helper()
		if got == nil || got.Status != 403 || got.Reason != want || got.Checks["template"] != "fail" || len(got.Checks) != 1 || got.Decision != "deny" {
			t.Errorf("%s: %+v want %q", name, got, want)
		}
	}
	if templateRefusal(pc, AuthorizeInput{}) != nil {
		t.Error("no requirement, no refusal")
	}
	// a PCActn that cannot be read is left to the verification that follows
	if templateRefusal(nil, mk(nil, nil)) != nil {
		t.Error("nil PCActn")
	}
	check("no grant", templateRefusal(pc, mk(nil, errors.New("down"))), "template: the grant has no readable envelope")
	check("no envelope", templateRefusal(pc, mk(map[string]any{"id": "g1", "caveats": []any{}}, nil)), "template: the grant has no readable envelope")
	check("no template_ref", templateRefusal(pc, mk(grantOf(goBEnv(nil)), nil)), "template: the grant carries no template_ref")
	check("bad template_ref", templateRefusal(pc, mk(grantOf(goBEnv(map[string]any{"template_ref": "x"})), nil)), "template: template_ref must be an object")
	// a grant that is the instantiation of its template is not refused (and one that is not, is)
	k := g05Key(t, 0x55)
	def := g05Tpl(map[string]any{})
	d, err := TemplateDigest(def)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{"def": def, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, def)}
	linked := map[string]any{"templates": map[string]any{d: signed}, "trusted": []any{k.Public}}
	ref := map[string]any{"template_id": "t", "version_digest": d, "slots": map[string]any{}}
	env := goBEnv(map[string]any{"template_ref": ref})
	in := mk(grantOf(env), nil)
	in.RequireLinkedTemplate = func() map[string]any { return linked }
	want := VerifyLinkedPolicy(env, linked)
	got := templateRefusal(pc, in)
	if want == "" {
		if got != nil {
			t.Errorf("a linked grant is not refused: %+v", got)
		}
	} else {
		check("linked", got, "template: "+want)
	}
	// the same grant against a registry that does not know the template
	in.RequireLinkedTemplate = func() map[string]any { return map[string]any{} }
	check("unknown template", templateRefusal(pc, in), "template: template version is not in the registry")
	// a registry source that panics is a refusal, not a crash
	in.RequireLinkedTemplate = func() map[string]any { panic("x") }
	check("panicking registry", templateRefusal(pc, in), "template: link verification error (fail closed)")
}

func TestGoB_CallLinkedPolicy(t *testing.T) {
	if got := callLinkedPolicy(func() map[string]any { return map[string]any{} }, map[string]any{}); got != "" {
		t.Errorf("no template_ref: %q", got)
	}
	if got := callLinkedPolicy(func() map[string]any { return map[string]any{} }, map[string]any{"template_ref": "x"}); got != "template_ref must be an object" {
		t.Errorf("bad ref: %q", got)
	}
	if got := callLinkedPolicy(func() map[string]any { panic("x") }, map[string]any{}); got != "link verification error (fail closed)" {
		t.Errorf("panic: %q", got)
	}
}

func TestGoB_AuthorizeGates(t *testing.T) {
	// forbid
	g01Refused(t, goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) {
		in.Forbid = goBForbidClauses(map[string]any{"id": "no-pay", "kind": "forbid", "when": map[string]any{"verb": "g01.pay"}})
	}), 403, "forbid", "forbid: deny by forbid no-pay")
	if r := goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) {
		in.Forbid = goBForbidClauses(map[string]any{"id": "ok", "kind": "permit", "when": map[string]any{"verb": "g01.pay"}})
	}); !r.Allow {
		t.Errorf("permitted: %+v", r)
	}
	// template
	g01Refused(t, goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) {
		in.RequireLinkedTemplate = func() map[string]any { return map[string]any{} }
	}), 403, "template", "template: the grant carries no template_ref")
}

func goBEnforcer(t *testing.T, kv AtomicKV, verb string) *ContractEnforcer {
	t.Helper()
	seed := bytes.Repeat([]byte{9}, 32)
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	c := goBJSON(t, `{"version":1,"principal":"`+kp.Public+`","invariants":[],"clauses":[{"id":"c1","kind":"never","p":{"verb":"`+verb+`"}}]}`)
	signed, err := SignContract(c, seed)
	if err != nil {
		t.Fatal(err)
	}
	e, err := OpenContractEnforcer(kv, signed, kp.Public, ContractEnforcerOptions{Now: func() float64 { return float64(g01Now) }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestGoB_AuthorizeContracts(t *testing.T) {
	// a violating operation is refused before the PCActn is read
	e := goBEnforcer(t, NewMemoryAtomicKV(), "g01.pay")
	g01Refused(t, goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) { in.Contracts = e }),
		403, "contract", "contract: violated (c1)")
	// an allowed operation advances the contract state
	e = goBEnforcer(t, NewMemoryAtomicKV(), "other.verb")
	r := goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) { in.Contracts = e })
	if !r.Allow {
		t.Fatalf("allowed: %+v", r)
	}
	st, err := e.State()
	if err != nil || st == nil || !jeq(st["state"].(map[string]any)["seq"], json.Number("1")) {
		t.Errorf("the allowed action advanced the contract state to seq 1: %v %v", st, err)
	}
	// a contract store that cannot be written denies, naming the contract
	e = goBEnforcer(t, goBFailUpdateKv{NewMemoryAtomicKV()}, "other.verb")
	r = goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) { in.Contracts = e })
	if r.Allow || r.Checks["contract"] != "fail" || !goBReasonHas(r, "contract: store-error") {
		t.Errorf("unwritable contract store: %+v", r)
	}
}

// ---- beacon -----------------------------------------------------------------------------------------------------------

func TestGoB_BeaconStepEdges(t *testing.T) {
	kp, _ := NewKeyPair()
	const now = 10_000_000
	b, err := IssueLivenessBeacon(kp, "inst", "", 5, now-1000, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := BeaconRef(b)
	p := map[string]any{"freshness": map[string]any{"beacon_ref": ref}}
	good := func() *BeaconInput { return &BeaconInput{Beacon: b, Issuers: []string{kp.Public}, Instance: "inst"} }
	type outcome struct {
		status, why string
		seq         *int64
	}
	run := func(store StateStore, grant map[string]any, in *BeaconInput) outcome {
		var o outcome
		a := AuthorizeInput{StateStore: store, Beacon: func(string, map[string]any) *BeaconInput { return in }}
		o.seq = beaconStep(a, p, grant, "g1", now, func(_, s string) { o.status = s }, func(_, w string) { o.status, o.why = "fail", w })
		return o
	}
	g1 := map[string]any{"id": "g1"}
	mem := func() *MemoryStateStore { return NewMemoryStateStore() }
	i64 := func(v int64) *int64 { return &v }

	// a beacon hook that panics, or hands over no beacon, is "no beacon": nothing is reported (the required check is then absent)
	panicOut := func() outcome {
		var o outcome
		a := AuthorizeInput{StateStore: mem(), Beacon: func(string, map[string]any) *BeaconInput { panic("hook") }}
		o.seq = beaconStep(a, p, g1, "g1", now, func(_, s string) { o.status = s }, func(_, w string) { o.status, o.why = "fail", w })
		return o
	}()
	if panicOut.status != "" || panicOut.why != "" || panicOut.seq != nil {
		t.Errorf("panicking hook: %+v", panicOut)
	}
	if o := run(mem(), g1, &BeaconInput{Issuers: []string{kp.Public}, Instance: "inst"}); o.status != "" || o.why != "" || o.seq != nil {
		t.Errorf("hook without a beacon: %+v", o)
	}

	// the host's own last accepted seq
	hostLast := func(v int64) outcome {
		in := good()
		in.LastAcceptedSeq = i64(v)
		return run(mem(), g1, in)
	}
	if o := hostLast(10); o.status != "fail" || o.why != "beacon seq 5 is older than the last accepted 10 (replay)" || o.seq != nil {
		t.Errorf("host last 10: %+v", o)
	}
	if o := hostLast(5); o.status != "pass" || o.seq == nil || *o.seq != 5 {
		t.Errorf("host last 5 (equal is accepted): %+v", o)
	}
	if o := hostLast(4); o.status != "pass" || o.seq == nil || *o.seq != 5 {
		t.Errorf("host last 4: %+v", o)
	}

	// the stored pin and the host value: the higher one counts
	pinned := func(pin float64, host *int64) outcome {
		s := mem()
		_ = s.RaisePin("g1:beacon", pin)
		in := good()
		in.LastAcceptedSeq = host
		return run(s, g1, in)
	}
	if o := pinned(3, i64(7)); o.status != "fail" || o.why != "beacon seq 5 is older than the last accepted 7 (replay)" {
		t.Errorf("pin 3, host 7: %+v", o)
	}
	if o := pinned(9, i64(2)); o.status != "fail" || o.why != "beacon seq 5 is older than the last accepted 9 (replay)" {
		t.Errorf("pin 9, host 2: %+v", o)
	}
	if o := pinned(3, i64(2)); o.status != "pass" {
		t.Errorf("pin 3, host 2: %+v", o)
	}
	if o := pinned(3, nil); o.status != "pass" {
		t.Errorf("pin 3, no host value: %+v", o)
	}
	if o := pinned(9, nil); o.status != "fail" || o.why != "beacon seq 5 is older than the last accepted 9 (replay)" {
		t.Errorf("pin 9, no host value: %+v", o)
	}

	// a pin that cannot be read denies
	for name, st := range map[string]goBPins{"error": {MemoryStateStore: mem(), pinErr: errors.New("down")}, "panic": {MemoryStateStore: mem(), pinPanic: true}} {
		if o := run(st, g1, good()); o.status != "fail" || o.why != "the beacon pin could not be read (fail closed)" || o.seq != nil {
			t.Errorf("%s: %+v", name, o)
		}
	}
	// a store without pins reads none (Authorize refuses that configuration up front)
	if o := run(unscopedStore{}, g1, good()); o.status != "pass" {
		t.Errorf("store without pins: %+v", o)
	}
	// a grant without an id has no pin key and nothing to pin
	idless := mem()
	_ = idless.RaisePin(":beacon", 100)
	if o := run(idless, map[string]any{}, good()); o.status != "pass" || o.seq != nil {
		t.Errorf("grant without an id: %+v", o)
	}
	// and with an id the pin is returned for raising
	if o := run(mem(), g1, good()); o.status != "pass" || o.seq == nil || *o.seq != 5 {
		t.Errorf("pass: %+v", o)
	}
	// a rejected beacon names its reason
	if o := run(mem(), g1, &BeaconInput{Beacon: b, Instance: "inst"}); o.status != "fail" || o.why != "issuer not pinned" {
		t.Errorf("rejected: %+v", o)
	}
}

func TestGoB_AuthorizeBeacon(t *testing.T) {
	kp, _ := NewKeyPair()
	b, err := IssueLivenessBeacon(kp, "inst", "", 5, g01Now-1000, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := BeaconRef(b)
	bound := map[string]any{"freshness": map[string]any{"beacon_ref": ref, "epoch": json.Number("0"), "accumulator_witness": ""}}
	hook := func(string, map[string]any) *BeaconInput {
		return &BeaconInput{Beacon: b, Issuers: []string{kp.Public}, Instance: "inst"}
	}

	// a good beacon passes, and its seq is pinned once the action is admitted
	var gid string
	var store *MemoryStateStore
	r := goBAuth(t, bound, func(in *AuthorizeInput, s *MemoryStateStore, g map[string]any) {
		in.Beacon, store, gid = hook, s, g["id"].(string)
	})
	if !r.Allow || r.Checks["beacon"] != "pass" {
		t.Fatalf("beacon: %+v", r)
	}
	if pin, _ := store.Pin(gid + ":beacon"); pin == nil || *pin != 5 {
		t.Errorf("the beacon seq was not pinned: %v", pin)
	}
	// a pin that cannot be stored denies
	r = goBAuth(t, bound, func(in *AuthorizeInput, s *MemoryStateStore, g map[string]any) {
		in.Beacon = hook
		in.StateStore = goBPins{MemoryStateStore: s, raiseErr: errors.New("down")}
	})
	if r.Allow || !goBReasonHas(r, "beacon: the beacon pin could not be stored (fail closed)") {
		t.Errorf("unstorable pin: %+v", r)
	}
	r = goBAuth(t, bound, func(in *AuthorizeInput, s *MemoryStateStore, g map[string]any) {
		in.Beacon = hook
		in.StateStore = goBPins{MemoryStateStore: s, raisePanic: true}
	})
	if r.Allow || !goBReasonHas(r, "beacon: the beacon pin could not be stored (fail closed)") {
		t.Errorf("panicking pin store: %+v", r)
	}
	// a beacon source with nothing to give leaves the required check absent: default-deny
	r = goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) {
		in.Beacon = func(string, map[string]any) *BeaconInput { return nil }
	})
	if r.Allow || r.Checks["beacon"] != "fail" || !goBReasonHas(r, "beacon: required check is absent (default-deny: not enforced by this resource server)") {
		t.Errorf("no beacon: %+v", r)
	}
	// without a beacon source the check is not required
	if r := goBAuth(t, nil, nil); !r.Allow || r.Checks["beacon"] != "" {
		t.Errorf("no beacon configured: %+v", r)
	}
	// an unbound beacon (the PCActn names another ref) denies
	r = goBAuth(t, nil, func(in *AuthorizeInput, _ *MemoryStateStore, _ map[string]any) { in.Beacon = hook })
	if r.Allow || !goBReasonHas(r, "beacon: PCActn freshness.beacon_ref does not bind the presented beacon") {
		t.Errorf("unbound: %+v", r)
	}
}

// ---- revocation pins ---------------------------------------------------------------------------------------------------

func TestGoB_WithRollbackPinMessages(t *testing.T) {
	epoch := map[string]any{"epoch": json.Number("5")}
	mem := NewMemoryStateStore()
	st := &RevocationState{Epoch: epoch}
	got, key, why := withRollbackPin(mem, st, map[string]any{})
	if got != st || key != "" || why != "the grant has no readable id for its revocation pin (fail closed)" {
		t.Errorf("no id: %v %q %q", got, key, why)
	}
	got, key, why = withRollbackPin(mem, st, map[string]any{"id": ""})
	if got != st || key != "" || why != "the grant has no readable id for its revocation pin (fail closed)" {
		t.Errorf("empty id: %v %q %q", got, key, why)
	}
	got, key, why = withRollbackPin(unscopedStore{}, st, map[string]any{"id": "g"})
	if got != st || key != "" || why != "the state store does not implement pins (fail closed)" {
		t.Errorf("no pins: %v %q %q", got, key, why)
	}
	for name, s := range map[string]goBPins{"error": {MemoryStateStore: mem, pinErr: errors.New("down")}, "panic": {MemoryStateStore: mem, pinPanic: true}} {
		got, key, why = withRollbackPin(s, st, map[string]any{"id": "g"})
		if got != st || key != "" || why != "the revocation pin store failed (fail closed)" {
			t.Errorf("%s: %v %q %q", name, got, key, why)
		}
	}
	// a pin equal to the host's value changes nothing
	five := 5.0
	_ = mem.RaisePin("g:epoch", 5)
	got, key, why = withRollbackPin(mem, &RevocationState{Epoch: epoch, LastAcceptedEpoch: &five}, map[string]any{"id": "g"})
	if why != "" || key != "g:epoch" || got.LastAcceptedEpoch == nil || *got.LastAcceptedEpoch != 5 {
		t.Errorf("equal pin: %+v %q %q", got, key, why)
	}
}

func TestGoB_ReadAndRaisePinReporting(t *testing.T) {
	mem := NewMemoryStateStore()
	_ = mem.RaisePin("k", 3)
	if v, failed := readPin(mem, "k"); failed || v == nil || *v != 3 {
		t.Errorf("read: %v %v", v, failed)
	}
	if v, failed := readPin(mem, "none"); failed || v != nil {
		t.Errorf("read none: %v %v", v, failed)
	}
	if v, failed := readPin(goBPins{MemoryStateStore: mem, pinErr: errors.New("x")}, "k"); !failed || v != nil {
		t.Errorf("read error: %v %v", v, failed)
	}
	if v, failed := readPin(goBPins{MemoryStateStore: mem, pinPanic: true}, "k"); !failed || v != nil {
		t.Errorf("read panic: %v %v", v, failed)
	}
	if raisePin(mem, "k", 4) {
		t.Error("raise reported a failure")
	}
	if v, _ := mem.Pin("k"); v == nil || *v != 4 {
		t.Errorf("raised: %v", v)
	}
	if !raisePin(goBPins{MemoryStateStore: mem, raiseErr: errors.New("x")}, "k", 5) {
		t.Error("raise error not reported")
	}
	if !raisePin(goBPins{MemoryStateStore: mem, raisePanic: true}, "k", 5) {
		t.Error("raise panic not reported")
	}
	if v, _ := mem.Pin("k"); *v != 4 {
		t.Errorf("a failed raise changed the pin: %v", *v)
	}
}

func TestGoB_AuthorizeRevocationPin(t *testing.T) {
	on := &RevocationStalenessPolicy{MaxRevocationAgeMs: func() *float64 { v := 300000.0; return &v }()}
	epoch := func(int64, string) *RevocationState { return &RevocationState{Epoch: map[string]any{}} }

	// an unreadable pin denies freshness
	r := stalenessAuthorizeWith(t, on, epoch, 30_000, func(in *AuthorizeInput) {
		in.StateStore = goBPins{MemoryStateStore: NewMemoryStateStore(), pinErr: errors.New("down")}
	})
	if r.Allow || r.Checks["freshness"] != "fail" || !goBReasonHas(r, "freshness: the revocation pin store failed (fail closed)") {
		t.Errorf("unreadable pin: %+v", r)
	}

	// an admitted action raises the pin of the verified epoch
	mem := NewMemoryStateStore()
	var gid string
	r = stalenessAuthorizeWith(t, on, epoch, 30_000, func(in *AuthorizeInput) {
		in.StateStore = mem
		g, _ := in.ResolveGrant("x")
		gid, _ = g["id"].(string)
	})
	if !r.Allow || r.Checks["freshness"] != "pass" {
		t.Fatalf("fresh epoch: %+v", r)
	}
	if pin, _ := mem.Pin(gid + ":epoch"); pin == nil {
		t.Error("the verified epoch was not pinned")
	}

	// a pin that cannot be raised denies
	for name, s := range map[string]goBPins{"error": {raiseErr: errors.New("down")}, "panic": {raisePanic: true}} {
		s.MemoryStateStore = NewMemoryStateStore()
		r = stalenessAuthorizeWith(t, on, epoch, 30_000, func(in *AuthorizeInput) { in.StateStore = s })
		if r.Allow || r.Checks["freshness"] != "fail" || !goBReasonHas(r, "freshness: the revocation pin store failed (fail closed)") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// ---- budget store ------------------------------------------------------------------------------------------------------

func TestGoB_AuthorizeBudgetStoreFaults(t *testing.T) {
	caution := map[string]any{"caution": json.Number("0.3")}
	// a store that cannot persist budgets refuses a metered action
	r := goBAuth(t, caution, func(in *AuthorizeInput, s *MemoryStateStore, _ map[string]any) { in.StateStore = goBClaimOnly{s} })
	if r.Allow || !goBReasonHas(r, "budget: this store does not persist trust budgets (a metered action cannot be admitted)") {
		t.Errorf("no budget seam: %+v", r)
	}
	// a concurrent spend is a conflict, never a replay or an allow
	conflict := func(s *MemoryStateStore) StateStore {
		return goBBudgetHook{MemoryStateStore: s, claim: func(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error) {
			return BudgetConflict, ClaimResult{}, nil
		}}
	}
	r = goBAuth(t, caution, func(in *AuthorizeInput, s *MemoryStateStore, _ map[string]any) { in.StateStore = conflict(s) })
	if r.Allow || !goBReasonHas(r, "budget: the trust budget changed while this action was decided (a concurrent spend): retry (fail closed)") {
		t.Errorf("conflict: %+v", r)
	}
	if goBReasonHas(r, "replay: 1 was already claimed (replay)") {
		t.Errorf("a conflict is not a replay: %v", r.Reasons)
	}
	// a store that errors or panics is a replay-store failure
	failing := map[string]func(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error){
		"error": func(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error) {
			return BudgetClaimed, ClaimResult{OK: true}, errors.New("down")
		},
		"panic": func(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error) { panic("down") },
	}
	for name, f := range failing {
		r = goBAuth(t, caution, func(in *AuthorizeInput, s *MemoryStateStore, _ map[string]any) {
			in.StateStore = goBBudgetHook{MemoryStateStore: s, claim: f}
		})
		if r.Allow || !goBReasonHas(r, "replay: the replay store failed (fail closed)") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestGoB_CallClaimBudgeted(t *testing.T) {
	ok := goBBudgetHook{claim: func(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error) {
		return BudgetReplay, ClaimResult{OK: false}, nil
	}}
	if o, r, failed := callClaimBudgeted(ok, "k", 1, nil, nil); failed || o != BudgetReplay || r.OK {
		t.Errorf("plain: %v %+v %v", o, r, failed)
	}
	boom := goBBudgetHook{claim: func(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error) { panic("x") }}
	if _, r, failed := callClaimBudgeted(boom, "k", 1, nil, nil); !failed || r.OK {
		t.Errorf("panic: %+v %v", r, failed)
	}
	bad := goBBudgetHook{claim: func(string, int64, map[string]any, map[string]any) (BudgetClaim, ClaimResult, error) {
		return BudgetClaimed, ClaimResult{OK: true}, errors.New("x")
	}}
	if _, _, failed := callClaimBudgeted(bad, "k", 1, nil, nil); !failed {
		t.Error("error")
	}
}

func TestGoB_CallK1(t *testing.T) {
	if callK1(func(map[string]any) (*K1Input, error) { panic("x") }, nil) != nil {
		t.Error("a panicking source is no input")
	}
	if callK1(func(map[string]any) (*K1Input, error) { return nil, errors.New("x") }, nil) != nil {
		t.Error("an error is no input")
	}
	if callK1(func(map[string]any) (*K1Input, error) { return nil, nil }, nil) != nil {
		t.Error("nil is no input")
	}
	src := &K1Input{HasNarrow: true}
	got := callK1(func(map[string]any) (*K1Input, error) { return src, nil }, nil)
	if got == nil || got == src || !got.HasNarrow {
		t.Errorf("a copy of the input: %v", got)
	}
}

// ---- passport ---------------------------------------------------------------------------------------------------------

func TestGoB_AuthorizePassportEdges(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	issuer, _ := NewKeyPair()
	mk := func(hw bool) map[string]any {
		pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": hw, "issued_at": g01Now - 1000})
		if err != nil {
			t.Fatal(err)
		}
		var evidence map[string]any
		if hw { // a hardware-rooted passport is only signed with attestation evidence
			evidence = map[string]any{"document": map[string]any{"nonce": "n"}}
		}
		sp, err := SignPassport(pp, issuer, k.agent.Public, 0, 0, g01Now+3_600_000, evidence, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sp
	}
	opts := PassportOptions{TrustedIssuers: []string{issuer.Public}, Revoked: func(string, string, string) (bool, error) { return false, nil },
		Attest: func(map[string]any, PassportBinding) (PassportAttestation, error) {
			return PassportAttestation{OK: true, Bound: true, Measured: map[string]any{"model_id": "m", "operator": "acme"}}, nil
		}}
	run := func(passport any, req *PassportRequirement, mut func(map[string]any)) AuthorizeResult {
		in := g01DynIn(g)
		in.RequirePassport, in.Passport = req, passport
		act := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
		if mut != nil {
			mut(act)
		}
		return Authorize(act, in)
	}
	// a hardware-rooted passport satisfies a hardware requirement
	if r := run(mk(true), &PassportRequirement{Options: opts, Hardware: true}, nil); !r.Allow || r.Checks["passport"] != "pass" {
		t.Errorf("hardware-rooted: %+v", r)
	}
	if r := run(mk(false), &PassportRequirement{Options: opts, Hardware: true}, nil); r.Allow || !goBReasonHas(r, "passport: hardware_evidence_missing") {
		t.Errorf("not hardware-rooted: %+v", r)
	}
	// a PCActn with no capability chain has no holder to bind the passport to
	r := run(mk(false), &PassportRequirement{Options: opts}, func(p map[string]any) { p["cap_chain"] = []any{} })
	if r.Allow || r.Checks["authorize"] != "" || r.Checks["passport"] != "fail" || !goBReasonHas(r, "passport: malformed") {
		t.Errorf("empty chain: %+v", r)
	}
}
