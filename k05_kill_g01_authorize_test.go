package pca

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---- fixture-based (testdata/authorize-fixtures.json, case 0: an allowed payments.send)

func g01Fix(t *testing.T) (in AuthorizeInput, grant, pcactn map[string]any) {
	t.Helper()
	d, c, s := firstFixtureStep(t)
	grant = c["grant"].(map[string]any)
	revoked := false
	in = fixInput(d, grant, NewMemoryStateStore(), &revoked)
	in.Operation = fixOp(s["operation"].(map[string]any))
	return in, grant, deepCopy(s["pcactn"]).(map[string]any)
}

func g01Has(rs []string, want string) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}

func g01HasPrefix(rs []string, prefix string) bool {
	for _, r := range rs {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

// g01Refused: the exact one-check refusal shape of refuse().
func g01Refused(t *testing.T, r AuthorizeResult, status int, check, reason string) {
	t.Helper()
	if r.Allow || r.Status != status || !reflect.DeepEqual(r.Checks, map[string]string{check: "fail"}) || r.Reason != reason ||
		!reflect.DeepEqual(r.Reasons, []string{reason}) {
		t.Fatalf("got status=%d checks=%v reason=%q reasons=%q, want %d %s %q", r.Status, r.Checks, r.Reason, r.Reasons, status, check, reason)
	}
}

func TestG01FixtureBaseline(t *testing.T) {
	in, _, p := g01Fix(t)
	r := Authorize(p, in)
	if !r.Allow || r.Status != 200 || r.Undo != nil || r.Obligations != nil {
		t.Fatalf("baseline: %+v", r)
	}
}

func TestG01PanicIsA403(t *testing.T) {
	in, _, p := g01Fix(t)
	in.Operation = &Operation{Verb: in.Operation.Verb, Resource: in.Operation.Resource, Params: map[string]any{"x": g01PanicJSON{}}}
	r := Authorize(p, in)
	if r.Allow || r.Status != 403 || !reflect.DeepEqual(r.Checks, map[string]string{"authorize": "fail"}) ||
		!strings.HasPrefix(r.Reason, "authorize: error (fail closed): ") || !strings.Contains(r.Reason, "g01 marshal") {
		t.Fatalf("got %+v", r)
	}
}

func TestG01ConfigAndInputRefusals(t *testing.T) {
	in, _, p := g01Fix(t)
	bad := in
	bad.Plan = "bogus"
	if r := Authorize(p, bad); r.Status != 403 || !reflect.DeepEqual(r.Missing, []string{`Plan (only "single-step" or "")`}) {
		t.Fatalf("bogus plan: %+v", r)
	}
	nan := in
	nan.Operation = &Operation{Verb: in.Operation.Verb, Resource: in.Operation.Resource, Params: map[string]any{"a": math.NaN()}}
	g01Refused(t, Authorize(p, nan), 403, "operation", "operation: the operation params are not canonical JSON (fail closed)")
	g01Refused(t, Authorize(nil, in), 401, "wire", "wire: no PCActn presented")
	q := deepCopy(p).(map[string]any)
	q["grant_ref"] = 1.0
	g01Refused(t, Authorize(q, in), 401, "malformed", "malformed: grant_ref is not a string")
}

func TestG01CallbackRefusals(t *testing.T) {
	in, _, p := g01Fix(t)
	boom := errors.New("g01")
	for name, f := range map[string]func(string) (map[string]any, error){
		"error": func(string) (map[string]any, error) { return nil, boom },
		"panic": func(string) (map[string]any, error) { panic("g01") },
	} {
		x := in
		x.ResolveGrant = f
		t.Run(name, func(t *testing.T) {
			g01Refused(t, Authorize(p, x), 403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)")
		})
	}
	x := in
	x.ResolveGrant = func(string) (map[string]any, error) { return nil, nil }
	g01Refused(t, Authorize(p, x), 401, "grant_ref", "grant_ref: does not resolve to a known grant")

	for name, f := range map[string]func(map[string]any) (*AuthorizeContext, error){
		"error": func(map[string]any) (*AuthorizeContext, error) { return nil, boom },
		"panic": func(map[string]any) (*AuthorizeContext, error) { panic("g01") },
	} {
		x := in
		x.Context = f
		t.Run("context "+name, func(t *testing.T) {
			g01Refused(t, Authorize(p, x), 403, "context", "context: the context callback failed (fail closed)")
		})
	}
	x = in
	x.Context = func(map[string]any) (*AuthorizeContext, error) { return nil, nil }
	if r := Authorize(p, x); !r.Allow {
		t.Fatalf("a nil context must be no context: %+v", r)
	}

	for name, f := range map[string]func(map[string]any) (*IntentV2Context, error){
		"error": func(map[string]any) (*IntentV2Context, error) { return nil, boom },
		"panic": func(map[string]any) (*IntentV2Context, error) { panic("g01") },
	} {
		x := in
		x.IntentV2 = f
		t.Run("intent_v2 "+name, func(t *testing.T) {
			g01Refused(t, Authorize(p, x), 403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)")
		})
	}
}

func TestG01Revocation(t *testing.T) {
	in, _, p := g01Fix(t)
	failed := "revocation: the revocation check failed (fail closed)"
	revoked := "revocation: the grant is revoked"
	for name, c := range map[string]struct {
		f    func(_, _ map[string]any) (bool, error)
		want string
	}{
		"panic":       {func(_, _ map[string]any) (bool, error) { panic("g01") }, failed},
		"true+error":  {func(_, _ map[string]any) (bool, error) { return true, errors.New("g01") }, failed},
		"revoked":     {func(_, _ map[string]any) (bool, error) { return true, nil }, revoked},
		"false+error": {func(_, _ map[string]any) (bool, error) { return false, errors.New("g01") }, failed},
	} {
		x := in
		x.IsRevoked = c.f
		r := Authorize(p, x)
		if r.Allow || r.Checks["revocation"] != "fail" || r.Reason != c.want || !g01Has(r.Reasons, c.want) {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	x := in
	x.StateStore = g01PanicStore{}
	if r := Authorize(p, x); r.Allow || r.Reason != "replay: the replay store failed (fail closed)" {
		t.Fatalf("panicking store: %+v", r)
	}
}

func TestG01WireHook(t *testing.T) {
	in, _, p := g01Fix(t)
	for _, c := range []struct{ reason, want string }{{"", "wire: malformed PCActn"}, {"wire: g01", "wire: g01"}} {
		reason := c.reason
		authorizeCoreHook = func(core *Verdict) {
			core.Checks["wire"] = false
			core.Allow, core.Reason = false, reason
		}
		r := Authorize(p, in)
		authorizeCoreHook = nil
		if r.Allow || r.Status != 401 || !reflect.DeepEqual(r.Checks, map[string]string{"wire": "fail", "malformed": "fail"}) ||
			r.Reason != c.want || !reflect.DeepEqual(r.Reasons, []string{c.want}) {
			t.Fatalf("reason %q: %+v", c.reason, r)
		}
	}
}

func TestG01CoreReasons(t *testing.T) {
	in, _, p := g01Fix(t)
	defer func() { authorizeCoreHook = nil }()
	// an allowing core contributes no reasons, whatever it carries
	authorizeCoreHook = func(core *Verdict) { core.Reasons = []string{"g01: stray"} }
	if r := Authorize(p, in); !r.Allow || g01Has(r.Reasons, "g01: stray") {
		t.Fatalf("stray reason: %+v", r)
	}
	// Reasons win over Reason
	authorizeCoreHook = func(core *Verdict) {
		core.Checks["leaf_signature"] = false
		core.Allow, core.Reasons, core.Reason = false, []string{"a: 1"}, "b: 2"
	}
	if r := Authorize(p, in); r.Allow || len(r.Reasons) == 0 || r.Reasons[0] != "a: 1" || g01Has(r.Reasons, "b: 2") {
		t.Fatalf("reasons: %+v", r)
	}
	// no reason at all adds no empty reason
	authorizeCoreHook = func(core *Verdict) {
		core.Checks["leaf_signature"] = false
		core.Allow, core.Reasons, core.Reason = false, nil, ""
	}
	if r := Authorize(p, in); r.Allow || g01Has(r.Reasons, "") {
		t.Fatalf("empty reason: %q", r.Reasons)
	}
}

func TestG01FixtureFailures(t *testing.T) {
	in, grant, p := g01Fix(t)

	zk := deepCopy(p).(map[string]any)
	zk["zk_compliance"] = map[string]any{}
	want := "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof"
	if r := Authorize(zk, in); r.Allow || r.Checks["zk_compliance"] != "fail" || !g01Has(r.Reasons, want) {
		t.Fatalf("zk: %+v", r)
	}

	x := in
	x.Operation = &Operation{Verb: "payments.refund", Resource: in.Operation.Resource, Params: in.Operation.Params}
	want = "operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme"
	if r := Authorize(p, x); r.Allow || r.Reason != want {
		t.Fatalf("verb: %q", r.Reason)
	}

	x = in
	x.Operation = &Operation{Verb: in.Operation.Verb, Resource: in.Operation.Resource, Params: map[string]any{"amount": 60.0, "currency": "usd"}}
	r := Authorize(p, x)
	if r.Allow || r.Reason != "operation: the proof's params_digest does not match the params of this payments.send operation" ||
		!g01Has(r.Reasons, "params_digest: supplied params do not hash to action.params_digest") {
		t.Fatalf("params: %q", r.Reasons)
	}

	g2 := deepCopy(grant).(map[string]any)
	g2["id"] = "g01-other"
	x = in
	x.ResolveGrant = func(string) (map[string]any, error) { return g2, nil }
	if r := Authorize(p, x); r.Allow || r.Checks["grant_ref"] != "fail" || !g01Has(r.Reasons, "grant_ref: does not reference the supplied grant") {
		t.Fatalf("grant id: %+v", r)
	}

	// the 400 case: exactly one reason (the policy one)
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[1].(map[string]any)
	s := c["steps"].([]any)[0].(map[string]any)
	revoked := false
	in1 := fixInput(d, c["grant"].(map[string]any), NewMemoryStateStore(), &revoked)
	in1.Operation = fixOp(s["operation"].(map[string]any))
	r = Authorize(s["pcactn"], in1)
	if !reflect.DeepEqual(r.Reasons, []string{"policy: amount <= 100 not satisfied for payments.send on payments/acme"}) || r.Checks["policy"] != "fail" {
		t.Fatalf("400: %q %v", r.Reasons, r.Checks)
	}

	x = in
	x.Require = []string{"g01_extra"}
	want = "g01_extra: required check is absent (default-deny: not enforced by this resource server)"
	if r := Authorize(p, x); r.Allow || r.Checks["g01_extra"] != "fail" || !reflect.DeepEqual(r.Reasons, []string{want}) {
		t.Fatalf("require: %+v", r)
	}
}

func TestG01FixturePlans(t *testing.T) {
	in, _, p := g01Fix(t)
	x := in
	x.Context = func(map[string]any) (*AuthorizeContext, error) {
		return &AuthorizeContext{Plan: []map[string]any{{"id": "other", "verb": "v", "resource": "r"}}, PlanAuthorized: true}, nil
	}
	if r := Authorize(p, x); r.Allow || !g01Has(r.Reasons, "plan_root_authorized: known plan does not match plan.root") {
		t.Fatalf("mismatch: %q", r.Reasons)
	}
	x.Context = func(pc map[string]any) (*AuthorizeContext, error) {
		return &AuthorizeContext{Plan: []map[string]any{planNodeOf(pc)}, PlanAuthorized: false}, nil
	}
	if r := Authorize(p, x); r.Allow || !g01Has(r.Reasons, "plan_root_authorized: the plan root has not been authorized by the principal") {
		t.Fatalf("unauthorized: %q", r.Reasons)
	}
	// a plan registry that does not know the root: single-step still decides it, no plan_state
	x = in
	x.Plans = NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return in.Now }})
	if r := Authorize(p, x); !r.Allow {
		t.Fatalf("registry + single-step: %+v", r)
	} else if _, has := r.Checks["plan_state"]; has {
		t.Fatalf("plan_state reported: %v", r.Checks)
	}
}

func TestG01FixtureAssuranceDegraded(t *testing.T) {
	in, _, p := g01Fix(t)
	defer func() { authorizeCoreHook = nil }()
	for _, legacy := range []bool{true, false} {
		lg := legacy
		authorizeCoreHook = func(core *Verdict) {
			core.Checks["tighten"] = true
			core.LegacyModelPolarity = lg
		}
		r := Authorize(p, in)
		a, ok := r.Assurance.Get("tighten")
		if !ok || a.Degraded != legacy {
			t.Fatalf("legacy=%v: %+v %v", legacy, a, ok)
		}
	}
}

func TestG01FixtureStaleness(t *testing.T) {
	in, _, p := g01Fix(t)
	age := 60_000.0
	in.RevocationStaleness = &RevocationStalenessPolicy{MaxRevocationAgeMs: &age}
	in.RevocationState = func(_, _ map[string]any) (*RevocationState, error) { return nil, errors.New("g01") }
	if r := Authorize(p, in); r.Allow || r.Checks["freshness"] != "fail" || !g01Has(r.Reasons, "freshness: the revocation state source failed (fail closed)") {
		t.Fatalf("staleness: %+v", r)
	}
}

func TestG01EscalationHead(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	// no LastStore: the history head is unknown, the answer is not verified at all
	r := Authorize(pcactn, in(bareStore{NewMemoryStateStore()}, signAnswer(t, sk, pub, grant, pcactn, nil, nil), nil))
	if r.Allow || g01HasPrefix(r.Reasons, "escalation:") {
		t.Fatalf("unknown head: %q", r.Reasons)
	}
	r = Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	if !r.Allow || !g01Has(r.Reasons, "escalation: answered allow by principal "+pub[:8]) {
		t.Fatalf("answered: %q", r.Reasons)
	}
}

func g01Workflow(t *testing.T, units any, prov *ArgProvenanceOptions) AuthorizeResult {
	t.Helper()
	F := load(t, "authorize-workflow-fixtures.json")
	var plan []map[string]any
	for _, n := range F["plan"].([]any) {
		plan = append(plan, n.(map[string]any))
	}
	grant := F["grant"].(map[string]any)
	var c map[string]any
	for _, x := range F["cases"].([]any) {
		if x.(map[string]any)["name"] == "pay-after-quote" {
			c = x.(map[string]any)
		}
	}
	s := c["steps"].([]any)[0].(map[string]any)
	op := s["operation"].(map[string]any)
	w := s["workflow"].(map[string]any)
	in := AuthorizeInput{Risk: InsecureCalmRisk,
		Operation:    &Operation{Verb: op["verb"].(string), Resource: op["resource"].(string), Params: op["params"].(map[string]any)},
		Audience:     F["audience"].(string),
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		StateStore:   NewMemoryStateStore(),
		IsRevoked:    func(_, _ map[string]any) (bool, error) { return false, nil },
		Now:          num(F["now"]),
		Context: func(map[string]any) (*AuthorizeContext, error) {
			return &AuthorizeContext{Plan: plan, PlanAuthorized: true}, nil
		},
		Workflow:      &WorkflowOption{Principal: F["principal"].(string), RsSigner: F["rs_signer"].(string)},
		WorkflowStep:  &WorkflowCall{Commitment: w["commitment"], Receipts: w["receipts"], Step: w["step"].(string), Units: units, GoalDigest: w["goal_digest"]},
		ArgProvenance: prov,
	}
	return Authorize(s["pcactn"], in)
}

func TestG01WorkflowUnits(t *testing.T) {
	if r := g01Workflow(t, nil, harnessProv()); !r.Allow {
		t.Fatalf("nil units: %+v", r)
	}
	r := g01Workflow(t, map[string]any{"!!": 1.0}, harnessProv())
	if r.Allow || r.Decision != "deny" || r.Reason != "workflow: bad_workflow" {
		t.Fatalf("bad units: %q %s", r.Reason, r.Decision)
	}
	// an admitted step makes the choice of the action the principal's
	r = g01Workflow(t, map[string]any{}, &ArgProvenanceOptions{Mediators: harnessPins()})
	for _, why := range r.Reasons {
		if strings.Contains(why, "the choice of") {
			t.Fatalf("admitted step, choice still unproven: %q", r.Reasons)
		}
	}
}

func TestG01ModelRulesV2Params(t *testing.T) {
	d := modelRulesVectors(t)
	for _, x := range d["cases"].([]any) {
		c := x.(map[string]any)
		if c["name"] != "tighten-escalate" {
			continue
		}
		r := runModelCase(d, c, func(in *AuthorizeInput) {
			in.IntentV2 = func(map[string]any) (*IntentV2Context, error) {
				return IntentV2ContextFromJSON(map[string]any{"params": map[string]any{"amount": 10.0, "currency": "usd"}}), nil
			}
		})
		if r.Checks["tighten"] != "pass" {
			t.Fatalf("the v2 context's own params were replaced: %v %q", r.Checks, r.Reasons)
		}
		return
	}
	t.Fatal("no tighten-escalate case")
}

// ---- dynamic (keys from seeds, envelope verb g01.pay on acct/*, operation acct/1 {amount: 5})

const (
	g01Now = int64(1792929600000)
	g01Aud = "rs-g01"
)

func g01Key(t *testing.T, b byte) *KeyPair {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func g01Risk() map[string]any {
	return map[string]any{"weights": map[string]any{"alpha": g01N("0"), "beta": g01N("0"), "gamma": g01N("0"), "delta": g01N("0"), "epsilon": g01N("0"), "zeta": g01N("0")},
		"theta1": g01N("0.5"), "theta2": g01N("0.8"), "kappa": g01N("1"), "lambda": g01N("0"), "rho": g01N("0"), "bMax": g01N("1000")}
}

// g01Grant mints a root grant to holder: the envelope (predicate g01.pay on acct/*, optional where) then rootExtra.
func g01Grant(t *testing.T, principal, holder *KeyPair, where []any, rootExtra ...any) map[string]any {
	t.Helper()
	pred := map[string]any{"verb": "g01.pay", "resource": "acct/*"}
	if where != nil {
		pred["where"] = where
	}
	env := map[string]any{"type": envelopeCaveat, "goal_commit": "g01-goal", "predicates": []any{pred}, "caveats": []any{},
		"agent_binding": map[string]any{}, "risk_policy": g01Risk()}
	g, err := MintRoot(principal, holder.Public, append([]any{env}, rootExtra...), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// g01N: canonicalization takes JSON numbers (json.Number), never Go floats.
func g01N(s string) json.Number { return json.Number(s) }

func g01Params() map[string]any { return map[string]any{"amount": g01N("5")} }

// g01Act signs the single-step PCActn for node n1 (reversibility class rc, "" = the default).
func g01Act(t *testing.T, grant map[string]any, chain []map[string]any, signer *KeyPair, rc string, iat, counter int64, extra map[string]any) map[string]any {
	t.Helper()
	digest, err := ParamsDigest(g01Params())
	if err != nil {
		t.Fatal(err)
	}
	node := map[string]any{"id": "n1", "verb": "g01.pay", "resource": "acct/1", "params_digest": digest}
	if rc != "" {
		node["reversibility_class"] = rc
	}
	p, err := BuildPCActn(PCActnInput{Grant: grant, Chain: chain, Plan: []map[string]any{node}, NodeID: "n1", Params: g01Params(),
		Counter: counter, Signer: signer, Aud: g01Aud, Iat: iat, Extra: extra})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func g01DynIn(grant map[string]any) AuthorizeInput {
	return AuthorizeInput{Risk: InsecureCalmRisk,
		Operation:     &Operation{Verb: "g01.pay", Resource: "acct/1", Params: g01Params()},
		Audience:      g01Aud,
		ResolveGrant:  func(string) (map[string]any, error) { return grant, nil },
		StateStore:    NewMemoryStateStore(),
		IsRevoked:     func(_, _ map[string]any) (bool, error) { return false, nil },
		Now:           g01Now,
		Plan:          PlanSingleStep,
		ArgProvenance: harnessProv(),
	}
}

type g01Keys struct{ principal, agent, sub *KeyPair }

func g01Keyset(t *testing.T) g01Keys {
	return g01Keys{principal: g01Key(t, 1), agent: g01Key(t, 2), sub: g01Key(t, 3)}
}

// g01Sub delegates grant (held by k.agent) to k.sub with caveats: the chain and the signer.
func g01Sub(t *testing.T, k g01Keys, grant map[string]any, caveats []any) []map[string]any {
	t.Helper()
	a, err := NewAgent(k.agent, grant, g01Aud, 0).Delegate(k.sub, caveats)
	if err != nil {
		t.Fatal(err)
	}
	return a.Chain
}

// g01PassHook: every core check passes except those in fail (check -> reason).
func g01PassHook(fail map[string]string) func() {
	authorizeCoreHook = func(core *Verdict) {
		for k := range core.Checks {
			core.Checks[k] = true
		}
		core.Allow, core.Reason, core.Reasons = true, "", nil
		for k, why := range fail {
			core.Checks[k] = false
			core.Allow, core.Reason, core.Reasons = false, why, []string{why}
		}
	}
	return func() { authorizeCoreHook = nil }
}

func TestG01DynamicBaselineAndClock(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	if r := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), g01DynIn(g)); !r.Allow {
		t.Fatalf("baseline: %+v", r)
	}
	in := g01DynIn(g)
	in.Now = 0 // the wall clock
	if r := Authorize(g01Act(t, g, chain, k.agent, "", time.Now().UnixMilli(), 1, nil), in); !r.Allow {
		t.Fatalf("wall clock: %+v", r)
	}
}

func TestG01DynamicReversibility(t *testing.T) {
	k := g01Keyset(t)
	eq := func(c string) []any {
		return []any{map[string]any{"field": "action.reversibility_class", "op": "eq", "value": c}}
	}
	run := func(declared, authoritative, wantEffective string) AuthorizeResult {
		g := g01Grant(t, k.principal, k.agent, eq(wantEffective))
		in := g01DynIn(g)
		in.Context = func(map[string]any) (*AuthorizeContext, error) {
			return &AuthorizeContext{ReversibilityClass: authoritative}, nil
		}
		return Authorize(g01Act(t, g, []map[string]any{g}, k.agent, declared, g01Now, 1, nil), in)
	}
	// a stricter declared class is the effective one
	if r := run("irreversible", "reversible", "irreversible"); !r.Allow || r.Checks["reversibility"] != "pass" {
		t.Fatalf("stricter declared: %v %q", r.Checks, r.Reasons)
	}
	// equal ranks: the authoritative class is the effective one
	if r := run("costly", "rate_limited", "rate_limited"); !r.Allow || r.Checks["reversibility"] != "pass" {
		t.Fatalf("equal ranks: %v %q", r.Checks, r.Reasons)
	}
	r := run("reversible", "irreversible", "irreversible")
	want := "reversibility: declared class 'reversible' is less restrictive than the authoritative 'irreversible'"
	if r.Allow || r.Checks["reversibility"] != "fail" || !g01Has(r.Reasons, want) {
		t.Fatalf("weaker declared: %v %q", r.Checks, r.Reasons)
	}
}

func TestG01DynamicPlanNodeClass(t *testing.T) {
	k := g01Keyset(t)
	revMax := map[string]any{"type": "reversibility_max", "class": "reversible"}
	// a signed class is the caveat class even when the context plan's node says otherwise
	g := g01Grant(t, k.principal, k.agent, nil, revMax)
	in := g01DynIn(g)
	in.Context = func(map[string]any) (*AuthorizeContext, error) {
		return &AuthorizeContext{Plan: []map[string]any{{"id": "n1", "verb": "g01.pay", "resource": "acct/1", "reversibility_class": "reversible"}}, PlanAuthorized: true}, nil
	}
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "irreversible", g01Now, 1, nil), in); r.Checks["policy"] != "fail" {
		t.Fatalf("signed class: %v %q", r.Checks, r.Reasons)
	}

	// no class anywhere else: the context plan's node of this id decides
	g = g01Grant(t, k.principal, k.agent, []any{map[string]any{"field": "action.reversibility_class", "op": "exists", "value": false}}, revMax)
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	delete(p["action"].(map[string]any), "reversibility_class")
	defer g01PassHook(nil)()
	in = g01DynIn(g)
	in.Context = func(map[string]any) (*AuthorizeContext, error) {
		return &AuthorizeContext{Plan: []map[string]any{
			{"id": "x", "verb": "g01.pay", "resource": "acct/1", "reversibility_class": "irreversible"},
			{"id": "n1", "verb": "g01.pay", "resource": "acct/1", "reversibility_class": "reversible"},
		}, PlanAuthorized: true}, nil
	}
	if r := Authorize(p, in); r.Checks["policy"] != "pass" {
		t.Fatalf("plan node class: %v %q", r.Checks, r.Reasons)
	}
}

func TestG01DynamicContextMembers(t *testing.T) {
	k := g01Keyset(t)
	where := []any{
		map[string]any{"field": "subject.tier", "op": "eq", "value": "gold"},
	}
	g := g01Grant(t, k.principal, k.agent, where,
		map[string]any{"type": "max_blast_radius", "max": g01N("5")},
		map[string]any{"type": "rate", "max": g01N("1"), "per_secs": g01N("60")},
		map[string]any{"type": "reversibility_max", "class": "irreversible"})
	in := g01DynIn(g)
	in.Context = func(map[string]any) (*AuthorizeContext, error) {
		return &AuthorizeContext{Subject: map[string]any{"tier": "gold"}, BlastRadius: 3.0, RecentActionTimes: []any{}}, nil
	}
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), in); !r.Allow {
		t.Fatalf("context members: %v %q", r.Checks, r.Reasons)
	}
	// no subject and no env: neither member exists in the predicate context
	absent := []any{
		map[string]any{"field": "subject", "op": "exists", "value": false},
		map[string]any{"field": "env", "op": "exists", "value": false},
	}
	g = g01Grant(t, k.principal, k.agent, absent)
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), g01DynIn(g)); !r.Allow {
		t.Fatalf("absent members: %v %q", r.Checks, r.Reasons)
	}
}

func TestG01DynamicDelegationDepth(t *testing.T) {
	k := g01Keyset(t)
	depth := func(max int64) map[string]any {
		return map[string]any{"type": "delegation_depth", "max": jsonNumberOf(max)}
	}
	g := g01Grant(t, k.principal, k.agent, nil, depth(0))
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), g01DynIn(g)); r.Checks["policy"] != "pass" {
		t.Fatalf("root chain: %v %q", r.Checks, r.Reasons)
	}
	if r := Authorize(g01Act(t, g, g01Sub(t, k, g, []any{}), k.sub, "", g01Now, 1, nil), g01DynIn(g)); r.Checks["policy"] != "fail" {
		t.Fatalf("one delegation: %v %q", r.Checks, r.Reasons)
	}
	defer g01PassHook(nil)()
	r := Authorize(g01Act(t, g, []map[string]any{}, k.agent, "", g01Now, 1, nil), g01DynIn(g))
	if _, has := r.Checks["delegated_caveats"]; r.Checks["policy"] != "pass" || has {
		t.Fatalf("empty chain: %v %q", r.Checks, r.Reasons)
	}
	if r.Reason != "replay: no counter stream for this proof (fail closed)" {
		t.Fatalf("empty chain reason: %q", r.Reason)
	}
	g = g01Grant(t, k.principal, k.agent, nil, depth(-1))
	if r := Authorize(g01Act(t, g, []map[string]any{}, k.agent, "", g01Now, 1, nil), g01DynIn(g)); r.Checks["policy"] != "fail" {
		t.Fatalf("empty chain, max -1: %v %q", r.Checks, r.Reasons)
	}
}

func TestG01DynamicEmptyChainEscalation(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	defer g01PassHook(map[string]string{"provenance": "provenance: intent_required: q"})()
	r := Authorize(g01Act(t, g, []map[string]any{}, k.agent, "", g01Now, 1, nil), g01DynIn(g))
	if r.Allow || r.Decision != "deny" || r.Escalation != nil || r.Checks["provenance"] != "fail" {
		t.Fatalf("no holder: %+v", r)
	}
}

func TestG01DynamicLongerGrant(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	// the resolved grant carries one more caveat than the presented leaf
	g2 := deepCopy(g).(map[string]any)
	g2["caveats"] = append(append([]any{}, g2["caveats"].([]any)...), map[string]any{"type": "expires", "at": jsonNumberOf(g01Now + 60_000)})
	in := g01DynIn(g2)
	if r := Authorize(p, in); r.Checks["delegated_caveats"] != "pass" {
		t.Fatalf("longer grant: %v %q", r.Checks, r.Reasons)
	}
}

func TestG01DynamicReplayNeedsTheGrantID(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	g2 := deepCopy(g).(map[string]any)
	delete(g2, "id")
	in := g01DynIn(g2)
	store := NewMemoryStateStore()
	if _, err := store.Claim(StateKey("", k.agent.Public), 100); err != nil {
		t.Fatal(err)
	}
	in.StateStore = store
	r := Authorize(p, in)
	if r.Allow || r.Checks["replay"] != "pass" || g01HasPrefix(r.Reasons, "replay:") {
		t.Fatalf("no grant id: %v %q", r.Checks, r.Reasons)
	}
}

func TestG01DynamicK1(t *testing.T) {
	k := g01Keyset(t)
	noInput := "the caveat language is not configured (no k1 input)"
	k1 := func(map[string]any) (*K1Input, error) { return &K1Input{}, nil }

	// T1: a root sealed caveat with no K1 option fails closed under delegated_caveats; the policy step leaves it to K1
	gs := g01Grant(t, k.principal, k.agent, nil, SealedCaveat())
	r := Authorize(g01Act(t, gs, []map[string]any{gs}, k.agent, "", g01Now, 1, nil), g01DynIn(gs))
	want := "delegated_caveats: delegation caveat(s) not satisfied: sealed (" + noInput + ")"
	if r.Allow || r.Checks["delegated_caveats"] != "fail" || !g01Has(r.Reasons, want) || r.Checks["policy"] != "pass" {
		t.Fatalf("T1: %v %q", r.Checks, r.Reasons)
	}

	// T2: no K1 caveat and no K1 option: K1 is not evaluated (an unsafe clock would fail it)
	g := g01Grant(t, k.principal, k.agent, nil)
	in := g01DynIn(g)
	in.Now = maxSafeInt + 3
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), in); r.Checks["delegated_caveats"] != "pass" {
		t.Fatalf("T2: %v %q", r.Checks, r.Reasons)
	}

	// T3: sealed with a K1 input: allowed, the policy step skips the K1 type
	in = g01DynIn(gs)
	in.K1 = k1
	if r := Authorize(g01Act(t, gs, []map[string]any{gs}, k.agent, "", g01Now, 1, nil), in); !r.Allow || r.Checks["policy"] != "pass" {
		t.Fatalf("T3: %v %q", r.Checks, r.Reasons)
	}

	// T5: a delegation hop appends sealed: with K1 it leaves the stock list
	in = g01DynIn(g)
	in.K1 = k1
	if r := Authorize(g01Act(t, g, g01Sub(t, k, g, []any{SealedCaveat()}), k.sub, "", g01Now, 1, nil), in); r.Checks["delegated_caveats"] != "pass" {
		t.Fatalf("T5: %v %q", r.Checks, r.Reasons)
	}

	// narrow block bound to this action: Authorize computes the action digest itself
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	ad, err := DischargeActionDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := CapHash(g)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := SignNarrow(k.agent, ch, []any{map[string]any{"type": "expires", "at": jsonNumberOf(g01Now + 60_000)}}, g01Now, g01Now+60_000, ad, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	in = g01DynIn(g)
	in.K1 = func(map[string]any) (*K1Input, error) { return &K1Input{Narrow: nb, HasNarrow: true}, nil }
	if r := Authorize(p, in); !r.Allow || r.Checks["delegated_caveats"] != "pass" {
		t.Fatalf("narrow: %v %q", r.Checks, r.Reasons)
	}

	defer g01PassHook(nil)()
	// T6: no chain: the root's K1 failure is reported under policy
	r = Authorize(g01Act(t, gs, []map[string]any{}, k.agent, "", g01Now, 1, nil), g01DynIn(gs))
	if want := "policy: k1 caveat(s) not satisfied: sealed (" + noInput + ")"; !g01Has(r.Reasons, want) {
		t.Fatalf("T6: %q", r.Reasons)
	}
	// T7: no chain, nothing K1: policy passes with and without a K1 input
	for _, withK1 := range []bool{false, true} {
		in = g01DynIn(g)
		if withK1 {
			in.K1 = k1
		}
		if r := Authorize(g01Act(t, g, []map[string]any{}, k.agent, "", g01Now, 1, nil), in); r.Checks["policy"] != "pass" {
			t.Fatalf("T7 k1=%v: %v %q", withK1, r.Checks, r.Reasons)
		}
	}
}

func TestG01DynamicMaxUses(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil, MaxUsesCaveat("u1", 1, g01Now+3_600_000))
	chain := []map[string]any{g}
	in := g01DynIn(g)
	in.K1 = func(map[string]any) (*K1Input, error) { return &K1Input{}, nil }
	nostore := in
	if r := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), nostore); r.Allow || r.Checks["max_uses"] != "fail" ||
		r.Reason != "max_uses: the chain carries a max_uses caveat and this guard has no UsesStore (fail closed)" {
		t.Fatalf("no UsesStore: %v %q", r.Checks, r.Reason)
	}
	in.StateStore = NewMemoryStateStore()
	in.UsesStore = NewMemoryStateStore()
	if r := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), in); !r.Allow {
		t.Fatalf("first use: %v %q", r.Checks, r.Reasons)
	}
	r := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 2, nil), in)
	if r.Allow || r.Checks["max_uses"] != "fail" || !strings.HasPrefix(r.Reason, "max_uses: ") {
		t.Fatalf("second use: %v %q", r.Checks, r.Reason)
	}
}

func TestG01DynamicUnhashablePCActn(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	p["threshold"] = make(chan int)
	// the core verifier stops at the unhashable PCActn, so its later checks are absent: report them all as passing
	authorizeCoreHook = func(core *Verdict) {
		for _, n := range []string{"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion",
			"leaf_signature", "counter_format"} {
			core.Checks[n] = true
		}
		core.Allow, core.Reason, core.Reasons = true, "", nil
	}
	defer func() { authorizeCoreHook = nil }()
	r := Authorize(p, g01DynIn(g))
	want := "authorize: error (fail closed): canonicalize: unsupported type chan int"
	if r.Allow || r.Status != 403 || !reflect.DeepEqual(r.Checks, map[string]string{"authorize": "fail"}) || r.Reason != want {
		t.Fatalf("unhashable: %+v", r)
	}
}
