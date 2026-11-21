package pca

// The attestation and zk verifier hooks of the core verifier, of Authorize and of the guards. A carried zk_compliance proof is
// verified when a zk hook enforces it and is refused otherwise (no hook, or a hook that did not enforce): the fail-closed
// default. A grant that binds the agent passes only with an enforced attestation. The PCActn, the grant and the compliance
// statement are the reference's (the zk corpus, case createZkVerifier/ok).

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type zkHookFunc func(ctx map[string]any) ZkHookResult

func (f zkHookFunc) Verify(ctx map[string]any) ZkHookResult { return f(ctx) }

type attestationHookFunc func(ctx map[string]any) AttestationHookResult

func (f attestationHookFunc) Verify(ctx map[string]any) AttestationHookResult { return f(ctx) }

// hookFixture is the reference's action with its compliance statement, the same action without one, its grant, the verification
// time and the zk verifier of the case.
type hookFixture struct {
	p, plain, grant map[string]any
	now             int64
	aud             string
	zk              func(edit func(*ZkVerifierOpts)) *ZkVerifier
}

func loadHookFixture(t *testing.T) hookFixture {
	t.Helper()
	var f hookFixture
	baseEachOrdered(t, zkCorpus, func(c *baseCase) {
		if c.Name != "createZkVerifier/ok" {
			return
		}
		spec, ctx := vecObj(vecArg(c.Args, 0)), vecObj(vecArg(c.Args, 1))
		f.p, f.grant = vecObj(ctx["pcactn"]), vecObj(ctx["grant"])
		f.now, _ = baseI64(spec["nowMs"])
		f.aud, _ = f.p["aud"].(string)
		f.zk = func(edit func(*ZkVerifierOpts)) *ZkVerifier {
			now := f.now
			o := ZkVerifierOpts{TrustedProverKeys: vecStrs(spec, "trustedProverKeys"), PolicyCommitments: vecStrs(spec, "policyCommitments"), Now: func() int64 { return now }}
			if edit != nil {
				edit(&o)
			}
			v, err := CreateZkVerifier(o)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	})
	if f.p == nil || f.grant == nil || f.aud == "" || f.p["zk_compliance"] == nil {
		t.Fatal("the corpus has no createZkVerifier/ok case")
	}
	f.plain = f.copy(f.p)
	delete(f.plain, "zk_compliance")
	// The oracle attaches the proof AFTER signing, so the carried signature does not cover it, but `zk_compliance` is a signed member:
	// re-sign both forms with the oracle's agent key (the label "zk/agent") so the leaf check is the same for each.
	d := sha256.Sum256([]byte("atlas-pca-conformance/zk/agent"))
	kp, err := KeyPairFromSeed(d[:])
	if err != nil {
		t.Fatal(err)
	}
	if chain, _ := f.p["cap_chain"].([]any); len(chain) > 0 {
		if leaf, _ := chain[len(chain)-1].(map[string]any); leaf["holder"] != kp.Public {
			t.Fatalf("the corpus leaf holder is not the oracle's agent key")
		}
	}
	for _, m := range []map[string]any{f.p, f.plain} {
		body := f.copy(m)
		delete(body, "sig")
		signed, err := SignPCActn(body, kp, nil)
		if err != nil {
			t.Fatal(err)
		}
		m["sig"] = signed["sig"]
	}
	return f
}

func (f hookFixture) copy(m map[string]any) map[string]any { return normalizeJSON(m).(map[string]any) }

func (f hookFixture) core(t *testing.T, p map[string]any, o VerifyOptions) Verdict {
	t.Helper()
	o.InsecureSkipPlanRootCheck = true
	v, err := VerifyPCActnCoreWith(f.copy(p), f.grant, f.now, f.aud, o)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// without returns the checks of v except one.
func checksWithout(m map[string]bool, name string) map[string]bool {
	out := map[string]bool{}
	for k, x := range m {
		if k != name {
			out[k] = x
		}
	}
	return out
}

func TestCoreZkHook(t *testing.T) {
	f := loadHookFixture(t)
	base := f.core(t, f.plain, VerifyOptions{})
	if _, has := base.Checks["zk_compliance"]; has {
		t.Fatal("no carried proof means no zk_compliance check")
	}
	// the zk check is the only difference a carried proof makes: its reason is the verdict's when nothing else failed
	reasonIs := func(v Verdict, want string) bool { return !base.Allow || v.Reason == want }
	refused := func(name string, v Verdict, why string) {
		t.Helper()
		if ok, has := v.Checks["zk_compliance"]; v.Allow || !has || ok || !reasonIs(v, "zk_compliance: "+why) || !reflect.DeepEqual(checksWithout(v.Checks, "zk_compliance"), base.Checks) {
			t.Fatalf("%s: allow %v, checks %v, reason %q", name, v.Allow, v.Checks, v.Reason)
		}
	}

	// fail closed: no hook, and a hook that did not enforce
	refused("no hook", f.core(t, f.p, VerifyOptions{}), zkNoVerifierReason)
	for name, res := range map[string]ZkHookResult{"zero result": {}, "ok without enforced": {OK: true}, "reason without enforced": {OK: true, Reason: "x"}} {
		res := res
		refused(name, f.core(t, f.p, VerifyOptions{Zk: zkHookFunc(func(map[string]any) ZkHookResult { return res })}), zkNoVerifierReason)
	}
	if v := f.core(t, f.p, VerifyOptions{Zk: (*ZkVerifier)(nil)}); v.Allow || v.Checks["zk_compliance"] {
		t.Fatalf("a nil verifier in the hook: %v", v.Checks)
	}

	// the real verifier passes the check for the reference's statement, and sees {pcactn, grant, nowEpoch}
	var seen []map[string]any
	inner := f.zk(nil)
	v := f.core(t, f.p, VerifyOptions{Zk: zkHookFunc(func(ctx map[string]any) ZkHookResult {
		seen = append(seen, ctx)
		return inner.Verify(ctx)
	})})
	if ok := v.Checks["zk_compliance"]; !ok || v.Allow != base.Allow || v.Reason != base.Reason || !reflect.DeepEqual(checksWithout(v.Checks, "zk_compliance"), base.Checks) {
		t.Fatalf("a valid statement: allow %v (without a proof %v), checks %v, reason %q", v.Allow, base.Allow, v.Checks, v.Reason)
	}
	if len(seen) != 1 || !reflect.DeepEqual(seen[0]["grant"], any(f.grant)) || jsF(seen[0]["nowEpoch"]) != float64(f.now) ||
		!reflect.DeepEqual(vecObj(seen[0]["pcactn"])["zk_compliance"], f.p["zk_compliance"]) || len(seen[0]) != 3 {
		t.Fatalf("the hook context: %v", seen)
	}
	if v := f.core(t, f.p, VerifyOptions{Zk: inner}); !v.Checks["zk_compliance"] {
		t.Fatalf("the verifier itself is a hook: %v", v.Checks)
	}

	// a rejected statement fails the check with the verifier's reason
	refused("no trusted prover", f.core(t, f.p, VerifyOptions{Zk: f.zk(func(o *ZkVerifierOpts) { o.TrustedProverKeys = nil })}), "prover key is not trusted")
	refused("a late clock", f.core(t, f.p, VerifyOptions{Zk: f.zk(func(o *ZkVerifierOpts) { o.Now = func() int64 { return f.now + 1_000_000_000 } })}), "compliance statement expired")
	tampered := f.copy(f.p)
	vecObj(tampered["zk_compliance"])["plan_commit"] = "AAAA"
	if v := f.core(t, tampered, VerifyOptions{Zk: f.zk(nil)}); v.Allow || v.Checks["zk_compliance"] {
		t.Fatalf("a tampered statement: %v", v.Checks)
	}
	// an enforced refusal without a reason, and a hook that panics, both deny
	refused("no reason", f.core(t, f.p, VerifyOptions{Zk: zkHookFunc(func(map[string]any) ZkHookResult { return ZkHookResult{Enforced: true} })}), "rejected")
	refused("a panic", f.core(t, f.p, VerifyOptions{Zk: zkHookFunc(func(map[string]any) ZkHookResult { panic("verifier down") })}), "zk verification error (fail closed): verifier down")

	// no carried proof: no zk check and the hook is not called
	called := 0
	v = f.core(t, f.plain, VerifyOptions{Zk: zkHookFunc(func(map[string]any) ZkHookResult { called++; return ZkHookResult{Enforced: true, OK: true} })})
	if called != 0 || !reflect.DeepEqual(v.Checks, base.Checks) || v.Allow != base.Allow {
		t.Fatalf("no proof: hook called %d times, checks %v", called, v.Checks)
	}
}

func TestCoreAttestationHook(t *testing.T) {
	f := loadHookFixture(t)
	base := f.core(t, f.plain, VerifyOptions{})
	if _, has := base.Checks["attestation"]; has {
		t.Fatal("no hook means no attestation check")
	}
	hook := func(res AttestationHookResult, seen *[]map[string]any) AttestationVerifierHook {
		return attestationHookFunc(func(ctx map[string]any) AttestationHookResult {
			if seen != nil {
				*seen = append(*seen, ctx)
			}
			return res
		})
	}
	var seen []map[string]any
	v := f.core(t, f.plain, VerifyOptions{Attestation: hook(AttestationHookResult{Enforced: true, OK: true}, &seen)})
	if !v.Checks["attestation"] || v.Allow != base.Allow || v.Reason != base.Reason || !reflect.DeepEqual(checksWithout(v.Checks, "attestation"), base.Checks) {
		t.Fatalf("a passing hook changes only its check: %v %q", v.Checks, v.Reason)
	}
	if len(seen) != 1 || !reflect.DeepEqual(seen[0]["grant"], any(f.grant)) || jsF(seen[0]["nowEpoch"]) != float64(f.now) || vecObj(seen[0]["pcactn"])["aud"] != any(f.aud) {
		t.Fatalf("the hook context: %v", seen)
	}
	for want, res := range map[string]AttestationHookResult{"measurement not allowlisted": {Enforced: true, Reason: "measurement not allowlisted"}, "rejected": {Enforced: true}} {
		v := f.core(t, f.plain, VerifyOptions{Attestation: hook(res, nil)})
		if ok, has := v.Checks["attestation"]; v.Allow || !has || ok || (base.Allow && v.Reason != "attestation: "+want) {
			t.Fatalf("an enforced refusal (%s): %v %q", want, v.Checks, v.Reason)
		}
	}
	for name, res := range map[string]AttestationHookResult{"not enforced": {}, "ok without enforced": {OK: true, Present: true, Bound: true}} {
		v := f.core(t, f.plain, VerifyOptions{Attestation: hook(res, nil)})
		if _, has := v.Checks["attestation"]; has || v.Allow != base.Allow {
			t.Fatalf("%s: the check must stay unreported: %v", name, v.Checks)
		}
	}
	v = f.core(t, f.plain, VerifyOptions{Attestation: attestationHookFunc(func(map[string]any) AttestationHookResult { panic("down") })})
	if ok, has := v.Checks["attestation"]; v.Allow || !has || ok || (base.Allow && v.Reason != "attestation: attestation verification error (fail closed): down") {
		t.Fatalf("a panicking hook: %v %q", v.Checks, v.Reason)
	}
	// both hooks on one action: the attestation hook is asked first
	var order []string
	f.core(t, f.p, VerifyOptions{
		Attestation: attestationHookFunc(func(map[string]any) AttestationHookResult {
			order = append(order, "attestation")
			return AttestationHookResult{}
		}),
		Zk: zkHookFunc(func(map[string]any) ZkHookResult { order = append(order, "zk"); return ZkHookResult{} })})
	if strings.Join(order, ",") != "attestation,zk" {
		t.Fatalf("hook order: %v", order)
	}
}

func hasReason(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func TestAuthorizeVerifierHooks(t *testing.T) {
	f := loadHookFixture(t)
	action := vecObj(f.p["action"])
	run := func(p, grant map[string]any, edit func(*AuthorizeInput)) AuthorizeResult {
		in := AuthorizeInput{Operation: &Operation{Verb: vecStr(action, "verb"), Resource: vecStr(action, "resource"), Params: map[string]any{}}, Audience: f.aud,
			ResolveGrant: func(string) (map[string]any, error) { return grant, nil }, StateStore: NewMemoryStateStore(),
			IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }, Now: f.now, Plan: PlanSingleStep}
		if edit != nil {
			edit(&in)
		}
		return Authorize(f.copy(p), in)
	}
	base := run(f.plain, f.grant, nil)
	if _, has := base.Checks["zk_compliance"]; has || base.Checks["wire"] == "fail" || len(base.Checks) < 5 {
		t.Fatalf("the action without a proof: %v %v", base.Checks, base.Reasons)
	}
	const noVerifier = "zk_compliance: " + zkNoVerifierReason

	// a carried proof: refused without a verifier, and with one that did not enforce
	r := run(f.p, f.grant, nil)
	if r.Allow || r.Checks["zk_compliance"] != "fail" || !hasReason(r.Reasons, noVerifier) {
		t.Fatalf("no zk hook: %v %v", r.Checks, r.Reasons)
	}
	r = run(f.p, f.grant, func(in *AuthorizeInput) {
		in.Zk = zkHookFunc(func(map[string]any) ZkHookResult { return ZkHookResult{OK: true} })
	})
	if r.Allow || r.Checks["zk_compliance"] != "fail" || !hasReason(r.Reasons, noVerifier) {
		t.Fatalf("a hook that did not enforce: %v %v", r.Checks, r.Reasons)
	}
	// verified by the zk verifier: the check passes, nothing else changes, and the report names what it rested on
	var seen []map[string]any
	inner := f.zk(nil)
	r = run(f.p, f.grant, func(in *AuthorizeInput) {
		in.Zk = zkHookFunc(func(ctx map[string]any) ZkHookResult { seen = append(seen, ctx); return inner.Verify(ctx) })
	})
	if r.Checks["zk_compliance"] != "pass" || hasReason(r.Reasons, "zk_compliance") || r.Allow != base.Allow || !reflect.DeepEqual(r.Reasons, base.Reasons) {
		t.Fatalf("a verified proof: %v %v (without a proof: %v)", r.Checks, r.Reasons, base.Reasons)
	}
	if len(seen) != 1 || !reflect.DeepEqual(seen[0]["grant"], any(f.grant)) || jsF(seen[0]["nowEpoch"]) != float64(f.now) || vecObj(seen[0]["pcactn"])["zk_compliance"] == nil {
		t.Fatalf("the hook context: %v", seen)
	}
	r = run(f.p, f.grant, func(in *AuthorizeInput) { in.Zk = inner })
	if e, has := r.Assurance.Get("zk_compliance"); r.Checks["zk_compliance"] != "pass" || !has || e.Outcome != "pass" || e.Level != "attested_vm" {
		t.Fatalf("the report of a verified proof: %v %+v", r.Checks, e)
	}
	r = run(f.p, f.grant, func(in *AuthorizeInput) {
		in.Zk, in.AssuranceHooks.Zk = inner, WithAssuranceLabel("mine", AssuranceLabel{Level: "groth16"})
	})
	if e, _ := r.Assurance.Get("zk_compliance"); e.Level != "groth16" {
		t.Fatalf("an explicit assurance hook keeps its label: %+v", e)
	}
	// rejected by the verifier, with its reason
	r = run(f.p, f.grant, func(in *AuthorizeInput) {
		in.Zk = f.zk(func(o *ZkVerifierOpts) { o.RevokedProverKeys = o.TrustedProverKeys })
	})
	if r.Allow || r.Checks["zk_compliance"] != "fail" || !hasReason(r.Reasons, "zk_compliance: prover key is revoked") || hasReason(r.Reasons, noVerifier) {
		t.Fatalf("a revoked prover: %v %v", r.Checks, r.Reasons)
	}
	// no carried proof: the hook is not asked
	called := 0
	r = run(f.plain, f.grant, func(in *AuthorizeInput) {
		in.Zk = zkHookFunc(func(map[string]any) ZkHookResult { called++; return ZkHookResult{Enforced: true, OK: true} })
	})
	if _, has := r.Checks["zk_compliance"]; has || called != 0 || !reflect.DeepEqual(r.Reasons, base.Reasons) {
		t.Fatalf("no proof: %v, hook called %d times", r.Checks, called)
	}

	// attestation. A grant that does not bind the agent: the hook decides its check, and no hook leaves it alone.
	pass := attestationHookFunc(func(map[string]any) AttestationHookResult {
		return AttestationHookResult{Enforced: true, OK: true, Present: true, Bound: true}
	})
	idle := attestationHookFunc(func(map[string]any) AttestationHookResult { return AttestationHookResult{} })
	deny := attestationHookFunc(func(map[string]any) AttestationHookResult {
		return AttestationHookResult{Enforced: true, Reason: "quote expired"}
	})
	const required = "attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED"
	if base.Checks["attestation"] == "fail" || hasReason(base.Reasons, "attestation") {
		t.Fatalf("an unbound grant needs no attestation: %v", base.Reasons)
	}
	r = run(f.plain, f.grant, func(in *AuthorizeInput) { in.Attestation = pass })
	if e, _ := r.Assurance.Get("attestation"); r.Checks["attestation"] != "pass" || r.Allow != base.Allow || !reflect.DeepEqual(r.Reasons, base.Reasons) || e.Outcome != "pass" {
		t.Fatalf("a passing hook on an unbound grant: %v %v", r.Checks, r.Reasons)
	}
	r = run(f.plain, f.grant, func(in *AuthorizeInput) { in.Attestation = idle })
	if r.Checks["attestation"] == "fail" || r.Checks["attestation"] == "pass" || hasReason(r.Reasons, "attestation") {
		t.Fatalf("a hook that did not enforce, unbound grant: %v %v", r.Checks, r.Reasons)
	}
	r = run(f.plain, f.grant, func(in *AuthorizeInput) { in.Attestation = deny })
	coreClean := base.Verdict != nil && base.Verdict.Allow // then the hook's refusal is the core's first, and so its reported, reason
	if r.Allow || r.Checks["attestation"] != "fail" || hasReason(r.Reasons, required) || (coreClean && !hasReason(r.Reasons, "attestation: quote expired")) {
		t.Fatalf("a refusing hook on an unbound grant: %v %v", r.Checks, r.Reasons)
	}

	// A grant that binds the agent REQUIRES an enforced, passing attestation. (The edited grant no longer verifies as a chain;
	// only the attestation check is read here.)
	bound := f.copy(f.grant)
	edited := false
	for _, c := range bound["caveats"].([]any) {
		if cv := vecObj(c); cv != nil && cv["agent_binding"] != nil {
			cv["agent_binding"], edited = map[string]any{"operator": "acme"}, true
		}
	}
	if env := ReadEnvelope(bound); !edited || env == nil || !requiresAttestation(env["agent_binding"]) {
		t.Fatal("the grant carries no envelope to bind")
	}
	r = run(f.plain, bound, nil)
	if r.Allow || r.Checks["attestation"] != "fail" || !hasReason(r.Reasons, required+" (no attestation verifier in this SDK: fail closed)") {
		t.Fatalf("a bound grant without a verifier: %v %v", r.Checks, r.Reasons)
	}
	r = run(f.plain, bound, func(in *AuthorizeInput) { in.Attestation = idle })
	if n := len(r.Reasons); r.Allow || r.Checks["attestation"] != "fail" || !hasReason(r.Reasons, required) || hasReason(r.Reasons, required+" (") || n == 0 {
		t.Fatalf("a bound grant with a verifier that did not enforce: %v %v", r.Checks, r.Reasons)
	}
	r = run(f.plain, bound, func(in *AuthorizeInput) { in.Attestation = deny })
	if r.Allow || r.Checks["attestation"] != "fail" || !hasReason(r.Reasons, required) {
		t.Fatalf("a bound grant with a refusing verifier: %v %v", r.Checks, r.Reasons)
	}
	r = run(f.plain, bound, func(in *AuthorizeInput) { in.Attestation = pass })
	if r.Checks["attestation"] != "pass" || hasReason(r.Reasons, "attestation") {
		t.Fatalf("a bound grant with an enforced, passing attestation: %v %v", r.Checks, r.Reasons)
	}
}

func TestGuardsForwardTheVerifierHooks(t *testing.T) {
	f := loadHookFixture(t)
	action := vecObj(f.p["action"])
	inner := f.zk(nil)
	label := WithAssuranceLabel("a label, not a verifier", AssuranceLabel{Level: "groth16"})

	// the executor: ExecutionHooks.Zk decides the check when it is a verifier; a value that only labels does not
	execute := func(p map[string]any, hooks ExecutionHooks) map[string]string {
		dec := AuthorizeExecution(f.copy(p), ExecutionOperation{Verb: vecStr(action, "verb"), Resource: vecStr(action, "resource"), Params: map[string]any{}},
			AuthorizeExecutionOptions{Audience: f.aud, Grant: f.grant, State: NewMemoryStateStore(), IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil },
				Now: func() int64 { return f.now }, Hooks: hooks})
		if dec.Verdict != nil {
			return dec.Verdict.Checks
		}
		return dec.Checks
	}
	if c := execute(f.p, ExecutionHooks{}); c["zk_compliance"] != "fail" {
		t.Fatalf("the executor without a zk hook: %v", c)
	}
	if c := execute(f.p, ExecutionHooks{Zk: label}); c["zk_compliance"] != "fail" {
		t.Fatalf("the executor with a label only: %v", c)
	}
	if c := execute(f.p, ExecutionHooks{Zk: inner}); c["zk_compliance"] != "pass" {
		t.Fatalf("the executor with the zk verifier: %v", c)
	}
	att := attestationHookFunc(func(map[string]any) AttestationHookResult { return AttestationHookResult{Enforced: true, OK: true} })
	if c := execute(f.plain, ExecutionHooks{Attestation: att}); c["attestation"] != "pass" {
		t.Fatalf("the executor with an attestation verifier: %v", c)
	}
	if c := execute(f.plain, ExecutionHooks{Attestation: label}); c["attestation"] == "pass" {
		t.Fatalf("the executor with an attestation label only: %v", c)
	}

	// the HTTP guard, signature-only and Authorize mode: the status of the action with a verified proof is the status of the same
	// action without one, and a carried proof without a verifier is 403 and never reaches the handler
	body := func(p map[string]any) string {
		s, err := Canonicalize(p)
		if err != nil {
			t.Fatal(err)
		}
		return `{"pcactn":` + s + `}` // the guard reads the PCActn from the body's `pcactn` member
	}
	resolve := func(string) (map[string]any, error) { return f.grant, nil }
	serve := func(o RequirePCAOptions, p map[string]any) (status int, reached bool, text string) {
		o.Audience, o.ResolveGrant, o.Now = f.aud, resolve, func() int64 { return f.now }
		h := RequirePCA(o)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusOK) }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/act", strings.NewReader(body(p))))
		return rec.Code, reached, rec.Body.String()
	}
	modes := map[string]func(att AttestationVerifierHook, zk ZkVerifierHook) RequirePCAOptions{
		"signature-only": func(att AttestationVerifierHook, zk ZkVerifierHook) RequirePCAOptions {
			return RequirePCAOptions{SignatureOnly: true, InsecureSkipPlanRootCheck: true, Attestation: att, Zk: zk}
		},
		"authorize": func(att AttestationVerifierHook, zk ZkVerifierHook) RequirePCAOptions {
			return RequirePCAOptions{Authorize: &AuthorizeOptions{StateStore: NewMemoryStateStore(), IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil },
				Plan: PlanSingleStep, Attestation: att, Zk: zk,
				Operation: func(*http.Request, []byte) (*Operation, error) {
					return &Operation{Verb: vecStr(action, "verb"), Resource: vecStr(action, "resource"), Params: map[string]any{}}, nil
				}}}
		},
	}
	refusing := attestationHookFunc(func(map[string]any) AttestationHookResult {
		return AttestationHookResult{Enforced: true, Reason: "quote expired"}
	})
	for name, mode := range modes {
		plainStatus, plainReached, _ := serve(mode(nil, nil), f.plain)
		if status, reached, text := serve(mode(nil, nil), f.p); status != http.StatusForbidden || reached || (plainReached && !strings.Contains(text, "zk_compliance")) {
			t.Fatalf("%s: a carried proof without a verifier: %d, handler reached %v, %s", name, status, reached, text)
		}
		if status, reached, text := serve(mode(nil, inner), f.p); status != plainStatus || reached != plainReached {
			t.Fatalf("%s: a verified proof: %d (without a proof %d), %s", name, status, plainStatus, text)
		}
		if status, reached, text := serve(mode(refusing, nil), f.plain); status != http.StatusForbidden || reached || (plainReached && !strings.Contains(text, "quote expired")) {
			t.Fatalf("%s: a refusing attestation verifier: %d, handler reached %v, %s", name, status, reached, text)
		}
	}
}
