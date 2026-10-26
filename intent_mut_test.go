package pca

// Mutation-kill tests for the Intent Layer M2 code paths (intent.go + the `intent` hooks in pca.go): every boundary is
// pinned on both sides so an off-by-one, negated or deleted branch changes a verdict. Uses the intent fixture of
// intent_test.go (newIntentFx / tIntent / boundCommit).

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// signedWith builds a bound-grant fixture whose PCActn carries `intent` mutated by mut (re-signed).
func signedWith(t *testing.T, mut func(m map[string]any) any) *fx {
	f := newIntentFx(t, boundCommit(t))
	f.p["intent"] = mut(tIntent())
	f.resign()
	return f
}

func set(k string, v any) func(m map[string]any) any {
	return func(m map[string]any) any { m[k] = v; return m }
}

func del(k string) func(m map[string]any) any {
	return func(m map[string]any) any { delete(m, k); return m }
}

func mustWire(t *testing.T, name string, v Verdict) {
	t.Helper()
	if v.Allow || len(v.Checks) != 1 || v.Checks["wire"] || !strings.HasPrefix(v.Reason, "wire: ") {
		t.Fatalf("%s: want terminal wire failure, got %+v", name, v)
	}
}

func mustIntentPass(t *testing.T, name string, v Verdict) {
	t.Helper()
	if !v.Allow || !v.Checks["intent"] || len(v.Checks) != 10 || v.Reason != "" {
		t.Fatalf("%s: want allow with intent pass, got %+v", name, v)
	}
}

func mustIntentFail(t *testing.T, name, why string, v Verdict) {
	t.Helper()
	got, has := v.Checks["intent"]
	if v.Allow || !has || got || len(v.Checks) != 10 || !strings.HasPrefix(v.Reason, "intent: ") || !strings.Contains(v.Reason, why) {
		t.Fatalf("%s: want intent failure (%q), got %+v", name, why, v)
	}
	for _, c := range []string{"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"} {
		if !v.Checks[c] {
			t.Fatalf("%s: check %s must pass", name, c)
		}
	}
}

// ---- wire: every member rule, both sides of every boundary --------------------------------------------------

func TestMutIntentWireAcceptedBoundaries(t *testing.T) {
	salt128 := strings.Repeat("é", 64)
	cases := map[string]struct {
		mut  func(m map[string]any) any
		salt string
	}{
		"fidelity-0":        {set("fidelity_ppm", jnum(0)), tSalt},
		"fidelity-1000000":  {set("fidelity_ppm", jnum(1_000_000)), tSalt},
		"residual-0":        {set("residual_risk_ppm", jnum(0)), tSalt},
		"residual-max-safe": {set("residual_risk_ppm", jnum(9_007_199_254_740_991)), tSalt},
		"salt-1-byte":       {set("goal_salt", "s"), "s"},
		"salt-128-bytes":    {set("goal_salt", salt128), salt128},
	}
	for name, c := range cases {
		gc, _ := IntentGoalCommit(tRef(), tMap(), c.salt)
		f := newIntentFx(t, gc)
		f.p["intent"] = c.mut(tIntent())
		f.resign()
		mustIntentPass(t, name, f.verifyIntent(nil))
	}
}

func TestMutIntentWireRefusals(t *testing.T) {
	cases := map[string]func(m map[string]any) any{
		"null":               func(map[string]any) any { return nil },
		"array":              func(m map[string]any) any { return []any{m} },
		"string":             func(map[string]any) any { return "x" },
		"number":             func(map[string]any) any { return jnum(1) },
		"extra-member":       set("extra", "x"),
		"missing-ref":        del("ref"),
		"missing-map-digest": del("map_digest"),
		"missing-goal-salt":  del("goal_salt"),
		"missing-fidelity":   del("fidelity_ppm"),
		"missing-residual":   del("residual_risk_ppm"),
		"ref-31-bytes":       set("ref", b64.EncodeToString(make([]byte, 31))),
		"ref-33-bytes":       set("ref", b64.EncodeToString(make([]byte, 33))),
		"ref-padded":         set("ref", tRef()+"="),
		"ref-number":         set("ref", jnum(1)),
		"map-31-bytes":       set("map_digest", b64.EncodeToString(make([]byte, 31))),
		"map-std-alphabet":   set("map_digest", "+"+tMap()[1:]),
		"map-null":           set("map_digest", nil),
		"salt-empty":         set("goal_salt", ""),
		"salt-129-bytes":     set("goal_salt", strings.Repeat("é", 64)+"a"),
		"salt-number":        set("goal_salt", jnum(5)),
		"salt-null":          set("goal_salt", nil),
		"fidelity-minus-1":   set("fidelity_ppm", jnum(-1)),
		"fidelity-1000001":   set("fidelity_ppm", jnum(1_000_001)),
		"fidelity-fraction":  set("fidelity_ppm", json.Number("1.5")),
		"fidelity-string":    set("fidelity_ppm", "950000"),
		"fidelity-bool":      set("fidelity_ppm", true),
		"residual-minus-1":   set("residual_risk_ppm", jnum(-1)),
		"residual-fraction":  set("residual_risk_ppm", json.Number("0.25")),
		"residual-bool":      set("residual_risk_ppm", true),
		"residual-string":    set("residual_risk_ppm", "0"),
	}
	for name, mut := range cases {
		mustWire(t, name, signedWith(t, mut).verifyIntent(nil))
	}
	// The direct wire validator agrees, member by member, and names the member.
	for k, want := range map[string]string{"ref": "'intent.ref'", "map_digest": "'intent.map_digest'", "goal_salt": "'intent.goal_salt'",
		"fidelity_ppm": "'intent.fidelity_ppm'", "residual_risk_ppm": "'intent.residual_risk_ppm'"} {
		m := tIntent()
		m[k] = jnum(-1)
		if k == "fidelity_ppm" || k == "residual_risk_ppm" {
			m[k] = "x"
		}
		if got := validateIntentWire(m); !strings.Contains(got, want) {
			t.Fatalf("%s: %q", k, got)
		}
		delete(m, k)
		if got := validateIntentWire(m); got != "missing field 'intent."+k+"'" {
			t.Fatalf("missing %s: %q", k, got)
		}
	}
	if got := validateIntentWire(tIntent()); got != "" {
		t.Fatalf("well-formed slot refused: %q", got)
	}
}

// ---- policy activation and misconfiguration ----------------------------------------------------------------

func TestMutIntentPolicyActivation(t *testing.T) {
	f := newIntentFx(t, boundCommit(t)) // PCActn WITHOUT intent
	for name, pol := range map[string]*IntentPolicy{"nil": nil, "empty": {}, "require-false": {Require: false}} {
		v := f.verifyIntent(pol)
		if _, has := v.Checks["intent"]; has || !v.Allow || len(v.Checks) != 9 {
			t.Fatalf("%s: inactive policy must not report intent: %+v", name, v)
		}
	}
	for name, pol := range map[string]*IntentPolicy{
		"require-true": {Require: true}, "min-alone": {MinFidelityPpm: fp(0)}, "max-alone": {MaxResidualRiskPpm: fp(0)},
	} {
		mustIntentFail(t, name, "requires an intent binding", f.verifyIntent(pol))
	}
	if (&IntentPolicy{}).active() || (*IntentPolicy)(nil).active() {
		t.Fatal("empty / nil policy is not active")
	}
	if !(&IntentPolicy{Require: true}).active() || !(&IntentPolicy{MinFidelityPpm: fp(1)}).active() || !(&IntentPolicy{MaxResidualRiskPpm: fp(1)}).active() {
		t.Fatal("require or any threshold activates")
	}
}

func TestMutIntentPolicyMisconfigured(t *testing.T) {
	f := signedWith(t, func(m map[string]any) any { return m }) // bound intent
	bad := map[string]float64{"minus-1": -1, "fraction": 0.5, "nan": math.NaN(), "+inf": math.Inf(1), "-inf": math.Inf(-1),
		"minus-zero": math.Copysign(0, -1), "2^53": 9_007_199_254_740_992}
	for name, x := range bad {
		mustIntentFail(t, "min "+name, "misconfigured", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(x)}))
		mustIntentFail(t, "max "+name, "misconfigured", f.verifyIntent(&IntentPolicy{MaxResidualRiskPpm: fp(x)}))
		// one bad threshold poisons the policy even when the other is fine
		mustIntentFail(t, "pair "+name, "misconfigured", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(0), MaxResidualRiskPpm: fp(x)}))
		mustIntentFail(t, "pair2 "+name, "misconfigured", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(x), MaxResidualRiskPpm: fp(0)}))
		if okThreshold(fp(x)) {
			t.Fatalf("okThreshold(%v)", x)
		}
	}
	for _, x := range []float64{0, 1, 9_007_199_254_740_991} {
		if !okThreshold(fp(x)) {
			t.Fatalf("okThreshold(%v) must hold", x)
		}
	}
	if !okThreshold(nil) {
		t.Fatal("unset threshold is fine")
	}
	// misconfiguration is checked BEFORE the absent-slot rule
	g := newIntentFx(t, boundCommit(t))
	mustIntentFail(t, "misconfig-before-absent", "misconfigured", g.verifyIntent(&IntentPolicy{Require: true, MinFidelityPpm: fp(-1)}))
}

func TestMutIntentThresholdsInclusive(t *testing.T) {
	f := signedWith(t, func(m map[string]any) any { return m }) // fidelity 950000, residual 4310000
	mustIntentPass(t, "min ==", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(950_000)}))
	mustIntentPass(t, "min -1", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(949_999)}))
	mustIntentFail(t, "min +1", "below the policy minimum", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(950_001)}))
	mustIntentPass(t, "max ==", f.verifyIntent(&IntentPolicy{MaxResidualRiskPpm: fp(4_310_000)}))
	mustIntentPass(t, "max +1", f.verifyIntent(&IntentPolicy{MaxResidualRiskPpm: fp(4_310_001)}))
	mustIntentFail(t, "max -1", "exceeds the policy maximum", f.verifyIntent(&IntentPolicy{MaxResidualRiskPpm: fp(4_309_999)}))
	mustIntentPass(t, "both ==", f.verifyIntent(&IntentPolicy{Require: true, MinFidelityPpm: fp(950_000), MaxResidualRiskPpm: fp(4_310_000)}))
	// the floor is checked before the ceiling
	mustIntentFail(t, "both fail", "below the policy minimum", f.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(950_001), MaxResidualRiskPpm: fp(0)}))
	// binding is checked before the thresholds
	g := signedWith(t, set("goal_salt", "wrong"))
	mustIntentFail(t, "binding first", "do not open", g.verifyIntent(&IntentPolicy{MinFidelityPpm: fp(950_001)}))
}

// ---- root-grant binding ------------------------------------------------------------------------------------

func TestMutIntentRootGrantBinding(t *testing.T) {
	bc := boundCommit(t)
	env := func(gc any) map[string]any { return map[string]any{"type": "envelope", "goal_commit": gc} }
	// The intent check reads the VERIFIER's grant; a grant that is not the chain root fails `chain` but the intent
	// check is still evaluated against it, which isolates the caveat-scan rules.
	f := signedWith(t, func(m map[string]any) any { return m })
	run := func(grant map[string]any) Verdict {
		v, err := VerifyPCActnCoreWith(f.norm(), grant, f.now, f.aud, VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		name  string
		grant map[string]any
		pass  bool
	}{
		{"non-object-caveat-skipped", map[string]any{"caveats": []any{jnum(5), "x", nil, env(bc)}}, true},
		{"non-envelope-caveat-skipped", map[string]any{"caveats": []any{map[string]any{"type": "max_spend"}, env(bc)}}, true},
		{"untyped-caveat-skipped", map[string]any{"caveats": []any{map[string]any{"goal_commit": "x"}, env(bc)}}, true},
		{"first-envelope-wins", map[string]any{"caveats": []any{env("decoy"), env(bc)}}, false},
		{"first-envelope-bad-type-wins", map[string]any{"caveats": []any{env(jnum(7)), env(bc)}}, false},
		{"goal-commit-number", map[string]any{"caveats": []any{env(jnum(7))}}, false},
		{"goal-commit-missing", map[string]any{"caveats": []any{map[string]any{"type": "envelope"}}}, false},
		{"no-envelope", map[string]any{"caveats": []any{map[string]any{"type": "max_spend"}}}, false},
		{"empty-caveats", map[string]any{"caveats": []any{}}, false},
		{"caveats-not-array", map[string]any{"caveats": env(bc)}, false},
		{"no-caveats-key", map[string]any{}, false},
		{"nil-grant", nil, false},
	}
	for _, c := range cases {
		v := run(c.grant)
		if v.Allow || v.Checks["chain"] {
			t.Fatalf("%s: a foreign grant must fail chain: %+v", c.name, v)
		}
		if got, has := v.Checks["intent"]; !has || got != c.pass {
			t.Fatalf("%s: intent = %v (has %v), want %v (%s)", c.name, got, has, c.pass, v.Reason)
		}
	}
	// reasons of the two binding failures are distinct
	if _, why := decideIntent(map[string]any{"intent": tIntent()}, map[string]any{}, nil); !strings.Contains(why, "no envelope goal commitment") {
		t.Fatalf("no commitment: %q", why)
	}
	if _, why := decideIntent(map[string]any{"intent": tIntent()}, map[string]any{"caveats": []any{env("decoy")}}, nil); !strings.Contains(why, "do not open") {
		t.Fatalf("mismatch: %q", why)
	}
	// each opening input is bound: ref, map_digest and salt each break the commitment
	for _, k := range []string{"ref", "map_digest"} {
		g := signedWith(t, set(k, b64.EncodeToString(sha([]byte("other")))))
		mustIntentFail(t, k+"-mismatch", "do not open", g.verifyIntent(nil))
	}
	mustIntentFail(t, "salt-mismatch", "do not open", signedWith(t, set("goal_salt", tSalt+"x")).verifyIntent(nil))
	// the goal string is "pca-intent:v1:" + ref + ":" + map_digest (a ref-only goal does not open it)
	refOnly, _ := HashCanonical(map[string]any{"d": "atlas-pca/goal/v1\x00", "goal": "pca-intent:v1:" + tRef(), "salt": tSalt})
	h := newIntentFx(t, refOnly)
	h.p["intent"] = tIntent()
	h.resign()
	mustIntentFail(t, "ref-only-goal", "do not open", h.verifyIntent(nil))
	// IntentGoalCommit pins the exact preimage
	want, _ := HashCanonical(map[string]any{"d": "atlas-pca/goal/v1\x00", "goal": "pca-intent:v1:" + tRef() + ":" + tMap(), "salt": tSalt})
	if got, err := IntentGoalCommit(tRef(), tMap(), tSalt); err != nil || got != want {
		t.Fatalf("IntentGoalCommit = %q, %v", got, err)
	}
}

// ---- verdict shape -----------------------------------------------------------------------------------------

func TestMutIntentVerdictShape(t *testing.T) {
	// not evaluated: absent key, 9 checks
	f := newIntentFx(t, boundCommit(t))
	if v := f.verifyIntent(nil); len(v.Checks) != 9 || !v.Allow {
		t.Fatalf("absent: %+v", v)
	} else if _, has := v.Checks["intent"]; has {
		t.Fatal("intent must be absent")
	}
	// evaluated after counter_format: when counter_format AND intent fail, the first reason is counter_format's
	g := signedWith(t, set("goal_salt", "wrong"))
	g.p["counter"] = jnum(-1)
	g.resign()
	v := g.verifyIntent(nil)
	if v.Allow || v.Checks["counter_format"] || v.Checks["intent"] || len(v.Checks) != 10 || !strings.HasPrefix(v.Reason, "counter_format: ") {
		t.Fatalf("counter before intent: %+v", v)
	}
	// ...and an intent failure alone is reported as the reason, with every earlier check passing
	h := signedWith(t, set("goal_salt", "wrong"))
	mustIntentFail(t, "intent alone", "do not open", h.verifyIntent(nil))
	// a wire failure never reports intent, even under an active policy
	w := signedWith(t, set("fidelity_ppm", jnum(-1)))
	mustWire(t, "wire beats policy", w.verifyIntent(&IntentPolicy{Require: true}))
}

func TestMutIntentTamperAfterSigning(t *testing.T) {
	f := signedWith(t, func(m map[string]any) any { return m })
	mustIntentPass(t, "signed", f.verifyIntent(nil))
	f.p["intent"].(map[string]any)["fidelity_ppm"] = jnum(999_999) // NOT re-signed
	v := f.verifyIntent(nil)
	if v.Allow || v.Checks["leaf_signature"] || !v.Checks["intent"] || len(v.Checks) != 10 || !strings.HasPrefix(v.Reason, "leaf_signature: ") {
		t.Fatalf("tamper: %+v", v)
	}
}

// ---- lenient policy loader (conformance runner / driver) ---------------------------------------------------

func TestMutIntentPolicyFromJSON(t *testing.T) {
	if IntentPolicyFromJSON(nil) != nil || IntentPolicyFromJSON([]any{}) != nil || IntentPolicyFromJSON("x") != nil {
		t.Fatal("non-object => nil")
	}
	p := IntentPolicyFromJSON(map[string]any{})
	if p == nil || p.Require || p.MinFidelityPpm != nil || p.MaxResidualRiskPpm != nil || p.active() {
		t.Fatalf("empty object: %+v", p)
	}
	if IntentPolicyFromJSON(map[string]any{"require": true}).Require != true || IntentPolicyFromJSON(map[string]any{"require": "true"}).Require {
		t.Fatal("require is true only for the JSON boolean true")
	}
	for name, c := range map[string]struct {
		in   any
		want float64
	}{
		"float64": {2.5, 2.5}, "int": {int(7), 7}, "int64": {int64(-3), -3}, "json.Number": {json.Number("-1"), -1},
		"json.Number-fraction": {json.Number("0.5"), 0.5},
	} {
		q := IntentPolicyFromJSON(map[string]any{"min_fidelity_ppm": c.in, "max_residual_risk_ppm": c.in})
		if q.MinFidelityPpm == nil || *q.MinFidelityPpm != c.want || q.MaxResidualRiskPpm == nil || *q.MaxResidualRiskPpm != c.want {
			t.Fatalf("%s: %+v", name, q)
		}
	}
	for name, in := range map[string]any{"string": "5", "bool": true, "null": nil, "object": map[string]any{}, "unparseable": json.Number("1e400")} {
		q := IntentPolicyFromJSON(map[string]any{"min_fidelity_ppm": in, "max_residual_risk_ppm": in})
		if q.MinFidelityPpm == nil || !math.IsNaN(*q.MinFidelityPpm) || q.MaxResidualRiskPpm == nil || !math.IsNaN(*q.MaxResidualRiskPpm) {
			t.Fatalf("%s: present non-number must become NaN: %+v", name, q)
		}
		if !q.active() || okThreshold(q.MinFidelityPpm) {
			t.Fatalf("%s: NaN threshold must be active and invalid", name)
		}
	}
}

// A threshold is valid iff its NUMERIC VALUE is a non-negative safe integer, whatever its lexical form.
func TestMutIntentPolicyLexicalForms(t *testing.T) {
	f := signedWith(t, func(m map[string]any) any { return m }) // fidelity 950000, residual 4310000
	pass := map[string]string{
		"float-literal":  `{"min_fidelity_ppm":950000.0}`,
		"exponent":       `{"max_residual_risk_ppm":4.31e6}`,
		"exponent-upper": `{"max_residual_risk_ppm":4.31E+6}`,
		"float-zero":     `{"min_fidelity_ppm":0.0}`,
		"max-safe":       `{"max_residual_risk_ppm":9007199254740991}`,
	}
	for name, text := range pass {
		p, err := IntentPolicyFromJSONText(text)
		if err != nil {
			t.Fatal(err)
		}
		mustIntentPass(t, name, f.verifyIntent(p))
	}
	p, _ := IntentPolicyFromJSONText(`{"min_fidelity_ppm":1e6}`)
	if p.MinFidelityPpm == nil || *p.MinFidelityPpm != 1_000_000 || !okThreshold(p.MinFidelityPpm) {
		t.Fatalf("1e6: %+v", p)
	}
	mustIntentFail(t, "1e6 floor", "below the policy minimum", f.verifyIntent(p))
	bad := map[string]string{
		"minus-zero-float": `{"min_fidelity_ppm":-0.0}`, "minus-zero-int": `{"min_fidelity_ppm":-0}`,
		"fraction": `{"min_fidelity_ppm":950000.5}`, "negative": `{"max_residual_risk_ppm":-1}`,
		"over-safe": `{"max_residual_risk_ppm":9007199254740992}`, "over-safe-exp": `{"max_residual_risk_ppm":1e16}`,
		"overflow": `{"max_residual_risk_ppm":1e400}`, "null": `{"min_fidelity_ppm":null}`,
		"bool": `{"min_fidelity_ppm":true}`, "string": `{"min_fidelity_ppm":"950000"}`,
	}
	for name, text := range bad {
		p, err := IntentPolicyFromJSONText(text)
		if err != nil {
			t.Fatal(err)
		}
		mustIntentFail(t, name, "misconfigured", f.verifyIntent(p))
	}
	for _, text := range []string{`[]`, `"x"`, `{`, `nul`} {
		if _, err := IntentPolicyFromJSONText(text); err == nil {
			t.Fatalf("%s must be an error", text)
		}
	}
}
