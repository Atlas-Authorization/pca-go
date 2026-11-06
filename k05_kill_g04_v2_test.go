package pca

// g04 mutation kills for intent_v2.go: rules 20/21 run on the session pipeline, W-B's single-source worlds and world env
// reach rule 21 (and only when W-B admits), plus the small model-rules helpers.

import (
	"strings"
	"testing"
)

func g04V2RiskPolicy() map[string]any {
	return map[string]any{"weights": map[string]any{"alpha": jnum(0), "beta": jnum(0), "gamma": jnum(0), "delta": jnum(0), "epsilon": jnum(0), "zeta": jnum(0)},
		"theta1": jnum(0), "theta2": jnum(1), "kappa": jnum(1), "lambda": jnum(0), "rho": jnum(0), "bMax": jnum(1)}
}

// g04V2EnvGrant re-mints the fixture's G_0 with a full (ReadEnvelope-valid) envelope carrying extra, and rebuilds the PCActn.
func g04V2EnvGrant(f *v2fx, extra map[string]any) {
	f.t.Helper()
	gc, err := intentGoalCommitV2(f.session, f.mapD, f.salt, f.committed)
	if err != nil {
		f.t.Fatal(err)
	}
	env := map[string]any{"type": "envelope", "goal_commit": gc, "predicates": []any{}, "caveats": []any{}, "risk_policy": g04V2RiskPolicy(), "agent_binding": map[string]any{}}
	for k, v := range extra {
		env[k] = v
	}
	sc := map[string]any{"type": "intent_session", "session": f.session, "seq": jnum(0), "root": f.R}
	f.grant = mkCap(f.t, f.principal, f.agent.id, []any{env, sc}, "", nil)
	f.build()
}

// g04V2World commits one fresh fact (a single oracle: world "fare" is single-source) and configures W-B for it; provDeny
// adds a provenance policy that denies the (unlabelled, so tainted) material offer_id AFTER the world passed.
func g04V2World(t *testing.T, f *v2fx, provDeny bool) {
	t.Helper()
	o := newKey(t)
	fact := signArt(t, o, factDomain, map[string]any{"v": jnum(1), "kind": "pca-fact", "name": "fare", "subject": "OF-1", "value": jnum(38_900), "t_obs": jnum(v2Now), "oracle": "o0"})
	f.is()["facts"] = []any{refOf(t, factRefDomain, "f", fact)}
	f.resign()
	pol := map[string]any{"world": farePolicy([]fxKey{o}, 1, 0, 1000, nil)}
	if provDeny {
		pol["provenance"] = map[string]any{"params": map[string]any{"action.params.offer_id": "material"}, "material_tainted": "deny"}
	}
	f.ctx["wb"] = map[string]any{"artifacts": map[string]any{"facts": []any{fact}}, "policy": pol}
}

func g04V2Reasons(v Verdict) string { return v.Reason + "\n" + strings.Join(v.Reasons, "\n") }

// The session pipeline runs rules 20/21 last: a policy model_polarity alone reports tighten.
func TestG04V2ModelRulesOnSessionPipeline(t *testing.T) {
	f := newV2Fx(t)
	f.ctx["policy"] = map[string]any{"model_polarity": "legacy"}
	v := f.verify()
	if ok, has := v.Checks["tighten"]; !has || !ok {
		t.Fatalf("tighten: %v (%s)", v.Checks, g04V2Reasons(v))
	}
}

// A single-oracle world makes env.world.fare model-derived: a grant-side where reading it is refused by rule 21.
func TestG04V2SingleSourceReachesRule21(t *testing.T) {
	f := newV2Fx(t)
	g04V2EnvGrant(f, map[string]any{"predicates": []any{map[string]any{"verb": "air.book",
		"where": []any{map[string]any{"field": "env.world.fare", "op": "exists"}}}}})
	g04V2World(t, f, false)
	v := f.verify()
	if ok, has := v.Checks["facts"]; !has || !ok {
		t.Fatalf("facts: %v (%s)", v.Checks, g04V2Reasons(v))
	}
	if ok, has := v.Checks["tighten"]; !has || ok || !strings.Contains(g04V2Reasons(v), "env.world.fare") {
		t.Fatalf("tighten: %v (%s)", v.Checks, g04V2Reasons(v))
	}
}

// The world env W-B computed is visible to tighten[] when W-B admits, and NOT when W-B denies.
func TestG04V2WorldEnvOnlyWhenAdmitted(t *testing.T) {
	rule := map[string]any{"tighten": []any{map[string]any{"id": "g04w", "when": map[string]any{"field": "env.world.fare", "op": "exists"}, "signal": "deny"}}}
	f := newV2Fx(t)
	g04V2EnvGrant(f, rule)
	g04V2World(t, f, false)
	v := f.verify()
	if ok, has := v.Checks["tighten"]; !has || ok || !strings.Contains(g04V2Reasons(v), "denied by tighten rule 'g04w'") {
		t.Fatalf("admitted world: %v (%s)", v.Checks, g04V2Reasons(v))
	}
	f = newV2Fx(t)
	g04V2EnvGrant(f, rule)
	g04V2World(t, f, true)
	v = f.verify()
	if ok, has := v.Checks["facts"]; !has || !ok {
		t.Fatalf("facts: %v (%s)", v.Checks, g04V2Reasons(v))
	}
	if ok, has := v.Checks["provenance"]; !has || ok {
		t.Fatalf("provenance: %v (%s)", v.Checks, g04V2Reasons(v))
	}
	if ok, has := v.Checks["tighten"]; !has || !ok {
		t.Fatalf("denied W-B leaks its world env: %v (%s)", v.Checks, g04V2Reasons(v))
	}
}

func TestG04V2Helpers(t *testing.T) {
	ctx := IntentV2ContextFromJSON(map[string]any{"layers": map[string]any{"org": map[string]any{"predicates": []any{"P"}}, "std": map[string]any{"predicates": []any{"Q"}}}})
	got := allowSidePredicates(nil, ctx)
	if len(got) != 4 || got[0] != nil || !sameJSON(got[1], []any{"P"}) || got[2] != nil || !sameJSON(got[3], []any{"Q"}) {
		t.Errorf("layers: %v", got)
	}
	if got := allowSidePredicates(map[string]any{"predicates": []any{"E"}}, nil); len(got) != 1 || !sameJSON(got[0], []any{"E"}) {
		t.Errorf("envelope only: %v", got)
	}
	if m, ok := ctxEnvOf(IntentV2ContextFromJSON(map[string]any{"env": "x"})); ok || m != nil {
		t.Errorf("non-object env: %v %v", m, ok)
	}
	if m, ok := ctxEnvOf(IntentV2ContextFromJSON(map[string]any{"env": map[string]any{"a": "b"}})); !ok || m["a"] != "b" {
		t.Errorf("env: %v %v", m, ok)
	}
	if _, ok := ctxEnvOf(IntentV2ContextFromJSON(map[string]any{})); ok {
		t.Error("absent env")
	}
	grant := func(preds []any) map[string]any {
		return map[string]any{"caveats": []any{map[string]any{"type": "envelope", "goal_commit": "g", "predicates": preds, "caveats": []any{},
			"risk_policy": g04V2RiskPolicy(), "agent_binding": map[string]any{}}}}
	}
	if needsModelRules(map[string]any{}) {
		t.Error("no envelope")
	}
	if needsModelRules(grant([]any{})) {
		t.Error("no model path")
	}
	if !needsModelRules(grant([]any{map[string]any{"where": []any{map[string]any{"field": "env.class.x", "op": "exists"}}}})) {
		t.Error("one model path")
	}
	if needsModelRules(grant([]any{map[string]any{"where": []any{map[string]any{"field": "action.params.x", "op": "exists"}}}})) {
		t.Error("a plain path")
	}
}
