package pca

import (
	"reflect"
	"testing"
)

// The reference's kill tests of the objective-risk binding, ported: every refusal of ReadObjectiveCommitment with its exact
// message and every outcome of ResolveObjectiveRisk (the commitments are computed natively from the same facts).

func obFixture(t *testing.T) (commit func(over map[string]any) map[string]any, reg *InMemoryInverseRegistry, gr *ObjResourceGraph, emb *NativeEmbedder, act map[string]any, instance map[string]any) {
	t.Helper()
	var err error
	emb, err = NativeHashEmbedder(DefaultNativeConfig())
	if err != nil {
		t.Fatal(err)
	}
	act = map[string]any{"verb": "revoke_session", "resource": "/acct/1/s", "params": map[string]any{"device": "laptop"}}
	reg = NewInMemoryInverseRegistry("acme").Register("revoke_session", InverseEntry{InverseKind: "restore_session", Fidelity: "exact", Verification: &InverseVerification{VerifierID: "acme", EvidenceDigest: "e1"}})
	gr = NewObjResourceGraph()
	gr.AddNode(ResourceNode{ID: "/acct/1/s", Harm: map[string]float64{"rows": 10}})
	gr.AddNode(ResourceNode{ID: "/acct/1", Harm: map[string]float64{"rows": 100}})
	gr.AddNode(ResourceNode{ID: "/other", Harm: map[string]float64{"rows": 1}})
	if err := gr.AddEdge(ResourceEdge{From: "/acct/1/s", To: "/acct/1", Kind: "owns"}); err != nil {
		t.Fatal(err)
	}
	goal, err := CommitGoal(emb, act)
	if err != nil {
		t.Fatal(err)
	}
	gd, err := gr.Digest()
	if err != nil {
		t.Fatal(err)
	}
	commit = func(over map[string]any) map[string]any {
		c := map[string]any{"v": jsNumber(1), "embedder": map[string]any{"scheme": "native", "model_id": emb.ModelID(), "config": DefaultNativeConfig()},
			"goal": map[string]any(goal), "registry_digest": reg.Digest(), "graph_digest": gd, "authorized_kinds": []any{"restore_session"}}
		for k, v := range over {
			if v == nil {
				delete(c, k)
			} else {
				c[k] = v
			}
		}
		return c
	}
	instance = map[string]any{
		"registry": map[string]any{"trusted_verifiers": []any{"acme"}, "entries": []any{map[string]any{"verb": "revoke_session", "inverse_kind": "restore_session", "fidelity": "exact",
			"verification": map[string]any{"verifier_id": "acme", "evidence_digest": "e1"}}}},
		"graph": map[string]any{
			"nodes": []any{map[string]any{"id": "/acct/1/s", "harm": map[string]any{"rows": jsNumber(10)}}, map[string]any{"id": "/acct/1", "harm": map[string]any{"rows": jsNumber(100)}}, map[string]any{"id": "/other", "harm": map[string]any{"rows": jsNumber(1)}}},
			"edges": []any{map[string]any{"from": "/acct/1/s", "to": "/acct/1", "kind": "owns"}}},
	}
	return
}

func obGrant(objective any, has bool) map[string]any {
	env := map[string]any{"type": "envelope", "goal_commit": "g", "predicates": []any{}, "caveats": []any{}, "agent_binding": map[string]any{}, "risk_policy": DefaultRiskPolicy()}
	if has {
		env["objective_risk"] = objective
	}
	return map[string]any{"caveats": []any{env}}
}

func TestReadObjectiveCommitment(t *testing.T) {
	commit, _, _, _, _, _ := obFixture(t)
	if c, m := ReadObjectiveCommitment(map[string]any{"caveats": []any{}}); c != nil || m != "" {
		t.Fatal("no envelope is empty")
	}
	if c, m := ReadObjectiveCommitment(obGrant(nil, false)); c != nil || m != "" {
		t.Fatal("no field is empty")
	}
	good := commit(nil)
	if c, m := ReadObjectiveCommitment(obGrant(good, true)); m != "" || !reflect.DeepEqual(c, good) {
		t.Fatalf("well-formed: %q", m)
	}
	const (
		shape = "objective_risk: unsupported shape/version"
		emb   = `objective_risk.embedder must be { scheme: "native", model_id, config }`
		goal  = "objective_risk.goal must be a goal commitment"
		dig   = "objective_risk needs registry_digest and graph_digest"
		cal   = "objective_risk.calibration_digest must be a string"
		kinds = "objective_risk.authorized_kinds must be string[]"
		den   = "objective_risk.denominations must be an array"
		onm   = `objective_risk.on_mismatch must be "deny" or "heuristic"`
	)
	cases := []struct {
		name string
		obj  any
		want string
	}{
		{"null", nil, shape}, {"string", "x", shape}, {"v2", commit(map[string]any{"v": jsNumber(2)}), shape},
		{"array", []any{1}, shape},
		{"embedder string", commit(map[string]any{"embedder": "native"}), emb},
		{"embedder byo", commit(map[string]any{"embedder": map[string]any{"scheme": "byo", "model_id": "m", "config": map[string]any{}}}), emb},
		{"embedder empty id", commit(map[string]any{"embedder": map[string]any{"scheme": "native", "model_id": "", "config": map[string]any{}}}), emb},
		{"embedder config array", commit(map[string]any{"embedder": map[string]any{"scheme": "native", "model_id": "m", "config": []any{1}}}), emb},
		{"goal string", commit(map[string]any{"goal": "x"}), goal},
		{"goal empty commit", commit(map[string]any{"goal": map[string]any{"commit": ""}}), goal},
		{"registry digest empty", commit(map[string]any{"registry_digest": ""}), dig},
		{"graph digest absent", commit(map[string]any{"graph_digest": nil}), dig},
		{"calibration empty", commit(map[string]any{"calibration_digest": ""}), cal},
		{"calibration number", commit(map[string]any{"calibration_digest": jsNumber(5)}), cal},
		{"kinds absent", commit(map[string]any{"authorized_kinds": nil}), kinds},
		{"kinds string", commit(map[string]any{"authorized_kinds": "a"}), kinds},
		{"kinds mixed", commit(map[string]any{"authorized_kinds": []any{"a", jsNumber(5)}}), kinds},
		{"denominations string", commit(map[string]any{"denominations": "x"}), den},
		{"on_mismatch bogus", commit(map[string]any{"on_mismatch": "bogus"}), onm},
		{"on_mismatch empty", commit(map[string]any{"on_mismatch": ""}), onm},
	}
	for _, tc := range cases {
		if c, m := ReadObjectiveCommitment(obGrant(tc.obj, true)); c != nil || m != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, m, tc.want)
		}
	}
	for _, over := range []map[string]any{{"on_mismatch": "deny"}, {"on_mismatch": "heuristic"}, {"denominations": []any{}}, {"calibration_digest": "cd"}, {"authorized_kinds": []any{}}} {
		if c, m := ReadObjectiveCommitment(obGrant(commit(over), true)); c == nil || m != "" {
			t.Errorf("%v refused: %q", over, m)
		}
	}
}

func TestResolveObjectiveRisk(t *testing.T) {
	commit, reg, gr, emb, act, instance := obFixture(t)
	deny := func(rs ...string) map[string]any {
		a := make([]any, len(rs))
		for i, r := range rs {
			a[i] = r
		}
		return map[string]any{"mode": "mismatch", "reasons": a, "onMismatch": "deny"}
	}
	if got := ResolveObjectiveRisk(obGrant(map[string]any{"v": jsNumber(2)}, true), act, instance, nil, nil); !reflect.DeepEqual(got, deny("objective_risk: unsupported shape/version")) {
		t.Fatalf("malformed: %v", got)
	}
	if got := ResolveObjectiveRisk(obGrant(nil, false), act, instance, nil, nil); got["mode"] != "none" {
		t.Fatalf("none: %v", got)
	}
	if got := ResolveObjectiveRisk(obGrant(commit(map[string]any{"on_mismatch": "heuristic"}), true), act, nil, nil, nil); !reflect.DeepEqual(got, deny("the grant commits objective-risk facts but the instance holds no objective-risk config")) {
		t.Fatalf("no instance: %v", got)
	}
	other := commit(map[string]any{"embedder": map[string]any{"scheme": "native", "model_id": "native:other", "config": DefaultNativeConfig()}})
	if got := ResolveObjectiveRisk(obGrant(other, true), act, instance, nil, nil); !reflect.DeepEqual(got, deny("embedder model_id does not match the committed one")) {
		t.Fatalf("model: %v", got)
	}
	if got := ResolveObjectiveRisk(obGrant(commit(nil), true), act, map[string]any{}, nil, nil); !reflect.DeepEqual(got, deny("registry digest does not match the committed digest", "graph digest does not match the committed digest")) {
		t.Fatalf("digests: %v", got)
	}
	// a grant cannot downgrade the verifier to the heuristic; the verifier's own opt-in can
	h := commit(map[string]any{"on_mismatch": "heuristic", "calibration_digest": "bogus"})
	if got := ResolveObjectiveRisk(obGrant(h, true), act, instance, nil, nil); got["onMismatch"] != "deny" {
		t.Fatalf("heuristic without opt-in: %v", got)
	}
	opt := map[string]any{"registry": instance["registry"], "graph": instance["graph"], "allow_heuristic_fallback": true}
	if got := ResolveObjectiveRisk(obGrant(h, true), act, opt, nil, nil); got["onMismatch"] != "heuristic" || got["mode"] != "mismatch" {
		t.Fatalf("heuristic with opt-in: %v", got)
	}
	// reproduced: equals a direct objective risk over the same facts
	taint, age := 0.25, 0.5
	got := ResolveObjectiveRisk(obGrant(commit(nil), true), act, instance, &taint, &age)
	gd, _ := gr.Digest()
	pol, _ := RiskPolicyOf(DefaultRiskPolicy())
	direct, err := ObjectiveRisk(act, &ObjectiveRiskContext{Registry: reg, AuthorizedKinds: []string{"restore_session"}, Graph: gr, Embedder: emb,
		Goal: commit(nil)["goal"].(map[string]any), Commitments: RiskCommitments{RegistryDigest: reg.Digest(), GraphDigest: gd}, Weights: pol.Weights, Taint: 0.25, Age: 0.5})
	if err != nil || !direct.Valid {
		t.Fatalf("direct: %v %v", err, direct.Reasons)
	}
	want := map[string]any{"mode": "objective", "inputs": map[string]any{"reversibility": direct.Inputs.Reversibility, "blastRadius": direct.Inputs.BlastRadius, "semanticDistance": direct.Inputs.SemanticDistance},
		"r": direct.R, "evidenceDigest": direct.EvidenceDigest}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("objective: got %v want %v", got, want)
	}
	// denominations change the blast radius
	den := commit(map[string]any{"denominations": []any{map[string]any{"id": "rows", "ceiling": jsNumber(1), "weight": jsNumber(1)}}})
	a := ResolveObjectiveRisk(obGrant(den, true), act, instance, nil, nil)
	b := ResolveObjectiveRisk(obGrant(commit(nil), true), act, instance, nil, nil)
	if a["mode"] != "objective" || b["mode"] != "objective" || a["inputs"].(map[string]any)["blastRadius"] == b["inputs"].(map[string]any)["blastRadius"] {
		t.Fatalf("denominations: %v %v", a, b)
	}
}
