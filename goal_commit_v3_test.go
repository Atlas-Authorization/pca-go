package pca

import "testing"

// Goal binding v3: replays goal-commit-vectors.json (commit, invalid, binding). A missing file fails the test.

func grows(t *testing.T, doc map[string]any, table string) []map[string]any {
	t.Helper()
	arr, ok := doc[table].([]any)
	if !ok {
		t.Fatalf("%s: missing table", table)
	}
	out := make([]map[string]any, len(arr))
	for i, v := range arr {
		out[i] = v.(map[string]any)
	}
	return out
}

func goalRefOf(v map[string]any) ApprovedGoalRef {
	g, _ := v["goal_digest"].(string)
	p, _ := v["policy_digest"].(string)
	return ApprovedGoalRef{GoalDigest: g, PolicyDigest: p}
}

func TestGoalCommitV3Commit(t *testing.T) {
	doc := load(t, "goal-commit-vectors.json")
	if doc["goal_prefix"] != intentGoalV3Prefix {
		t.Fatalf("prefix %v", doc["goal_prefix"])
	}
	cs := grows(t, doc, "commit")
	if len(cs) != 7 {
		t.Fatalf("commit rows %d", len(cs))
	}
	for _, v := range cs {
		g, err := IntentGoalV3(goalRefOf(v))
		if err != nil || g != v["goal"] {
			t.Errorf("%s: goal %q %v", v["name"], g, err)
		}
		c, err := IntentGoalCommitV3(goalRefOf(v), v["salt"].(string))
		if err != nil || c != v["commit"] {
			t.Errorf("%s: commit %q want %v (%v)", v["name"], c, v["commit"], err)
		}
	}
}

func TestGoalCommitV3InvalidDigestsRefused(t *testing.T) {
	doc := load(t, "goal-commit-vectors.json")
	iv := grows(t, doc, "invalid")
	if len(iv) != 4 {
		t.Fatalf("invalid rows %d", len(iv))
	}
	for _, v := range iv {
		if g, err := IntentGoalV3(goalRefOf(v)); err == nil {
			t.Errorf("%s: accepted %q", v["name"], g)
		}
		if c, err := IntentGoalCommitV3(goalRefOf(v), "s"); err == nil {
			t.Errorf("%s: committed %q", v["name"], c)
		}
	}
}

func TestGoalCommitV3Binding(t *testing.T) {
	doc := load(t, "goal-commit-vectors.json")
	bs := grows(t, doc, "binding")
	if len(bs) != 16 {
		t.Fatalf("binding rows %d", len(bs))
	}
	for _, v := range bs {
		pcactn := map[string]any{}
		if in, ok := v["intent"].(map[string]any); ok {
			pcactn["intent"] = in
		}
		if s, ok := v["session"].(string); ok {
			pcactn["intent_session"] = map[string]any{"session": s}
		}
		grant := map[string]any{}
		if gc, ok := v["grant_commit"].(string); ok {
			grant["caveats"] = []any{map[string]any{"type": "envelope", "goal_commit": gc}}
		}
		pol := IntentPolicyFromJSON(v["policy"])
		evaluated, why := decideIntent(pcactn, grant, pol)
		got := "pass"
		if !evaluated {
			got = "absent"
		} else if why != "" {
			got = "fail"
		}
		if got != v["expect"] {
			t.Errorf("%s: got %s (%s) want %v", v["name"], got, why, v["expect"])
		}
	}
}

// Closed object: an extra member, a non-string digest, a non-object are all fail-closed misconfigurations, and the
// misconfiguration alone activates the policy (an absent intent still fails, never "absent").
func TestGoalCommitV3MisconfiguredPolicyFailsClosed(t *testing.T) {
	g := "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw"
	for name, ag := range map[string]any{
		"extra":      map[string]any{"goal_digest": g, "policy_digest": g, "x": 1},
		"missing":    map[string]any{"goal_digest": g},
		"non-string": map[string]any{"goal_digest": g, "policy_digest": 5},
		"null":       nil,
		"array":      []any{},
	} {
		p := IntentPolicyFromJSON(map[string]any{"approved_goal": ag})
		ev, why := decideIntent(map[string]any{}, map[string]any{}, p)
		if !ev || why == "" {
			t.Errorf("%s: want fail, got evaluated=%v why=%q", name, ev, why)
		}
	}
	if ev, why := decideIntent(map[string]any{}, map[string]any{}, &IntentPolicy{ApprovedGoal: &ApprovedGoalRef{GoalDigest: "AAAA", PolicyDigest: g}}); !ev || why == "" {
		t.Error("short digest must fail closed")
	}
}
