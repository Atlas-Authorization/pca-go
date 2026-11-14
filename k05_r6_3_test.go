package pca

import (
	"errors"
	"reflect"
	"testing"
)

func TestR6N3BindContextActionPresentButNotAnObjectIsRefused(t *testing.T) {
	old := mcActHook
	defer func() { mcActHook = old }()
	bound := map[string]any{"action": map[string]any{"verb": "v", "resource": "r"}}
	sup := map[string]any{"action": map[string]any{"params": map[string]any{"a": "1", "b": "2"}}}
	// a bound action that is present and not an object refuses every supplied action.params leaf (and none is written)
	mcActHook = func(any, bool) (any, bool) { return "junk", true }
	b := BindContext(bound, sup, nil)
	if !reflect.DeepEqual(b.Conflicts, []string{"action.params.a", "action.params.b"}) {
		t.Fatalf("conflicts %v", b.Conflicts)
	}
	if act, _ := b.Context["action"].(map[string]any); act == nil || act["verb"] != "v" || act["params"] != nil {
		t.Errorf("context action = %v", b.Context["action"])
	}
	// a nil bound action is replaced by the empty default action, as the reference does
	mcActHook = func(any, bool) (any, bool) { return nil, true }
	b = BindContext(bound, map[string]any{"action": map[string]any{"params": map[string]any{"x": "1"}}}, nil)
	want := map[string]any{"verb": "", "resource": "", "params": map[string]any{"x": "1"}}
	if len(b.Conflicts) != 0 || !reflect.DeepEqual(b.Context["action"], want) {
		t.Errorf("nil action: conflicts %v context %v", b.Conflicts, b.Context["action"])
	}
}

func TestR6N3SignersReportASigningFault(t *testing.T) {
	k, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	old := signBodyFault
	defer func() { signBodyFault = old }()
	signBodyFault = func(string) error { return errors.New("canon fault") }
	if _, err := SignWorkflow(k, vectorBody(t, "sign_workflow", k)); err == nil {
		t.Error("SignWorkflow swallowed the signing error")
	}
	if _, err := SignReadGrant(k, vectorBody(t, "sign_read_grant", k)); err == nil {
		t.Error("SignReadGrant swallowed the signing error")
	}
	if _, err := SignAggregateGrant(k, vectorBody(t, "sign_aggregate_grant", k)); err == nil {
		t.Error("SignAggregateGrant swallowed the signing error")
	}
	if _, err := SignStepReceipt(k, map[string]any{"a": 1}, "s", "ok", "pd", map[string]any{}, 1, nil); err == nil {
		t.Error("SignStepReceipt swallowed the signing error")
	}
	if _, err := SignFreshAt(k, "s", map[string]any{}, 1); err == nil {
		t.Error("SignFreshAt swallowed the signing error")
	}
}

func TestR6N3GrantedPermissionMissingTokenIsTheEmptyToken(t *testing.T) {
	// the reference reads String(tokenAddress ?? ''): a missing token equals an empty one, in either direction
	g, s, r := g11Perm(nil, false)
	s["permission"].(map[string]any)["data"].(map[string]any)["tokenAddress"] = ""
	if got := VerifyGrantedPermission(g, s, r, []string{g11Mgr}, nil); got != "" {
		t.Errorf("sent empty, got missing: %q", got)
	}
	g, s, r = g11Perm(nil, false)
	r["permission"].(map[string]any)["data"].(map[string]any)["tokenAddress"] = ""
	if got := VerifyGrantedPermission(g, s, r, []string{g11Mgr}, nil); got != "" {
		t.Errorf("sent missing, got empty: %q", got)
	}
}

func TestR6N3AgentCaveatNonObjectIsNeverHandedToTheStockEvaluator(t *testing.T) {
	old := agentStockCaveats
	defer func() { agentStockCaveats = old }()
	agentStockCaveats = func(any, map[string]any) (bool, []string) { return true, nil }
	for _, cv := range []any{"junk", nil, []any{}, 5} {
		if agentCaveatSatisfied(cv, nil, nil, nil, &regexBudget{}) {
			t.Errorf("non-object caveat %v satisfied", cv)
		}
	}
}

func TestR6N3FailedCaveatWithoutAStringTypeIsNamedMalformed(t *testing.T) {
	ok, failed := EvaluateAgentCaveats([]any{map[string]any{"type": 5}, map[string]any{}, "junk"}, nil, nil, nil)
	if ok || !reflect.DeepEqual(failed, []string{"<malformed>", "<malformed>", "<malformed>"}) {
		t.Errorf("ok %v failed %q", ok, failed)
	}
	for _, c := range []any{"x", nil, map[string]any{"type": 5}, map[string]any{"type": nil}, map[string]any{}} {
		if got := clCaveatName(c); got != "<malformed>" {
			t.Errorf("clCaveatName(%v) = %q", c, got)
		}
	}
	if got := clCaveatName(map[string]any{"type": "sealed"}); got != "sealed" {
		t.Errorf("clCaveatName(typed) = %q", got)
	}
}
