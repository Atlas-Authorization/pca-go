package pca

import "testing"

// F4: the admission hook of a blueprint with runtime pins.
func TestF4_BlueprintAdmissionHook(t *testing.T) {
	op := newKey(t)
	reg := NewBlueprintRegistry([]string{op.id}, MemoryBlueprintKv())
	if code, _ := reg.Accept(parityBlueprint(t, op, "K", "active", nil)); code != "" {
		t.Fatalf("accept: %q", code)
	}
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	run := func(h ...BlueprintAdmitted) BlueprintDecision {
		return CheckBlueprints(chain, reg, jnum(2), "any", nil, h...)
	}
	if d := run(); d.Decision != "deny" || d.Code != "admission_required" || d.Blueprint != "bp1" {
		t.Errorf("no hook: %+v", d)
	}
	var seenHolder string
	if d := run(func(k string, bp map[string]any) bool { seenHolder = k; return bp["id"] == "bp1" }); d.Decision != "allow" || len(d.Governed) != 1 || seenHolder != "inst" {
		t.Errorf("admitted: %+v (holder %q)", d, seenHolder)
	}
	if d := run(func(string, map[string]any) bool { return false }); d.Decision != "deny" || d.Code != "not_admitted" || d.Blueprint != "bp1" {
		t.Errorf("not admitted: %+v", d)
	}
	if d := run(func(string, map[string]any) bool { panic("boom") }); d.Decision != "deny" || d.Code != "not_admitted" {
		t.Errorf("a hook that panics: %+v", d)
	}
	// a nil hook value is no hook
	var none BlueprintAdmitted
	if d := run(none); d.Code != "admission_required" {
		t.Errorf("nil hook: %+v", d)
	}
	// a blueprint without pins never calls the hook
	reg2 := NewBlueprintRegistry([]string{op.id}, MemoryBlueprintKv())
	_, _ = reg2.Accept(parityBlueprint(t, op, "K", "active", func(b map[string]any) { delete(b, "runtime_pins") }))
	called := false
	if d := CheckBlueprints(chain, reg2, jnum(2), "any", nil, func(string, map[string]any) bool { called = true; return false }); d.Decision != "allow" || called {
		t.Errorf("no pins: %+v called=%v", d, called)
	}
}
