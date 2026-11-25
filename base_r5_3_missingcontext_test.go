package pca

import (
	"reflect"
	"testing"
)

func TestR5N3SupplierTableMustBeAnObject(t *testing.T) {
	for _, v := range []any{"x", 5, nil, []any{}} {
		if got := SupplierTableError(v); got != "the supplier table must be an object" {
			t.Errorf("SupplierTableError(%v) = %q", v, got)
		}
	}
	if got := SupplierTableError(map[string]any{}); got != "" {
		t.Errorf("empty table: %q", got)
	}
	if got := supplierTable("x"); len(got) != 0 {
		t.Errorf("supplierTable(non-object) = %v", got)
	}
}

func TestR5N3BindContextNonObjectSuppliedNeverReachesTheMerge(t *testing.T) {
	old := mcPanicHook
	mcPanicHook = func(where string) { panic("hook " + where) }
	defer func() { mcPanicHook = old }()
	for _, sup := range []any{"junk", nil, []any{}} {
		b := BindContext(map[string]any{"action": map[string]any{}}, sup, nil)
		if len(b.Conflicts) != 0 || len(b.Dropped) != 0 {
			t.Errorf("supplied %v: conflicts %v dropped %v", sup, b.Conflicts, b.Dropped)
		}
	}
}

func TestR5N3BindContextKeepsGoingAfterADropAndABlock(t *testing.T) {
	// "env.x" is dropped (untrusted) and "env.y" is still merged
	b := BindContext(map[string]any{"action": map[string]any{}},
		map[string]any{"env": map[string]any{"x": "xs", "y": "ys"}},
		map[string]string{"env.x": "agent_declared_untrusted"})
	if !reflect.DeepEqual(b.Dropped, []string{"env.x"}) || len(b.Conflicts) != 0 {
		t.Fatalf("dropped %v conflicts %v", b.Dropped, b.Conflicts)
	}
	if env, _ := b.Context["env"].(map[string]any); env["y"] != "ys" || len(env) != 1 {
		t.Errorf("context env = %v", b.Context["env"])
	}
	// "env.a" sits under a bound leaf (a conflict) and "subject.b" is still merged
	b = BindContext(map[string]any{"action": map[string]any{}, "env": "leaf"},
		map[string]any{"env": map[string]any{"a": "1"}, "subject": map[string]any{"b": "2"}}, nil)
	if !reflect.DeepEqual(b.Conflicts, []string{"env.a"}) || b.Context["env"] != "leaf" {
		t.Fatalf("conflicts %v env %v", b.Conflicts, b.Context["env"])
	}
	if sub, _ := b.Context["subject"].(map[string]any); sub["b"] != "2" {
		t.Errorf("context subject = %v", b.Context["subject"])
	}
}

func TestR5N3DecideWithMissingCollectsEveryKindOfCondition(t *testing.T) {
	bound := map[string]any{"action": map[string]any{"verb": "v", "resource": "r"}}
	leaf := map[string]any{"field": "subject.a", "op": "eq", "value": "x"}
	// a condition that is not an object or a list makes the missing set ill typed even when another one names a path
	res := DecideWithMissing([]any{leaf, "junk"}, bound, nil, nil)
	if res.Decision != "deny" || res.Reason != "ill_typed_context" {
		t.Errorf("junk condition: %+v", res)
	}
	// an any_of group is collected through its children
	res = DecideWithMissing([]any{map[string]any{"any_of": []any{leaf}}}, bound, nil, nil)
	if res.Decision != "escalate" || res.Reason != "escalate: missing_context principal:subject.a" ||
		!reflect.DeepEqual(res.Missing, []MissingContext{{"subject.a", "principal"}}) {
		t.Errorf("any_of: %+v", res)
	}
	// a condition with a ref and no field still names the ref
	res = DecideWithMissing([]any{map[string]any{"op": "eq", "ref": "subject.r"}}, bound, nil, nil)
	if res.Decision != "escalate" || res.Reason != "escalate: missing_context principal:subject.r" {
		t.Errorf("ref only: %+v", res)
	}
}
