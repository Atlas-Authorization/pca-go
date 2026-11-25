package pca

import "testing"

// F6: a JSON null obligations member is refused (the reference reads only absent as empty).
func TestF6_ObligationsMemberTriState(t *testing.T) {
	if l, why := ObligationsMember(map[string]any{}, "obligations"); l != nil || why != "" {
		t.Errorf("absent: %v %q", l, why)
	}
	if l, why := ObligationsMember(map[string]any{"obligations": nil}, "obligations"); l != nil || why != "obligations must be an array" {
		t.Errorf("null: %v %q", l, why)
	}
	list := []any{}
	if l, why := ObligationsMember(map[string]any{"obligations": list}, "obligations"); why != "" || l == nil {
		t.Errorf("empty list: %v %q", l, why)
	}
	if l, why := ObligationsMember(map[string]any{"obligations": "x"}, "obligations"); why != "" || l != "x" {
		t.Errorf("a non-list is passed on for validation: %v %q", l, why)
	}
	if got := ObligationsError("x"); got != "obligations must be an array" {
		t.Errorf("a string: %q", got)
	}
	// the gate: allow with an absent member passes through, with a refused null the caller denies
	if g := PepObligationGate("allow", false, nil, []any{}); g.Decision != "allow" {
		t.Errorf("absent: %+v", g)
	}
}
