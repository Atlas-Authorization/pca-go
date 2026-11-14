package pca

import "testing"

// TS decisionOf (decision.ts:75): a check refused as unsupported denies, even beside an escalate-class failure.
func TestR6N9_DecisionUnsupportedDenies(t *testing.T) {
	v := map[string]any{
		"allow":   false,
		"checks":  map[string]any{"a": "unsupported", "b": "fail"},
		"reasons": []any{"a: unsupported: feature x", "b: escalate: needs a human"},
	}
	if got := DecisionOf(v); got != "deny" {
		t.Fatalf("got %q, want deny", got)
	}
	v["reasons"] = []any{"b: escalate: needs a human"}
	if got := DecisionOf(v); got != "escalate" {
		t.Fatalf("unsupported without its reason must not deny: got %q", got)
	}
}
