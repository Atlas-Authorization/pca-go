package pca

import "testing"

// F10: the shared budget_alloc monotonicity vectors (conformance/budget-alloc-vectors.json).
func TestF10_BudgetAllocVectors(t *testing.T) {
	doc := load(t, "budget-alloc-vectors.json")
	cases := doc["budget_alloc"].([]any)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, x := range cases {
		c := x.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			why, ok := allocationsMonotone(c["caveats"])
			exp := c["expect"].(map[string]any)
			if ok != exp["ok"].(bool) {
				t.Fatalf("ok=%v (%s), want %v", ok, why, exp["ok"])
			}
			if !ok && why != exp["reason"] {
				t.Errorf("reason %q, want %q", why, exp["reason"])
			}
		})
	}
}
