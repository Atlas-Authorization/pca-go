package pca

import (
	"reflect"
	"testing"
)

// Replays packages/pca/conformance/obligations-vectors.json: validate, merge, gate, outcome.
func TestObligationVectors(t *testing.T) {
	doc := load(t, "obligations-vectors.json")
	for _, x := range doc["validate"].([]any) {
		c := x.(map[string]any)
		if got := ObligationsError(c["input"]) == ""; got != c["expect"].(map[string]any)["ok"].(bool) {
			t.Errorf("validate %v: ok=%v", c["name"], got)
		}
	}
	for _, x := range doc["merge"].([]any) {
		c := x.(map[string]any)
		exp := c["expect"].(map[string]any)
		got, ok := MergeObligations(c["inputs"].([]any)...)
		if ok != exp["ok"].(bool) || (ok && !reflect.DeepEqual(got, exp["obligations"])) {
			t.Errorf("merge %v: ok=%v %v", c["name"], ok, got)
		}
	}
	for _, x := range doc["gate"].([]any) {
		c := x.(map[string]any)
		exp := c["expect"].(map[string]any)
		got := PepObligationGate(c["decision"].(string), c["answered"].(bool), c["obligations"], c["supported"])
		if got.Decision != exp["decision"] || !reflect.DeepEqual(got.Perform, exp["perform"]) || len(got.Unsupported) != len(exp["unsupported"].([]any)) {
			t.Errorf("gate %v: %+v", c["name"], got)
			continue
		}
		for i, u := range exp["unsupported"].([]any) {
			if got.Unsupported[i] != u {
				t.Errorf("gate %v: unsupported %v", c["name"], got.Unsupported)
			}
		}
	}
	for _, x := range doc["outcome"].([]any) {
		c := x.(map[string]any)
		exp := c["expect"].(map[string]any)
		got := ObligationOutcome(c["obligations"], c["fulfilled"], c["now"])
		want := exp["overdue"].([]any)
		okOverdue := len(got.Overdue) == len(want)
		for i := 0; okOverdue && i < len(want); i++ {
			okOverdue = int64(got.Overdue[i]) == num(want[i])
		}
		st, _ := exp["status"].(string)
		if got.Outcome != exp["outcome"] || !okOverdue || got.Status != st {
			t.Errorf("outcome %v: %+v", c["name"], got)
		}
	}
}
