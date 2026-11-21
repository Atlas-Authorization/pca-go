package pca

import "testing"

// TestAccPostRefusesUnknownAgg pins TS 80ad8c7ff (mutation-kill-r13-g2-history.test.ts "refuses an agg outside ..."): an agg
// outside sum/count/max/distinct throws first, selected or not, keyed or not.
func TestAccPostRefusesUnknownAgg(t *testing.T) {
	task := map[string]any{"kind": "task"}
	hist := []any{g09iEv("pay", 1, map[string]any{"total": jnum(2)})}
	for _, agg := range []any{"SUM", "tVm", "", "avg", nil, jnum(1), "absent"} {
		a := map[string]any{"agg": agg, "val": "action.params.total", "sel": map[string]any{"verbs": []any{"pay"}}, "win": task}
		if agg == "absent" {
			delete(a, "agg")
		}
		keyed := map[string]any{"key": "action.params.k"}
		for k, v := range a {
			keyed[k] = v
		}
		for _, c := range []struct {
			a    map[string]any
			verb string
		}{{a, "pay"}, {a, "look"}, {keyed, "pay"}} {
			if v, ok := accPost(c.a, hist, c.verb, map[string]any{"total": jnum(5)}, jnum(2), nil, false); ok || v != 0 {
				t.Errorf("agg %v verb %s keyed %v: %v %v, want the refusal", agg, c.verb, c.a["key"] != nil, v, ok)
			}
		}
	}
	// control: sum is accepted (empty pre-state + 5)
	a := map[string]any{"agg": "sum", "val": "action.params.total", "sel": map[string]any{"verbs": []any{"pay"}}, "win": task}
	if v, ok := accPost(a, []any{}, "pay", map[string]any{"total": jnum(5)}, jnum(2), nil, false); !ok || v != 5 {
		t.Errorf("sum control: %v %v, want 5 true", v, ok)
	}
}
