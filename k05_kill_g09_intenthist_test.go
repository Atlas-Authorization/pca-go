package pca

import (
	"fmt"
	"reflect"
	"testing"
)

// g09 mutation kills for intent_history.go: window edges, the exact failure values of accPost, throwing selections,
// empty pre-states and the distinct-values fold.

func g09iEv(verb string, t int64, params map[string]any) map[string]any {
	return map[string]any{"status": "committed", "t": jnum(t), "verb": verb, "params": params}
}

func TestG09IntentHistoryWindowAndPre(t *testing.T) {
	other := map[string]any{"kind": "x"}
	if inWindow(other, jnum(5), jnum(5)) || inWindow(other, jnum(1), jnum(5)) || !inWindow(other, jnum(6), jnum(5)) {
		t.Error("an unknown window counts only events stamped after t")
	}
	if !reflect.DeepEqual(emptyPre("count"), map[string]any{"count": jsNumber(0)}) || !reflect.DeepEqual(emptyPre("max"), map[string]any{"max": jsNumber(0)}) {
		t.Errorf("emptyPre: %v %v", emptyPre("count"), emptyPre("max"))
	}
}

func TestG09IntentHistoryFailures(t *testing.T) {
	task := map[string]any{"kind": "task"}
	throwing := map[string]any{"verbs": []any{nil}}
	ai := map[string]any{"agg": "sum", "sel": map[string]any{"accumulates_into": "x"}, "win": task}
	if pre, ok := accPreState(ai, []any{g09iEv("v", 1, map[string]any{})}, map[string]any{}, jnum(2), throwing, true); ok || pre != nil {
		t.Errorf("a throwing selection: %v %v", pre, ok)
	}
	byVal := map[string]any{"agg": "sum", "val": "action.params.x", "sel": map[string]any{"verbs": []any{"v"}}, "win": task}
	for _, c := range []struct {
		name   string
		a      map[string]any
		params map[string]any
		t      any
		schema any
	}{
		{"pre-state fails", byVal, map[string]any{"x": jnum(1)}, "x", nil},
		{"selection throws", ai, map[string]any{}, jnum(1), throwing},
		{"value unreadable", byVal, map[string]any{"x": jnum(-1)}, jnum(1), nil},
	} {
		if v, ok := accPost(c.a, []any{}, "v", c.params, c.t, c.schema, c.schema != nil); ok || v != 0 {
			t.Errorf("%s: %v %v", c.name, v, ok)
		}
	}
	if v, ok := accPost(byVal, []any{}, "v", map[string]any{"x": jnum(4)}, jnum(1), nil, false); !ok || v != 4 {
		t.Errorf("accPost: %v %v", v, ok)
	}
}

func TestG09IntentHistoryValues(t *testing.T) {
	task := map[string]any{"kind": "task"}
	// an aggregate outside sum / count / max / distinct folds to values; its per-event values carry no key
	weird := map[string]any{"agg": "weird", "val": "action.params.x", "sel": map[string]any{"verbs": []any{"v"}}, "win": task}
	pre, ok := accPreState(weird, []any{g09iEv("v", 1, map[string]any{"x": jnum(1)})}, map[string]any{}, jnum(2), nil, false)
	if !ok || !reflect.DeepEqual(pre, map[string]any{"values": []any{}}) {
		t.Errorf("keyless values: %v %v", pre, ok)
	}
	distinct := map[string]any{"agg": "distinct", "val": "action.params.x", "sel": map[string]any{"verbs": []any{"v"}}, "win": task}
	var hist []any
	want := []any{}
	for i := 0; i < 40; i++ {
		hist = append(hist, g09iEv("v", int64(i), map[string]any{"x": fmt.Sprintf("k%02d", (i*7)%13)}))
	}
	for i := 0; i < 13; i++ {
		want = append(want, fmt.Sprintf(`"k%02d"`, i))
	}
	pre, ok = accPreState(distinct, hist, map[string]any{}, jnum(100), nil, false)
	if !ok || !reflect.DeepEqual(pre, map[string]any{"values": want}) {
		t.Errorf("distinct values: %v %v", pre, ok)
	}
}
