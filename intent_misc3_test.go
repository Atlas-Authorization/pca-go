package pca

import (
	"errors"
	"testing"
)

func TestIntentMisc3(t *testing.T) {
	omega := map[string]any{"verbs": []any{map[string]any{"verb": "a"}, map[string]any{"verb": "b"}}}
	if vs := IntentVsOf(omega, map[string]any{"verb": "b"}); vs == nil || vs["verb"] != "b" {
		t.Fatal("vsOf")
	}
	if IntentVsOf(omega, map[string]any{"verb": "z"}) != nil {
		t.Fatal("vsOf unknown")
	}
	if _, _, ok := IntentLiftedCell(omega, map[string]any{"verb": "z"}); ok {
		t.Fatal("lifted outside")
	}
	var order []string
	snap, err := IntentCaptureState(map[string]func() (any, error){
		"b": func() (any, error) { order = append(order, "b"); return jsNumber(2), nil },
		"a": func() (any, error) { order = append(order, "a"); return jsNumber(1), nil },
	}, true)
	if err != nil || len(snap) != 2 || order[0] != "a" || snap["a"].(map[string]any)["value"] == nil {
		t.Fatalf("capture: %v %v", snap, err)
	}
	if s, _ := IntentCaptureState(map[string]func() (any, error){"a": func() (any, error) { return jsNumber(1), nil }}, false); s["a"].(map[string]any)["value"] != nil {
		t.Fatal("values kept")
	}
	if _, err := IntentCaptureState(map[string]func() (any, error){"a": func() (any, error) { return nil, errors.New("boom") }}, true); err == nil {
		t.Fatal("reader error swallowed")
	}
	if r := IntentProfileUsable(map[string]any{}, jsNumber(1), jsNumber(1), nil, nil, false, nil); r["ok"] != false {
		t.Fatal("malformed profile usable")
	}
}
