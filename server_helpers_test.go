package pca

import "testing"

func TestServerHelpers(t *testing.T) {
	if DecisionOfResult(true, "deny") != "allow" || DecisionOfResult(false, "escalate") != "escalate" || DecisionOfResult(false, "") != "deny" {
		t.Fatal("decision")
	}
	aud := "https://rs.example/a b"
	if got := PcaStateKey("g", "h", "", nil); got != "g:h" {
		t.Fatal(got)
	}
	if got := PcaStateKey("g", "h", "", &aud); got != "aud:https%3A%2F%2Frs.example%2Fa%20b:g:h" {
		t.Fatal(got)
	}
	if got := PcaStateKey("g", "h", "grant-holder", &aud); got != "g:h" {
		t.Fatal(got)
	}
	if encodeURIComponent("é!~*'()-_.") != "%C3%A9!~*'()-_." {
		t.Fatal("encodeURIComponent")
	}
	ok := map[string]any{"id": "a", "window_end": jsNumber(5), "compensation": map[string]any{"verb": "undo"}}
	if UndoAdmissionError(ok) != "" || UndoAdmissionError(&UndoAdmission{ID: "a", WindowEnd: 5, Compensation: UndoCompensation{Verb: "undo"}}) != "" {
		t.Fatal("valid admission refused")
	}
	for _, bad := range []any{nil, "x", []any{}, map[string]any{"id": "", "window_end": jsNumber(5), "compensation": map[string]any{"verb": "v"}},
		map[string]any{"id": "a", "window_end": jsNumber(-1), "compensation": map[string]any{"verb": "v"}},
		map[string]any{"id": "a", "window_end": jsNumber(1), "compensation": map[string]any{"verb": ""}},
		&UndoAdmission{ID: "a", WindowEnd: -1, Compensation: UndoCompensation{Verb: "v"}}} {
		if UndoAdmissionError(bad) == "" {
			t.Fatalf("accepted %v", bad)
		}
	}
}
