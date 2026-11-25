package pca

import "testing"

func TestControlExampleEvalRuns(t *testing.T) {
	rep, err := ControlExampleEval(2, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"safety", "usefulness", "episodes", "byStrategy", "catches", "analyticBound", "safetyLowerBound"} {
		if _, ok := rep[k]; !ok {
			t.Fatalf("report lacks %s", k)
		}
	}
	// deterministic: the same seed gives the same report
	again, err := ControlExampleEval(2, 1, nil)
	if err != nil || jsValueString(rep["safety"]) != jsValueString(again["safety"]) || jsValueString(rep["usefulness"]) != jsValueString(again["usefulness"]) {
		t.Fatal("not deterministic")
	}
}
