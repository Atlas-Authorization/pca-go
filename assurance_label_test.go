package pca

import "testing"

func TestAssuranceLabelHelpers(t *testing.T) {
	hook := SetAssuranceLabel(func() {}, AssuranceLabel{Level: "hardware", Vendor: "azure-maa"})
	if l, ok := AssuranceLabelOf(hook); !ok || l.Level != "hardware" || l.Vendor != "azure-maa" {
		t.Fatalf("%+v %v", l, ok)
	}
	if _, ok := AssuranceLabelOf(struct{}{}); ok {
		t.Fatal("an unlabelled value must report no label")
	}
}

func TestRefreshAssuranceDowngradesAndAdds(t *testing.T) {
	rep := AssuranceReport{names: []string{"a", "b", "c"}, by: map[string]CheckAssurance{
		"a": {Outcome: "pass", Level: "hardware"}, "b": {Outcome: "unsupported", Reason: "x"}, "c": {Outcome: "pass", Level: "software"}}}
	out := RefreshAssurance(rep, []NamedStatus{{"a", "fail"}, {"b", "pass"}, {"c", "pass"}, {"d", "pass"}})
	if g, _ := out.Get("a"); g.Outcome != "fail" || g.Level != "" {
		t.Fatalf("a: %+v", g)
	}
	if g, _ := out.Get("b"); g.Outcome != "unsupported" {
		t.Fatalf("b must stay unsupported: %+v", g)
	}
	if g, _ := out.Get("c"); g.Level != "software" {
		t.Fatalf("a still-passing check keeps its level: %+v", g)
	}
	if g, ok := out.Get("d"); !ok || g.Outcome != "pass" || len(out.Names()) != 4 {
		t.Fatalf("d: %+v %v %v", g, ok, out.Names())
	}
	if g, _ := rep.Get("a"); g.Outcome != "pass" {
		t.Fatal("the argument must not be modified")
	}
}
