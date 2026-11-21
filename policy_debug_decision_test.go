package pca

import (
	"math"
	"strings"
	"testing"
)

// The explanation must agree with the decision it explains: over every case of the decide corpus the decomposed risk equals the
// decided r, and the baseline of a counterfactual report is that explanation.
func TestExplainPolicyDecisionAgreesWithDecide(t *testing.T) {
	checked := 0
	baseEachOrdered(t, "ref-decide-java.json.gz", func(c *baseCase) {
		in := vecObj(c.Args[0])
		e := ExplainPolicyDecision(in)
		if w, g := baseCanon(c.Out), baseCanon(vecJSON(e.Decision)); w != g {
			t.Fatalf("%s: the explained decision is not the reference's: want %s got %s", c.Name, w, g)
		}
		out := vecObj(c.Out)
		r := jsF(out["r"])
		reasons, _ := out["reasons"].([]any)
		failClosed := false
		for _, x := range reasons {
			s, _ := x.(string)
			for _, p := range []string{"grant carries no valid envelope", "invalid decision time", "capability chain unverified", "policy evaluation error"} {
				failClosed = failClosed || strings.HasPrefix(s, p)
			}
		}
		if e.T != int(jsF(vecObj(out["requiredThreshold"])["t"])) || e.AutoAllow != (out["admit"] == true) || len(e.Reasons) != len(reasons) {
			t.Fatalf("%s: summary fields disagree with the decision: %+v", c.Name, e)
		}
		if !failClosed {
			if !e.EnvelopeValid || math.Abs(e.Risk.R-r) > 1e-12 || len(e.Risk.Terms) != 6 {
				t.Fatalf("%s: decomposed risk %v, decided %v", c.Name, e.Risk.R, r)
			}
			checked++
		}
		rep := Counterfactual(in, []CounterfactualDelta{{}, {HumanCosignFull: true}, {Label: "calm", Risk: map[string]any{"blastRadius": jsNumber(0), "taint": jsNumber(0)}}})
		if len(rep.Outcomes) != 3 || rep.Outcomes[0].Label != "no-op" || rep.Outcomes[2].Label != "calm" || !strings.HasPrefix(rep.Outcomes[1].Label, "human re-confirms goal") {
			t.Fatalf("%s: labels: %+v", c.Name, rep.Outcomes)
		}
		if !failClosed && (rep.Outcomes[0].FlipsAllow || rep.Outcomes[0].ChangesThreshold || rep.Outcomes[0].RDelta != 0) {
			t.Fatalf("%s: the empty delta changed the decision", c.Name)
		}
		if _, touched := in["rFloor"]; !touched {
			if _, has := ApplyDelta(in, CounterfactualDelta{})["rFloor"]; has {
				t.Fatalf("%s: ApplyDelta invented a caution floor", c.Name)
			}
		}
	})
	if checked < 100 {
		t.Fatalf("only %d decided cases were checked", checked)
	}
}
