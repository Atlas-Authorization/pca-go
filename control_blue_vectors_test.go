package pca

// Replays the blue control protocol corpus (ref-control-blue): the example agent, the example blue protocol, the decision procedure
// behind every episode (replay, predicates and caveats through ReviewAction, data-flow governance, the immune-adapted metered
// budget) and the example evaluation, all against the real Go blue stack (ref-control-evals replays only the aggregation, from a
// stub blue). Numbers compare to a relative 1e-12 (the leak decays exponentially).
//
// Counted deviation (asserted, never skipped): a params value that cannot be canonical JSON (an integer past 2^53) makes the
// reference's reviewAction throw out of the episode (5 cases); here the local check refuses such params up front ("params are not
// JSON"), so the episode completes with a denial at that action: fail closed, asserted as a denial.

import (
	"math"
	"strings"
	"testing"
)

func cbEqual(w, g any) bool {
	if wf, ok := jsNum(w); ok {
		gf, gok := jsNum(g)
		return gok && (wf == gf || math.Abs(wf-gf) <= 1e-12*math.Max(1, math.Abs(wf)))
	}
	switch x := w.(type) {
	case map[string]any:
		y, ok := g.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			gv, has := y[k]
			if !has || !cbEqual(v, gv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := g.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !cbEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return w == g
}

func cbAgent(name string) (*FacadeAgent, error) {
	if name == "example" {
		return ControlBuildExampleAgent(nil, nil)
	}
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	zero := int64(0)
	o := AgentOptions{Principal: kp, Goal: "handle refunds and customer email for October",
		Permissions: map[string][]string{"stripe": {"refund"}, "gmail": {"send", "draft"}, "files": {"read", "write"}, "github": {"read"}},
		Aud:         "ins_example", At: &zero}
	if name == "cap50" {
		o.Limits = map[string]string{"refund": "$50/day"}
	}
	return CreateAgent(o)
}

func cbBlue(spec map[string]any) (*ControlPcaBlue, error) {
	name, _ := spec["agent"].(string)
	a, err := cbAgent(name)
	if err != nil {
		return nil, err
	}
	b := ControlExampleBlue(a)
	if spec["dlp"] == false {
		b.Dlp = nil
	}
	if spec["theta"] == "agent" {
		b.BasePolicy = nil
	}
	if x, ok := jsNum(spec["stepMs"]); ok {
		b.StepMsValue = x
	}
	if x, ok := jsNum(spec["startMs"]); ok {
		b.StartMsValue = x
	}
	if im, ok := spec["immune"].(map[string]any); ok {
		b.Immune = &ImmuneConfig{Alpha: jsF(im["alpha"]), HalfLifeMs: jsF(im["halfLifeMs"]), DriftZSat: jsF(im["driftZSat"]), StepUpSat: jsF(im["stepUpSat"]), DenySat: jsF(im["denySat"])}
	}
	if ad, ok := spec["adapt"].(map[string]any); ok {
		b.Adapt = &AdaptConfig{MaxKappaMult: jsF(ad["maxKappaMult"]), MinThetaMult: jsF(ad["minThetaMult"])}
	}
	return b, nil
}

func cbEnv(name any) ControlEnv {
	if name == "example" {
		return ControlExampleEnv()
	}
	return ControlGapAwareEnv("")
}

func cbStrings(l []string) []any {
	out := []any{}
	for _, s := range l {
		out = append(out, s)
	}
	return out
}

func cbReview(a *FacadeAgent, e map[string]any) map[string]any {
	now, _ := baseI64(e["now"])
	params, _ := e["params"].(map[string]any)
	r := ReviewAction(a, e["verb"].(string), e["resource"].(string), params, ReviewOptions{Now: &now, InsecureUnboundApproval: true})
	out := map[string]any{}
	for k, v := range e {
		out[k] = v
	}
	rv := map[string]any{"kind": r.Kind}
	if r.Reason != "" {
		rv["reason"] = r.Reason
	}
	out["review"] = rv
	return out
}

func TestControlBlueMatchesTheReference(t *testing.T) {
	var k baseTally
	deviations := 0
	baseEachOrdered(t, "ref-control-blue.json.gz", func(c *baseCase) {
		k.run(c.Fn)
		throws, _ := baseThrows(c.Out)
		var got any
		panicked := baseCall(func() {
			switch c.Fn {
			case "buildExampleAgent":
				a, err := ControlBuildExampleAgent(nil, nil)
				if err != nil {
					panic(err)
				}
				var acts []any
				for _, s := range a.Policy.Actions {
					m := map[string]any{"connector": s.Connector, "action": s.Action, "verb": s.Verb, "reversibility": s.Reversibility, "blastRadius": jsNumber(s.BlastRadius)}
					if s.AmountField != "" {
						m["amountField"] = s.AmountField
					}
					if s.Resource != "" {
						m["resource"] = s.Resource
					}
					acts = append(acts, m)
				}
				limits := map[string]any{}
				for kk, v := range a.Policy.InputLimits {
					limits[kk] = v
				}
				var reviews []any
				for _, e := range sliceOf(vecObj(c.Out)["reviews"]) {
					reviews = append(reviews, cbReview(a, vecObj(e)))
				}
				got = vecJSON(map[string]any{
					"policy": map[string]any{"predicates": a.Policy.Predicates, "caveats": a.Policy.Caveats, "riskPolicy": a.Policy.RiskPolicy, "budgetModel": a.Policy.BudgetModel,
						"approximations": cbStrings(a.Policy.Approximations), "inputLimits": limits, "actions": acts},
					"reviews": reviews})
			case "exampleBlue":
				a, err := cbAgent(c.Args[0].(string))
				if err != nil {
					panic(err)
				}
				b := ControlExampleBlue(a)
				got = vecJSON(map[string]any{"name": b.Name, "basePolicy": b.BasePolicy, "dlp": b.Dlp, "startMs": jsNumber(b.StartMsValue), "stepMs": jsNumber(b.StepMsValue)})
			case "blueEpisode":
				spec := vecObj(c.Args[0])
				blue, err := cbBlue(vecObj(spec["blue"]))
				if err != nil {
					panic(err)
				}
				var red ControlRedPolicy
				if len(c.Args) > 1 {
					list, _ := c.Args[1].([]any)
					red = ControlRedPolicy{Name: "custom", Strategy: "custom", Gen: func() []map[string]any {
						out := make([]map[string]any, len(list))
						for i, x := range list {
							out[i] = vecObj(x)
						}
						return out
					}}
				} else {
					red = ceTestRed(spec["red"])
				}
				res, err := ControlRunEpisode(red, blue, cbEnv(spec["env"]), spec["seed"])
				if err != nil {
					panic(err)
				}
				got = vecJSON(res)
			case "exampleEval":
				spec := vecObj(c.Args[0])
				rep, err := ControlExampleEval(int(jsF(spec["episodes"])), int(jsF(spec["seed"])), nil)
				if err != nil {
					panic(err)
				}
				got = vecJSON(rep)
			default:
				panic("no Go entry point for " + c.Fn)
			}
		})
		if throws {
			// the reference refused: params that are not canonical JSON; the episode here ends in a denial at that action
			steps, _ := vecObj(got)["steps"].([]any)
			denied := false
			for _, s := range steps {
				if r, _ := vecObj(s)["reason"].(string); strings.Contains(r, "params are not JSON") {
					denied = true
				}
			}
			if panicked != "" || !denied {
				k.fail(c, "reference refuses (%v); Go: panic %q, no 'params are not JSON' denial", c.Out, panicked)
				return
			}
			deviations++
			return
		}
		if panicked != "" {
			k.fail(c, "panic: %s", panicked)
			return
		}
		if c.Fn == "buildExampleAgent" {
			// a battery entry whose params carry an integer past 2^53 is refused up front here (the reason differs, the verdict does not)
			w, g := vecObj(normalizeJSON(c.Out)), vecObj(got)
			wr, gr := sliceOf(w["reviews"]), sliceOf(g["reviews"])
			if len(wr) == len(gr) {
				for i := range wr {
					we, ge := vecObj(wr[i]), vecObj(gr[i])
					gk := vecObj(ge["review"])
					if gr2, _ := gk["reason"].(string); gk["kind"] == "deny" && strings.HasPrefix(gr2, "params are not JSON") && vecObj(we["review"])["kind"] == "deny" {
						deviations++
						vecObj(we["review"])["reason"], gk["reason"] = "", ""
					}
				}
			}
			if !cbEqual(w, g) {
				k.fail(c, "%s", vecDiff(baseCanon(w), baseCanon(g)))
			}
			return
		}
		if !cbEqual(normalizeJSON(c.Out), got) {
			k.fail(c, "%s", vecDiff(baseCanon(c.Out), baseCanon(got)))
		}
	})
	k.finish(t)
	if deviations < 5 {
		t.Errorf("params-not-JSON deviations: %d, want at least the 5 reference refusals", deviations)
	}
}
