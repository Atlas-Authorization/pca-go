package pca

// Replays the control-evals reference corpus: the seeded PRNG and seed mixing, the Wilson bound, the CI gate, the built-in red
// policies, the modeled environments, the example DLP policy, and the episode runner / evaluation aggregation. The blue decisions
// come from the reference stack and are replayed from the recorded decisions (a stub blue answers the i-th decision from
// recorded.steps[i]).

import "testing"

func ceTestReds() map[string]ControlRedPolicy {
	return map[string]ControlRedPolicy{"over-cap": ControlOverCapRed(), "off-verb": ControlOffVerbRed(), "slow-burn": ControlSlowBurnRed(),
		"taint-exfil": ControlTaintExfilRed(), "replay": ControlReplayRed(), "immune-probe": ControlImmuneProbeBurstRed(), "benign": ControlBenignBaselineRed(),
		"gap-exploit": ControlGapExploitRed("")}
}

func ceTestEnv(name string) ControlEnv {
	switch {
	case name == "example":
		return ControlExampleEnv()
	case name == "gap-aware":
		return ControlGapAwareEnv("")
	}
	return ControlGapAwareEnv(name[len("gap-aware:"):])
}

type ceStubBlue struct {
	start, step, bound float64
	episodes           []map[string]any
	next               int
}

func (b *ceStubBlue) StartMs() float64       { return b.start }
func (b *ceStubBlue) StepMs() float64        { return b.step }
func (b *ceStubBlue) AnalyticBound() float64 { return b.bound }
func (b *ceStubBlue) NewEpisode() ControlBlueEpisode {
	var rec map[string]any
	if b.next < len(b.episodes) {
		rec = b.episodes[b.next]
	}
	b.next++
	return &ceStubEpisode{rec: rec, i: -1}
}

type ceStubEpisode struct {
	rec map[string]any
	i   int
}

func (e *ceStubEpisode) step() map[string]any {
	steps := sliceOf(e.rec["steps"])
	if e.i >= 0 && e.i < len(steps) {
		return vecObj(steps[e.i])
	}
	return map[string]any{}
}

func (e *ceStubEpisode) Decide(action map[string]any, atMs float64) map[string]any {
	e.i++
	s := e.step()
	d := map[string]any{"outcome": s["outcome"], "caughtBy": s["caughtBy"], "r": s["r"], "threat": s["threat"]}
	if r, ok := s["reason"]; ok {
		d["reason"] = r
	}
	return d
}

func (e *ceStubEpisode) MoneyAmount(action map[string]any) float64 {
	return connTestFloat(e.step()["money"], 0)
}
func (e *ceStubEpisode) EndBudget() any { return e.rec["endBudget"] }

func ceTestRed(name any) ControlRedPolicy { n, _ := name.(string); return ceTestReds()[n] }

func actionsOf(r ControlRedPolicy) any {
	out := []any{}
	for _, a := range r.Gen() {
		out = append(out, a)
	}
	return out
}

func TestControlEvalsReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-control-evals.json.gz", map[string]vecFn{
		"mulberry32": func(args []any) (any, error) {
			r := ControlMulberry32(vecArg(args, 0))
			n := int(connTestFloat(vecArg(args, 1), 0))
			out := make([]any, n)
			for i := range out {
				out[i] = jsNumber(r())
			}
			return out, nil
		},
		"mixSeed": func(args []any) (any, error) {
			return jsNumber(float64(ControlMixSeed(vecArg(args, 0), vecArg(args, 1), vecArg(args, 2)))), nil
		},
		"wilsonLowerBound": func(args []any) (any, error) {
			z := 1.645
			if len(args) > 2 {
				z = connTestFloat(args[2], z)
			}
			return jsNumber(ControlWilsonLowerBound(connTestFloat(args[0], 0), connTestFloat(args[1], 0), z)), nil
		},
		"assertControlGate": func(args []any) (any, error) { return nil, AssertControlGate(vecArg(args, 0), vecArg(args, 1)) },
		"redGen": func(args []any) (any, error) {
			r := ceTestRed(vecArg(args, 0))
			return map[string]any{"name": r.Name, "strategy": r.Strategy, "actions": actionsOf(r)}, nil
		},
		"gapExploitCustom": func(args []any) (any, error) {
			r := ControlGapExploitRed("file:x")
			return map[string]any{"name": r.Name, "actions": actionsOf(r)}, nil
		},
		"redLists": func(args []any) (any, error) {
			strategies := func(rs []ControlRedPolicy) []any {
				out := []any{}
				for _, r := range rs {
					out = append(out, r.Strategy)
				}
				return out
			}
			return map[string]any{"builtin": strategies(ControlBuiltinRedPolicies()), "example": strategies(ControlExampleRedPolicies())}, nil
		},
		"exampleDlpPolicy": func(args []any) (any, error) { return ExampleDlpPolicy(), nil },
		"envJudge": func(args []any) (any, error) {
			name, _ := vecArg(args, 0).(string)
			ctx := vecObj(vecArg(args, 2))
			return ceTestEnv(name).UnacceptableIfAllowed(vecArg(args, 1), sliceOf(ctx["allowedSoFar"]), connTestFloat(ctx["allowedSpend"], 0))
		},
		"runEpisode": func(args []any) (any, error) {
			spec := vecObj(vecArg(args, 0))
			blue := &ceStubBlue{start: connTestFloat(spec["startMs"], 0), step: connTestFloat(spec["stepMs"], 1000), episodes: []map[string]any{vecObj(spec["recorded"])}}
			return ControlRunEpisode(ceTestRed(spec["red"]), blue, ceTestEnv(vecStr(spec, "env")), spec["seed"])
		},
		"controlEval": func(args []any) (any, error) {
			spec := vecObj(vecArg(args, 0))
			blue := &ceStubBlue{start: connTestFloat(spec["startMs"], 0), step: connTestFloat(spec["stepMs"], 1000), bound: connTestFloat(spec["analyticBound"], 0)}
			for _, perRed := range sliceOf(spec["recorded"]) {
				for _, rec := range sliceOf(perRed) {
					blue.episodes = append(blue.episodes, vecObj(rec))
				}
			}
			var reds []ControlRedPolicy
			for _, n := range sliceOf(spec["reds"]) {
				reds = append(reds, ceTestRed(n))
			}
			return ControlEval(reds, blue, ceTestEnv(vecStr(spec, "env")), spec["episodes"], spec["seed"])
		},
	})
}
