package pca

// Replay of the reference corpus for the goal benchmark: the deterministic generator, labelled cases, simulated model fixtures, the
// four-level evaluation and the calibration report.

import "testing"

func goalBenchArgInt(v any) int {
	f, _ := jsNum(v)
	return int(f)
}

func goalBenchTest(f func(a []any) any) vecFn {
	return func(a []any) (any, error) { return anlTry(func() any { return f(a) }) }
}

func goalBenchSpec(id any) GoalSimSpec {
	for _, s := range GoalSimSpecs {
		if goalReviewEqS(id, s.ID) {
			return s
		}
	}
	anlFail("unknown simulated model %s", anlJS(id))
	return GoalSimSpec{}
}

func goalBenchTruthItems(cases any) []GoalBenchItem {
	items := []GoalBenchItem{}
	for _, c := range anlReqList(cases) {
		goal := goalBenchTruthGoal(c)
		items = append(items, GoalBenchItem{Goal: goal, Ont: goalBenchTruthOnt(c, goal)})
	}
	return items
}

func TestGoalBenchVectors(t *testing.T) {
	replayVectors(t, "ref-goal-bench.json.gz", map[string]vecFn{
		"rngSeq": goalBenchTest(func(a []any) any {
			f, _ := jsNum(vecArg(a, 0))
			r := goalBenchRng(goalBenchU32(f))
			out := []any{}
			for i := goalBenchArgInt(vecArg(a, 1)); i > 0; i-- {
				out = append(out, jsNumber(r()))
			}
			return out
		}),
		"generateCases": goalBenchTest(func(a []any) any {
			seed, _ := jsNum(vecArg(a, 2))
			he := 0
			if vecArg(a, 3) != nil {
				he = goalBenchArgInt(vecArg(a, 3))
			}
			ho, _ := vecArg(a, 4).(bool)
			return goalBenchGenerateCases(vecArg(a, 0).(string), goalBenchArgInt(vecArg(a, 1)), seed, he, ho)
		}),
		"truthGoalOf":       goalBenchTest(func(a []any) any { return goalBenchTruthGoal(vecArg(a, 0)) }),
		"simulateOutputOf":  goalBenchTest(func(a []any) any { return goalBenchSimulateOutput(vecArg(a, 0), goalBenchSpec(vecArg(a, 1))) }),
		"recordFixturesOf":  goalBenchTest(func(a []any) any { return goalBenchRecordFixtures(vecArg(a, 0)) }),
		"caseSetDigest":     goalBenchTest(func(a []any) any { return goalBenchCaseSetDigest(vecArg(a, 0)) }),
		"compileWideningOf": goalBenchTest(func(a []any) any { return goalBenchCompileWideningCount(goalBenchTruthItems(vecArg(a, 0)), nil) }),
		"evalCaseOf": goalBenchTest(func(a []any) any {
			c := vecArg(a, 0)
			return goalBenchEvalCase(c, goalBenchCompletionsFrom(goalBenchRecordFixtures([]any{c})), GoalBenchEvalOpts{})
		}),
		"runDomainOf": goalBenchTest(func(a []any) any {
			cases, _ := vecArg(a, 1).([]any)
			return goalBenchRunDomain(vecArg(a, 0).(string), cases, goalBenchRecordFixtures(cases), "recorded-fixtures", false)
		}),
		"summarizeOf": goalBenchTest(func(a []any) any {
			return goalBenchSummarize(vecArg(a, 0).(string), vecArg(a, 1), vecArg(a, 2).(string), vecArg(a, 3))
		}),
	})
}
