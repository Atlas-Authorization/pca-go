package pca

// Replay of the reference corpus for goal nversion and disambiguate: the semantic meet of readings, the panel check, N-version
// interpretation, witness questions and version-space halving.

import (
	"math"
	"testing"
)

// goalVxApprox is value equality with a relative tolerance on numbers (entropy scores come from a binary logarithm).
func goalVxApprox(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, x := range w {
			y, has := g[k]
			if !has || !goalVxApprox(x, y) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !goalVxApprox(w[i], g[i]) {
				return false
			}
		}
		return true
	}
	if a, ok := jsNum(want); ok {
		b, ok := jsNum(got)
		return ok && math.Abs(a-b) <= 1e-12*math.Max(1, math.Max(math.Abs(a), math.Abs(b)))
	}
	return baseCanon(want) == baseCanon(got)
}

func goalVxDisambiguate(a []any) any {
	readings, ont, mode, budget := vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3)
	ask := func(q any) string {
		if mode == "allow" || mode == "deny" {
			return mode.(string)
		}
		m := goalVecStr(mode)
		idx := 0
		for _, c := range m[6:] {
			idx = idx*10 + int(c-'0')
		}
		if goalAllowsWitness(anlGet(anlReqList(readings)[idx], "goal"), ont, q) {
			return "allow"
		}
		return "deny"
	}
	return goalDisambiguate(readings, ask, GoalDisambOpts{Ont: ont, Budget: budget})
}

func TestGoalNVersionVectors(t *testing.T) {
	approx := func(want, got any) bool { return goalVxApprox(want, got) }
	replayVectorsCmp(t, "ref-goal-nversion.json.gz", map[string]vecFn{
		"meet": func(a []any) (any, error) { return goalVecTry(func() any { return goalMeet(vecArg(a, 0)) }) },
		"meetGrants": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalMeetGrants(vecArg(a, 0), vecArg(a, 1)) })
		},
		"checkPanel": func(a []any) (any, error) { return goalVecTry(func() any { return goalCheckPanel(vecArg(a, 0)) }) },
		"nVersion": func(a []any) (any, error) {
			return goalVecTry(func() any {
				return goalNVersion(vecArg(a, 0), GoalDisambOpts{Ont: vecArg(a, 1), MassThreshold: vecArg(a, 2)})
			})
		},
		"questions": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalQuestions(vecArg(a, 0), GoalDisambOpts{Ont: vecArg(a, 1)}) })
		},
		"disagreementMass": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalDisagreementMass(vecArg(a, 0), vecArg(a, 1)) })
		},
		"allowsWitness": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalAllowsWitness(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) })
		},
		"disambiguate": func(a []any) (any, error) { return goalVecTry(func() any { return goalVxDisambiguate(a) }) },
	}, map[string]func(want, got any) bool{"nVersion": approx, "questions": approx, "disagreementMass": approx, "disambiguate": approx})
}
