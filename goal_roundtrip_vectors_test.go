package pca

// Replay of the reference corpus for goal roundtrip: the card tape round trip, widening mutations and the explainer + comparator
// detector (injected explainers and comparators are chosen by mode name).

import (
	"errors"
	"strings"
	"testing"
)

type goalVxExplainer struct{ mode string }

func (e goalVxExplainer) Explain(lines []string) (string, error) {
	if e.mode == "throw" {
		return "", errors.New("boom")
	}
	return strings.Join(lines, "\n"), nil
}

type goalVxComparator struct{ mode string }

func (c goalVxComparator) Equivalent(_, explanation string) (map[string]any, error) {
	switch {
	case c.mode == "throw":
		return nil, errors.New("boom")
	case c.mode == "ok":
		return map[string]any{"equivalent": true}, nil
	case c.mode == "no":
		return map[string]any{"equivalent": false, "reason": "x"}, nil
	}
	needle := ""
	if len(c.mode) > 9 {
		needle = c.mode[9:]
	}
	return map[string]any{"equivalent": strings.Contains(explanation, needle)}, nil
}

func TestGoalRoundtripVectors(t *testing.T) {
	replayVectors(t, "ref-goal-roundtrip.json.gz", map[string]vecFn{
		"cardRoundTrips": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCardRoundTrips(vecArg(a, 0)) })
		},
		"mutateGoal": func(a []any) (any, error) {
			return goalVecTry(func() any {
				if m := goalMutateGoal(vecArg(a, 0), goalVecStr(vecArg(a, 1)), vecArg(a, 2)); m != nil {
					return m
				}
				return nil
			})
		},
		"roundTrip": func(a []any) (any, error) {
			return goalVecTry(func() any {
				return goalRoundTrip(vecArg(a, 0), goalVecStr(vecArg(a, 1)), goalVxExplainer{goalVecStr(vecArg(a, 2))}, goalVxComparator{goalVecStr(vecArg(a, 3))})
			})
		},
		"measureDetection": func(a []any) (any, error) {
			return goalVecTry(func() any {
				return goalMeasureDetection(vecArg(a, 0), vecArg(a, 1), goalVxExplainer{goalVecStr(vecArg(a, 2))}, goalVxComparator{goalVecStr(vecArg(a, 3))})
			})
		},
	})
}
