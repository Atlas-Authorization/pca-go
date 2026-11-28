package pca

// Replay of the reference corpus for goal examples: decision cells, boundary examples, goal tests and the policy pin.

import (
	"encoding/base64"
	"testing"
)

// goalVxStrs reads a JSON string array (nil when v is not an array).
func goalVxStrs(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, anlStr(x, "verb"))
	}
	return out
}

func goalVxB64(v any) []byte {
	b, err := base64.RawURLEncoding.DecodeString(goalVecStr(v))
	if err != nil {
		anlFail("bad base64url: %v", err)
	}
	return b
}

func TestGoalExamplesVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-goal-examples.json.gz", map[string]vecFn{
		"buildSpace": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalBuildSpace(vecArg(a, 0), goalVxStrs(vecArg(a, 1))).JSON() })
		},
		"cellKey": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCellKey(goalBuildSpace(vecArg(a, 0), goalVxStrs(vecArg(a, 1))), vecArg(a, 2)) })
		},
		"cells": func(a []any) (any, error) {
			return goalVecTry(func() any {
				return goalCells(goalBuildSpace(vecArg(a, 0), goalVxStrs(vecArg(a, 1))), goalVxStrs(vecArg(a, 2)))
			})
		},
		"decideCase": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalDecideCase(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) })
		},
		"replay": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalReplay(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3)) })
		},
		"allowWitness": func(a []any) (any, error) {
			return goalVecTry(func() any {
				g := vecArg(a, 0)
				i, ok := jsNum(vecArg(a, 1))
				grants := anlReqList(anlGet(g, "grants"))
				if !ok || i < 0 || int(i) >= len(grants) {
					anlFail("no such grant")
				}
				if w := goalAllowWitness(g, grants[int(i)], vecArg(a, 2)); w != nil {
					return w
				}
				return nil
			})
		},
		"boundaryExamples": func(a []any) (any, error) {
			return goalVecTry(func() any {
				opts := GoalExampleOpts{Ont: vecArg(a, 1)}
				if l, ok := vecArg(a, 2).([]any); ok && len(l) > 0 {
					opts.Extra = l
				}
				if vs := goalVxStrs(vecArg(a, 3)); len(vs) > 0 {
					opts.Verbs = vs
				}
				return goalBoundaryExamples(vecArg(a, 0), opts)
			})
		},
		"reviewSet": func(a []any) (any, error) {
			return goalVecTry(func() any {
				n, ok := jsNum(vecArg(a, 1))
				if !ok {
					anlFail("cap is not a number")
				}
				return goalReviewSet(vecArg(a, 0), int(n))
			})
		},
		"testsDigest": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalTestsDigest(vecArg(a, 0)) })
		},
		"makeGoalTests": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalMakeGoalTests(vecArg(a, 0), vecArg(a, 1)) })
		},
		"signGoalTestsSeed": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalSignGoalTests(vecArg(a, 0), goalVxB64(vecArg(a, 1))) })
		},
		"checkGoalTests": func(a []any) (any, error) {
			return goalVecTry(func() any {
				mode, g, ont := vecArg(a, 2), vecArg(a, 3), vecArg(a, 4)
				decide := func(t any) string {
					if mode == "ref" {
						return goalDecideCase(g, ont, t)["decision"].(string)
					}
					if mode == "allow" || mode == "deny" {
						return mode.(string)
					}
					return "escalate"
				}
				return goalCheckGoalTests(vecArg(a, 0), vecArg(a, 1), decide)
			})
		},
		"signPinSeed": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalSignPin(vecArg(a, 0), goalVxB64(vecArg(a, 1))) })
		},
		"checkPin": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCheckPin(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) })
		},
	})
}
