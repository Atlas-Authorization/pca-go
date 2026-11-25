package pca

// Replays the reference corpora for business rules (the plain one and the one added for the scripting lanes, which also covers
// resolveParamRef and knownTimeZone). Signing seeds are labels ({"$bytes": {"$seed": label}}, see packTestSeed).

import "testing"

func actionRulesFns() map[string]vecFn {
	str := func(a []any, i int) string { s, _ := vecArg(a, i).(string); return s }
	return map[string]vecFn{
		"businessRulesError": func(a []any) (any, error) {
			return vecIsNull(ActionBusinessRulesError(vecObj(vecArg(a, 0)), vecArg(a, 1))), nil
		},
		"compileBusinessRules": func(a []any) (any, error) { return ActionCompileBusinessRules(vecObj(vecArg(a, 0)), vecArg(a, 1)) },
		"businessRulesDigest": func(a []any) (any, error) {
			return ActionBusinessRulesDigest(str(a, 0), vecObj(vecArg(a, 1)))
		},
		"moneyOf": func(a []any) (any, error) { return ActionMoneyOf(vecObj(vecArg(a, 0))) },
		"minorUnits": func(a []any) (any, error) {
			exp, _ := jsNum(vecArg(a, 1))
			at := "x"
			if s, ok := vecArg(a, 2).(string); ok {
				at = s
			}
			n, err := ActionMinorUnits(vecArg(a, 0), int(exp), at)
			if err != nil {
				return nil, err
			}
			return jsNumber(float64(n)), nil
		},
		"evaluateBusinessRules": func(a []any) (any, error) {
			return ActionEvaluateBusinessRules(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"runRuleExamples":      func(a []any) (any, error) { return ActionRunRuleExamples(vecObj(vecArg(a, 0)), vecArg(a, 1)) },
		"explainBusinessRules": func(a []any) (any, error) { return ActionExplainBusinessRules(vecObj(vecArg(a, 0)), vecArg(a, 1)) },
		"lintBusinessRules":    func(a []any) (any, error) { return ActionLintBusinessRules(vecObj(vecArg(a, 0)), vecArg(a, 1)), nil },
		"diffBusinessRules": func(a []any) (any, error) {
			return ActionDiffBusinessRules(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2)))
		},
		"clockAt": func(a []any) (any, error) {
			k := ActionClockAt(vecArg(a, 0), str(a, 1))
			if k == nil {
				return nil, nil
			}
			return k, nil
		},
		"formatMoney": func(a []any) (any, error) {
			f, _ := jsNum(vecArg(a, 0))
			e, _ := jsNum(vecArg(a, 2))
			return ActionFormatMoney(int64(f), str(a, 1), int(e)), nil
		},
		"knownTimeZone": func(a []any) (any, error) { return ActionKnownTimeZone(vecArg(a, 0)), nil },
		"resolveParamRef": func(a []any) (any, error) {
			name, p, err := ActionResolveParamRef(vecObj(vecArg(a, 0)), vecArg(a, 1), str(a, 2))
			if err != nil {
				return nil, err
			}
			return map[string]any{"name": name, "p": p}, nil
		},
		"rulesReviewMessage": func(a []any) (any, error) {
			m, err := ActionRulesReviewMessage(vecObj(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(m), nil
		},
		"signRulesReview": func(a []any) (any, error) {
			seed, err := packTestSeed(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return ActionSignRulesReview(vecObj(vecArg(a, 0)), seed)
		},
		"rulesReviewError": func(a []any) (any, error) {
			return vecIsNull(ActionRulesReviewError(vecArg(a, 0), vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2)), vecArg(a, 3))), nil
		},
	}
}

func TestActionRulesVectors(t *testing.T) {
	replayVectors(t, "ref-actions-rules.json.gz", vecSeeded(actionRulesFns()))
}

func TestActionRulesVectorsScripting(t *testing.T) {
	replayVectors(t, "ref-actions-rules-py.json.gz", vecSeeded(actionRulesFns()))
}
