package pca

// Replays the explainer reference corpus: cleanText, the verification / decision / chain explanations and their text renderers.
// Explanations compare as their JSON (an absent member is a JavaScript undefined); a reference throw requires an error.

import "testing"

func TestExplainReferenceVectors(t *testing.T) {
	opts := func(args []any, i int) any {
		if i < len(args) {
			return args[i]
		}
		return map[string]any{}
	}
	siemReplay(t, "ref-explain.json.gz", map[string]vecFn{
		"cleanText": func(args []any) (any, error) { return ExplainCleanText(vecArg(args, 0)), nil },
		"explainVerification": func(args []any) (any, error) {
			return ExplainVerification(vecArg(args, 0), vecArg(args, 1), opts(args, 2)), nil
		},
		"explainVerificationText": func(args []any) (any, error) {
			return ExplainVerificationText(ExplainVerification(vecArg(args, 0), vecArg(args, 1), opts(args, 2)))
		},
		"explainDecision": func(args []any) (any, error) {
			return ExplainDecision(vecArg(args, 0), vecArg(args, 1), opts(args, 2))
		},
		"explainDecisionText": func(args []any) (any, error) {
			e, err := ExplainDecision(vecArg(args, 0), vecArg(args, 1), opts(args, 2))
			if err != nil {
				return nil, err
			}
			return ExplainDecisionText(e)
		},
		"explainChain": func(args []any) (any, error) { return ExplainChain(vecArg(args, 0), opts(args, 1)) },
		"explainChainText": func(args []any) (any, error) {
			e, err := ExplainChain(vecArg(args, 0), opts(args, 1))
			if err != nil {
				return nil, err
			}
			return ExplainChainText(e)
		},
		"consts": func(args []any) (any, error) {
			order := make([]any, len(ExplainVerifyCheckOrder))
			for i, s := range ExplainVerifyCheckOrder {
				order[i] = s
			}
			return map[string]any{"VERIFY_CHECK_ORDER": order, "MAX_TEXT": jsonNumberOf(ExplainMaxText)}, nil
		},
	})
}
