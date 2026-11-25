package pca

// Replays the interpreter corpus: candidate extraction, slot filling, the rule, form and model interpreters, prompts and keys,
// grounding, vendor completions over an injected fetch, the typed refund form and the lexical comparator. A shipped ontology
// travels by name and is resolved from the shipped data.

import (
	"errors"
	"testing"
)

func goalInterpretTestOnt(x any) any {
	if s, ok := x.(string); ok {
		if o := goalShippedOntology(s); o != nil {
			return o
		}
	}
	return x
}

func goalInterpretTestReq(on any, text any, src any) map[string]any {
	r := map[string]any{"principal": "p1", "text": text, "ontology": goalInterpretTestOnt(on)}
	if src != nil {
		r["sources"] = src
	}
	return r
}

func goalInterpretTestStr(v any) string {
	s, ok := v.(string)
	if !ok {
		anlFail("not a string")
	}
	return s
}

func goalInterpretTestTemplate(on any, tid any, key string) any {
	for _, t := range anlReqList(anlGet(on, key)) {
		if anlGet(t, "id") == tid || anlGet(t, "name") == tid {
			return t
		}
	}
	anlFail("StopIteration")
	return nil
}

func goalInterpretTestVendor(a []any) (any, error) {
	kind, _ := a[1].(string)
	cfg := vecObj(a[2])
	fake := vecObj(a[3])
	req := map[string]any{}
	if len(fake) == 0 { // the generator's plain success stub
		var body any = map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "x"}}}}
		if kind == "anthropic" {
			body = map[string]any{"content": []any{map[string]any{"type": "text", "text": "x"}}}
		}
		fake = map[string]any{"ok": true, "status": goalNum(200), "body": body}
	}
	fetch := func(url string, init GoalFetchInit) (GoalFetchResponse, error) {
		req["url"], req["method"], req["headers"], req["body"] = url, init.Method, init.Headers, init.Body
		if m, _ := fake["throwMsg"].(string); m != "" {
			return GoalFetchResponse{}, errors.New(m)
		}
		status, has := fake["status"]
		if !has {
			status = anlUndef
		}
		return GoalFetchResponse{Ok: anlTruthy(fake["ok"]), Status: status, Body: fake["body"]}, nil
	}
	var c GoalComplete
	if kind == "anthropic" {
		maxTokens := int64(1024)
		if v, ok := cfg["maxTokens"]; ok {
			f, _ := jsNum(v)
			maxTokens = int64(f)
		}
		c = goalAnthropicCompletion(goalInterpretTestStr(cfg["apiKey"]), goalInterpretTestStr(cfg["model"]), fetch, maxTokens)
	} else {
		base, _ := cfg["baseUrl"].(string)
		c = goalOpenaiCompletion(goalInterpretTestStr(cfg["apiKey"]), goalInterpretTestStr(cfg["model"]), fetch, base)
	}
	text, err := c(GoalPrompt{System: goalInterpretTestStr(a[4]), User: goalInterpretTestStr(a[5])})
	if err != nil {
		return map[string]any{"error": err.Error(), "req": req}, nil
	}
	return map[string]any{"text": text, "req": req}, nil
}

func TestGoalInterpretReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-goal-interpret.json.gz", map[string]vecFn{
		"slotStemsOf": func(a []any) (any, error) {
			return anlTry(func() any {
				out := []any{}
				for _, s := range goalSlotStems(vecArg(a, 0)) {
					out = append(out, s)
				}
				return out
			})
		},
		"sourceDigest": func(a []any) (any, error) { return anlTry(func() any { return goalSourceDigest(vecArg(a, 0)) }) },
		"extractCandidates": func(a []any) (any, error) {
			return anlTry(func() any {
				return goalExtractCandidates(goalInterpretTestStr(vecArg(a, 1)), goalInterpretTestOnt(vecArg(a, 0)), vecArg(a, 2))
			})
		},
		"fillTemplateById": func(a []any) (any, error) {
			return anlTry(func() any {
				on := goalInterpretTestOnt(vecArg(a, 0))
				return goalFillTemplate(goalInterpretTestTemplate(on, vecArg(a, 1), "templates"), on, goalInterpretTestStr(vecArg(a, 2)), vecArg(a, 3))
			})
		},
		"interpretRule": func(a []any) (any, error) {
			return anlTry(func() any {
				return goalRuleInterpreter("rule", vecArg(a, 3)).interpret(goalInterpretTestReq(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)))
			})
		},
		"buildPromptOf": func(a []any) (any, error) {
			return anlTry(func() any {
				req := goalInterpretTestReq(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2))
				req["principal"] = "p"
				p := goalBuildPrompt(req, anlTruthy(vecArg(a, 3)))
				return map[string]any{"system": p.System, "user": p.User}
			})
		},
		"interpretForm": func(a []any) (any, error) {
			return anlTry(func() any {
				req := goalInterpretTestReq(vecArg(a, 0), vecArg(a, 2), nil)
				if f := vecArg(a, 1); f != nil {
					req["form"] = f
				}
				if vecArg(a, 2) == "form text" {
					req["sources"] = []any{"s"}
				}
				return goalFormInterpreter("form").interpret(req)
			})
		},
		"interpretLlm": func(a []any) (any, error) {
			return anlTry(func() any {
				mode := vecObj(vecArg(a, 3))
				complete := func(GoalPrompt) (string, error) {
					if anlTruthy(mode["throw"]) {
						return "", errors.New("boom")
					}
					return goalInterpretTestStr(mode["raw"]), nil
				}
				return goalLlmInterpreter("m", "f", complete, anlTruthy(vecArg(a, 4)), vecArg(a, 5)).interpret(goalInterpretTestReq(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)))
			})
		},
		"promptKeyOf": func(a []any) (any, error) {
			return anlTry(func() any {
				return goalPromptKey(goalInterpretTestStr(vecArg(a, 1)), GoalPrompt{System: goalInterpretTestStr(vecArg(a, 2)), User: goalInterpretTestStr(vecArg(a, 3))})
			})
		},
		"replayLookup": func(a []any) (any, error) {
			rec := vecObj(vecArg(a, 2))
			return goalReplayCompletion(goalInterpretTestStr(vecArg(a, 1)), rec)(GoalPrompt{System: goalInterpretTestStr(vecArg(a, 3)), User: goalInterpretTestStr(vecArg(a, 4))})
		},
		"parseTemplateJSON": func(a []any) (any, error) {
			return anlTry(func() any { return goalParseTemplateJSON(goalInterpretTestStr(vecArg(a, 0))) })
		},
		"groundedOf": func(a []any) (any, error) {
			return anlTry(func() any {
				on := goalInterpretTestOnt(vecArg(a, 0))
				tpl := goalInterpretTestTemplate(on, vecArg(a, 1), "templates")
				slot := goalInterpretTestTemplate(tpl, vecArg(a, 2), "slots")
				return goalGrounded(slot, vecArg(a, 3), goalExtractCandidates(goalInterpretTestStr(vecArg(a, 4)), on, nil), on)
			})
		},
		"vendor": func(a []any) (any, error) { return anlTry(func() any { r, _ := goalInterpretTestVendor(a); return r }) },
		"interpretRefundForm": func(a []any) (any, error) {
			return anlTry(func() any {
				pr := "pr1"
				if p, ok := vecArg(a, 2).(string); ok {
					pr = p
				}
				return goalInterpretRefundForm(vecArg(a, 0), vecArg(a, 1), pr)
			})
		},
		"lexicalCompare": func(a []any) (any, error) {
			return GoalLexicalComparator(goalInterpretTestOnt(vecArg(a, 0))).Equivalent(goalInterpretTestStr(vecArg(a, 1)), goalInterpretTestStr(vecArg(a, 2)))
		},
	})
}
