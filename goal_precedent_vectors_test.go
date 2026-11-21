package pca

// Replay of the reference corpus for the goal precedent log: a stateful hash-chained log over principal-signed escalation answers,
// driven through a step script exactly as the reference's generator drives it.

import (
	"errors"
	"testing"
)

func goalPrecedentFlow(a []any) (any, error) {
	goal, ont, grant := vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)
	principals, _ := vecArg(a, 3).([]any)
	steps, _ := vecArg(a, 4).([]any)
	log := NewGoalPrecedentLog(principals)
	space := goalBuildSpace([]any{goal}, nil)
	out := []any{}
	for _, sv := range steps {
		s := sv.(map[string]any)
		switch s["op"] {
		case "append":
			r := log.Append(s["answer"], s["answered"], grant, space, s["now"])
			if r["ok"] == true {
				e := r["entry"].(map[string]any)
				out = append(out, map[string]any{"ok": true, "digest": e["digest"], "cell": e["cell"], "seq": e["seq"]})
			} else {
				out = append(out, r)
			}
		case "revoke":
			r := log.Revoke(s["rev"])
			if r["ok"] == true {
				e := r["entry"].(map[string]any)
				out = append(out, map[string]any{"ok": true, "digest": e["digest"], "seq": e["seq"]})
			} else {
				out = append(out, r)
			}
		case "verifyChain":
			out = append(out, log.VerifyChain(space))
		case "lookup":
			if h := log.Lookup(s["policyDigest"], space, s["case"], s["now"]); h != nil {
				out = append(out, map[string]any{"decision": h["decision"], "digest": h["entry"].(map[string]any)["digest"]})
			} else {
				out = append(out, nil)
			}
		case "authorize":
			r := goalAuthorizeWithPrecedents(goal, ont, s["policyDigest"], log, s["case"], s["now"])
			m := map[string]any{"decision": r["decision"], "via": r["via"]}
			if p, ok := r["precedent"].(map[string]any); ok {
				m["digest"] = p["digest"]
			}
			out = append(out, m)
		case "tamper":
			i, _ := jsNum(s["index"])
			if del, _ := s["del"].(bool); del {
				delete(log.Entries[int(i)], s["key"].(string))
			} else {
				log.Entries[int(i)][s["key"].(string)] = s["value"]
			}
			out = append(out, true)
		default:
			out = append(out, log.Head())
		}
	}
	return out, nil
}

func TestGoalPrecedentVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-goal-precedent.json.gz", map[string]vecFn{
		"flow":       goalPrecedentFlow,
		"ceilingsOf": func(a []any) (any, error) { return anlTry(func() any { return goalCeilingsOf(vecArg(a, 0)) }) },
		"answerBodyFor": func(a []any) (any, error) {
			return anlTry(func() any { return goalAnswerBodyFor(vecArg(a, 0), vecArg(a, 1)) })
		},
		"signRevocationSeed": func(a []any) (any, error) {
			seed, ok := DecodeB64uStrict(vecArg(a, 1).(string), -1)
			if !ok {
				return nil, errors.New("bad seed")
			}
			return anlTry(func() any { return goalSignRevocation(vecArg(a, 0), seed) })
		},
	})
}
