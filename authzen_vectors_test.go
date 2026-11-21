package pca

// Replays the AuthZEN reference corpus: the guards, the default action mapping, AARP, the PDP refusal / merge paths, the handler
// and the search handler. The PDP and provider configurations are named by the cases and kept here as fixed tables. Permit paths
// that need the risk decision or a signed PCActn are not in the corpus.

import (
	"encoding/json"
	"errors"
	"testing"
)

const azTestNow = 1000000

func azTestMap(a []any, i int) map[string]any {
	if i < len(a) {
		m, _ := a[i].(map[string]any)
		return m
	}
	return nil
}

func azTestPdp(name string) *AuthzenPdp {
	cfg := AuthzenConfig{Now: func() int64 { return azTestNow }}
	grant := func(map[string]any) (*AuthzenContext, error) {
		return &AuthzenContext{Grant: map[string]any{}, Policy: map[string]any{}}, nil
	}
	switch name {
	case "none":
		cfg.Resolve = func(map[string]any) (*AuthzenContext, error) { return nil, nil }
	case "throws":
		cfg.Resolve = func(map[string]any) (*AuthzenContext, error) { return nil, errors.New("boom") }
	case "noauth":
		cfg.Resolve = grant
	case "auth":
		cfg.Resolve = grant
		cfg.Authorizer = func(map[string]any) (AuthzenAuthorizerResult, error) {
			return AuthzenAuthorizerResult{Allow: true}, nil
		}
	case "max2":
		two := 2
		cfg.Resolve = func(map[string]any) (*AuthzenContext, error) { return nil, nil }
		cfg.MaxEvaluations = &two
	case "toolmap":
		cfg.Resolve = func(map[string]any) (*AuthzenContext, error) { return nil, nil }
		cfg.ToolCapability = func(n string) (string, error) { return "cap." + n, nil }
	case "toolthrow":
		cfg.Resolve = func(map[string]any) (*AuthzenContext, error) { return nil, nil }
		cfg.ToolCapability = func(string) (string, error) { return "", errors.New("bad tool") }
	}
	return NewAuthzenPdp(cfg)
}

// azTestObj is an object literal whose member order is kept (parsed from text), as a JavaScript literal keeps it: the reference
// de-duplicates search results by their JSON text, so {type, id} and {id, type} are two different results.
func azTestObj(text string) map[string]any {
	v, err := StrictParse(text)
	if err != nil {
		panic(err)
	}
	return v.(map[string]any)
}

func azTestUser(id string) map[string]any { return azTestObj(`{"type":"user","id":"` + id + `"}`) }

func azTestNum(n int) json.Number { return json.Number(jsNumberString(float64(n))) }

func azTestProvider(name string) AuthzenSearchProvider {
	boom := func(map[string]any) (any, error) { return nil, errors.New("x") }
	res := func(rs ...any) map[string]any { return map[string]any{"results": rs} }
	switch name {
	case "full":
		return AuthzenSearchProvider{
			SearchSubject: func(map[string]any) (any, error) {
				return map[string]any{
					"results": []any{azTestUser("a"), azTestUser("b"), map[string]any{"type": "group", "id": "g"}, azTestUser("a"), azTestObj(`{"id":"a","type":"user"}`)},
					"page":    map[string]any{"next_token": "", "total": azTestNum(3), "properties": map[string]any{"k": azTestNum(1)}},
					"context": map[string]any{"c": azTestNum(1)},
				}, nil
			},
			SearchResource: func(map[string]any) (any, error) {
				return map[string]any{
					"results": []any{map[string]any{"type": "doc", "id": "1"}, map[string]any{"type": "doc", "id": "2"}, map[string]any{"type": "user", "id": "x"}},
					"page":    map[string]any{"next_token": "n1"},
				}, nil
			},
			SearchAction: func(map[string]any) (any, error) {
				return res(map[string]any{"name": "read"}, map[string]any{"name": "write"}, map[string]any{"name": "read"},
					map[string]any{"name": "read", "properties": map[string]any{"p": azTestNum(1)}}), nil
			},
		}
	case "nopage":
		return AuthzenSearchProvider{
			SearchSubject:  func(map[string]any) (any, error) { return res(azTestUser("a"), azTestUser("b")), nil },
			SearchResource: func(map[string]any) (any, error) { return res(), nil },
			SearchAction:   func(map[string]any) (any, error) { return res(), nil },
		}
	case "emptyprops":
		return AuthzenSearchProvider{SearchSubject: func(map[string]any) (any, error) {
			return map[string]any{"results": []any{azTestUser("a")}, "page": map[string]any{"next_token": "z", "properties": map[string]any{}}, "context": map[string]any{}}, nil
		}}
	case "bad":
		return AuthzenSearchProvider{
			SearchSubject:  func(map[string]any) (any, error) { return res(nil), nil },
			SearchResource: func(map[string]any) (any, error) { return res(azTestNum(5)), nil },
			SearchAction:   func(map[string]any) (any, error) { return res(nil, azTestNum(5)), nil },
		}
	case "notarray":
		return AuthzenSearchProvider{
			SearchSubject:  func(map[string]any) (any, error) { return map[string]any{"results": "x"}, nil },
			SearchResource: func(map[string]any) (any, error) { return map[string]any{}, nil },
			SearchAction:   func(map[string]any) (any, error) { return map[string]any{"results": nil}, nil },
		}
	case "throws":
		return AuthzenSearchProvider{SearchSubject: boom, SearchResource: boom, SearchAction: boom}
	case "echo":
		echo := func(r map[string]any) (any, error) {
			return map[string]any{"results": []any{}, "context": map[string]any{"saw": r}}, nil
		}
		return AuthzenSearchProvider{SearchSubject: echo, SearchResource: echo, SearchAction: echo}
	case "partial":
		return AuthzenSearchProvider{SearchResource: func(map[string]any) (any, error) { return res(), nil }}
	}
	return AuthzenSearchProvider{}
}

func azTestGuard(f func(any) bool) vecFn {
	return func(a []any) (any, error) { return f(a[0]), nil }
}

func TestAuthzenVectors(t *testing.T) {
	str := func(a []any, i int) string { s, _ := a[i].(string); return s }
	replayVectors(t, "ref-authzen.json.gz", map[string]vecFn{
		"isAccessEvaluationRequest":      azTestGuard(IsAccessEvaluationRequest),
		"isAccessEvaluationsRequest":     azTestGuard(IsAccessEvaluationsRequest),
		"isCoazToolAuthorizationRequest": azTestGuard(IsCoazToolAuthorizationRequest),
		"isAuthzenSubject":               azTestGuard(IsAuthzenSubject),
		"isAuthzenAction":                azTestGuard(IsAuthzenAction),
		"isAuthzenResource":              azTestGuard(IsAuthzenResource),
		"isSubjectSearch":                azTestGuard(IsSubjectSearch),
		"isResourceSearch":               azTestGuard(IsResourceSearch),
		"isActionSearch":                 azTestGuard(IsActionSearch),
		"defaultToAction":                func(a []any) (any, error) { return AuthzenDefaultToAction(azTestMap(a, 0)), nil },
		"approvalOf": func(a []any) (any, error) {
			m, err := ApprovalOf(a[0])
			if m == nil {
				return nil, err
			}
			return m, err
		},
		"isApprovalRequired": func(a []any) (any, error) { return IsApprovalRequired(a[0]) },
		"pdp.evaluate": func(a []any) (any, error) {
			m := azTestMap(a, 1)
			if m == nil {
				return nil, vecSkip("non-object request: the Go PDP takes an object")
			}
			return azTestPdp(str(a, 0)).Evaluate(m), nil
		},
		"pdp.evaluations":  func(a []any) (any, error) { return azTestPdp(str(a, 0)).Evaluations(a[1]) },
		"pdp.evaluateTool": func(a []any) (any, error) { return azTestPdp(str(a, 0)).EvaluateTool(azTestMap(a, 1)), nil },
		"authzenHandler":   func(a []any) (any, error) { return AuthzenHandler(azTestPdp(str(a, 0)))(azTestMap(a, 1)), nil },
		"authzenSearchHandler": func(a []any) (any, error) {
			r := AuthzenSearchHandler(azTestProvider(str(a, 0)))(azTestMap(a, 1))
			if r == nil {
				return nil, nil
			}
			return r, nil
		},
		"searchMetadata": func(a []any) (any, error) { return SearchMetadata(str(a, 0), azTestProvider(str(a, 1))), nil },
	})
}
