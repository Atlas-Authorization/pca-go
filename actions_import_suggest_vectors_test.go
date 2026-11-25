package pca

// Replays the reference corpus for the suggestion rules (validation, digest, signature, matching, application), the model assist and
// the provider adapters. A signing seed is a label: the key is sha256("atlas-pca-conformance/" + label).

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func aisTestRules(v any) any {
	if v == "default" {
		return ActionDefaultRules()
	}
	return v
}

func aisTestReg(v any) Registry {
	if v == "core" {
		return coreRegistry
	}
	return nil
}

func aisTestAdapters(v any) []ActionModelAdapter {
	out := []ActionModelAdapter{}
	for _, x := range aisList(v) {
		spec := vecObj(x)
		out = append(out, ActionModelAdapter{ID: vecStr(spec, "id"), Version: vecStr(spec, "version"), Complete: func(map[string]any) (any, error) {
			if t, ok := spec["throws"]; ok {
				return nil, errors.New(jsValueString(t))
			}
			if a, ok := spec["answer"]; ok {
				return a, nil
			}
			return "undefined", nil // String(undefined)
		}})
	}
	return out
}

func aisTestProvider(a []any) (any, error) {
	cfg, spec, req := vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2))
	var call any
	fetch := func(url string, init map[string]any) (*ActionModelResponse, error) {
		call = map[string]any{"url": url, "headers": init["headers"], "body": init["body"]}
		if t, ok := spec["throws"]; ok {
			return nil, errors.New(jsValueString(t))
		}
		ok := true
		if v, has := spec["ok"]; has && v != nil {
			ok = aimTruthy(v)
		}
		var status any = jsNumber(200)
		if v, has := spec["status"]; has && v != nil {
			status = v
		}
		return &ActionModelResponse{OK: ok, Status: status, JSON: func() (any, error) {
			if aimTruthy(spec["badjson"]) {
				return nil, errors.New("bad json")
			}
			return spec["json"], nil
		}}, nil
	}
	ad := ActionProviderAdapter(NewActionModelConfig(vecStr(cfg, "provider"), vecStr(cfg, "model"), vecStr(cfg, "apiKey")), fetch, 0)
	text, err := ad.Complete(req)
	if err != nil {
		return map[string]any{"call": call, "error": err.Error()}, nil
	}
	// the reference reads `call` before it awaits the answer: a success carries null
	return map[string]any{"call": nil, "text": text}, nil
}

func TestActionImportSuggestVectors(t *testing.T) {
	replayVectors(t, "ref-actions-import-suggest.json.gz", map[string]vecFn{
		"stem":                        func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return ActionSuggestStem(s), nil },
		"factsOf":                     func(a []any) (any, error) { return ActionSuggestFactsOf(vecObj(vecArg(a, 0))), nil },
		"DEFAULT_RULES":               func([]any) (any, error) { return ActionDefaultRules(), nil },
		"DEFAULT_RULES_SEALED_DIGEST": func([]any) (any, error) { s, err := ActionDefaultRulesSealed(); return s["digest"], err },
		"suggestRulesError": func(a []any) (any, error) {
			var known map[string]bool
			if l := aisList(vecArg(a, 1)); vecArg(a, 1) != nil {
				known = map[string]bool{}
				for _, x := range l {
					s, _ := x.(string)
					known[s] = true
				}
			}
			if bad := ActionSuggestRulesError(aisTestRules(vecArg(a, 0)), known); bad != "" {
				return bad, nil
			}
			return nil, nil
		},
		"rulesDigest": func(a []any) (any, error) { return ActionRulesDigest(aisTestRules(vecArg(a, 0))) },
		"sealRules":   func(a []any) (any, error) { return ActionSealRules(aisTestRules(vecArg(a, 0))) },
		"signRules": func(a []any) (any, error) {
			kid, _ := vecArg(a, 1).(string)
			label, _ := vecArg(a, 2).(string)
			seed := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			return ActionSignRules(aisTestRules(vecArg(a, 0)), kid, seed[:])
		},
		"verifyRules": func(a []any) (any, error) { return ActionVerifyRules(vecArg(a, 0), vecArg(a, 1)), nil },
		"suggestWithRules": func(a []any) (any, error) {
			return ActionSuggestWithRules(vecObj(vecArg(a, 0)), aisTestRules(vecArg(a, 1)), aisTestReg(vecArg(a, 2)))
		},
		"applySuggestion": func(a []any) (any, error) {
			return ActionApplySuggestion(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2)))
		},
		"unionSuggestions": func(a []any) (any, error) {
			return ActionUnionSuggestions(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"vocabulary":   func([]any) (any, error) { return ActionModelVocabulary(coreRegistry), nil },
		"promptDigest": func([]any) (any, error) { return ActionModelPromptDigest(coreRegistry) },
		"buildRequest": func(a []any) (any, error) { return ActionModelBuildRequest(vecObj(vecArg(a, 0)), coreRegistry), nil },
		"parseTraitList": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			return ActionModelParseTraitList(s, coreRegistry), nil
		},
		"suggestWithModels": func(a []any) (any, error) {
			return ActionSuggestWithModels(vecObj(vecArg(a, 0)), aisTestAdapters(vecArg(a, 1)), coreRegistry)
		},
		"modelConfigFromEnv": func(a []any) (any, error) {
			c, err := ActionModelConfigFromEnv(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			return c.ToMap(), nil
		},
		"providerAdapterComplete": aisTestProvider,
	})
}

func TestActionImportJSRegex(t *testing.T) {
	for _, c := range []struct {
		pat, in string
		want    bool
	}{
		{`^/v1/(charges|refunds)/?$`, "/v1/refunds", true},
		{`^/v1/(charges|refunds)/?$`, "/v1/refunds/x", false},
		{`\d{2,}`, "a1", false},
		{`\d{2,}`, "a12", true},
		{`[^/]+\.json$`, "/a/b.json", true},
		{`\s`, "a b", true},
		{`a.b`, "a\nb", false},
		{`[A-C]`, "xBx", true},
	} {
		re, err := jsrCompile(c.pat)
		if err != nil {
			t.Fatalf("%s: %v", c.pat, err)
		}
		if got := jsrTest(re, c.in); got != c.want {
			t.Errorf("%s on %q: got %v want %v", c.pat, c.in, got, c.want)
		}
	}
	for _, bad := range []string{`(`, `)`, `*a`, `a{2,1}`, `[b-a]`, `\1`, `(?=a)`, `\`} {
		if _, err := jsrCompile(bad); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}
