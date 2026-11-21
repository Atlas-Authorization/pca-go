package pca

// Replays the reference corpus for the OpenAPI / MCP / JSON Schema / AsyncAPI importers and their shared helpers (limits, text
// hygiene, verb naming, `$ref` pointers). A reference throw needs a refusal here (and the same error code where the reference has one).

import "testing"

func aimTestStrs(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func aimTestInt(v any) int { f, _ := jsNum(v); return int(f) }

func aimTestReport(r *ActionImportReport, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return r, nil
}

func aimTestOpts(v any) map[string]any { m, _ := v.(map[string]any); return m }

func TestActionImportCoreVectors(t *testing.T) {
	replayVectors(t, "ref-actions-import-core.json.gz", map[string]vecFn{
		"tokensOf": func(a []any) (any, error) { return aimTestStrs(aimTokensOf(vecArg(a, 0))), nil },
		"humanize": func(a []any) (any, error) { return aimHumanize(vecArg(a, 0)), nil },
		"verbOf": func(a []any) (any, error) {
			ns, _ := vecArg(a, 0).(string)
			return aimVerbOf(ns, vecArg(a, 1)), nil
		},
		"aliasOf": func(a []any) (any, error) {
			verb, _ := vecArg(a, 1).(string)
			if s, ok := aimAliasOf(vecArg(a, 0), verb); ok {
				return s, nil
			}
			return nil, nil
		},
		"paramSeg": func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return aimParamSeg(s), nil },
		"clip":     func(a []any) (any, error) { return aimClip(vecArg(a, 0), aimTestInt(vecArg(a, 1))), nil },
		"pointer": func(a []any) (any, error) {
			if v, ok := aimPointer(vecArg(a, 0), vecArg(a, 1)); ok {
				return v, nil
			}
			return nil, nil
		},
		"resolveLimits": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			return aimResolveLimits(vecArg(a, 0)).asMap(), nil
		},
		"checkParsed": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			return aimCheckParsed(vecArg(a, 0), aimResolveLimits(vecArg(a, 1))), nil
		},
		"textSizeCheck": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			aimTextSizeCheck(vecArg(a, 0), aimResolveLimits(vecArg(a, 1)))
			return nil, nil
		},
		"importOpenApi": func(a []any) (any, error) {
			return aimTestReport(ActionImportOpenAPI(vecArg(a, 0), aimTestOpts(vecArg(a, 1))))
		},
		"importMcp": func(a []any) (any, error) {
			return aimTestReport(ActionImportMCP(vecArg(a, 0), aimTestOpts(vecArg(a, 1))))
		},
		"importJsonSchema": func(a []any) (any, error) {
			return aimTestReport(ActionImportJSONSchema(vecArg(a, 0), aimTestOpts(vecArg(a, 1))))
		},
		"importAsyncApi": func(a []any) (any, error) {
			return aimTestReport(ActionImportAsyncAPI(vecArg(a, 0), aimTestOpts(vecArg(a, 1))))
		},
	})
}
