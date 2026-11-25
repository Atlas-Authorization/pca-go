package pca

// Replays the reference corpus for the action derivations (`confirmed` is the attestation check answering that constant).

import "testing"

func TestActionDeriveVectors(t *testing.T) {
	confirmedOf := func(v any) ActionDiffConfirmed {
		if c, ok := v.(bool); ok {
			return func(map[string]any) bool { return c }
		}
		return nil
	}
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-derive.json.gz", map[string]vecFn{
		"flattenParams": func(a []any) (any, error) { return ActionFlattenParams(vecObj(vecArg(a, 0))), nil },
		"paramByRole": func(a []any) (any, error) {
			role, _ := vecArg(a, 1).(string)
			return ActionParamByRole(vecObj(vecArg(a, 0)), role)
		},
		"effectClass":     func(a []any) (any, error) { return ActionEffectClass(vecObj(vecArg(a, 0))), nil },
		"resourceMatcher": func(a []any) (any, error) { return ActionResourceMatcher(vecObj(vecArg(a, 0))), nil },
		"toSchemaVerb": func(a []any) (any, error) {
			v, u, err := ActionToSchemaVerb(vecObj(vecArg(a, 0)), coreRegistry, confirmedOf(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"verb": v, "units": u}, nil
		},
		"toSchemaDoc": func(a []any) (any, error) {
			reg := coreRegistry
			if rd, ok := vecArg(a, 3).([]any); ok {
				r, err := extendRegistry(coreRegistry, rd)
				if err != nil {
					return nil, err
				}
				reg = r
			}
			return ActionToSchemaDoc(list(vecArg(a, 0)), reg, vecObj(vecArg(a, 1)), confirmedOf(vecArg(a, 2)))
		},
		"operationOf": func(a []any) (any, error) {
			return ActionOperationOf(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"riskOf": func(a []any) (any, error) {
			var params map[string]any
			if p, ok := vecArg(a, 2).(map[string]any); ok {
				params = p
			}
			opts := vecObj(vecArg(a, 3))
			return ActionRiskOf(vecObj(vecArg(a, 0)), confirmedOf(vecArg(a, 1)), params, opts["kappa"], opts["taint"])
		},
		"predicatesOf": func(a []any) (any, error) {
			return ActionPredicatesOf(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))["max_amount"])
		},
		"toOntology": func(a []any) (any, error) {
			return ActionToOntology(list(vecArg(a, 0)), coreRegistry, confirmedOf(vecArg(a, 1)))
		},
		"cardOf": func(a []any) (any, error) {
			return ActionCardOf(vecObj(vecArg(a, 0)), confirmedOf(vecArg(a, 1)), coreRegistry)
		},
		"escalationOf": func(a []any) (any, error) { return ActionEscalationOf(vecObj(vecArg(a, 0)), confirmedOf(vecArg(a, 1))) },
		"mcpAnnotationsOf": func(a []any) (any, error) {
			return ActionMcpAnnotationsOf(vecObj(vecArg(a, 0)), confirmedOf(vecArg(a, 1)))
		},
		"REVERSIBILITY_SCORE": func([]any) (any, error) { return ActionReversibilityScore(), nil },
		"explainDef": func(a []any) (any, error) {
			return ActionExplainDef(vecObj(vecArg(a, 0)), coreRegistry, confirmedOf(vecArg(a, 1)))
		},
	})
}
