package pca

// Replays the reference corpus for the approval render, the facade spec and the provenance floors (`confirmed` is the attestation
// check answering that constant; the registry is the core registry).

import "testing"

func TestActionRenderVectors(t *testing.T) {
	confirmedOf := func(v any) ActionDiffConfirmed {
		if c, ok := v.(bool); ok {
			return func(map[string]any) bool { return c }
		}
		return nil
	}
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-render-facade.json.gz", map[string]vecFn{
		"renderApproval": func(a []any) (any, error) {
			return ActionRenderApproval(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), confirmedOf(vecArg(a, 2)))
		},
		"renderDigestForAction": func(a []any) (any, error) {
			return ActionRenderDigestForAction(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2)), confirmedOf(vecArg(a, 3)))
		},
		"approverRenderCheck": func(a []any) (any, error) {
			return ActionApproverRenderCheck(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), vecArg(a, 2), confirmedOf(vecArg(a, 3)))
		},
		"singleTapAllowed": func(a []any) (any, error) { return ActionSingleTapAllowed(vecObj(vecArg(a, 0))), nil },
		"renderersFromDefs": func(a []any) (any, error) {
			verb, _ := vecArg(a, 1).(string)
			return ActionRenderersFromDefs(list(vecArg(a, 0)), confirmedOf(vecArg(a, 3)))(verb, vecObj(vecArg(a, 2)))
		},
		"specOfDef": func(a []any) (any, error) {
			reviewed, _ := vecArg(a, 1).(bool)
			return ActionSpecOfDef(vecObj(vecArg(a, 0)), coreRegistry, reviewed, confirmedOf(vecArg(a, 2)))
		},
		"facadeSpecs": func(a []any) (any, error) {
			reviewed, _ := vecArg(a, 1).(bool)
			out := []any{}
			for _, d := range list(vecArg(a, 0)) {
				s, err := ActionSpecOfDef(vecObj(d), coreRegistry, reviewed, confirmedOf(vecArg(a, 2)))
				if err != nil {
					return nil, err
				}
				out = append(out, s)
			}
			return out, nil
		},
		"provenanceInfoOf": func(a []any) (any, error) {
			return ActionProvenanceInfoOf(vecObj(vecArg(a, 0)), coreRegistry, confirmedOf(vecArg(a, 1)))
		},
		"provenanceActions": func(a []any) (any, error) {
			look, err := ActionProvenanceActions(list(vecArg(a, 0)), coreRegistry, confirmedOf(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, v := range list(vecArg(a, 2)) {
				verb, _ := v.(string)
				if info := look(verb); info != nil {
					out = append(out, info)
				} else {
					out = append(out, nil)
				}
			}
			return out, nil
		},
	})
}
