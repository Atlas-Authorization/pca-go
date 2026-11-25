package pca

// Replays the policy-bridge reference corpus: the Cedar / Rego / OpenFGA / strict-CEL translators and the deny-overrides-permit
// decision. The ordered loader is used because the translators report model members in the order the model lists them.
//
// Skips: none.

import "testing"

func TestPolicyBridgeVectors(t *testing.T) {
	arg := vecArg
	str := func(a []any, i int) string { s, _ := arg(a, i).(string); return s }
	siemReplay(t, "ref-policy-bridge.json.gz", map[string]vecFn{
		"cedarToPca": func(a []any) (any, error) { return CedarToPca(str(a, 0)), nil },
		"translateCedar": func(a []any) (any, error) {
			g, _ := arg(a, 1).(bool)
			return TranslateCedar(str(a, 0), g), nil
		},
		"regoToPca":    func(a []any) (any, error) { return RegoToPca(str(a, 0)), nil },
		"openfgaToPca": func(a []any) (any, error) { return OpenfgaToPca(arg(a, 0), arg(a, 1)), nil },
		"decide": func(a []any) (any, error) {
			return PolicyBridgeDecide(vecObj(arg(a, 0)), vecObj(arg(a, 1)))
		},
		"parseCel":       func(a []any) (any, error) { return ParseCel(arg(a, 0)), nil },
		"celToCondition": func(a []any) (any, error) { return CelToCondition(arg(a, 0), arg(a, 1)), nil },
		"celToPredicate": func(a []any) (any, error) {
			return CelToPredicate(arg(a, 0), arg(a, 1), vecObj(arg(a, 2))), nil
		},
		"celConditionsToPca": func(a []any) (any, error) { return CelConditionsToPca(arg(a, 0), arg(a, 1)) },
	})
}
