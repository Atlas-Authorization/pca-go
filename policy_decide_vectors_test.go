package pca

import "testing"

// Replay of the Policy VM decision and of the input derivation against the reference (ref-decide-java, ref-decide-derive).

func TestDecideMatchesTheReference(t *testing.T) {
	replayVectors(t, "ref-decide-java.json.gz", map[string]vecFn{"decide": func(a []any) (any, error) {
		return Decide(vecObj(a[0])), nil
	}})
}

// dvPcactn reads the PCActn argument: JSON null stays nil (refused); any other non-object reads as an object without members, as
// the reference reads no member off it.
func dvPcactn(v any) map[string]any {
	if m := vecObj(v); m != nil || v == nil {
		return m
	}
	return map[string]any{}
}

func TestDeriveDecideInputMatchesTheReference(t *testing.T) {
	// the corpus spells a non-finite number {"$num": "NaN" | "Infinity" | "-Infinity"}: the inputs are revived to the numbers and the
	// results spelled back, so the decision runs on the real values
	replayVectors(t, "ref-decide-derive.json.gz", map[string]vecFn{
		"deriveDecideInput": func(a []any) (any, error) {
			a = anlTestRevive(a).([]any)
			in, err := DeriveDecideInput(dvPcactn(a[0]), vecObj(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			return anlTestOut(in), nil
		},
		"deriveThenDecide": func(a []any) (any, error) {
			a = anlTestRevive(a).([]any)
			in, err := DeriveDecideInput(dvPcactn(a[0]), vecObj(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			return anlTestOut(map[string]any{"input": in, "decision": Decide(in)}), nil
		},
	})
}
