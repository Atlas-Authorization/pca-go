package pca

// Replays the intent numerics corpus: Clopper-Pearson (exact, with certificate), binomial CDF, dyadic form, the Hoeffding
// half-width and the Wilson interval. A reference throw requires an error.

import (
	"math"
	"math/big"
	"testing"
)

func intentxNumOut(f float64) any {
	switch {
	case math.IsNaN(f):
		return map[string]any{"$num": "NaN"}
	case math.IsInf(f, 1):
		return map[string]any{"$num": "Infinity"}
	case math.IsInf(f, -1):
		return map[string]any{"$num": "-Infinity"}
	}
	return jsNumber(f)
}

func intentxF(args []any, i int) float64 {
	f, _ := jsNum(vecArg(args, i))
	return f
}

func intentxBig(v any) *big.Int {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["$bigint"].(string); ok {
			if n, ok := new(big.Int).SetString(s, 10); ok {
				return n
			}
		}
	}
	if f, ok := jsNum(v); ok {
		n, _ := new(big.Float).SetFloat64(f).Int(nil)
		return n
	}
	return new(big.Int)
}

func intentxBigOut(n *big.Int) any { return map[string]any{"$bigint": n.String()} }

func TestIntentStatsReferenceVectors(t *testing.T) {
	// The Clopper-Pearson bound and its certificate gate decisions, so they compare exactly; only the reported statistics keep the
	// relative 1e-12 tolerance (they decide nothing).
	cmp := map[string]func(want, got any) bool{}
	for _, fn := range []string{"binomialCdf", "hoeffdingHalfWidth", "wilsonInterval"} {
		cmp[fn] = goalVxApprox
	}
	replayVectorsCmp(t, "ref-intent-stats.json.gz", map[string]vecFn{
		"clopperPearsonUpper": func(args []any) (any, error) {
			c, err := IntentClopperPearsonCertified(intentxF(args, 0), intentxF(args, 1), intentxF(args, 2))
			if err != nil {
				return nil, err
			}
			return jsNumber(c.Upper), nil
		},
		"clopperPearsonCertified": func(args []any) (any, error) {
			c, err := IntentClopperPearsonCertified(intentxF(args, 0), intentxF(args, 1), intentxF(args, 2))
			if err != nil {
				return nil, err
			}
			return map[string]any{"upper": jsNumber(c.Upper), "upperUnits": intentxBigOut(big.NewInt(c.UpperUnits)),
				"lowerUnits": intentxBigOut(big.NewInt(c.LowerUnits))}, nil
		},
		"binomialCdf": func(args []any) (any, error) {
			return intentxNumOut(IntentBinomialCdf(intentxF(args, 0), intentxF(args, 1), intentxF(args, 2))), nil
		},
		"doubleToDyadic": func(args []any) (any, error) {
			d, err := IntentDoubleToDyadic(intentxF(args, 0))
			if err != nil {
				return nil, err
			}
			return map[string]any{"num": intentxBigOut(d.Num), "exp": jsNumber(float64(d.Exp))}, nil
		},
		"cdfRecNumerator": func(args []any) (any, error) {
			n, err := IntentCdfRecNumerator(int(intentxF(args, 0)), int(intentxF(args, 1)), intentxBig(vecArg(args, 2)))
			if err != nil {
				return nil, err
			}
			return intentxBigOut(n), nil
		},
		"cdfExceeds": func(args []any) (any, error) {
			d := vecObj(vecArg(args, 3))
			num := intentxBig(d["num"])
			e, _ := jsNum(d["exp"])
			return IntentCdfExceeds(int(intentxF(args, 0)), int(intentxF(args, 1)), intentxBig(vecArg(args, 2)), IntentDyadic{Num: num, Exp: int(e)})
		},
		"hoeffdingHalfWidth": func(args []any) (any, error) {
			d := 0.05
			if len(args) > 2 {
				d = intentxF(args, 2)
			}
			return intentxNumOut(IntentHoeffdingHalfWidth(intentxF(args, 0), intentxF(args, 1), d)), nil
		},
		"wilsonInterval": func(args []any) (any, error) {
			z := 1.959963984540054
			if len(args) > 2 {
				z = intentxF(args, 2)
			}
			p, lo, hi := IntentWilsonInterval(intentxF(args, 0), intentxF(args, 1), z)
			return map[string]any{"p": intentxNumOut(p), "lo": intentxNumOut(lo), "hi": intentxNumOut(hi)}, nil
		},
	}, cmp)
}
