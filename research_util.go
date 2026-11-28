package pca

import (
	"math"
	"math/big"
	"strings"
)

// JavaScript value helpers the policy-and-agent modules (DLP, immune system, console, session, policy simulation, reputation,
// catalog, approval channels) lean on, over decoded JSON values (numbers are json.Number or float64).

// rsFinite is Number.isFinite over a decoded JSON value: a number that is finite; a string, bool or null is not.
func rsFinite(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// rsIsNum is typeof x === 'number' && !Number.isNaN(x).
func rsIsNum(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsNaN(f)
}

// rsTruthy is JavaScript truthiness of a decoded JSON value.
func rsTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return !(f == 0 || math.IsNaN(f))
	}
	return true
}

// rsN is the JSON value of a computed number; a non-finite one stays a float64 so a validator can still see and refuse it.
func rsN(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return f
	}
	if f == 0 {
		f = 0 // never "-0" in an emitted value
	}
	return jsNumber(f)
}

// rsNumStr is the ECMAScript String(number) spelling (negative zero is "0").
func rsNumStr(f float64) string {
	if f == 0 {
		return "0"
	}
	return jsNumberString(f)
}

// rsNaNum is the double of a decoded number and NaN for a non-number.
func rsNaNum(v any) float64 { return jsF(v) }

// rsToFixed is JavaScript x.toFixed(digits): the exact decimal expansion, ties away from zero on the magnitude.
func rsToFixed(x float64, digits int) string {
	if math.IsNaN(x) {
		return "NaN"
	}
	if math.IsInf(x, 0) {
		if x > 0 {
			return "Infinity"
		}
		return "-Infinity"
	}
	if math.Abs(x) >= 1e21 {
		return rsNumStr(x)
	}
	neg := x < 0 || (x == 0 && math.Signbit(x))
	r := new(big.Rat)
	r.SetFloat64(math.Abs(x))
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	r.Mul(r, new(big.Rat).SetInt(scale))
	r.Add(r, big.NewRat(1, 2))
	n := new(big.Int).Quo(r.Num(), r.Denom()) // floor: the value is non-negative
	s := n.String()
	if digits > 0 {
		for len(s) <= digits {
			s = "0" + s
		}
		s = s[:len(s)-digits] + "." + s[len(s)-digits:]
	}
	if neg {
		return "-" + s
	}
	return s
}

// rsRound is Math.round: ties toward +Infinity.
func rsRound(x float64) float64 { return math.Floor(x + 0.5) }

func rsClamp01(x float64) float64 { return math.Max(0, math.Min(1, x)) }

// rsCmp is the -1/0/1 of a comparator difference (NaN and zero are equal).
func rsCmp(d float64) int {
	if math.IsNaN(d) || d == 0 {
		return 0
	}
	if d < 0 {
		return -1
	}
	return 1
}

func rsObj(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func rsHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func rsMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func rsJoin(xs []string, sep string) string { return strings.Join(xs, sep) }
