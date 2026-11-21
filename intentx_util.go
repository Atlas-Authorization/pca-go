package pca

// Shared plumbing of the intent remainder (outcome space, layers, profiles, runtime...). Intent values are plain JSON trees
// (map[string]any / []any / string / float64 / bool / nil), as in the reference. Numbers are float64 once they enter through
// ixIn; a reference throw is a panic(ixThrow) turned into an error at the public boundary by ixTry.

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

type ixThrow struct{ msg string }

func (e ixThrow) Error() string { return e.msg }

func ixFail(format string, a ...any) { panic(ixThrow{fmt.Sprintf(format, a...)}) }

// ixTry runs f and turns any panic (a reference throw, or an out-of-range read the reference also refuses) into an error.
func ixTry(f func() any) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	return f(), nil
}

// ixIn copies a JSON tree turning json.Number (and {"$num":...} markers) into float64.
func ixIn(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["$num"].(string); ok && len(t) == 1 {
			switch s {
			case "NaN":
				return math.NaN()
			case "Infinity":
				return math.Inf(1)
			case "-Infinity":
				return math.Inf(-1)
			case "-0":
				return math.Copysign(0, -1)
			}
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = ixIn(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = ixIn(x)
		}
		return a
	case json.Number, int, int64:
		f, _ := jsNum(t)
		return f
	}
	return v
}

// ixOut copies a result tree making it marshalable: non-finite numbers become {"$num":...}.
func ixOut(v any) any {
	switch t := v.(type) {
	case float64:
		switch {
		case math.IsNaN(t):
			return map[string]any{"$num": "NaN"}
		case math.IsInf(t, 1):
			return map[string]any{"$num": "Infinity"}
		case math.IsInf(t, -1):
			return map[string]any{"$num": "-Infinity"}
		}
		return t
	case int:
		return float64(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = ixOut(x)
		}
		return m
	case []any:
		if t == nil {
			return nil
		}
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = ixOut(x)
		}
		return a
	case []string:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = x
		}
		return a
	case []float64:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = ixOut(x)
		}
		return a
	case []int:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = float64(x)
		}
		return a
	}
	return v
}

// ixWrap adapts a port function to the replay helper: args in, panics to errors, result out.
func ixWrap(f func(a []any) any) func([]any) (any, error) {
	return func(args []any) (any, error) {
		in := make([]any, len(args))
		for i, x := range args {
			in[i] = ixIn(x)
		}
		r, err := ixTry(func() any { return f(in) })
		if err != nil {
			return nil, err
		}
		return ixOut(r), nil
	}
}

func ixArg(a []any, i int) any {
	if i < len(a) {
		return a[i]
	}
	return nil
}

func ixM(v any) map[string]any { m, _ := v.(map[string]any); return m }
func ixL(v any) []any          { l, _ := v.([]any); return l }
func ixS(v any) string         { s, _ := v.(string); return s }

func ixIsNum(v any) bool { _, ok := v.(float64); return ok }
func ixIsFin(v any) bool {
	f, ok := v.(float64)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}
func ixIsStr(v any) bool  { _, ok := v.(string); return ok }
func ixIsObj(v any) bool  { _, ok := v.(map[string]any); return ok }
func ixIsList(v any) bool { _, ok := v.([]any); return ok }

// ixF reads a number, failing like a reference TypeError for anything else.
func ixF(v any) float64 {
	f, ok := v.(float64)
	if !ok {
		ixFail("not a number")
	}
	return f
}

// ixFOr reads a number or def when absent / not a number.
func ixFOr(v any, def float64) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return def
}

func ixHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// ixTruthy is JavaScript truthiness.
func ixTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	case json.Number:
		f, ok := jsNum(t)
		return !ok || (f != 0 && !math.IsNaN(f))
	case string:
		return t != ""
	}
	return true
}

// ixSortU16 sorts strings by UTF-16 code units (the default JavaScript order).
func ixSortU16(ss []string) []string {
	sort.SliceStable(ss, func(i, j int) bool { return compareUnits(utf16Units(ss[i]), utf16Units(ss[j])) < 0 })
	return ss
}

func ixKeysSorted(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ixSortU16(ks)
}

func ixStrList(v any) []string {
	var out []string
	for _, x := range ixL(v) {
		out = append(out, ixS(x))
	}
	return out
}

func ixToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// ixClone deep-copies a JSON tree.
func ixClone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = ixClone(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = ixClone(x)
		}
		return a
	}
	return v
}

// ixNums turns float64 numbers of a JSON tree into json.Number, the form the strict canonicalizer takes.
func ixNums(v any) any {
	switch t := v.(type) {
	case float64:
		return jsNumber(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = ixNums(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = ixNums(x)
		}
		return a
	}
	return v
}

// ixHashCanon is HashCanonical of a JSON tree; a value the strict canonicalizer refuses is a throw.
func ixHashCanon(v any) string {
	h, err := HashCanonical(ixNums(v))
	if err != nil {
		ixFail("%v", err)
	}
	return h
}
