package pca

// JavaScript-semantics helpers of the policy analyzer. Inputs are JSON trees as ParseJSONLenient yields them (map[string]any,
// []any, json.Number, string, bool, nil). A missing member is anlUndef (JavaScript `undefined`), nil is `null`; anlUndef never
// appears in a result (anlU drops it). A JavaScript throw is a panic carrying *anlThrow; anlTry turns it into an error.

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"unicode/utf16"
)

type anlUndefT struct{}
type anlAbsentT struct{}

var anlUndef any = anlUndefT{}

// anlAbsent marks "this field is not set" in a probe grid.
var anlAbsent any = anlAbsentT{}

var anlRevOrder = []string{"reversible", "rate_limited", "irreversible"}

type anlThrow struct{ msg string }

func (e *anlThrow) Error() string { return e.msg }

func anlFail(format string, a ...any) { panic(&anlThrow{fmt.Sprintf(format, a...)}) }

// anlTry runs f, mapping any panic (a reference throw, or a Go runtime fault) to an error.
func anlTry(f func() any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	return f(), nil
}

func anlIsUndef(v any) bool  { _, ok := v.(anlUndefT); return ok }
func anlIsAbsent(v any) bool { _, ok := v.(anlAbsentT); return ok }

// anlGet is `o[k]`: undefined for an absent member or a non-object; reading a member of null / undefined throws.
func anlGet(o any, k string) any {
	if o == nil || anlIsUndef(o) {
		anlFail("cannot read properties of %s (reading '%s')", map[bool]string{true: "null", false: "undefined"}[o == nil], k)
	}
	if m, ok := o.(map[string]any); ok {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return anlUndef
}

// anlOget is `o?.k`.
func anlOget(o any, k string) any {
	if o == nil || anlIsUndef(o) {
		return anlUndef
	}
	return anlGet(o, k)
}

// anlOwn is an own member of a plain object, else undefined (never throws).
func anlOwn(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return anlUndef
}

func anlHas(o any, k string) bool {
	m, ok := o.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m[k]
	return ok
}

// anlNN is `v ?? d`.
func anlNN(v, d any) any {
	if v == nil || anlIsUndef(v) {
		return d
	}
	return v
}

// anlFin is `typeof v === 'number' && Number.isFinite(v)`: the binary64 value.
func anlFin(v any) (float64, bool) {
	f, ok := jsNum(v)
	if ok && !math.IsInf(f, 0) && !math.IsNaN(f) {
		return f, true
	}
	return 0, false
}

func anlIsFin(v any) bool { _, ok := anlFin(v); return ok }

func anlIsNum(v any) bool { _, ok := jsNum(v); return ok }

func anlIsArr(v any) bool { _, ok := v.([]any); return ok }

func anlIsObj(v any) bool { _, ok := v.(map[string]any); return ok }

// anlStr is a string value, else a JavaScript-style throw naming what was missing.
func anlStr(v any, what string) string {
	s, ok := v.(string)
	if !ok {
		anlFail("%s is not a string", what)
	}
	return s
}

func anlTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case anlUndefT:
		return false
	case bool:
		return t
	case string:
		return len(t) > 0
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && f == f
	}
	return true
}

func anlSamePtr(a, b any) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Kind() != vb.Kind() || (va.Kind() != reflect.Map && va.Kind() != reflect.Slice) {
		return false
	}
	return va.Pointer() == vb.Pointer() && (va.Kind() == reflect.Map || va.Len() == vb.Len())
}

// anlStrictEq is `a === b` over JSON values (objects by identity).
func anlStrictEq(a, b any) bool {
	if anlIsUndef(a) || anlIsUndef(b) {
		return anlIsUndef(a) && anlIsUndef(b)
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ab, aok := a.(bool)
	bb, bok := b.(bool)
	if aok || bok {
		return aok && bok && ab == bb
	}
	af, an := jsNum(a)
	bf, bn := jsNum(b)
	if an || bn {
		return an && bn && af == bf
	}
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok || bok {
		return aok && bok && as == bs
	}
	return anlSamePtr(a, b)
}

func anlReqList(x any) []any {
	l, ok := x.([]any)
	if !ok {
		anlFail("not an array")
	}
	return l
}

// anlIncludes is `xs.includes(x)`; a non-array throws.
func anlIncludes(xs, x any) bool {
	for _, e := range anlReqList(xs) {
		if anlStrictEq(e, x) {
			return true
		}
	}
	return false
}

// anlToNumber is `Number(v)` for a JSON value.
func anlToNumber(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case anlUndefT:
		return math.NaN()
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		return jsStringToNumber(t)
	case []any:
		if len(t) == 0 {
			return 0
		}
		if len(t) == 1 {
			return anlToNumber(t[0])
		}
		return math.NaN()
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func anlGt(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as > bs
	}
	return anlToNumber(a) > anlToNumber(b)
}

func anlLt(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as < bs
	}
	return anlToNumber(a) < anlToNumber(b)
}

// anlNumStr is the JavaScript string of a number (-0 prints as 0).
func anlNumStr(f float64) string {
	if f == 0 {
		return "0"
	}
	return jsNumberString(f)
}

// anlJS is `String(v)` of a value (an undefined member is "undefined").
func anlJS(v any) string {
	if anlIsUndef(v) {
		return "undefined"
	}
	if f, ok := v.(float64); ok {
		return anlNumStr(f)
	}
	if n, ok := v.(int); ok {
		return fmt.Sprint(n)
	}
	return jsValueString(v)
}

func anlQuote(s string) string {
	var b strings.Builder
	lenientString(&b, s) // JSON.stringify: a lone surrogate is its \udXXX escape and U+2028 stays raw
	return b.String()
}

// anlJSON is `JSON.stringify(v)` of a JSON tree (undefined members dropped, -0 as 0, own-key order).
func anlJSON(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		return anlQuote(t)
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if anlIsUndef(x) {
				parts[i] = "null"
			} else {
				parts[i] = anlJSON(x)
			}
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		var parts []string
		for _, k := range jsKeys(t) {
			if anlIsUndef(t[k]) {
				continue
			}
			parts = append(parts, anlQuote(k)+":"+anlJSON(t[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	if f, ok := jsNum(v); ok {
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return "null"
		}
		return anlNumStr(f)
	}
	return "null"
}

// anlU is an object literal: members whose value is undefined are absent.
func anlU(m map[string]any) map[string]any {
	for k, v := range m {
		if anlIsUndef(v) {
			delete(m, k)
		}
	}
	return m
}

// anlSpread is `{...o}` (nullish spreads nothing; a string or array spreads its indices).
func anlSpread(o any) map[string]any {
	out := map[string]any{}
	switch t := o.(type) {
	case map[string]any:
		for k, v := range t {
			out[k] = v
		}
	case []any:
		for i, v := range t {
			out[fmt.Sprint(i)] = v
		}
	case string:
		for i, u := range utf16.Encode([]rune(t)) {
			out[fmt.Sprint(i)] = string(utf16.Decode([]uint16{u}))
		}
	}
	return out
}

// anlCopy is a shallow copy of an object.
func anlCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	recordKeyOrder(out, jsKeys(m))
	return out
}

// anlPutKey is `m[k] = v` on an object whose key order matters: a new key is appended to the recorded order, an overwritten one
// keeps its place (JavaScript).
func anlPutKey(m map[string]any, k string, v any) {
	_, had := m[k]
	m[k] = v
	if had {
		return
	}
	var keys []string
	if e, ok := keyOrders.Load(uintptr(reflect.ValueOf(m).UnsafePointer())); ok && len(e.(*keyOrderEntry).keys) == len(m)-1 {
		keys = append(keys, e.(*keyOrderEntry).keys...)
	} else {
		keys = make([]string, 0, len(m))
		for key := range m {
			if key != k {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
	}
	recordKeyOrder(m, append(keys, k))
}

func anlIsGroup(c any) bool {
	m, ok := c.(map[string]any)
	if !ok {
		return false
	}
	return anlHas(m, "all_of") || anlHas(m, "any_of") || anlHas(m, "not")
}

// anlLeaf reports a leaf condition (an object with a string `field`, no group member).
func anlLeaf(c any) (map[string]any, bool) {
	m, ok := c.(map[string]any)
	if !ok || anlIsGroup(m) {
		return nil, false
	}
	if _, ok := m["field"].(string); !ok {
		return nil, false
	}
	return m, true
}

// anlSet is an insertion-ordered string set.
type anlSet struct {
	keys []string
	seen map[string]bool
}

func (s *anlSet) add(k string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if !s.seen[k] {
		s.seen[k] = true
		s.keys = append(s.keys, k)
	}
}

func (s *anlSet) list() []any {
	out := make([]any, len(s.keys))
	for i, k := range s.keys {
		out[i] = k
	}
	return out
}

func anlStrList(xs []any) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i], _ = x.(string)
	}
	return out
}

func anlJoin(xs []any, sep string) string { return strings.Join(anlStrList(xs), sep) }

func anlSortedF(xs []float64) { sort.Float64s(xs) }
