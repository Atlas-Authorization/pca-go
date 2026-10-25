package pca

// JavaScript value semantics for the Intent Layer v2 checks (intent_v2.go and the files it calls). The reference
// verifier is TypeScript over JSON.parse values: a JSON number IS an IEEE-754 binary64 (whatever its lexeme), strings
// are UTF-16, `x.length` counts code units, and an ordering comparison of non-numbers coerces. Every v2 rule is ported
// against these helpers so the Go verdict is the reference verdict bit for bit (README "Numbers": binary64; rule 4:
// strict canonical JSON; UTF-8 byte order for sorting).
//
// Representation: v2 inputs are JSON values as produced by StrictParse / ParseJSONLenient (map[string]any, []any,
// string, bool, nil, json.Number). normalizeJSON rewrites every json.Number to the lexeme JavaScript's
// Number::toString prints for its binary64 value (so `950000.0` becomes `950000` and `1e3` becomes `1000`, exactly
// what JSON.parse + canonicalizeStrict see), keeping "-0" for negative zero so the strict canonical form still refuses
// it. Numbers the checks compute are emitted the same way (jsNumber).

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// jsNum reads a JSON number as its binary64 value (JSON.parse semantics: the nearest double, ties to even;
// out-of-range magnitudes are +-Infinity). ok is false for a non-number.
func jsNum(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		return parseJSNumberLexeme(string(t))
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

func parseJSNumberLexeme(s string) (float64, bool) {
	switch s {
	case "Infinity":
		return math.Inf(1), true
	case "-Infinity":
		return math.Inf(-1), true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f, true // +-Inf or a denormal-underflowed 0, as JSON.parse
		}
		return 0, false
	}
	return f, true
}

// jsIsSafeInteger is Number.isSafeInteger (-0 IS a safe integer).
func jsIsSafeInteger(v any) bool {
	f, ok := jsNum(v)
	return ok && f == math.Trunc(f) && math.Abs(f) <= maxSafeInt
}

// jsIsInt is the reference `isInt` / `isSafeInt`: a safe integer that is not -0.
func jsIsInt(v any) bool {
	f, ok := jsNum(v)
	return ok && f == math.Trunc(f) && math.Abs(f) <= maxSafeInt && !(f == 0 && math.Signbit(f))
}

// jsIsNonNeg is the reference `isNonNeg`: a safe integer >= 0 that is not -0.
func jsIsNonNeg(v any) bool {
	f, _ := jsNum(v)
	return jsIsInt(v) && f >= 0
}

// jsF reads a number (NaN for a non-number: every ordering comparison with it is false, like JS for a non-number
// operand of a number comparison after ToNumber; callers that need full coercion use jsToNumber).
func jsF(v any) float64 {
	f, ok := jsNum(v)
	if !ok {
		return math.NaN()
	}
	return f
}

// jsNumber is the JSON value of a computed binary64.
func jsNumber(f float64) json.Number { return json.Number(jsNumberString(f)) }

// jsMemberString is ECMAScript String(o?.k) over a decoded JSON object (a nil / non-object o or a missing member is
// undefined): "undefined", "null", "true" / "false", the string, Number::toString, an array joined with "," (null and
// undefined elements empty), "[object Object]".
func jsMemberString(o map[string]any, k string) string {
	v, ok := o[k]
	if !ok {
		return "undefined"
	}
	return jsValueString(v)
}

func jsValueString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil {
				parts[i] = jsValueString(e)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		return "[object Object]"
	}
	if f, ok := jsNum(v); ok {
		if f == 0 {
			return "0" // String(-0) is "0"
		}
		return jsNumberString(f)
	}
	return fmt.Sprint(v)
}

// jsNumberString is ECMAScript Number::toString(f), except that negative zero is "-0" (kept so the strict canonical
// form refuses it, as canonicalizeStrict refuses -0; the lenient form prints it as "0").
func jsNumberString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		if math.Signbit(f) {
			return "-0"
		}
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // shortest round-trip digits: d[.ddd]e+-XX
	mant, expS, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(expS)
	k := len(digits)
	n := x + 1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := n - 1
		if ev < 0 {
			ev = -ev
		}
		if k == 1 {
			out = digits + "e" + es + strconv.Itoa(ev)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ev)
		}
	}
	return sign + out
}

// normalizeJSON deep-copies a JSON value, rewriting every number to its JavaScript lexeme (see the file comment).
// A lexeme that is not a JSON number at all is kept as is (it can only come from a caller-built value).
func normalizeJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = normalizeJSON(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = normalizeJSON(x)
		}
		return a
	case json.Number, float64, int, int64:
		if f, ok := jsNum(t); ok {
			return jsNumber(f)
		}
	}
	return v
}

// ---- strings ----------------------------------------------------------------------------------------------------

// utf16Units decodes a (WTF-8) string into UTF-16 code units: a lone surrogate the strict parser kept as its 3-byte
// WTF-8 form is one code unit, exactly as in the JavaScript string.
func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			out = append(out, uint16(0xD000|uint16(s[i+1]&0x3f)<<6|uint16(s[i+2]&0x3f)))
			i += 3
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			a, b := utf16.EncodeRune(r)
			out = append(out, uint16(a), uint16(b))
		} else {
			out = append(out, uint16(r))
		}
		i += n
	}
	return out
}

// jsLen is String.prototype.length (UTF-16 code units).
func jsLen(s string) int { return len(utf16Units(s)) }

// utf8Len is the UTF-8 byte length TextEncoder produces (a lone surrogate encodes as U+FFFD: 3 bytes, the same as its
// WTF-8 form).
func utf8Len(s string) int { return len(s) }

// wellFormedUTF8 replaces every WTF-8 lone surrogate with U+FFFD (what TextEncoder writes).
func wellFormedUTF8(s string) string {
	if !hasLoneSurrogate(s) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			sb.WriteString("�")
			i += 3
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// compareUtf8 is the reference compareUtf8: UTF-8 byte order of the TextEncoder bytes, ties between distinct strings
// (only possible through lone surrogates) broken by UTF-16 code-unit order.
func compareUtf8(a, b string) int {
	if a == b {
		return 0
	}
	x, y := wellFormedUTF8(a), wellFormedUTF8(b)
	if c := strings.Compare(x, y); c != 0 {
		return c
	}
	return compareUnits(utf16Units(a), utf16Units(b))
}

func compareUnits(x, y []uint16) int {
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(x) < len(y):
		return -1
	case len(x) > len(y):
		return 1
	}
	return 0
}

// boundedStr is the reference isBoundedString: a non-empty string of at most max UTF-8 bytes.
func boundedStr(v any, max int) bool {
	s, ok := v.(string)
	return ok && len(s) > 0 && utf8Len(s) <= max
}

// isDigestV is a canonical base64url 32-byte string.
func isDigestV(v any) bool { return b64uOK(v, b32) }

// matchName is ^[a-z][a-z0-9_]{0,63}$.
func matchName(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// matchIdent is ^[A-Za-z0-9_]{min,max}$ (with segmentDash: also '-').
func matchIdent(s string, max int, dash bool) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || dash && c == '-') {
			return false
		}
	}
	return true
}

// matchParamPath is ^action\.params\.[A-Za-z0-9_]{1,64}$.
func matchParamPath(s string) bool {
	const pre = "action.params."
	return strings.HasPrefix(s, pre) && matchIdent(s[len(pre):], 64, false)
}

// matchUnitID is ^[a-z0-9_]+(?:\.[a-z0-9_]+)*$.
func matchUnitID(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
	}
	return true
}

// matchDataClass is ^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$.
func matchDataClass(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	segs := strings.Split(s, ".")
	for i, seg := range segs {
		if seg == "" {
			return false
		}
		for j := 0; j < len(seg); j++ {
			c := seg[j]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
		_ = i
	}
	return true
}

// ---- helpers ---------------------------------------------------------------------------------------------------

func arrayIndex(k string) (int, bool) {
	if k == "" || len(k) > 10 || (k[0] == '0' && len(k) > 1) {
		return 0, false
	}
	n := 0
	for i := 0; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return 0, false
		}
		n = n*10 + int(k[i]-'0')
	}
	return n, n < 4294967295
}

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// jsStrictEq is `===` over JSON values (numbers by value, so 0 === -0; containers by identity: never equal here).
func jsStrictEq(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	fa, oka := jsNum(a)
	fb, okb := jsNum(b)
	return oka && okb && fa == fb
}

// isScalarV is the reference isScalar: a string, a boolean or a safe integer that is not -0.
func isScalarV(v any) bool {
	switch v.(type) {
	case string, bool:
		return true
	}
	return jsIsInt(v)
}

// scalarEqV is the reference scalarEq: same JSON type and `===`.
func scalarEqV(a, b any) bool {
	_, an := jsNum(a)
	_, bn := jsNum(b)
	if an != bn {
		return false
	}
	return jsStrictEq(a, b)
}

// jsLenientNumber is Number::toString with -0 printed "0" (the lenient canonical form).
func jsLenientNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	return jsNumberString(f)
}

// ---- lenient canonical JSON (predicates' deepEq) ---------------------------------------------------------------

// canonicalLenient is the reference __canonicalizeLenientServerOnly: keys in UTF-8 order, JSON.stringify strings (a
// lone surrogate escaped as \uXXXX), Number::toString numbers (-0 as "0", non-finite refused), no depth limit.
func canonicalLenient(v any) (string, bool) {
	var sb strings.Builder
	ok := serLenient(&sb, v)
	return sb.String(), ok
}

func serLenient(sb *strings.Builder, v any) bool {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		lenientString(sb, t)
	case map[string]any:
		keys := sortedKeysUtf8(t)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			lenientString(sb, k)
			sb.WriteByte(':')
			if !serLenient(sb, t[k]) {
				return false
			}
		}
		sb.WriteByte('}')
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if !serLenient(sb, x) {
				return false
			}
		}
		sb.WriteByte(']')
	default:
		f, ok := jsNum(v)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return false
		}
		sb.WriteString(jsLenientNumber(f))
	}
	return true
}

func lenientString(sb *strings.Builder, s string) {
	const hexd = "0123456789abcdef"
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			u := 0xD000 | uint16(s[i+1]&0x3f)<<6 | uint16(s[i+2]&0x3f)
			sb.WriteString(`\u`)
			sb.WriteByte(hexd[u>>12&15])
			sb.WriteByte(hexd[u>>8&15])
			sb.WriteByte(hexd[u>>4&15])
			sb.WriteByte(hexd[u&15])
			i += 2
			continue
		}
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\b':
			sb.WriteString(`\b`)
		case c == '\f':
			sb.WriteString(`\f`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			sb.WriteString(`\u00`)
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&15])
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
}

// sortedKeysUtf8 returns the keys of m in compareUtf8 order.
func sortedKeysUtf8(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sortUtf8(ks)
	return ks
}

func sortUtf8(ks []string) {
	// insertion sort keeps this dependency-free and stable; key sets here are small (<= a few hundred)
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && compareUtf8(ks[j-1], ks[j]) > 0; j-- {
			ks[j-1], ks[j] = ks[j], ks[j-1]
		}
	}
}

// hashCanonicalV is the reference hashCanonical (strict canonical form; ok false when it would throw).
func hashCanonicalV(v any) (string, bool) {
	h, err := HashCanonical(v)
	return h, err == nil
}

// strictBytes is canonicalBytesStrict.
func strictBytes(v any) ([]byte, bool) {
	b, err := canonBytes(v)
	return b, err == nil
}
