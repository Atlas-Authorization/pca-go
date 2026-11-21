package pca

// Self-explaining PCA decisions: the verifier's per-check result, the Policy VM decision and a delegation chain become precise,
// human-readable explanations plus renderers. Everything is pure and read-only: it consumes the real shapes of the core, never
// re-authorizes anything, and degrades a malformed input to a best-effort explanation. Inputs are decoded JSON values; the
// JavaScript value semantics (String(x), JSON.stringify, Number(x), relational comparison, truthiness, property reads on any
// value) are reproduced where an untrusted field reaches them, so a hostile shape yields the same text or the same refusal.
// Explanations are plain maps with exactly the members of the reference's explanation objects (an absent member is undefined).

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ExplainMaxText is the cap of an explanation text field (UTF-16 units).
const ExplainMaxText = 400

// ExplainVerifyCheckOrder is the normative order of the offline verification checks.
var ExplainVerifyCheckOrder = []string{"wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion",
	"leaf_signature", "counter_format"}

var xpCheckTitle = map[string]string{
	"wire": "wire format", "version": "version", "audience": "audience binding", "validity": "freshness window",
	"cap_chain": "capability chain", "grant_ref_bound": "grant reference binding", "plan_inclusion": "plan inclusion",
	"leaf_signature": "leaf signature", "counter_format": "counter format", "counter": "counter format", "replay": "replay",
	"plan_root_authorized": "plan-root authorization", "taint_gate": "taint gate", "attestation": "agent attestation",
	"threshold": "threshold signature", "revocation": "revocation", "zk_compliance": "zk compliance", "bond": "bond",
	"malformed": "structure",
}

type xpUndefT struct{}

// xpUndef is the JavaScript undefined (a member that is absent, as opposed to JSON null = nil).
var xpUndef any = xpUndefT{}

func xpIsUndef(v any) bool { _, ok := v.(xpUndefT); return ok }

type xpThrow struct{ msg string }

func xpPanic(msg string) { panic(xpThrow{msg}) }

// xpTry runs f and turns a thrown value (the reference's TypeError) into an error; any other panic is rethrown.
func xpTry(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if t, ok := r.(xpThrow); ok {
				err = fmt.Errorf("%s", t.msg)
				return
			}
			err = fmt.Errorf("explain: %v", r)
		}
	}()
	f()
	return nil
}

// ---- JavaScript value semantics --------------------------------------------------------------------------------------------

func xpLen16(s string) int { return len(utf16Units(s)) }

func xpSlice16(s string, a, b int) string {
	u := utf16Units(s)
	if b < 0 || b > len(u) {
		b = len(u)
	}
	if a > b {
		a = b
	}
	return utf16String(u[a:b])
}

func xpNum(v any) (float64, bool) { return jsNum(v) }

func xpIsFin(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f)
}

func xpIsObj(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func xpNumStr(f float64) string { return jsNumString(f) }

func xpTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case xpUndefT:
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

func xpNN(a, b any) any {
	if a == nil || xpIsUndef(a) {
		return b
	}
	return a
}

var xpIdxRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func xpIsIdx(k string) (int, bool) {
	if !xpIdxRe.MatchString(k) || len(k) > 9 {
		return 0, false
	}
	n, _ := strconv.Atoi(k)
	return n, true
}

// xpGet is o[k] without throwing: undefined for an absent member or a value without members.
func xpGet(o any, k string) any {
	switch t := o.(type) {
	case map[string]any:
		if v, ok := t[k]; ok {
			return v
		}
	case []any:
		if k == "length" {
			return jsonNumberOf(int64(len(t)))
		}
		if n, ok := xpIsIdx(k); ok && n < len(t) {
			return t[n]
		}
	case string:
		if k == "length" {
			return jsonNumberOf(int64(xpLen16(t)))
		}
		if n, ok := xpIsIdx(k); ok && n < xpLen16(t) {
			return xpSlice16(t, n, n+1)
		}
	}
	return xpUndef
}

// xpOpt is o?.[k].
func xpOpt(o any, k string) any {
	if o == nil || xpIsUndef(o) {
		return xpUndef
	}
	return xpGet(o, k)
}

// xpRd is o[k] where o must not be null or undefined (a TypeError otherwise).
func xpRd(o any, k string) any {
	if o == nil || xpIsUndef(o) {
		xpPanic("cannot read '" + k + "'")
	}
	return xpGet(o, k)
}

// xpKeys is Object.keys.
func xpKeys(o any) []string {
	switch t := o.(type) {
	case map[string]any:
		return jsKeys(t)
	case []any:
		out := make([]string, len(t))
		for i := range t {
			out[i] = strconv.Itoa(i)
		}
		return out
	case string:
		n := xpLen16(t)
		out := make([]string, n)
		for i := 0; i < n; i++ {
			out[i] = strconv.Itoa(i)
		}
		return out
	}
	return nil
}

func xpPut(m map[string]any, k string, v any) {
	if !xpIsUndef(v) {
		m[k] = v
	}
}

func xpStr(v any) string {
	if xpIsUndef(v) {
		return "undefined"
	}
	return jsValueString(v)
}

// xpJSON is `${JSON.stringify(v)}` (undefined stringifies to the text "undefined").
func xpJSON(v any) string {
	if xpIsUndef(v) {
		return "undefined"
	}
	s, err := ap2Stringify(v)
	if err != nil {
		xpPanic("JSON.stringify: " + err.Error())
	}
	return s
}

func xpToNum(v any) float64 {
	switch t := v.(type) {
	case xpUndefT:
		return math.NaN()
	case nil:
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		return jsStringToNumber(t)
	case []any:
		return jsStringToNumber(jsValueString(t))
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func xpPrim(v any) any {
	switch t := v.(type) {
	case []any:
		return jsValueString(t)
	case map[string]any:
		return "[object Object]"
	}
	return v
}

func xpU16Less(a, b string) bool {
	x, y := utf16Units(a), utf16Units(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func xpLt(a, b any) bool {
	a, b = xpPrim(a), xpPrim(b)
	sa, aok := a.(string)
	sb, bok := b.(string)
	if aok && bok {
		return xpU16Less(sa, sb)
	}
	return xpToNum(a) < xpToNum(b)
}

func xpLe(a, b any) bool {
	a, b = xpPrim(a), xpPrim(b)
	sa, aok := a.(string)
	sb, bok := b.(string)
	if aok && bok {
		return !xpU16Less(sb, sa)
	}
	return xpToNum(a) <= xpToNum(b)
}

func xpGt(a, b any) bool { return xpLt(b, a) }

// xpAdd is `a + n` for a number n: a string or array on the left makes it a concatenation.
func xpAdd(a any, n int) any {
	a = xpPrim(a)
	if s, ok := a.(string); ok {
		return s + strconv.Itoa(n)
	}
	return xpToNum(a) + float64(n)
}

func xpIter(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case string:
		var out []any
		for _, r := range t {
			out = append(out, string(r))
		}
		return out
	}
	xpPanic("not iterable")
	return nil
}

func xpSliceFrom(v any, n int) any {
	switch t := v.(type) {
	case []any:
		if n > len(t) {
			return []any{}
		}
		return t[n:]
	case string:
		return xpSlice16(t, n, -1)
	}
	xpPanic("slice is not a function")
	return nil
}

func xpPadEnd(s string, n int) string {
	if d := n - xpLen16(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func xpLength(v any) any {
	switch t := v.(type) {
	case []any:
		return jsonNumberOf(int64(len(t)))
	case string:
		return jsonNumberOf(int64(xpLen16(t)))
	}
	return xpUndef
}

func xpInt(n int) any { return jsonNumberOf(int64(n)) }

// ---- cleanText -------------------------------------------------------------------------------------------------------------

const xpWS = `\t\n\x0b\x0c\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

var (
	xpReJWT     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	xpReBearer  = regexp.MustCompile(`(?i)\b(Bearer|Basic|Token)[` + xpWS + `]+[A-Za-z0-9_.~+/=-]{6,}`)
	xpReUserinf = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^` + xpWS + `/@]*:[^` + xpWS + `/@]*@`)
	xpRePair    = regexp.MustCompile(`(?i)\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|authorization|auth)["']?[` +
		xpWS + `]*[:=][` + xpWS + `]*)("[^"]*"|'[^']*'|[^` + xpWS + `"'&,;]+)`)
	xpReRun = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)
)

// ExplainCleanText removes what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL
// userinfo, `token=` style pairs, long unbroken token runs); the result is cut to 400 characters. A net, not a proof.
func ExplainCleanText(text any) string {
	t := xpStr(text)
	t = xpReJWT.ReplaceAllLiteralString(t, "[redacted]")
	t = xpReBearer.ReplaceAllString(t, "${1} [redacted]")
	t = xpReUserinf.ReplaceAllString(t, "${1}[redacted]@")
	t = xpRePair.ReplaceAllString(t, "${1}[redacted]")
	t = xpReRun.ReplaceAllLiteralString(t, "[redacted]")
	if xpLen16(t) > ExplainMaxText {
		return xpSlice16(t, 0, ExplainMaxText) + "..."
	}
	return t
}

func xpClean(v any) string { return ExplainCleanText(v) }

// ---- shared helpers --------------------------------------------------------------------------------------------------------

func xpShort(key any) string {
	s, ok := key.(string)
	if !ok || len(s) == 0 {
		return "<none>"
	}
	if xpLen16(s) <= 11 {
		return s
	}
	return xpSlice16(s, 0, 10) + "…"
}

func xpRound(y float64) float64 {
	f := math.Floor(y)
	if y-f >= 0.5 {
		return f + 1
	}
	return f
}

// xpN is the compact number: integers stay integers, fractions round to 4 dp; anything else prints as String(x).
func xpN(x any) string {
	if !xpIsFin(x) {
		return xpStr(x)
	}
	f, _ := jsNum(x)
	if f == math.Floor(f) {
		return xpNumStr(f)
	}
	return xpNumStr(xpRound(f*1e4) / 1e4)
}

type xpRest struct {
	keys []string
	m    map[string]any
}

func xpValueSummary(r xpRest) string {
	ks := r.keys
	if len(ks) > 6 {
		ks = ks[:6]
	}
	parts := make([]string, 0, len(ks))
	for _, k := range ks {
		v := r.m[k]
		if xpIsObj(v) {
			parts = append(parts, k+"="+xpJSON(v))
		} else {
			parts = append(parts, k+"="+xpN(v))
		}
	}
	return strings.Join(parts, ", ")
}

func xpCaveatType(cv any) string {
	if s, ok := xpOpt(cv, "type").(string); ok {
		return s
	}
	return "<malformed>"
}

func xpCaveatRest(cv any) xpRest {
	r := xpRest{m: map[string]any{}}
	if xpIsObj(cv) {
		for _, k := range xpKeys(cv) {
			if k != "type" {
				if _, dup := r.m[k]; !dup {
					r.keys = append(r.keys, k)
				}
				r.m[k] = xpGet(cv, k)
			}
		}
	}
	return r
}

func xpCondToText(c any, depth int) string {
	if !xpIsObj(c) {
		return "<malformed>"
	}
	if depth > 6 {
		return "…"
	}
	if m, ok := c.(map[string]any); ok {
		if l, ok := m["all_of"].([]any); ok {
			ps := make([]string, len(l))
			for i, x := range l {
				ps[i] = xpCondToText(x, depth+1)
			}
			return "(" + strings.Join(ps, " AND ") + ")"
		}
		if l, ok := m["any_of"].([]any); ok {
			ps := make([]string, len(l))
			for i, x := range l {
				ps[i] = xpCondToText(x, depth+1)
			}
			return "(" + strings.Join(ps, " OR ") + ")"
		}
		if n, ok := m["not"]; ok {
			return "NOT " + xpCondToText(n, depth+1)
		}
	}
	operand := ""
	if ref := xpGet(c, "ref"); !xpIsUndef(ref) {
		operand = "→" + xpStr(ref)
	} else if m, ok := c.(map[string]any); ok {
		if v, has := m["value"]; has {
			operand = xpN(v)
		}
	}
	return jsTrim(xpStr(xpGet(c, "field")) + " " + xpStr(xpGet(c, "op")) + " " + operand)
}

func xpWhereSummary(where any) string {
	l, ok := where.([]any)
	if !ok || len(l) == 0 {
		return "any (no where-bound)"
	}
	ps := make([]string, len(l))
	for i, c := range l {
		ps[i] = xpCondToText(c, 0)
	}
	return strings.Join(ps, " AND ")
}
