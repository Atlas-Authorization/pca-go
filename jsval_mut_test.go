package pca

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Kill tests for jsval.go: the JavaScript value semantics (Number::toString, UTF-16 units, UTF-8 ordering, the name
// matchers, the lenient canonical form). Expected values are what the TS reference prints (JSON.stringify / String(n)).

func TestJsvalNumberStringTable(t *testing.T) {
	cases := []struct {
		f    float64
		want string
	}{
		{1, "1"}, {10, "10"}, {-7, "-7"}, {0.5, "0.5"}, {-0.5, "-0.5"}, {1.5, "1.5"}, {123.456, "123.456"},
		{0.05, "0.05"}, {0.000001, "0.000001"}, {1.5e-6, "0.0000015"}, {1e-7, "1e-7"}, {1.5e-7, "1.5e-7"},
		{1.25e-10, "1.25e-10"}, {-1e-7, "-1e-7"},
		{1e20, "100000000000000000000"}, {1.5e20, "150000000000000000000"}, {123456789012345680000, "123456789012345680000"},
		{1e21, "1e+21"}, {1.5e21, "1.5e+21"}, {1.25e21, "1.25e+21"}, {-1e21, "-1e+21"}, {1e100, "1e+100"},
		{1.7976931348623157e308, "1.7976931348623157e+308"}, {5e-324, "5e-324"},
		{9007199254740991, "9007199254740991"}, {0.1, "0.1"}, {100, "100"}, {1e5, "100000"},
		{math.Inf(1), "Infinity"}, {math.Inf(-1), "-Infinity"}, {math.NaN(), "NaN"},
		{0, "0"}, {math.Copysign(0, -1), "-0"},
	}
	for _, c := range cases {
		if got := jsNumberString(c.f); got != c.want {
			t.Errorf("jsNumberString(%v) = %q, want %q", c.f, got, c.want)
		}
	}
	if jsLenientNumber(math.Copysign(0, -1)) != "0" || jsLenientNumber(0) != "0" || jsLenientNumber(2.5) != "2.5" {
		t.Error("jsLenientNumber")
	}
	if string(jsNumber(1.5)) != "1.5" {
		t.Error("jsNumber")
	}
}

func TestJsvalNum(t *testing.T) {
	type c struct {
		v    any
		f    float64
		ok   bool
		nan  bool
		sign int
	}
	cases := []c{
		{v: json.Number("5"), f: 5, ok: true},
		{v: json.Number("-0"), f: 0, ok: true, sign: -1},
		{v: json.Number("1e3"), f: 1000, ok: true},
		{v: json.Number("Infinity"), f: math.Inf(1), ok: true},
		{v: json.Number("-Infinity"), f: math.Inf(-1), ok: true},
		{v: json.Number("1e999"), f: math.Inf(1), ok: true},
		{v: json.Number("-1e999"), f: math.Inf(-1), ok: true},
		{v: json.Number("1e-999"), f: 0, ok: true},
		{v: json.Number("abc"), ok: false},
		{v: json.Number(""), ok: false},
		{v: float64(2.5), f: 2.5, ok: true},
		{v: int(7), f: 7, ok: true},
		{v: int64(-9), f: -9, ok: true},
		{v: "5", ok: false},
		{v: nil, ok: false},
		{v: true, ok: false},
	}
	for i, x := range cases {
		f, ok := jsNum(x.v)
		if ok != x.ok || (ok && f != x.f) || (!ok && f != 0) {
			t.Errorf("case %d (%#v): got (%v,%v)", i, x.v, f, ok)
		}
		if x.sign < 0 && !math.Signbit(f) {
			t.Errorf("case %d lost the -0 sign", i)
		}
	}
	if !math.IsNaN(jsF("x")) || jsF(json.Number("3")) != 3 {
		t.Error("jsF")
	}
}

func TestJsvalNumberPredicates(t *testing.T) {
	negz := json.Number("-0")
	if !jsIsSafeInteger(negz) || jsIsInt(negz) || jsIsNonNeg(negz) {
		t.Error("-0: safe integer yes, int / nonneg no")
	}
	for _, c := range []struct {
		v                 any
		safe, isInt, nonn bool
	}{
		{json.Number("0"), true, true, true},
		{json.Number("5"), true, true, true},
		{json.Number("-5"), true, true, false},
		{json.Number("9007199254740991"), true, true, true},
		{json.Number("9007199254740992"), false, false, false},
		{json.Number("1.5"), false, false, false},
		{"5", false, false, false},
	} {
		if jsIsSafeInteger(c.v) != c.safe || jsIsInt(c.v) != c.isInt || jsIsNonNeg(c.v) != c.nonn {
			t.Errorf("%#v", c.v)
		}
	}
}

func TestJsvalNormalizeJSON(t *testing.T) {
	in := map[string]any{"a": json.Number("950000.0"), "b": []any{json.Number("1e3"), "s", nil, true, float64(2)}, "c": map[string]any{"d": json.Number("-0")}}
	got := normalizeJSON(in).(map[string]any)
	if got["a"] != json.Number("950000") {
		t.Errorf("a = %#v", got["a"])
	}
	b := got["b"].([]any)
	if b[0] != json.Number("1000") || b[1] != "s" || b[2] != nil || b[3] != true || b[4] != json.Number("2") {
		t.Errorf("b = %#v", b)
	}
	if got["c"].(map[string]any)["d"] != json.Number("-0") {
		t.Error("-0 kept")
	}
	if normalizeJSON(json.Number("zz")) != json.Number("zz") {
		t.Error("a non-number lexeme is kept")
	}
}

func TestJsvalUtf16Units(t *testing.T) {
	cases := []struct {
		s    string
		want []uint16
	}{
		{"", []uint16{}},
		{"abc", []uint16{'a', 'b', 'c'}},
		{"é", []uint16{0xE9}},
		{"😀", []uint16{0xD83D, 0xDE00}},
		{"\xed\xa0\x80", []uint16{0xD800}},
		{"\xed\xaf\xbf", []uint16{0xDBFF}},
		{"\xed\xb0\x80", []uint16{0xDC00}},
		{"\xed\xbf\xbf", []uint16{0xDFFF}},
		{"\xed\xa5\xab", []uint16{0xD96B}},
		{"\xed\xa0\xbf", []uint16{0xD83F}},
		{"a\xed\xa0\x80b", []uint16{'a', 0xD800, 'b'}},
		{"\xed\xa0\x80\xed\xb0\x80", []uint16{0xD800, 0xDC00}},
		{"\xed\x9f\xbf", []uint16{0xD7FF}},
		{"\xed\x80\x80", []uint16{0xD000}},
		{"\xed\xc0\x80", []uint16{0xFFFD, 0xFFFD, 0xFFFD}},
		{"\xed\xa0", []uint16{0xFFFD, 0xFFFD}},
		{"x\xed\xa0", []uint16{'x', 0xFFFD, 0xFFFD}},
		{"\xed", []uint16{0xFFFD}},
	}
	for _, c := range cases {
		if got := utf16Units(c.s); !reflect.DeepEqual(got, c.want) {
			t.Errorf("utf16Units(%q) = %x, want %x", c.s, got, c.want)
		}
	}
	if jsLen("a😀\xed\xa0\x80") != 4 || utf8Len("é") != 2 {
		t.Error("jsLen / utf8Len")
	}
}

func TestJsvalWellFormedUTF8(t *testing.T) {
	cases := [][2]string{
		{"", ""},
		{"abc", "abc"},
		{"\xed\xa0\x80", "�"},
		{"\xed\xbf\xbf", "�"},
		{"a\xed\xa0\x80b", "a�b"},
		{"\xed\xa0\x80\xed\xb0\x80", "��"},
		{"x\xed\xa0\x80", "x�"},
		{"\xed\xa0\x80x", "�x"},
		{"é\xed\xa0\x80é", "é�é"},
		{"\xed\x9f\xbfa", "\xed\x9f\xbfa"},
		{"ab\xed\xa0", "ab\xed\xa0"},
		{"\xed\xa0\x80\xed\xa0", "�\xed\xa0"},
	}
	for _, c := range cases {
		if got := wellFormedUTF8(c[0]); got != c[1] {
			t.Errorf("wellFormedUTF8(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestJsvalCompare(t *testing.T) {
	hi, lo := "\xed\xa0\x80", "\xed\xb0\x80"
	cases := []struct {
		a, b string
		want int
	}{
		{"a", "a", 0}, {"", "", 0}, {"a", "b", -1}, {"b", "a", 1}, {"a", "ab", -1}, {"ab", "a", 1},
		{"é", "z", 1}, {"z", "é", -1}, {"😀", "￿", 1},
		{hi, lo, -1}, {lo, hi, 1}, {hi, hi, 0}, {"x" + hi, "x" + lo, -1}, {"x" + lo, "x" + hi, 1},
	}
	for _, c := range cases {
		if got := compareUtf8(c.a, c.b); got != c.want {
			t.Errorf("compareUtf8(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	u := func(x ...uint16) []uint16 { return x }
	ucases := []struct {
		x, y []uint16
		want int
	}{
		{u(), u(), 0}, {u(1, 2), u(1, 2), 0}, {u(1, 2), u(1, 3), -1}, {u(1, 3), u(1, 2), 1}, {u(1), u(2), -1}, {u(2), u(1), 1},
		{u(1), u(1, 2), -1}, {u(1, 2), u(1), 1}, {u(), u(1), -1}, {u(1), u(), 1}, {u(5, 1), u(4, 9, 9), 1}, {u(4, 9, 9), u(5, 1), -1},
	}
	for _, c := range ucases {
		if got := compareUnits(c.x, c.y); got != c.want {
			t.Errorf("compareUnits(%v,%v) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
}

func TestJsvalSortUtf8(t *testing.T) {
	ks := []string{"b", "a", "\xed\xb0\x80", "\xed\xa0\x80", "ab", "😀", "z"}
	sortUtf8(ks)
	want := []string{"a", "ab", "b", "z", "\xed\xa0\x80", "\xed\xb0\x80", "😀"}
	// a lone surrogate sorts as U+FFFD (EF BF BD), before U+1F600 (F0 ...); the tie is broken by code unit.
	if !reflect.DeepEqual(ks, want) {
		t.Errorf("sortUtf8 = %q, want %q", ks, want)
	}
	two := []string{"b", "a"}
	sortUtf8(two)
	if two[0] != "a" || two[1] != "b" {
		t.Error("two keys")
	}
	three := []string{"c", "b", "a"}
	sortUtf8(three)
	if !reflect.DeepEqual(three, []string{"a", "b", "c"}) {
		t.Errorf("three keys %q", three)
	}
	m := map[string]any{"b": 1, "a": 2, "c": 3}
	if got := sortedKeysUtf8(m); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("sortedKeysUtf8 %q", got)
	}
}

// exhaustive: every byte value at every position class, against the reference regular expression
func matcherAgainst(t *testing.T, name string, got func(string) bool, re *regexp.Regexp, extra []string) {
	t.Helper()
	var subjects []string
	subjects = append(subjects, "", "a", "z", "0", "9", "_", "A", "Z", "-", ".", "a.b", "a..b", ".a", "a.", "..", ".", "a.b.c", "ab.cd")
	subjects = append(subjects, extra...)
	for b := 0; b < 256; b++ {
		c := string([]byte{byte(b)})
		subjects = append(subjects, c, "a"+c, "a"+c+"b", c+"a", "ab"+c, "a."+c, c+".a", "a."+c+"b")
	}
	for _, n := range []int{1, 2, 63, 64, 65, 66, 100} {
		subjects = append(subjects, strings.Repeat("a", n), "a"+strings.Repeat("0", n-1), strings.Repeat("a", n)+"-", strings.Repeat("A", n))
	}
	for _, s := range subjects {
		if g, w := got(s), re.MatchString(s); g != w {
			t.Errorf("%s(%q) = %v, want %v", name, s, g, w)
		}
	}
}

func TestJsvalMatchers(t *testing.T) {
	matcherAgainst(t, "matchName", matchName, regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`), nil)
	matcherAgainst(t, "matchIdent", func(s string) bool { return matchIdent(s, 64, false) }, regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`), nil)
	matcherAgainst(t, "matchIdent8", func(s string) bool { return matchIdent(s, 8, false) }, regexp.MustCompile(`^[A-Za-z0-9_]{1,8}$`), []string{"abcdefgh", "abcdefghi"})
	matcherAgainst(t, "matchIdentDash", func(s string) bool { return matchIdent(s, 64, true) }, regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`), nil)
	matcherAgainst(t, "matchUnitID", matchUnitID, regexp.MustCompile(`^[a-z0-9_]+(?:\.[a-z0-9_]+)*$`), nil)
	matcherAgainst(t, "matchDataClass", matchDataClass, regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`), []string{"0a", "_a", "a_", "a.0", "a._"})
	pp := regexp.MustCompile(`^action\.params\.[A-Za-z0-9_]{1,64}$`)
	for _, s := range []string{"action.params.x", "action.params.", "action.params", "action.param.x", "action.params.x.y", "action.params.x-y", "Action.params.x",
		"action.params." + strings.Repeat("a", 64), "action.params." + strings.Repeat("a", 65), "x.action.params.x", ""} {
		if matchParamPath(s) != pp.MatchString(s) {
			t.Errorf("matchParamPath(%q)", s)
		}
	}
}

func TestJsvalArrayIndex(t *testing.T) {
	cases := []struct {
		k    string
		n    int
		ok   bool
		nBad bool
	}{
		{"", 0, false, true}, {"0", 0, true, false}, {"9", 9, true, false}, {"7", 7, true, false}, {"10", 10, true, false}, {"01", 0, false, true}, {"00", 0, false, true},
		{"a", 0, false, true}, {"1a", 0, false, true}, {"a1", 0, false, true}, {"/", 0, false, true}, {":", 0, false, true}, {"-1", 0, false, true}, {"1.5", 0, false, true},
		{"4294967294", 4294967294, true, false}, {"4294967295", 4294967295, false, false}, {"4294967296", 4294967296, false, false},
		{"9999999999", 9999999999, false, false}, {"12345678901", 0, false, true}, {"1234567890", 1234567890, true, false},
	}
	for _, c := range cases {
		n, ok := arrayIndex(c.k)
		if ok != c.ok || (c.nBad && n != 0) || (!c.nBad && n != c.n) {
			t.Errorf("arrayIndex(%q) = (%d,%v), want (%d,%v)", c.k, n, ok, c.n, c.ok)
		}
	}
}

func TestJsvalEqualityHelpers(t *testing.T) {
	n := func(s string) any { return json.Number(s) }
	if !jsStrictEq(n("0"), n("-0")) || jsStrictEq(n("1"), n("2")) || jsStrictEq(n("1"), "1") || !jsStrictEq("a", "a") || jsStrictEq("a", "b") ||
		jsStrictEq("a", 1) || !jsStrictEq(true, true) || jsStrictEq(true, false) || jsStrictEq(true, "t") || !jsStrictEq(nil, nil) || jsStrictEq(nil, "x") ||
		jsStrictEq([]any{}, []any{}) {
		t.Error("jsStrictEq")
	}
	if !scalarEqV(n("1"), n("1")) || scalarEqV(n("1"), "1") || scalarEqV("1", n("1")) || !scalarEqV("a", "a") || scalarEqV(true, n("1")) {
		t.Error("scalarEqV")
	}
	if !isScalarV("s") || !isScalarV(true) || !isScalarV(n("5")) || isScalarV(n("1.5")) || isScalarV(n("-0")) || isScalarV(nil) || isScalarV([]any{}) {
		t.Error("isScalarV")
	}
	s := setOf("a", "b")
	if !s["a"] || !s["b"] || s["c"] || len(s) != 2 {
		t.Error("setOf")
	}
}

func TestJsvalCanonicalLenient(t *testing.T) {
	n := func(s string) any { return json.Number(s) }
	cases := []struct {
		v    any
		want string
		ok   bool
	}{
		{nil, "null", true}, {true, "true", true}, {false, "false", true}, {n("5"), "5", true}, {n("-0"), "0", true}, {n("1.50"), "1.5", true},
		{n("1e21"), "1e+21", true}, {float64(3), "3", true}, {"", `""`, true}, {"a", `"a"`, true},
		{map[string]any{}, "{}", true}, {[]any{}, "[]", true},
		{[]any{n("1"), "b", nil}, `[1,"b",null]`, true},
		{[]any{n("1")}, `[1]`, true},
		{map[string]any{"b": n("1"), "a": []any{true, false}, "c": map[string]any{"z": nil, "y": "q"}}, `{"a":[true,false],"b":1,"c":{"y":"q","z":null}}`, true},
		{map[string]any{"a": n("1")}, `{"a":1}`, true},
		{map[string]any{"\xed\xa0\x80": n("1"), "😀": n("2"), "b": n("3")}, `{"b":3,"\ud800":1,"😀":2}`, true},
		{n("NaN"), "", false}, {n("Infinity"), "", false}, {n("-Infinity"), "", false}, {math.Inf(1), "", false}, {math.Inf(-1), "", false}, {math.NaN(), "", false},
		{struct{}{}, "", false}, {n("zz"), "", false},
		{[]any{n("NaN")}, "", false}, {[]any{n("1"), n("NaN")}, "", false}, {map[string]any{"a": n("NaN")}, "", false}, {map[string]any{"a": n("1"), "b": n("NaN")}, "", false},
		{[]any{map[string]any{"k": []any{n("Infinity")}}}, "", false},
	}
	for i, c := range cases {
		got, ok := canonicalLenient(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("case %d (%#v) = (%q,%v), want (%q,%v)", i, c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestJsvalLenientString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`}, {"abc", `"abc"`}, {`a"b`, `"a\"b"`}, {`a\b`, `"a\\b"`},
		{"\b", `"\b"`}, {"\f", `"\f"`}, {"\n", `"\n"`}, {"\r", `"\r"`}, {"\t", `"\t"`},
		{"\x00", `"\u0000"`}, {"\x01", `"\u0001"`}, {"\x0b", `"\u000b"`}, {"\x0e", `"\u000e"`}, {"\x10", `"\u0010"`}, {"\x1f", `"\u001f"`}, {"\x1a", `"\u001a"`},
		{" ", `" "`}, {"\x7f", "\"\x7f\""}, {"é😀", "\"é😀\""}, {"/", `"/"`},
		{"\xed\xa0\x80", `"\ud800"`}, {"\xed\xaf\xbf", `"\udbff"`}, {"\xed\xb0\x80", `"\udc00"`}, {"\xed\xbf\xbf", `"\udfff"`},
		{"\xed\xa5\xab", `"\ud96b"`}, {"\xed\xa0\xbf", `"\ud83f"`}, {"\xed\xb7\x90", `"\uddd0"`}, {"\xed\xa4\x84", `"\ud904"`}, {"\xed\xaa\xa5", lenientRef("\xed\xaa\xa5")},
		{"a\xed\xa0\x80b", `"a\ud800b"`}, {"\xed\xa0\x80\xed\xb0\x80", `"\ud800` + `\udc00"`}, {"x\xed\xa0\x80", `"x\ud800"`},
		{"\xed\x9f\xbf", "\"\xed\x9f\xbf\""}, {"\xed\xa0", "\"\xed\xa0\""}, {"ab\xed\xa0", "\"ab\xed\xa0\""}, {"\xed", "\"\xed\""},
	}
	for _, c := range cases {
		var sb strings.Builder
		lenientString(&sb, c.in)
		if sb.String() != c.want {
			t.Errorf("lenientString(%q) = %s, want %s", c.in, sb.String(), c.want)
		}
	}
}

// lenientRef builds the expected `"\uXXXX"` for one WTF-8 lone surrogate independently of lenientString.
func lenientRef(s string) string {
	u := 0xD000 | int(s[1]&0x3f)<<6 | int(s[2]&0x3f)
	const hexd = "0123456789abcdef"
	return `"\u` + string([]byte{hexd[u>>12&15], hexd[u>>8&15], hexd[u>>4&15], hexd[u&15]}) + `"`
}

func TestJsvalStrictBytesAndHash(t *testing.T) {
	b, ok := strictBytes(map[string]any{"b": json.Number("1"), "a": "x"})
	if !ok || string(b) != `{"a":"x","b":1}` {
		t.Errorf("strictBytes = %q %v", b, ok)
	}
	if _, ok := strictBytes(json.Number("-0")); ok {
		t.Error("strict form refuses -0")
	}
	h, ok := hashCanonicalV(map[string]any{"a": "x"})
	if !ok || h == "" {
		t.Error("hashCanonicalV")
	}
	if _, ok := hashCanonicalV(json.Number("-0")); ok {
		t.Error("hashCanonicalV refuses -0")
	}
}
