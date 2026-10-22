package pca

import (
	"encoding/json"
	"math"
	"testing"
)

// jsNumberString against ECMAScript Number::toString (values computed with Node): plain / exponent boundaries (1e21, 1e-7),
// shortest round-trip digits, signs, infinities and zero.
func TestJSNumberStringMatchesEcmaScript(t *testing.T) {
	cases := []struct{ lex, want string }{
		{"5e-324", "5e-324"},
		{"-5e-324", "-5e-324"},
		{"1e-7", "1e-7"},
		{"-1e-7", "-1e-7"},
		{"1.5e-7", "1.5e-7"},
		{"-1.5e-7", "-1.5e-7"},
		{"1.23e-10", "1.23e-10"},
		{"-1.23e-10", "-1.23e-10"},
		{"1e+21", "1e+21"},
		{"-1e+21", "-1e+21"},
		{"1.5e+21", "1.5e+21"},
		{"-1.5e+21", "-1.5e+21"},
		{"1e+22", "1e+22"},
		{"-1e+22", "-1e+22"},
		{"1.7976931348623157e+308", "1.7976931348623157e+308"},
		{"-1.7976931348623157e+308", "-1.7976931348623157e+308"},
		{"1e+100", "1e+100"},
		{"-1e+100", "-1e+100"},
		{"1.23e-18", "1.23e-18"},
		{"-1.23e-18", "-1.23e-18"},
		{"0.000001", "0.000001"},
		{"-0.000001", "-0.000001"},
		{"0.0000015", "0.0000015"},
		{"-0.0000015", "-0.0000015"},
		{"0.000001234", "0.000001234"},
		{"-0.000001234", "-0.000001234"},
		{"100000000000000000000", "100000000000000000000"},
		{"-100000000000000000000", "-100000000000000000000"},
		{"123456789012345680000", "123456789012345680000"},
		{"-123456789012345680000", "-123456789012345680000"},
		{"9007199254740992", "9007199254740992"},
		{"-9007199254740992", "-9007199254740992"},
		{"4.35", "4.35"},
		{"-4.35", "-4.35"},
		{"0.1", "0.1"},
		{"-0.1", "-0.1"},
		{"0.30000000000000004", "0.30000000000000004"},
		{"-0.30000000000000004", "-0.30000000000000004"},
		{"0.3333333333333333", "0.3333333333333333"},
		{"-0.3333333333333333", "-0.3333333333333333"},
		{"100", "100"},
		{"-100", "-100"},
		{"1000000000000000", "1000000000000000"},
		{"-1000000000000000", "-1000000000000000"},
		{"1.5e+300", "1.5e+300"},
		{"-1.5e+300", "-1.5e+300"},
		{"2.5e-300", "2.5e-300"},
		{"-2.5e-300", "-2.5e-300"},
		{"1234.5678", "1234.5678"},
		{"-1234.5678", "-1234.5678"},
		{"5e-7", "5e-7"},
		{"-5e-7", "-5e-7"},
		{"9.5e-7", "9.5e-7"},
		{"-9.5e-7", "-9.5e-7"},
		{"1e-10", "1e-10"},
		{"-1e-10", "-1e-10"},
		{"1.1e+21", "1.1e+21"},
		{"-1.1e+21", "-1.1e+21"},
		{"1.2345e+21", "1.2345e+21"},
		{"-1.2345e+21", "-1.2345e+21"},
		{"1e400", "Infinity"}, {"-1e400", "-Infinity"}, {"0", "0"}, {"1", "1"}, {"-1", "-1"}, {"10", "10"}, {"1e2", "100"}, {"0.5", "0.5"},
	}
	for _, c := range cases {
		f, ok := parseJSNumberLexeme(c.lex)
		if !ok {
			t.Fatalf("%s: not parsed", c.lex)
		}
		got := jsNumberString(f)
		if c.want == "-0" {
			continue
		}
		if got != c.want {
			t.Errorf("jsNumberString(%s) = %q, want %q", c.lex, got, c.want)
		}
		if n := jsNumber(f); string(n) != c.want {
			t.Errorf("jsNumber(%s) = %q", c.lex, n)
		}
	}
	if jsNumberString(math.NaN()) == "" {
		t.Error("NaN")
	}
	if got := jsNumberString(math.Copysign(0, -1)); got != "-0" {
		t.Errorf("negative zero keeps its sign in the strict spelling, got %q", got)
	}
	for _, lex := range []string{"Infinity", "-Infinity"} {
		f, ok := parseJSNumberLexeme(lex)
		if !ok || !math.IsInf(f, 0) {
			t.Errorf("%s", lex)
		}
	}
	if _, ok := parseJSNumberLexeme("abc"); ok {
		t.Error("abc parsed")
	}
	if f, ok := parseJSNumberLexeme("1e999"); !ok || !math.IsInf(f, 1) {
		t.Error("overflow lexeme is +Inf")
	}
	if f, ok := parseJSNumberLexeme("-1e999"); !ok || !math.IsInf(f, -1) {
		t.Error("overflow lexeme is -Inf")
	}
	if f, ok := parseJSNumberLexeme("1e-999"); !ok || f != 0 {
		t.Error("underflow lexeme is 0")
	}
	_ = json.Number("")
}
