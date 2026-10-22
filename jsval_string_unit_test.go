package pca

// Unit tests for jsMemberString / jsValueString (ECMAScript String(o?.k)): every branch.

import (
	"encoding/json"
	"math"
	"testing"
)

func TestJSValueStringEveryBranch(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"null", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"string", "abc", "abc"},
		{"empty string", "", ""},
		{"json.Number int", json.Number("5"), "5"},
		{"json.Number fraction", json.Number("1.5"), "1.5"},
		{"json.Number exponent spelling", json.Number("1e3"), "1000"},
		{"json.Number big", json.Number("1e21"), "1e+21"},
		{"json.Number negative", json.Number("-7"), "-7"},
		{"json.Number zero", json.Number("0"), "0"},
		{"json.Number negative zero", json.Number("-0"), "0"},
		{"json.Number 0.0", json.Number("0.0"), "0"},
		{"float64", 2.5, "2.5"},
		{"float64 negative zero", math.Copysign(0, -1), "0"},
		{"float64 zero", 0.0, "0"},
		{"int", 7, "7"},
		{"int zero", 0, "0"},
		{"int64", int64(-9), "-9"},
		{"Infinity lexeme", json.Number("1e400"), "Infinity"},
		{"-Infinity lexeme", json.Number("-1e400"), "-Infinity"},
		{"empty array", []any{}, ""},
		{"array of scalars", []any{json.Number("1"), "a", true}, "1,a,true"},
		{"array with null elements", []any{nil, "x", nil}, ",x,"},
		{"array of one null", []any{nil}, ""},
		{"nested arrays join recursively", []any{[]any{json.Number("1"), json.Number("2")}, []any{json.Number("3")}}, "1,2,3"},
		{"nested null in nested array", []any{[]any{nil, "a"}, "b"}, ",a,b"},
		{"array holding an object", []any{map[string]any{"a": 1}}, "[object Object]"},
		{"object", map[string]any{"a": "b"}, "[object Object]"},
		{"empty object", map[string]any{}, "[object Object]"},
		{"unknown type falls back to fmt", uint8(3), "3"},
	}
	for _, c := range cases {
		if got := jsValueString(c.in); got != c.want {
			t.Errorf("%s: jsValueString(%#v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestJSMemberStringEveryBranch(t *testing.T) {
	o := map[string]any{"s": "x", "n": nil, "z": json.Number("-0"), "a": []any{"p", nil}, "o": map[string]any{}, "e": ""}
	cases := []struct {
		k, want string
	}{
		{"s", "x"},
		{"n", "null"}, // a present JSON null is String(null), not String(undefined)
		{"z", "0"},
		{"a", "p,"},
		{"o", "[object Object]"},
		{"e", ""}, // a present empty string is not "undefined"
		{"missing", "undefined"},
		{"", "undefined"},
	}
	for _, c := range cases {
		if got := jsMemberString(o, c.k); got != c.want {
			t.Errorf("jsMemberString(%q) = %q, want %q", c.k, got, c.want)
		}
	}
	if got := jsMemberString(nil, "s"); got != "undefined" {
		t.Errorf("nil object: %q", got)
	}
	if got := jsMemberString(map[string]any{}, "s"); got != "undefined" {
		t.Errorf("empty object: %q", got)
	}
}
