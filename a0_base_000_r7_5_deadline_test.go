package pca

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// This file sorts early so that a mutant that makes a parser loop for ever, or panic, is decided by an ordinary assertion
// (within two seconds, or a recovered panic) before the run goes on.

func r7n5within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return: a parser loop does not advance", what)
	}
}

func TestR7N5_StrictParseAdvancesOverWhitespaceStringsAndEscapes(t *testing.T) {
	var v any
	var err error
	for _, c := range []struct {
		name, in string
		want     any
	}{
		{"whitespace around a number", " \t\r\n1 \n", json.Number("1")},
		{"plain string", `"ab"`, "ab"},
		{"escape", `"a\nb"`, "a\nb"},
		{"array with whitespace", "[1, 2]", nil},
	} {
		in := c.in
		r7n5within(t, c.name, func() { v, err = StrictParse(in) })
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.want != nil && v != c.want {
			t.Errorf("%s: %#v, want %#v", c.name, v, c.want)
		}
		if a, ok := v.([]any); c.want == nil && (!ok || len(a) != 2 || a[0] != json.Number("1") || a[1] != json.Number("2")) {
			t.Errorf("%s: %#v", c.name, v)
		}
	}
}

// The parser moves past a comma: a value then missing is reported where the value should start (offset 4), not behind the comma.
func TestR7N5_StrictParseArrayStepsPastTheComma(t *testing.T) {
	var err error
	r7n5within(t, "array with a trailing comma", func() { _, err = StrictParse("[[],]") })
	if err == nil || err.Error() != "strict JSON: unexpected token (at offset 4)" {
		t.Fatalf("trailing comma: %v", err)
	}
}

func TestR7N5_NoPanicOnShortRadixLookalikesAndOddPemLengths(t *testing.T) {
	for in, want := range map[string]float64{"5": 5, "0x10": 16, "1.5": 1.5} {
		var f float64
		r7n5within(t, "jsStringToNumber("+in+")", func() { f = jsStringToNumber(in) })
		if f != want {
			t.Errorf("jsStringToNumber(%q) = %v, want %v", in, f, want)
		}
	}
	var f float64
	r7n5within(t, "jsStringToNumber(x)", func() { f = jsStringToNumber("x") })
	if !math.IsNaN(f) {
		t.Errorf("jsStringToNumber(x) = %v", f)
	}
	var got string
	r7n5within(t, "pemOfDerB64", func() { got = pemOfDerB64(strings.Repeat("A", 130)) })
	want := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 64) + "\n" + strings.Repeat("A", 64) + "\nAA\n-----END CERTIFICATE-----"
	if got != want {
		t.Errorf("pemOfDerB64: %q", got)
	}
}
