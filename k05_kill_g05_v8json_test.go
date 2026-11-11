package pca

import "testing"

// g05: v8JSONError against the engine it imitates (Node 22 JSON.parse; every expected message was produced by it). Rows pin
// each escape, hex-digit bound, literal break-off, context-window bound, line terminator and the trailing-garbage check.

func g05v8Rows(t *testing.T, rows [][2]string) {
	t.Helper()
	for _, r := range rows {
		if got := v8JSONError(r[0]); got != r[1] {
			t.Fatalf("v8JSONError(%q) = %q, want %q", r[0], got, r[1])
		}
	}
}

func TestG05V8JSONStrings(t *testing.T) {
	g05v8Rows(t, [][2]string{
		{"\"ab\n\"", "Bad control character in string literal in JSON at position 3 (line 1 column 4)"},
		{"\"a\"", ""},
		{"\"a", "Unterminated string in JSON at position 2 (line 1 column 3)"},
		{"\"a b\"", ""},
		{"\" \"", ""},
		{"\"\u0001\"", "Bad control character in string literal in JSON at position 1 (line 1 column 2)"},
		{"\"\u0000\"", "Bad control character in string literal in JSON at position 1 (line 1 column 2)"},
		{"\"\\\\n\"", ""},
		{"\"\\n\"", ""},
		{"\"\\x\"", "Bad escaped character in JSON at position 2 (line 1 column 3)"},
		{"\"\\", "Unexpected end of JSON input"},
		{"\"\\u0041\"", ""},
		{"\"\\u004\"", "Bad Unicode escape in JSON at position 6 (line 1 column 7)"},
		{"\"\\u00g1\"", "Bad Unicode escape in JSON at position 5 (line 1 column 6)"},
		{"\"\\uaAfF\"", ""},
		{"\"\\u09aF\"", ""},
		{"\"\\u00af\"", ""},
		{"\"\\\u0100\"", "Unexpected token '\u0100', \"\"\\\u0100\"\" is not valid JSON"},
		{"\"\\\u00ff\"", "Bad escaped character in JSON at position 2 (line 1 column 3)"},
		{"\"a\\", "Unexpected end of JSON input"},
	})
}

func TestG05V8JSONObjects(t *testing.T) {
	g05v8Rows(t, [][2]string{
		{"{\"a\"\r", "Expected ':' after property name in JSON at position 5 (line 2 column 1)"},
		{"{\"a\"\r\n", "Expected ':' after property name in JSON at position 6 (line 2 column 1)"},
		{"", "Unexpected end of JSON input"},
		{"{}", ""},
		{"{ }", ""},
		{"{\"a\":1}", ""},
		{"{\"a\" :1}", ""},
		{"{\"a\":1 }", ""},
		{"{\"a\":1,\"b\":2}", ""},
		{"{\"a\":1, \"b\":2}", ""},
		{"{x}", "Expected property name or '}' in JSON at position 1 (line 1 column 2)"},
		{"{\"a\"1}", "Expected ':' after property name in JSON at position 4 (line 1 column 5)"},
		{"{\"a\":1,x}", "Expected double-quoted property name in JSON at position 7 (line 1 column 8)"},
		{"{\"a\":1x}", "Expected ',' or '}' after property value in JSON at position 6 (line 1 column 7)"},
		{"{\"a", "Unterminated string in JSON at position 3 (line 1 column 4)"},
		{"{\"a\":\"b", "Unterminated string in JSON at position 7 (line 1 column 8)"},
		{"{\"a\":tru}", "Unexpected token '}', \"{\"a\":tru}\" is not valid JSON"},
	})
}

func TestG05V8JSONArrays(t *testing.T) {
	g05v8Rows(t, [][2]string{
		{"[1 x]", "Expected ',' or ']' after array element in JSON at position 3 (line 1 column 4)"},
		{"[]", ""},
		{"[ ]", ""},
		{"[1]", ""},
		{"[1 ]", ""},
		{"[1 ,2]", ""},
		{"[1x]", "Expected ',' or ']' after array element in JSON at position 2 (line 1 column 3)"},
		{"[\"a", "Unterminated string in JSON at position 3 (line 1 column 4)"},
		{"[\"a\"]", ""},
		{"[t\"a\"]", "Unexpected string in JSON at position 2 (line 1 column 3)"},
	})
}

func TestG05V8JSONMisc(t *testing.T) {
	g05v8Rows(t, [][2]string{
		{"1 x\n", "Unexpected non-whitespace character after JSON at position 2 (line 1 column 3)"},
		{"\n1 x", "Unexpected non-whitespace character after JSON at position 3 (line 2 column 3)"},
		{"\r1 x", "Unexpected non-whitespace character after JSON at position 3 (line 2 column 3)"},
		{"\r\n1 x", "Unexpected non-whitespace character after JSON at position 4 (line 2 column 3)"},
		{"\u0000", "Unexpected token '\u0000', \"\u0000\" is not valid JSON"},
		{"x", "Unexpected token 'x', \"x\" is not valid JSON"},
		{"tru", "Unexpected end of JSON input"},
		{"tx", "Unexpected token 'x', \"tx\" is not valid JSON"},
		{"true", ""},
		{"false", ""},
		{"null", ""},
		{"t\"", "Unexpected string in JSON at position 1 (line 1 column 2)"},
		{"t1", "Unexpected number in JSON at position 1 (line 1 column 2)"},
		{"t-", "Unexpected number in JSON at position 1 (line 1 column 2)"},
		{"nu1", "Unexpected number in JSON at position 2 (line 1 column 3)"},
	})
}

func TestG05V8JSONContext(t *testing.T) {
	g05v8Rows(t, [][2]string{
		{"xyyyyyyyyyyyyyyyyyyy", "Unexpected token 'x', \"xyyyyyyyyyyyyyyyyyyy\" is not valid JSON"},
		{"xyyyyyyyyyyyyyyyyyyyy", "Unexpected token 'x', \"xyyyyyyyyy\"... is not valid JSON"},
		{"         xyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "Unexpected token 'x', \"         xyyyyyyyyy\"... is not valid JSON"},
		{"          xyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "Unexpected token 'x', ...\"          xyyyyyyyyy\"... is not valid JSON"},
		{"                             xyyyyyyyyyy", "Unexpected token 'x', ...\"          xyyyyyyyyy\"... is not valid JSON"},
		{"                              xyyyyyyyyy", "Unexpected token 'x', ...\"          xyyyyyyyyy\" is not valid JSON"},
	})
}

func TestG05V8JSONNumbers(t *testing.T) {
	g05v8Rows(t, [][2]string{
		{"1", ""},
		{"1 ", ""},
		{" 1", ""},
		{"1 x", "Unexpected non-whitespace character after JSON at position 2 (line 1 column 3)"},
		{" ", "Unexpected end of JSON input"},
		{"0", ""},
		{"9", ""},
		{"-0", ""},
		{"-9", ""},
		{"-x", "No number after minus sign in JSON at position 1 (line 1 column 2)"},
		{"12", ""},
		{"01", "Unexpected number in JSON at position 1 (line 1 column 2)"},
		{"0", ""},
		{"1.5", ""},
		{"1.x", "Unterminated fractional number in JSON at position 2 (line 1 column 3)"},
		{"1e5", ""},
		{"1E5", ""},
		{"1e+5", ""},
		{"1e-5", ""},
		{"1ex", "Exponent part is missing a number in JSON at position 2 (line 1 column 3)"},
		{"1.", "Unterminated fractional number in JSON at position 2 (line 1 column 3)"},
		{"1x", "Unexpected non-whitespace character after JSON at position 1 (line 1 column 2)"},
	})
}
