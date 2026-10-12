package pca

// Golden-table mutation-kill tests for strictjson.go (parser accept/reject + exact error text/offsets, lenient mode,
// number lexeme canonical form, hex4, lone-surrogate detection). Golden file reviewed by hand against RFC 8259 and the
// PCA strict profile; regenerate with GOLDEN_UPDATE=1 go test -run TestMutStrictJSONGolden.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func strictInputs() []string {
	ins := []string{
		``, ` `, `null`, ` null `, "\t\n\r null\t\n\r ", "\fnull", "\vnull", `nul`, `nullx`, `true`, `false`, `tru`, `fals`, `falsy`, `truex`, `x`, `+1`,
		`0`, `-0`, `-`, `-a`, `01`, `1.`, `1.5`, `1.50`, `1.05`, `-1.5`, `0.5`, `0.000001`, `0.0000001`, `0.0000011`, `1e5`, `1E5`, `1.5e3`, `1e`, `1e+`, `1e+5`, `1e-`, `1e-5`, `1E+5`, `1ex`,
		`123456789012345`, `1234567890123456`, `9007199254740991`, `9007199254740992`, `-9007199254740991`, `-9007199254740992`, `99999999999999999`, `00`, `-01`,
		`1.23456789012345`, `1.234567890123456`, `0.123456789012345`, `0.1234567890123456`, `0.00123456789012345`, `-0.5`, `-0.0`, `0.0`, `1.0`, `10.5`, `100.25`, `0.5.5`, `1.5.`, `5.x`, `1.5x`,
		`0.0000005`, `0.000000`, `0.00000000000001`, `-0.0000009`, `123456.7`, `1.1000001`,
		`""`, `"a"`, `"abc`, `"a\`, `"\"`, `"\""`, `"\\"`, `"\/"`, `"\b\f\n\r\t"`, `"\x"`, `"\u0041"`, `"\u004"`, `"\u00zz"`, `"\u00ZZ"`, `"\uABCD"`, `"\uabcd"`, `"\uFFFF"`, `"\u0000"`, `"\u00g0"`, `"\u`, `"\u00`,
		`"\u0030\u0039\u0061\u0066\u0041\u0046"`, `"\u/000"`, `"\u:000"`, `"\u@000"`, `"\u` + "`" + `000"`, `"\ug000"`, `"\uG000"`, `"\u0/00"`, `"\u00:0"`, `"\u000g"`, `"\u000G"`, `"\u000/"`, `"\u000:"`,
		`"\ud83d\ude00"`, `"\uD83D\uDE00"`, `"\ud83d"`, `"\ud83dx"`, `"\ud83d\u0041"`, `"\ud83d\ude0"`, `"\ud83d\u"`, `"\ude00"`, `"\udbff\udfff"`, `"\ud800\udc00"`, `"\ud7ff"`, `"\ue000"`, `"\udbff\ue000"`, `"\ud800\udbff"`,
		`"\ud7ff\udc00"`, `"\udc00"`, `"\udfff"`, `"\udbff"`, `"\ud800"`, `"\ud800\udbff\udc00"`, `"\ud800\udfff"`, `"\ud800\udc00\udc00"`, `"\ud83d\ude00\ud83d\ude00"`, `"\ud83d\ud83d\ude00"`, `"\ud800\ud7ff"`, `"\ud800\ue000"`,
		"\"a\x01b\"", "\"a\x1fb\"", "\"a\x20b\"", "\"\x7f\"", "\"\xff\"", "\"€\"", "\"\x00\"", "\"\n\"", "\"\t\"",
		`[]`, `[ ]`, `[1]`, `[1,]`, `[,1]`, `[1 2]`, `[1,2]`, `[1 , 2 ]`, `[`, `[1`, `[1,`, `[[]]`, `[1]x`, `[1] `, `]`, `[ 1 ]`, "[\t1\n,\r2 ]", `[1,,2]`, `[1;2]`,
		`{}`, `{ }`, `{"a":1}`, `{"a":1,}`, `{"a":1 "b":2}`, `{"a" 1}`, `{"a":}`, `{a:1}`, `{"a":1,"a":2}`, `{"a":1,"b":2}`, `{"a" :1}`, `{"a": 1 }`, `{`, `{"a"`, `{"a":`, `{"a":1`, `{"a":1,`, `{,}`, `{1:2}`, `{"a":1}}`, `{"\u0061":1,"a":2}`,
		`{ "a" : 1 , "b" : 2 }`, "{\n\t\"a\"\r:\t1\n}", `{"a":1;"b":2}`, `{"a"=1}`, `{"a":1,"b"}`, `{"a":1,"b":}`, `{"":1}`, `{"a":1,"A":2}`, `{"a":{"a":1},"b":{"a":2}}`, `{"a":[1,2],"b":[3]}`,
		`{"a":{"b":[1,{"c":null}]}}`, `[true,false,null,"x",1.5]`, `[null,null]`, `[true,true]`, `[false]`, `{"t":true,"f":false,"n":null}`, `[nul]`, `[tr]`,
		`"\udc00\udc00"`, `"\udbff\udc00"`, `"\udbff\udfff\udc00"`, `{"a`, `{"\ud800":1}`, `{"a\x":1}`, `{"a":"\ud800"}`, `["\ud800"]`, `["a\u00e9\u20ac"]`,
		"\xff", "\"\xc3\"", "{\"a\":\"\xed\xa0\x80\"}",
	}
	for d := 30; d <= 34; d++ {
		ins = append(ins, strings.Repeat("[", d)+strings.Repeat("]", d), strings.Repeat(`{"a":`, d)+"1"+strings.Repeat("}", d),
			strings.Repeat(`[{"a":`, d/2)+"1"+strings.Repeat("}]", d/2), strings.Repeat(`{"a":[`, d/2)+"1"+strings.Repeat("]}", d/2))
	}
	return ins
}

func strictDump() string {
	var sb strings.Builder
	short := func(s string) string {
		if len(s) > 60 {
			return fmt.Sprintf("%q...(%d)", s[:40], len(s))
		}
		return fmt.Sprintf("%q", s)
	}
	for _, in := range strictInputs() {
		v, err := StrictParse(in)
		l, lerr := ParseJSONLenient([]byte(in))
		o, oerr := ParseJSON([]byte(in))
		vs, ls, os_ := fmt.Sprintf("%#v", v), fmt.Sprintf("%#v", l), fmt.Sprintf("%#v", o)
		if len(vs) > 200 {
			vs = fmt.Sprintf("len=%d", len(vs))
		}
		if len(ls) > 200 {
			ls = fmt.Sprintf("len=%d", len(ls))
		}
		if len(os_) > 200 {
			os_ = fmt.Sprintf("len=%d", len(os_))
		}
		fmt.Fprintf(&sb, "S %s => %s | %v\nL %s => %s | %v\nO %s => %s | %v\n", short(in), vs, err, short(in), ls, lerr, short(in), os_, oerr)
	}
	// number lexemes
	for _, lex := range []string{"0", "-0", "1", "-1", "12", "-12", "1.5", "-1.5", "1.50", "1e1", "1E1", "-", "", "9007199254740991", "-9007199254740991", "9007199254740992",
		"1234567890123456", "12345678901234567", "0.000001", "0.0000009", "-0.0000009", "0.1234567890123456", "0.123456789012345", "1.23456789012345", "123456789.123456",
		"0001", "-0.5", "0.0", "1.0", "0.10", "1.05", "-.5", ".5", "-1e5", "9007199254740993", "00000000000000000", "-0000000000000000", "0.00000000000000001"} {
		fmt.Fprintf(&sb, "N %q => %q\n", lex, numberLexemeError(lex))
		i, ok := safeInt(jn(lex))
		fmt.Fprintf(&sb, "I %q => %d %v\n", lex, i, ok)
	}
	for _, s := range []string{"", "0", "000", "0000", "00000", "abcd", "ABCD", "09afAF", "0g00", "00g0", "000g", "g000", "0/00", ":000", "@000", "`000", "FFFF", "ffff", "d83d", "DC00", "0001", "1000", "0100", "0010"} {
		r, ok := hex4(s)
		fmt.Fprintf(&sb, "H %q => %d %v\n", s, r, ok)
	}
	for _, s := range []string{"", "a", "\xed", "\xed\x9f\xbf", "\xed\xa0", "\xed\xa0\x80", "\xed\xbf\xbf", "a\xed\xa0\x80", "\xee\xa0\x80", "\xed\x80\x80", "ab\xed\xa0", "\xec\xa0\x80"} {
		fmt.Fprintf(&sb, "W %q => %v\n", s, hasLoneSurrogate(s))
	}
	return sb.String()
}

func TestMutStrictJSONGolden(t *testing.T) {
	got := strictDump()
	const path = "testdata/strictjson_mut_golden.txt"
	if os.Getenv("GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	if len(gl) != len(wl) {
		t.Fatalf("line count %d vs %d", len(gl), len(wl))
	}
	for i := range gl {
		if gl[i] != wl[i] {
			t.Fatalf("line %d:\n got  %s\n want %s", i+1, gl[i], wl[i])
		}
	}
}

func TestMutStrictJSONSize(t *testing.T) {
	ok := `[` + strings.Repeat(" ", 1048576-2) + `]`
	if len(ok) != 1048576 {
		t.Fatal("setup")
	}
	if _, err := StrictParse(ok); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	if _, err := StrictParse(ok + " "); err == nil || err.Error() != "strict JSON: input too large" {
		t.Fatalf("limit+1: %v", err)
	}
	// lenient mode has no size or depth limit and no UTF-8 requirement
	if _, err := ParseJSONLenient([]byte(ok + " ")); err != nil {
		t.Fatalf("lenient size: %v", err)
	}
	if _, err := ParseJSONLenient([]byte(strings.Repeat("[", 40) + strings.Repeat("]", 40))); err != nil {
		t.Fatalf("lenient depth: %v", err)
	}
}

func jn(s string) any { return json.Number(s) }
