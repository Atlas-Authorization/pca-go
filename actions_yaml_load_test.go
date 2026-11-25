package pca

import (
	"strings"
	"testing"
)

func TestYamlResolveCorePlain(t *testing.T) {
	str := func(v any) string { return jsValueString(v) }
	for in, want := range map[string]string{
		"": "null", "~": "null", "null": "null", "Null": "null", "NULL": "null", "nULL": "nULL",
		"true": "true", "True": "true", "tRUE": "tRUE", "FALSE": "false", "yes": "yes", "no": "no", "on": "on",
		"010": "10", "+12": "12", "-12": "-12", "0o10": "8", "0x1F": "31", "1_000": "1_000", "0b11": "0b11",
		"1e3": "1000", "1.5E-3": "0.0015", ".5": "0.5", "1.": "1", ".inf": "Infinity", "-.INF": "-Infinity", ".NaN": "NaN",
		"12345678901234567890": "12345678901234567000", "2001-12-14": "2001-12-14", "1e400": "Infinity",
	} {
		if got := str(yamlResolveCorePlain(in)); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	if v, _ := jsNum(yamlResolveCorePlain("-0")); v != 0 || !strings.HasPrefix(jsNumberLexeme(v), "-") {
		t.Errorf("-0 must stay negative zero")
	}
}

func TestYamlParseRefusals(t *testing.T) {
	for name, tc := range map[string]struct{ text, want string }{
		"alias":        {"a: &x 1\nb: *x\n", "Alias resolution is disabled"},
		"custom tag":   {"a: !custom 1\n", "unsupported tag"},
		"binary tag":   {"a: !!binary aGk=\n", "unsupported tag"},
		"int tag":      {"a: !!int 5\n", "unsupported tag"},
		"bare tag":     {"a: ! 5\n", "unsupported tag"},
		"two docs":     {"a: 1\n---\nb: 2\n", "multiple documents"},
		"bare CR":      {"a: 1\rb: 2\r", "carriage return"},
		"dup keys":     {"a: 1\na: 2\n", "unique"},
		"same string":  {"1: a\n\"1\": b\n", "unique"},
		"complex key":  {"? [a, b]\n: c\n", "complex"},
		"tab indent":   {"a:\n\t- b\n", ""},
		"unterminated": {"a: \"x\n", ""},
	} {
		_, err := yamlParseDocument(tc.text, true)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestYamlParseValue(t *testing.T) {
	root, err := yamlParseDocument("# c\nns: acme\nn: 010\nflag: yes\nq: \"yes\"\nt: !!str 5\nl: [a, 1, ~, {k: v}]\n<<: x\n", true)
	if err != nil {
		t.Fatal(err)
	}
	v, err := yamlToValue(root)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["ns"] != "acme" || m["flag"] != "yes" || m["q"] != "yes" || m["t"] != "5" || m["<<"] != "x" {
		t.Errorf("unexpected value %v", m)
	}
	if jsValueString(m["n"]) != "10" {
		t.Errorf("n = %v", m["n"])
	}
	if got := strings.Join(jsKeys(m), ","); got != "ns,n,flag,q,t,l,<<" {
		t.Errorf("member order %s", got)
	}
	pos := yamlPositionsOf(root)
	if len(pos) != 1 || pos[0].line != 2 || pos[0].col != 1 {
		t.Errorf("positions %+v", pos)
	}
	if n, err := yamlParseDocument("", true); n != nil || err != nil {
		t.Errorf("an empty stream has no document: %v %v", n, err)
	}
}

func TestYamlParseJSON(t *testing.T) {
	n, err := yamlParseJSON("{\n \"a\": [1, {\"p\": \"\\ud83d\\ude00\\u00e9\"}],\n \"a\": 2}")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := yamlToValue(n)
	if jsValueString(v.(map[string]any)["a"]) != "2" {
		t.Errorf("a repeated member keeps the last value: %v", v)
	}
	n, err = yamlParseJSON("{\n \"a\": [1, {\"p\": \"\\ud83d\\ude00\\u00e9\"}]}")
	if err != nil {
		t.Fatal(err)
	}
	inner := n.items[1].items[1] // the object in the array
	if inner.line != 2 || inner.col != 11 {
		t.Errorf("position %d:%d", inner.line, inner.col)
	}
	if s := inner.items[1].value.(string); s != "\U0001F600é" {
		t.Errorf("escapes decode to %q", s)
	}
	for _, bad := range []string{"", "{", "[1,", `{"a":1,}`, `{'a':1}`, "[1] x", "01", "-", "\"a\x01\"", `"\x"`, "NaN"} {
		if _, err := yamlParseJSON(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// The YAML 1.2 escape \/ is rewritten only where it is that escape: an unescaped backslash inside a double-quoted scalar.
func TestYamlSlashEscapeRewrite(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`a: "x\/y"`, `a: "x/y"`},                  // the escape
		{`a: '\/'`, `a: '\/'`},                      // single-quoted: two literal characters
		{`a: "\\/"`, `a: "\\/"`},                    // an escaped backslash, then a slash
		{`a: "\\\/"`, `a: "\\/"`},                   // an odd run: the last backslash escapes the slash
		{"# a \\/ b\na: \"\\/\"", "# a \\/ b\na: \"/\""}, // a comment is left alone
		{`a: x\/y`, `a: x\/y`},                      // plain text is left alone
		{`a: "it's \/"`, `a: "it's /"`},             // an apostrophe inside a double-quoted scalar does not open a single one
	} {
		if got := ydSlashEscapes(c.in); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := yamlParseDocument(`a: "x\/y"`, false); err != nil {
		t.Errorf("the escape must load: %v", err)
	}
}
