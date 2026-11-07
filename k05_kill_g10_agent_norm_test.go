package pca

import (
	"encoding/json"
	"testing"
)

const (
	g10agLone    = "\xed\xa0\x80" // a lone surrogate (U+D800) as WTF-8
	g10agLoneErr = "canonicalize: lone surrogate in string"
	g10agChanErr = "json: unsupported type: chan int"
)

func g10agErr(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Errorf("%s: error %v, want %q", name, err, want)
	}
}

type g10agStruct struct {
	A string
	B string
	c string
}

type g10agNest struct{ X any }

func TestG10AgentNormalizeShapes(t *testing.T) {
	_, err := NormalizeJSON(make(chan int))
	g10agErr(t, "chan", err, g10agChanErr)
	_, err = normObj(make(chan int))
	g10agErr(t, "normObj chan", err, g10agChanErr)
	_, err = normList([]any{make(chan int)})
	g10agErr(t, "normList chan", err, g10agChanErr)
	if l, err := normList(nil); err != nil || l == nil || len(l) != 0 {
		t.Fatalf("normList(nil): %v %v", l, err)
	}

	_, err = NormalizeJSON("\xff")
	g10agErr(t, "invalid UTF-8", err, "canonicalize: invalid UTF-8")
	_, err = NormalizeJSON(g10agLone)
	g10agErr(t, "lone surrogate", err, g10agLoneErr)
	_, err = NormalizeJSON([]any{"\xff"})
	g10agErr(t, "in a slice", err, "canonicalize: invalid UTF-8")
	_, err = NormalizeJSON([]any{"ok", "\xff"})
	g10agErr(t, "second element", err, "canonicalize: invalid UTF-8")
	_, err = NormalizeJSON([]any{"\xff", "ok"})
	g10agErr(t, "first element", err, "canonicalize: invalid UTF-8")
	_, err = NormalizeJSON(map[string]any{"\xff": 1})
	g10agErr(t, "map key", err, "canonicalize: invalid UTF-8")
	_, err = NormalizeJSON(g10agStruct{A: "\xff"})
	g10agErr(t, "first field", err, "canonicalize: invalid UTF-8")
	_, err = NormalizeJSON(g10agStruct{A: "ok", B: "\xff"})
	g10agErr(t, "second field", err, "canonicalize: invalid UTF-8")
	if v, err := NormalizeJSON(g10agStruct{A: "a", c: "\xff"}); err != nil || v.(map[string]any)["A"] != "a" {
		t.Fatalf("an unexported field is not marshalled, so not checked: %v %v", v, err)
	}
	var np *string
	if v, err := NormalizeJSON([]any{np, nil}); err != nil || len(v.([]any)) != 2 {
		t.Fatalf("nil pointer / nil interface: %v %v", v, err)
	}
}

// Strings nested exactly at the depth limit (10000) are checked; one level deeper they are left to json.Marshal (which
// rewrites them, and the strict parser then refuses the nesting). Each container level is two reflect levels (the
// container, then the interface element); a pointer at the bottom adds one.
func TestG10AgentBadUTF8DepthLimit(t *testing.T) {
	const levels = 5000
	wrap := map[string]func(any) any{
		"slice":  func(x any) any { return []any{x} },
		"map":    func(x any) any { return map[string]any{"k": x} },
		"struct": func(x any) any { return g10agNest{X: x} },
	}
	for name, w := range wrap {
		var at any = g10agLone // depth 2*levels = 10000
		s := g10agLone
		var below any = &s // depth 2*levels+1 = 10001
		for i := 0; i < levels; i++ {
			at, below = w(at), w(below)
		}
		_, err := NormalizeJSON(at)
		g10agErr(t, name+" at the limit", err, g10agLoneErr)
		if _, err := NormalizeJSON(below); err != nil && err.Error() == g10agLoneErr {
			t.Errorf("%s below the limit: %v", name, err)
		}
	}
}

func TestG10AgentRiskPolicy(t *testing.T) {
	d := DefaultRiskPolicy()
	if d["kappa"] != 1 || d["bMax"] != 1 {
		t.Fatalf("default kappa / bMax: %v %v", d["kappa"], d["bMax"])
	}
	if f, ok := numOf("x"); f != 0 || ok {
		t.Fatalf("numOf(x) = %v %v", f, ok)
	}
	pol := func(set map[string]string, wset map[string]string) map[string]any {
		n, err := NormalizeJSON(DefaultRiskPolicy())
		if err != nil {
			t.Fatal(err)
		}
		m := n.(map[string]any)
		for k, v := range set {
			m[k] = json.Number(v)
		}
		for k, v := range wset {
			m["weights"].(map[string]any)[k] = json.Number(v)
		}
		return m
	}
	if got := riskPolicyError("x"); got != "risk_policy must be an object" {
		t.Fatalf("non-object: %q", got)
	}
	for _, c := range []struct {
		set, w map[string]string
		want   string
	}{
		{nil, nil, ""},
		{nil, map[string]string{"alpha": "0"}, ""},
		{map[string]string{"theta1": "0"}, nil, ""},
		{map[string]string{"theta1": "0.6", "theta2": "0.6"}, nil, ""},
		{map[string]string{"lambda": "0", "rho": "0", "bMax": "0"}, nil, ""},
		{map[string]string{"lambda": "0.5"}, nil, ""},
		{map[string]string{"bMax": "0.5"}, nil, ""},
		{map[string]string{"lambda": "-1"}, nil, "risk_policy lambda/rho/bMax must be >= 0"},
	} {
		if got := riskPolicyError(pol(c.set, c.w)); got != c.want {
			t.Errorf("%v %v: %q, want %q", c.set, c.w, got, c.want)
		}
	}
}

func TestG10AgentWfOutput(t *testing.T) {
	_, err := WfOutput(make(chan int), nil, "", false)
	g10agErr(t, "chan", err, g10agChanErr)
	var deep any = "s"
	for i := 0; i < MaxJSONDepth; i++ {
		deep = []any{deep}
	}
	_, err = WfOutput(deep, nil, "", false)
	g10agErr(t, "too deep to digest", err, "WfOutput: not a scalar")

	o, err := WfOutput(5, []string{"b", "a", "c", "a"}, "ms", true)
	if err != nil || o["num"] != json.Number("5") || o["unit"] != "ms" {
		t.Fatalf("number with num: %v %v", o, err)
	}
	if l := o["labels"].([]any); len(l) != 4 || l[0] != "a" || l[1] != "a" || l[2] != "b" || l[3] != "c" {
		t.Fatalf("labels: %v", l)
	}
	if o, err := WfOutput(5, nil, "", false); err != nil || o["num"] != nil || o["unit"] != nil || len(o["labels"].([]any)) != 0 {
		t.Fatalf("number without num: %v %v", o, err)
	}
	if o, err := WfOutput("s", []string{"x"}, "", true); err != nil || o["num"] != nil || len(o["labels"].([]any)) != 1 {
		t.Fatalf("string with num: %v %v", o, err)
	}
	// Array.prototype.sort order: UTF-16 code units (an astral character before U+FFFD)
	if got := sortedStrings([]string{"�", "\U0001F600", "z"}); len(got) != 3 || got[0] != "z" || got[1] != "\U0001F600" || got[2] != "�" {
		t.Fatalf("UTF-16 order: %q", got)
	}
}
