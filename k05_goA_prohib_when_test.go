package pca

import "testing"

func goACtxRes(verb, res string) map[string]any {
	return goAJ(`{"action":{"verb":"` + verb + `","resource":"` + res + `"}}`).(map[string]any)
}

func TestGoAWhenMatches(t *testing.T) {
	wc := func(s string) any { return goAJ(s) }
	condRes := func(v string) string { return `{"field":"action.resource","op":"eq","value":"` + v + `"}` }
	unknown := `{"field":"subject.nope","op":"eq","value":1}`
	rows := []struct {
		name string
		when any
		ctx  any
		want bool
	}{
		{"verb hit", wc(`{"verb":"read"}`), goACtxRes("read", "r"), true},
		{"verb miss", wc(`{"verb":"read"}`), goACtxRes("write", "r"), false},
		{"verb list hit", wc(`{"verb":["a","read"]}`), goACtxRes("read", "r"), true},
		{"verb list miss", wc(`{"verb":["a","b"]}`), goACtxRes("read", "r"), false},
		{"verb wildcard", wc(`{"verb":"*"}`), goACtxRes("anything", "r"), true},
		{"resource exact hit", wc(`{"verb":"read","resource":"x"}`), goACtxRes("read", "x"), true},
		{"resource exact miss", wc(`{"verb":"read","resource":"x"}`), goACtxRes("read", "y"), false},
		{"resource prefix hit", wc(`{"verb":"read","resource":"x*"}`), goACtxRes("read", "xy"), true},
		{"resource prefix miss", wc(`{"verb":"read","resource":"x*"}`), goACtxRes("read", "y"), false},
		{"resource regex hit", wc(`{"verb":"read","resource":"re:b"}`), goACtxRes("read", "b"), true},
		{"resource regex miss", wc(`{"verb":"read","resource":"re:b"}`), goACtxRes("read", "c"), false},
		{"resource right but verb wrong", wc(`{"verb":"write","resource":"x"}`), goACtxRes("read", "x"), false},
		{"where false", wc(`{"verb":"read","where":[` + condRes("zz") + `]}`), goACtxRes("read", "r"), false},
		{"where true", wc(`{"verb":"read","where":[` + condRes("r") + `]}`), goACtxRes("read", "r"), true},
		{"where unknown still vetoes", wc(`{"verb":"read","where":[` + unknown + `]}`), goACtxRes("read", "r"), true},
		{"where true then false", wc(`{"verb":"read","where":[` + condRes("r") + `,` + condRes("zz") + `]}`), goACtxRes("read", "r"), false},
		{"where unknown then false", wc(`{"verb":"read","where":[` + unknown + `,` + condRes("zz") + `]}`), goACtxRes("read", "r"), false},
		{"where unknown then true", wc(`{"verb":"read","where":[` + unknown + `,` + condRes("r") + `]}`), goACtxRes("read", "r"), true},
		{"where on a missed verb", wc(`{"verb":"read","where":[` + unknown + `]}`), goACtxRes("write", "r"), false},
		{"empty trigger", wc(`{}`), goACtxRes("read", "r"), true},
		{"trigger not an object", "x", goACtxRes("read", "r"), true},
		{"unsafe regex trigger", wc(`{"verb":"read","resource":"re:\\1"}`), goACtxRes("read", "r"), true},
		{"context without a verb", wc(`{"verb":"read"}`), goAJ(`{"action":{"resource":"r"}}`), true},
		{"context without a resource", wc(`{"verb":"read"}`), goAJ(`{"action":{"verb":"zzz"}}`), true},
		{"context with a numeric verb", wc(`{"verb":"read"}`), goAJ(`{"action":{"verb":1,"resource":"r"}}`), true},
		{"context with a numeric resource", wc(`{"verb":"read"}`), goAJ(`{"action":{"verb":"zzz","resource":1}}`), true},
		{"context without an action", wc(`{"verb":"read"}`), goAJ(`{}`), true},
		{"context not an object", wc(`{"verb":"read"}`), "x", true},
		{"regex subject of 512", wc(`{"verb":"read","resource":"re:b"}`), goACtxRes("read", goAStrs(512, "a")), false},
		{"regex subject of 513 cannot be judged", wc(`{"verb":"read","resource":"re:b"}`), goACtxRes("read", goAStrs(513, "a")), true},
		{"plain resource with a long subject", wc(`{"verb":"read","resource":"x"}`), goACtxRes("read", goAStrs(513, "a")), false},
		{"prefix resource with a long subject", wc(`{"verb":"read","resource":"x*"}`), goACtxRes("read", goAStrs(513, "a")), false},
	}
	for _, r := range rows {
		if got := WhenMatches(r.when, r.ctx); got != r.want {
			t.Errorf("%s: got %v want %v", r.name, got, r.want)
		}
	}
	// a regex the document budget refuses to run is "could not decide", never "no match"
	w := wc(`{"verb":"read","resource":"re:b"}`)
	if !whenMatchesB(w, goACtxRes("read", "c"), &regexBudget{evaluations: maxRegexEvaluationsPerDoc}) {
		t.Error("a refused evaluation must veto")
	}
	if whenMatchesB(w, goACtxRes("read", "c"), &regexBudget{}) {
		t.Error("a decided miss must not veto")
	}
	// a fault while evaluating vetoes
	if !whenMatchesB(wc(`{"verb":"read"}`), goACtxRes("write", "r"), nil) {
		t.Error("a fault must veto")
	}
}

func TestGoAWhenAffirmative(t *testing.T) {
	unknown := `{"field":"subject.nope","op":"eq","value":1}`
	rows := []struct {
		name string
		when any
		ctx  any
		want bool
	}{
		{"hit", goAJ(`{"verb":"read"}`), goACtxRes("read", "r"), true},
		{"miss", goAJ(`{"verb":"read"}`), goACtxRes("write", "r"), false},
		{"where unknown is not a match", goAJ(`{"verb":"read","where":[` + unknown + `]}`), goACtxRes("read", "r"), false},
		{"where true", goAJ(`{"verb":"read","where":[{"field":"action.resource","op":"eq","value":"r"}]}`), goACtxRes("read", "r"), true},
		{"invalid trigger", goAJ(`{}`), goACtxRes("read", "r"), false},
		{"trigger not an object", "x", goACtxRes("read", "r"), false},
		{"unsafe regex", goAJ(`{"verb":"read","resource":"re:\\1"}`), goACtxRes("read", "r"), false},
		{"context not an object", goAJ(`{"verb":"read"}`), "x", false},
	}
	for _, r := range rows {
		if got := WhenAffirmative(r.when, r.ctx); got != r.want {
			t.Errorf("%s: got %v want %v", r.name, got, r.want)
		}
	}
}
