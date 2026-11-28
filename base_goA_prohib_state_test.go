package pca

import (
	"fmt"
	"testing"
)

func goAState(mut func(m map[string]any)) map[string]any {
	m := goAJ(`{"now":100,"seq":0,"parent":null,"ledger":{},"latched":{}}`).(map[string]any)
	if mut != nil {
		mut(m)
	}
	return m
}

func goAEntries(n int) []any {
	e := map[string]any{"t": goAN("1"), "amount": goAN("1")}
	out := make([]any, n)
	for i := range out {
		out[i] = e
	}
	return out
}

func goAKeys(n int, v any) map[string]any {
	out := make(map[string]any, n)
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("k%d", i)] = v
	}
	return out
}

func TestGoAStateProblem(t *testing.T) {
	const bad = "malformed monitor state"
	e := func(t, a string) any { return map[string]any{"t": goAN(t), "amount": goAN(a)} }
	rows := []struct {
		name string
		s    any
		want string
	}{
		{"not an object", "x", bad},
		{"genesis", goAState(nil), ""},
		{"now missing", goAState(func(m map[string]any) { delete(m, "now") }), bad},
		{"now infinite", goAState(func(m map[string]any) { m["now"] = goAN("Infinity") }), bad},
		{"now negative infinite", goAState(func(m map[string]any) { m["now"] = goAN("-Infinity") }), bad},
		{"now a string", goAState(func(m map[string]any) { m["now"] = "5" }), bad},
		{"ledger missing", goAState(func(m map[string]any) { delete(m, "ledger") }), bad},
		{"latched missing", goAState(func(m map[string]any) { delete(m, "latched") }), bad},
		{"ledger not an object", goAState(func(m map[string]any) { m["ledger"] = []any{} }), bad},
		{"latched not an object", goAState(func(m map[string]any) { m["latched"] = []any{} }), bad},
		{"seq fraction", goAState(func(m map[string]any) { m["seq"] = goAN("1.5") }), bad + ": seq"},
		{"seq negative", goAState(func(m map[string]any) { m["seq"] = goAN("-1") }), bad + ": seq"},
		{"seq negative zero", goAState(func(m map[string]any) { m["seq"] = goAN("-0") }), bad + ": seq"},
		{"seq missing", goAState(func(m map[string]any) { delete(m, "seq") }), bad + ": seq"},
		{"parent missing", goAState(func(m map[string]any) { delete(m, "parent") }), bad + ": parent"},
		{"parent number", goAState(func(m map[string]any) { m["seq"] = goAN("1"); m["parent"] = goAN("5") }), bad + ": parent"},
		{"genesis with a parent", goAState(func(m map[string]any) { m["parent"] = "p" }), bad + ": genesis has a parent"},
		{"later state without a link", goAState(func(m map[string]any) { m["seq"] = goAN("1") }), bad + ": missing chain link"},
		{"later state with a link", goAState(func(m map[string]any) { m["seq"] = goAN("1"); m["parent"] = "p" }), ""},
		{"ledger bad key proto", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"__proto__": []any{}} }), bad + ": bad ledger key"},
		{"ledger key 129", goAState(func(m map[string]any) { m["ledger"] = map[string]any{goAStrs(129, "k"): []any{}} }), bad + ": bad ledger key"},
		{"ledger key 128", goAState(func(m map[string]any) { m["ledger"] = map[string]any{goAStrs(128, "k"): []any{}} }), ""},
		{"ledger value not a list", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": "x"} }), bad + ": bad ledger"},
		{"ledger 10000 entries", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": goAEntries(10000)} }), ""},
		{"ledger 10001 entries", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": goAEntries(10001)} }), bad + ": bad ledger"},
		{"entry not an object", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{5}} }), bad + ": bad ledger entry"},
		{"entry without t", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{map[string]any{"amount": goAN("1")}}} }), bad + ": bad ledger entry"},
		{"entry without amount", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{map[string]any{"t": goAN("1")}}} }), bad + ": bad ledger entry"},
		{"entry t infinite", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{e("Infinity", "1")}} }), bad + ": bad ledger entry"},
		{"entry amount infinite", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{e("1", "Infinity")}} }), bad + ": bad ledger entry"},
		{"entry amount negative", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{e("1", "-1")}} }), bad + ": bad ledger entry"},
		{"entry amount zero", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{e("1", "0")}} }), ""},
		{"entry at now", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{e("100", "1")}} }), ""},
		{"entry after now", goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{e("101", "1")}} }), bad + ": ledger entry after now (clock regression)"},
		{"latch bad key", goAState(func(m map[string]any) { m["latched"] = map[string]any{"constructor": goAN("1")} }), bad + ": bad latch key"},
		{"latch key 129", goAState(func(m map[string]any) { m["latched"] = map[string]any{goAStrs(129, "k"): goAN("1")} }), bad + ": bad latch key"},
		{"latch at now", goAState(func(m map[string]any) { m["latched"] = map[string]any{"a": goAN("100")} }), ""},
		{"latch after now", goAState(func(m map[string]any) { m["latched"] = map[string]any{"a": goAN("101")} }), bad + ": bad latch"},
		{"latch not a number", goAState(func(m map[string]any) { m["latched"] = map[string]any{"a": "x"} }), bad + ": bad latch"},
		{"latch infinite", goAState(func(m map[string]any) { m["latched"] = map[string]any{"a": goAN("-Infinity")} }), bad + ": bad latch"},
		{"ledger 1024 keys", goAState(func(m map[string]any) { m["ledger"] = goAKeys(1024, []any{}) }), ""},
		{"ledger 1025 keys", goAState(func(m map[string]any) { m["ledger"] = goAKeys(1025, []any{}) }), bad + ": too many keys"},
		{"latched 1024 keys", goAState(func(m map[string]any) { m["latched"] = goAKeys(1024, goAN("1")) }), ""},
		{"latched 1025 keys", goAState(func(m map[string]any) { m["latched"] = goAKeys(1025, goAN("1")) }), bad + ": too many keys"},
		{"deadlines not an object", goAState(func(m map[string]any) { m["deadlines"] = []any{} }), bad + ": deadlines"},
		{"deadlines ok", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"a": goAN("1"), "b": goAN("1000000")} }), ""},
		{"deadlines empty", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{} }), ""},
		{"deadlines 1024", goAState(func(m map[string]any) { m["deadlines"] = goAKeys(1024, goAN("1")) }), ""},
		{"deadlines 1025", goAState(func(m map[string]any) { m["deadlines"] = goAKeys(1025, goAN("1")) }), bad + ": too many deadline keys"},
		{"deadline bad key", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"prototype": goAN("1")} }), bad + ": bad deadline key"},
		{"deadline zero", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"a": goAN("0")} }), bad + ": bad deadline"},
		{"deadline too big", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"a": goAN("1000001")} }), bad + ": bad deadline"},
		{"deadline fraction", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"a": goAN("1.5")} }), bad + ": bad deadline"},
		{"deadline string", goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"a": "x"} }), bad + ": bad deadline"},
	}
	for _, r := range rows {
		if got := StateProblem(r.s); got != r.want {
			t.Errorf("%s: got %q want %q", r.name, got, r.want)
		}
	}
}

func TestGoAStateEntryTotal(t *testing.T) {
	const bad = "malformed monitor state"
	mk := func(keys, extra int) map[string]any {
		return goAState(func(m map[string]any) {
			l := map[string]any{}
			for i := 0; i < keys; i++ {
				l[fmt.Sprintf("k%d", i)] = goAEntries(10000)
			}
			if extra > 0 {
				l["extra"] = goAEntries(extra)
			}
			m["ledger"] = l
		})
	}
	if got := StateProblem(mk(10, 0)); got != "" {
		t.Errorf("100000 entries: %q", got)
	}
	if got := StateProblem(mk(10, 1)); got != bad+": too many entries" {
		t.Errorf("100001 entries: %q", got)
	}
}

func goALedgerState(entries ...any) map[string]any {
	return goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": entries} })
}

func TestGoAStateDigestCanonicalForm(t *testing.T) {
	e := func(t, a string) any { return map[string]any{"t": goAN(t), "amount": goAN(a)} }
	digest := func(s any) string {
		d, err := StateDigest(s)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		return d
	}
	sorted := digest(goALedgerState(e("1", "9"), e("2", "1"), e("2", "5")))
	if got := digest(goALedgerState(e("2", "5"), e("1", "9"), e("2", "1"))); got != sorted {
		t.Error("ledger entries are sorted by time then amount")
	}
	if got := digest(goALedgerState(e("2", "5"), e("2", "1"), e("1", "9"))); got != sorted {
		t.Error("ledger entries are sorted by time then amount (second order)")
	}
	if got := digest(goALedgerState(e("1", "9"), e("2", "5"), e("2", "1"))); got != sorted {
		t.Error("equal times order by amount")
	}
	if got := digest(goALedgerState(e("1", "9"), e("2", "1"), e("3", "5"))); got == sorted {
		t.Error("different content must differ")
	}
	// unknown fields are dropped from the state and from entries
	extra := goALedgerState(map[string]any{"t": goAN("1"), "amount": goAN("9"), "zz": "x"}, e("2", "1"), e("2", "5"))
	extra["zzz"] = "y"
	if digest(extra) != sorted {
		t.Error("unknown fields do not enter the digest")
	}
	// an empty ledger list and an empty deadlines object are omitted
	plain := digest(goAState(nil))
	if digest(goAState(func(m map[string]any) { m["ledger"] = map[string]any{"a": []any{}} })) != plain {
		t.Error("an empty ledger list is omitted")
	}
	if digest(goAState(func(m map[string]any) { m["deadlines"] = map[string]any{} })) != plain {
		t.Error("an empty deadlines object is omitted")
	}
	if digest(goAState(func(m map[string]any) { m["deadlines"] = map[string]any{"a": goAN("5")} })) == plain {
		t.Error("deadlines enter the digest")
	}
	if digest(goAState(func(m map[string]any) { m["latched"] = map[string]any{"a": goAN("5")} })) == plain {
		t.Error("latches enter the digest")
	}
	if d, err := StateDigest("x"); d != "" || err == nil || err.Error() != "malformed monitor state" {
		t.Errorf("malformed state: %q %v", d, err)
	}
	if d, err := StateDigest(goAState(func(m map[string]any) { m["seq"] = goAN("1.5") })); d != "" || err == nil || err.Error() != "malformed monitor state: seq" {
		t.Errorf("malformed seq: %q %v", d, err)
	}
	c, ok := canonicalState(goALedgerState(e("2", "5"), e("1", "9"), e("2", "1")))
	if !ok {
		t.Fatal("canonicalState")
	}
	got, _ := Canonicalize(c["ledger"])
	if want := `{"a":[{"amount":9,"t":1},{"amount":1,"t":2},{"amount":5,"t":2}]}`; got != want {
		t.Errorf("canonical ledger %s", got)
	}
	if _, ok := canonicalState(map[string]any{}); ok {
		t.Error("a malformed state has no canonical form")
	}
}

func TestGoAEmptyMonitorState(t *testing.T) {
	s := EmptyMonitorState(goAN("5"))
	if StateProblem(s) != "" || s["seq"] != goAN("0") || s["parent"] != nil || s["now"] != goAN("5") {
		t.Errorf("genesis state: %v", s)
	}
}

func TestGoATickState(t *testing.T) {
	s := goAState(func(m map[string]any) { m["extra"] = "keep" })
	r := TickState(s, goAN("100"))
	if r["ok"] != true {
		t.Errorf("same time: %v", r)
	}
	r = TickState(s, goAN("250"))
	st, _ := r["state"].(map[string]any)
	if r["ok"] != true || st["now"] != goAN("250") || st["extra"] != "keep" || st["seq"] != goAN("0") {
		t.Errorf("later: %v", r)
	}
	for name, now := range map[string]any{"earlier": goAN("99"), "missing": nil, "string": "5", "infinite": goAN("Infinity")} {
		if r := TickState(s, now); r["ok"] != false || r["reason"] != "clock regression" {
			t.Errorf("%s: %v", name, r)
		}
	}
	if r := TickState("x", goAN("5")); r["ok"] != false || r["reason"] != "malformed monitor state" {
		t.Errorf("malformed: %v", r)
	}
}
