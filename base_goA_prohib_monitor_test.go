package pca

import (
	"fmt"
	"strings"
	"testing"
)

func goAAct(verb, params string) map[string]any {
	return goAJ(`{"action":{"verb":"` + verb + `","resource":"acct","params":{` + params + `}}}`).(map[string]any)
}

func goAActSubj(verb, params, subject string) map[string]any {
	return goAJ(`{"action":{"verb":"` + verb + `","resource":"acct","params":{` + params + `}},"subject":{` + subject + `}}`).(map[string]any)
}

func goAC(invs ...string) any { return goAJ(goAConstitution(strings.Join(invs, ","))) }

func goAStateJ(now, seq, parent, ledger, latched string) map[string]any {
	return goAJ(`{"now":` + now + `,"seq":` + seq + `,"parent":` + parent + `,"ledger":` + ledger + `,"latched":` + latched + `}`).(map[string]any)
}

func goAGenesis(ledger, latched string) map[string]any {
	return goAStateJ("1000000", "0", "null", ledger, latched)
}

func goARes(r map[string]any) string {
	return fmt.Sprintf("ok=%v violated=%v reasons=%v", r["ok"], r["violated"], r["reasons"])
}

const (
	goANever   = `{"id":"n","kind":"never","when":{"verb":"pay"}}`
	goACap     = `{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":10,"window_secs":60}`
	goACapOpen = `{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":10}`
	goARate    = `{"id":"r","kind":"rate","when":{"verb":"pay"},"max":2,"window_secs":60}`
)

func TestGoACheckProhibitionsKinds(t *testing.T) {
	now := 1000000
	ago := func(ms int) string { return fmt.Sprint(now - ms) }
	ent := func(t string, a string) string { return `{"t":` + t + `,"amount":` + a + `}` }
	unlessOK := `{"id":"u","kind":"never_unless","when":{"verb":"pay"},"unless":[{"field":"action.params.ok","op":"eq","value":true}]}`
	na := `{"id":"na","kind":"never_after","after":{"verb":"login"},"forbid":{"verb":"pay"}}`
	rp := `{"id":"rp","kind":"require_prior","when":{"verb":"pay"},"prior":{"verb":"auth"}}`
	ap := `{"id":"ap","kind":"require_approval_over","when":{"verb":"pay"},"amount":"action.params.n","threshold":100,"approved":[{"field":"subject.approved","op":"eq","value":true}]}`
	const okAll = "ok=true violated=[] reasons=[]"
	rows := []struct {
		name   string
		act    map[string]any
		inv    string
		ledger string
		latch  string
		want   string
	}{
		{"never hit", goAAct("pay", ""), goANever, "{}", "{}", "ok=false violated=[n] reasons=[n: forbidden action]"},
		{"never miss", goAAct("read", ""), goANever, "{}", "{}", okAll},
		{"never custom description", goAAct("pay", ""), `{"id":"n","kind":"never","when":{"verb":"pay"},"description":"no paying"}`, "{}", "{}", "ok=false violated=[n] reasons=[n: no paying]"},
		{"never null description", goAAct("pay", ""), `{"id":"n","kind":"never","when":{"verb":"pay"},"description":null}`, "{}", "{}", "ok=false violated=[n] reasons=[n: forbidden action]"},
		{"never empty description", goAAct("pay", ""), `{"id":"n","kind":"never","when":{"verb":"pay"},"description":""}`, "{}", "{}", "ok=false violated=[n] reasons=[n: violated]"},
		{"never_unless excepted", goAAct("pay", `"ok":true`), unlessOK, "{}", "{}", okAll},
		{"never_unless not excepted", goAAct("pay", `"ok":false`), unlessOK, "{}", "{}", "ok=false violated=[u] reasons=[u: forbidden without required condition]"},
		{"never_unless unresolvable exception", goAAct("pay", ""), unlessOK, "{}", "{}", "ok=false violated=[u] reasons=[u: forbidden without required condition]"},
		{"never_unless out of scope", goAAct("read", ""), unlessOK, "{}", "{}", okAll},
		{"cap at the limit", goAAct("pay", `"n":10`), goACap, "{}", "{}", okAll},
		{"cap over the limit", goAAct("pay", `"n":11`), goACap, "{}", "{}", "ok=false violated=[c] reasons=[c: cap exceeded: 0 + 11 > 10]"},
		{"cap adds the window", goAAct("pay", `"n":6`), goACap, `{"c":[` + ent(ago(100), "4") + `]}`, "{}", okAll},
		{"cap over with the window", goAAct("pay", `"n":7`), goACap, `{"c":[` + ent(ago(100), "4") + `]}`, "{}", "ok=false violated=[c] reasons=[c: cap exceeded: 4 + 7 > 10]"},
		{"cap entry at the window edge is out", goAAct("pay", `"n":10`), goACap, `{"c":[` + ent(ago(60000), "5") + `]}`, "{}", okAll},
		{"cap entry just inside the window", goAAct("pay", `"n":10`), goACap, `{"c":[` + ent(ago(59999), "5") + `]}`, "{}", "ok=false violated=[c] reasons=[c: cap exceeded: 5 + 10 > 10]"},
		{"cap entry at now is in", goAAct("pay", `"n":10`), goACap, `{"c":[` + ent(ago(0), "1") + `]}`, "{}", "ok=false violated=[c] reasons=[c: cap exceeded: 1 + 10 > 10]"},
		{"cap without a window counts everything", goAAct("pay", `"n":10`), goACapOpen, `{"c":[` + ent("1", "1") + `]}`, "{}", "ok=false violated=[c] reasons=[c: cap exceeded: 1 + 10 > 10]"},
		{"cap zero amount", goAAct("pay", `"n":0`), `{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":0}`, "{}", "{}", okAll},
		{"cap amount missing", goAAct("pay", ""), goACap, "{}", "{}", "ok=false violated=[c] reasons=[c: amount unresolvable (fail closed)]"},
		{"cap amount not a number", goAAct("pay", `"n":"x"`), goACap, "{}", "{}", "ok=false violated=[c] reasons=[c: amount unresolvable (fail closed)]"},
		{"cap amount negative", goAAct("pay", `"n":-1`), goACap, "{}", "{}", "ok=false violated=[c] reasons=[c: amount unresolvable (fail closed)]"},
		{"cap out of scope", goAAct("read", `"n":999`), goACap, "{}", "{}", okAll},
		{"cap sums in time order", goAAct("pay", `"n":0`), `{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":0.6}`, `{"c":[` + ent("3", "0.1") + `,` + ent("2", "0.2") + `,` + ent("1", "0.3") + `]}`, "{}", okAll},
		{"rate under", goAAct("pay", ""), goARate, `{"r":[` + ent(ago(10), "1") + `]}`, "{}", okAll},
		{"rate over", goAAct("pay", ""), goARate, `{"r":[` + ent(ago(10), "1") + `,` + ent(ago(20), "1") + `]}`, "{}", "ok=false violated=[r] reasons=[r: rate exceeded: 3 > 2 per 60s]"},
		{"rate old entries expire", goAAct("pay", ""), goARate, `{"r":[` + ent(ago(60000), "1") + `,` + ent(ago(60001), "1") + `,` + ent(ago(10), "1") + `]}`, "{}", okAll},
		{"rate max zero", goAAct("pay", ""), `{"id":"r","kind":"rate","when":{"verb":"pay"},"max":0,"window_secs":60}`, "{}", "{}", "ok=false violated=[r] reasons=[r: rate exceeded: 1 > 0 per 60s]"},
		{"rate out of scope", goAAct("read", ""), goARate, `{"r":[` + ent(ago(10), "1") + `,` + ent(ago(20), "1") + `]}`, "{}", okAll},
		{"never_after not latched", goAAct("pay", ""), na, "{}", "{}", okAll},
		{"never_after latched and forbidden", goAAct("pay", ""), na, "{}", `{"na":50}`, "ok=false violated=[na] reasons=[na: forbidden after trigger]"},
		{"never_after latched but another verb", goAAct("read", ""), na, "{}", `{"na":50}`, okAll},
		{"require_prior missing", goAAct("pay", ""), rp, "{}", "{}", "ok=false violated=[rp] reasons=[rp: required prior action not admitted]"},
		{"require_prior present", goAAct("pay", ""), rp, "{}", `{"rp":50}`, okAll},
		{"require_prior out of scope", goAAct("read", ""), rp, "{}", "{}", okAll},
		{"approval at the threshold", goAActSubj("pay", `"n":100`, `"approved":false`), ap, "{}", "{}", okAll},
		{"approval over and approved", goAActSubj("pay", `"n":101`, `"approved":true`), ap, "{}", "{}", okAll},
		{"approval over and not approved", goAActSubj("pay", `"n":101`, `"approved":false`), ap, "{}", "{}", "ok=false violated=[ap] reasons=[ap: approval required over 100]"},
		{"approval amount missing", goAActSubj("pay", ``, `"approved":false`), ap, "{}", "{}", "ok=false violated=[ap] reasons=[ap: approval required over 100]"},
		{"approval amount not a number", goAActSubj("pay", `"n":"x"`, `"approved":false`), ap, "{}", "{}", "ok=false violated=[ap] reasons=[ap: approval required over 100]"},
		{"approval amount negative", goAActSubj("pay", `"n":-1`, `"approved":false`), ap, "{}", "{}", "ok=false violated=[ap] reasons=[ap: approval required over 100]"},
		{"approval out of scope", goAActSubj("read", `"n":999`, `"approved":false`), ap, "{}", "{}", okAll},
		{"approval approver unresolvable", goAAct("pay", `"n":999`), ap, "{}", "{}", "ok=false violated=[ap] reasons=[ap: approval required over 100]"},
	}
	for _, r := range rows {
		got := goARes(CheckProhibitions(r.act, goAC(r.inv), goAGenesis(r.ledger, r.latch)))
		if got != r.want {
			t.Errorf("%s:\n got  %s\n want %s", r.name, got, r.want)
		}
	}
}

func TestGoACheckProhibitionsShape(t *testing.T) {
	c := goAC(goANever, `{"id":"ok1","kind":"never","when":{"verb":"zzz"}}`, `{"id":"d","kind":"never","when":{"verb":"pay"},"description":""}`)
	r := CheckProhibitions(goAAct("pay", ""), c, goAGenesis("{}", "{}"))
	rows := r["evaluated"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows: %v", rows)
	}
	if got := fmt.Sprint(rows[0]); got != "map[id:n kind:never reason:forbidden action result:violated]" {
		t.Errorf("violated row: %s", got)
	}
	if got := fmt.Sprint(rows[1]); got != "map[id:ok1 kind:never result:pass]" {
		t.Errorf("pass row: %s", got)
	}
	if got := fmt.Sprint(rows[2]); got != "map[id:d kind:never result:violated]" {
		t.Errorf("a falsy reason is left out: %s", got)
	}
	if got := goARes(r); got != "ok=false violated=[n d] reasons=[n: forbidden action d: violated]" {
		t.Errorf("summary: %s", got)
	}
}

func TestGoACheckProhibitionsStructural(t *testing.T) {
	st := goAGenesis("{}", "{}")
	rows := []struct {
		name         string
		act, c, s    any
		id, reason   string
		wantViolated string
	}{
		{"constitution", goAAct("pay", ""), goAJ(`{"version":2,"principal":"P","invariants":[]}`), st, "<constitution>", "unsupported version 2", ""},
		{"action", goAJ(`{"action":{"verb":"pay"}}`), goAC(goANever), st, "<action>", "malformed action", ""},
		{"state", goAAct("pay", ""), goAC(goANever), goAJ(`{"now":1}`), "<state>", "malformed monitor state", ""},
	}
	for _, r := range rows {
		res := CheckProhibitions(r.act, r.c, r.s)
		want := fmt.Sprintf("ok=false violated=[%s] reasons=[%s]", r.id, r.reason)
		if got := goARes(res); got != want {
			t.Errorf("%s: got %s want %s", r.name, got, want)
		}
		ev := res["evaluated"].([]any)
		if fmt.Sprint(ev[0]) != fmt.Sprintf("map[id:%s kind:structural reason:%s result:violated]", r.id, r.reason) {
			t.Errorf("%s: evaluated %v", r.name, ev)
		}
	}
	// the constitution is checked before the action, the action before the state
	if res := CheckProhibitions("x", goAJ(`{}`), "y"); res["violated"].([]any)[0] != "<constitution>" {
		t.Errorf("order: %v", res)
	}
	if res := CheckProhibitions("x", goAC(goANever), "y"); res["violated"].([]any)[0] != "<action>" {
		t.Errorf("order: %v", res)
	}
}

func TestGoACheckProhibitionsEvaluationFault(t *testing.T) {
	// a nil regex budget faults inside the invariant's evaluation: that row fails closed, the others still run
	u := `{"id":"u","kind":"never_unless","when":{"verb":"pay"},"unless":[{"field":"action.params.s","op":"matches","value":"a+"}]}`
	a := goAAct("pay", `"s":"aaa"`)
	res := checkProhibitionsB(a, goAC(u, goANever), goAGenesis("{}", "{}"), nil)
	if got := goARes(res); got != "ok=false violated=[u n] reasons=[u: evaluation error (fail closed) n: forbidden action]" {
		t.Errorf("got %s", got)
	}
	// the same invariant with a real budget decides normally
	if got := goARes(CheckProhibitions(a, goAC(u), goAGenesis("{}", "{}"))); got != "ok=true violated=[] reasons=[]" {
		t.Errorf("with a budget: %s", got)
	}
}

func TestGoAWindowEntriesDirect(t *testing.T) {
	ent := func(t string) any { return map[string]any{"t": goAN(t), "amount": goAN("1")} }
	state := map[string]any{"now": goAN("100000"), "ledger": map[string]any{"a": []any{ent("100001"), ent("100000"), ent("99001"), ent("99000"), ent("5")}}}
	count := func(inv map[string]any) int { return len(windowEntries(state, "a", inv)) }
	if got := count(map[string]any{"window_secs": goAN("1")}); got != 2 {
		t.Errorf("window of 1s: %d", got)
	}
	if got := count(map[string]any{}); got != 4 {
		t.Errorf("no window counts every entry up to now: %d", got)
	}
	if got := count(map[string]any{"window_secs": nil}); got != 4 {
		t.Errorf("a null window is no window: %d", got)
	}
	if got := windowEntries(state, "missing", map[string]any{}); len(got) != 0 {
		t.Errorf("unknown id: %v", got)
	}
	if got := windowEntries(map[string]any{"now": goAN("1"), "ledger": map[string]any{"a": "x"}}, "a", map[string]any{}); got != nil {
		t.Errorf("a non-list ledger value: %v", got)
	}
	got := windowEntries(state, "a", map[string]any{})
	if got[0].(map[string]any)["t"] != goAN("5") || got[3].(map[string]any)["t"] != goAN("100000") {
		t.Errorf("entries are returned in time order: %v", got)
	}
}

func TestGoAAllHold(t *testing.T) {
	ctx := goAAct("pay", `"x":1`)
	yes := goAJ(`{"field":"action.params.x","op":"eq","value":1}`)
	no := goAJ(`{"field":"action.params.x","op":"eq","value":2}`)
	unknown := goAJ(`{"field":"subject.nope","op":"eq","value":2}`)
	b := &regexBudget{}
	if !allHold([]any{yes, yes}, ctx, b) || allHold([]any{yes, no}, ctx, b) || allHold([]any{unknown}, ctx, b) || allHold([]any{yes, unknown}, ctx, b) {
		t.Error("allHold")
	}
	if !allHold(nil, ctx, b) || !allHold("x", ctx, b) {
		t.Error("a missing list holds vacuously")
	}
}

func goAAdvance(t *testing.T, act map[string]any, c any, s map[string]any) map[string]any {
	t.Helper()
	r := AdvanceStateStrict(act, c, s)
	if r["ok"] != true {
		t.Fatalf("advance refused: %v", r)
	}
	return r["state"].(map[string]any)
}

func goACanon(v any) string {
	s, err := Canonicalize(v)
	if err != nil {
		panic(err)
	}
	return s
}

func TestGoAAdvanceLedger(t *testing.T) {
	now := 1000000
	ent := func(t int, a string) string { return fmt.Sprintf(`{"t":%d,"amount":%s}`, t, a) }
	// window edge (60s), drop of the oldest, the new entry sorted among equal times
	st := goAGenesis(`{"c":[`+ent(now-60000, "1")+`,`+ent(now-59999, "2")+`,`+ent(now, "3")+`]}`, "{}")
	nx := goAAdvance(t, goAAct("pay", `"n":1`), goAC(goACap), st)
	if got := goACanon(nx["ledger"]); got != fmt.Sprintf(`{"c":[{"amount":2,"t":%d},{"amount":1,"t":%d},{"amount":3,"t":%d}]}`, now-59999, now, now) {
		t.Errorf("cap ledger: %s", got)
	}
	// a cap without a window keeps old entries
	st = goAGenesis(`{"c":[`+ent(5, "2")+`]}`, "{}")
	nx = goAAdvance(t, goAAct("pay", `"n":4`), goAC(goACapOpen), st)
	if got := goACanon(nx["ledger"]); got != fmt.Sprintf(`{"c":[{"amount":2,"t":5},{"amount":4,"t":%d}]}`, now) {
		t.Errorf("open cap ledger: %s", got)
	}
	// a zero amount is recorded; a rate records 1
	nx = goAAdvance(t, goAAct("pay", `"n":0`), goAC(goACapOpen), goAGenesis("{}", "{}"))
	if got := goACanon(nx["ledger"]); got != fmt.Sprintf(`{"c":[{"amount":0,"t":%d}]}`, now) {
		t.Errorf("zero amount: %s", got)
	}
	nx = goAAdvance(t, goAAct("pay", `"n":9`), goAC(goARate), goAGenesis("{}", "{}"))
	if got := goACanon(nx["ledger"]); got != fmt.Sprintf(`{"r":[{"amount":1,"t":%d}]}`, now) {
		t.Errorf("rate ledger: %s", got)
	}
	// out of scope: old entries expire and an emptied key disappears
	st = goAGenesis(`{"r":[`+ent(now-60000, "1")+`]}`, "{}")
	nx = goAAdvance(t, goAAct("read", ""), goAC(goARate), st)
	if got := goACanon(nx["ledger"]); got != `{}` {
		t.Errorf("expired ledger: %s", got)
	}
	// an unresolvable cap amount refuses
	for _, params := range []string{``, `"n":"x"`, `"n":-1`} {
		r := AdvanceStateStrict(goAAct("pay", params), goAC(goACap), goAGenesis("{}", "{}"))
		if r["ok"] != false || r["reason"] != "c: amount unresolvable" {
			t.Errorf("amount %q: %v", params, r)
		}
	}
}

func goABigLedger(n int, amount func(i int) string) string {
	var sb strings.Builder
	sb.WriteString(`{"c":[`)
	for i := 1; i <= n; i++ {
		if i > 1 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"t":%d,"amount":%s}`, i, amount(i))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func TestGoAAdvanceLedgerBounds(t *testing.T) {
	one := func(int) string { return "1" }
	own := func(i int) string { return fmt.Sprint(i) }
	capC := `{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":99999999}`
	rateC := `{"id":"c","kind":"rate","when":{"verb":"pay"},"max":10000,"window_secs":100000}`
	st := func(n int, amount func(int) string) map[string]any {
		return goAStateJ("20000", "0", "null", goABigLedger(n, amount), "{}")
	}
	length := func(s map[string]any) int { return len(s["ledger"].(map[string]any)["c"].([]any)) }

	if nx := goAAdvance(t, goAAct("pay", `"n":7`), goAC(capC), st(9999, one)); length(nx) != 10000 {
		t.Errorf("9999 + 1 entries must stay as they are: %d", length(nx))
	} else if e := nx["ledger"].(map[string]any)["c"].([]any); goACanon(e[0]) != `{"amount":1,"t":1}` {
		t.Errorf("no merge below the bound: %s", goACanon(e[0]))
	}
	nx := goAAdvance(t, goAAct("pay", `"n":7`), goAC(capC), st(10000, own))
	e := nx["ledger"].(map[string]any)["c"].([]any)
	if len(e) != 10000 || goACanon(e[0]) != `{"amount":3,"t":2}` || goACanon(e[1]) != `{"amount":3,"t":3}` || goACanon(e[9998]) != `{"amount":10000,"t":10000}` || goACanon(e[9999]) != `{"amount":7,"t":20000}` {
		t.Errorf("merge of the two oldest: len %d first %s second %s", len(e), goACanon(e[0]), goACanon(e[1]))
	}
	if nx := goAAdvance(t, goAAct("pay", ""), goAC(rateC), st(9999, one)); length(nx) != 10000 {
		t.Errorf("rate 9999 + 1: %d", length(nx))
	}
	r := AdvanceStateStrict(goAAct("pay", ""), goAC(rateC), st(10000, one))
	if r["ok"] != false || r["reason"] != "c: rate ledger overflow" {
		t.Errorf("rate overflow: %v", r)
	}
}

func TestGoAAdvanceTotalEntries(t *testing.T) {
	// 1024 ledger keys is a valid state (<= maxStateKeys); the rate's own new key makes the next one 1025. (100000 entries cannot be
	// built: the strict parser caps a state at 1 MiB of JSON, so the entry-total bound is covered by TestGoAStateEntryTotal.)
	st := goAState(func(m map[string]any) { m["ledger"] = goAKeys(1024, goAEntries(1)) })
	r := AdvanceStateStrict(goAAct("pay", ""), goAC(goARate), st)
	if r["ok"] != false || r["reason"] != "resulting state invalid" {
		t.Errorf("a result over the entry bound: %v", r)
	}
	if r := AdvanceStateStrict(goAAct("read", ""), goAC(goARate), st); r["ok"] != true {
		t.Errorf("an unchanged total is fine: %v", r)
	}
}

func TestGoAAdvanceLatches(t *testing.T) {
	na := `{"id":"na","kind":"never_after","after":{"verb":"login"},"forbid":{"verb":"pay"}}`
	naAmbig := `{"id":"na","kind":"never_after","after":{"verb":"login","where":[{"field":"subject.nope","op":"eq","value":1}]},"forbid":{"verb":"pay"}}`
	rp := `{"id":"rp","kind":"require_prior","when":{"verb":"pay"},"prior":{"verb":"auth"}}`
	rpAmbig := `{"id":"rp","kind":"require_prior","when":{"verb":"pay"},"prior":{"verb":"auth","where":[{"field":"subject.nope","op":"eq","value":1}]}}`
	at := func(act map[string]any, inv string, st map[string]any) string {
		r := AdvanceStateStrictAt(act, goAC(inv), st, goAN("1000150"))
		if r["ok"] != true {
			t.Fatalf("advance: %v", r)
		}
		return goACanon(r["state"].(map[string]any)["latched"])
	}
	g := goAGenesis("{}", "{}")
	if got := at(goAAct("login", ""), na, g); got != `{"na":1000150}` {
		t.Errorf("never_after latches at the given time: %s", got)
	}
	if got := at(goAAct("read", ""), na, g); got != `{}` {
		t.Errorf("never_after unmatched: %s", got)
	}
	if got := at(goAAct("login", ""), na, goAGenesis("{}", `{"na":50}`)); got != `{"na":50}` {
		t.Errorf("an existing latch is kept: %s", got)
	}
	if got := at(goAAct("read", ""), na, goAGenesis("{}", `{"na":50}`)); got != `{"na":50}` {
		t.Errorf("an existing latch is kept (other action): %s", got)
	}
	if got := at(goAAct("login", ""), naAmbig, g); got != `{"na":1000150}` {
		t.Errorf("an ambiguous trigger latches: %s", got)
	}
	if got := at(goAAct("read", ""), naAmbig, g); got != `{}` {
		t.Errorf("an ambiguous trigger of another verb does not latch: %s", got)
	}
	if got := at(goAAct("auth", ""), rp, g); got != `{"rp":1000150}` {
		t.Errorf("require_prior latches: %s", got)
	}
	if got := at(goAAct("read", ""), rp, g); got != `{}` {
		t.Errorf("require_prior unmatched: %s", got)
	}
	if got := at(goAAct("auth", ""), rp, goAGenesis("{}", `{"rp":50}`)); got != `{"rp":50}` {
		t.Errorf("an existing prior latch is kept: %s", got)
	}
	if got := at(goAAct("auth", ""), rpAmbig, g); got != `{}` {
		t.Errorf("an ambiguous prerequisite does not count: %s", got)
	}
}

func TestGoAAdvanceChain(t *testing.T) {
	act := goAAct("pay", `"n":1`)
	c := goAC(goACap)
	st := goAStateJ("1000000", "4", `"p"`, `{}`, `{}`)
	nx := goAAdvance(t, act, c, st)
	prev, err := StateDigest(st)
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := HashCanonical(act)
	wantParent, _ := HashCanonical(map[string]any{"d": stateChainDomain, "state": prev, "action": ad})
	if nx["seq"] != goAN("5") || nx["parent"] != wantParent || nx["now"] != goAN("1000000") {
		t.Errorf("next state: seq %v parent %v now %v (want %s)", nx["seq"], nx["parent"], nx["now"], wantParent)
	}
	if StateProblem(nx) != "" {
		t.Error("the next state is well formed")
	}
	// the input is not changed
	st2 := goAStateJ("1000000", "0", "null", `{"c":[{"t":1,"amount":1}]}`, `{}`)
	_ = goAAdvance(t, act, c, st2)
	if goACanon(st2["ledger"]) != `{"c":[{"amount":1,"t":1}]}` {
		t.Error("the input state must be untouched")
	}
	// at a later time the clock moves
	r := AdvanceStateStrictAt(act, c, st, goAN("1000500"))
	if r["ok"] != true || r["state"].(map[string]any)["now"] != goAN("1000500") {
		t.Errorf("later now: %v", r)
	}
	// AdvanceState keeps the input on failure
	bad := goAJ(`{"version":2,"principal":"P","invariants":[]}`)
	if got := AdvanceState(act, bad, st); !strings.Contains(goACanon(got), `"seq":4`) {
		t.Errorf("failure returns the input: %v", got)
	}
	if got := AdvanceState(act, c, st).(map[string]any); got["seq"] != goAN("5") {
		t.Errorf("success returns the next state: %v", got)
	}
}

func TestGoAAdvanceRefusals(t *testing.T) {
	act := goAAct("pay", `"n":1`)
	c := goAC(goACap)
	st := goAGenesis("{}", "{}")
	badC := goAJ(`{"version":2,"principal":"P","invariants":[]}`)
	badS := goAJ(`{"now":1}`)
	rows := []struct {
		name   string
		r      map[string]any
		reason string
	}{
		{"constitution first", AdvanceStateStrictAt(act, badC, badS, goAN("1")), "unsupported version 2"},
		{"state before clock", AdvanceStateStrictAt(act, c, badS, goAN("1")), "malformed monitor state"},
		{"clock before action", AdvanceStateStrictAt("x", c, st, goAN("999999")), "clock regression"},
		{"clock missing", AdvanceStateStrictAt(act, c, st, nil), "clock regression"},
		{"clock not a number", AdvanceStateStrictAt(act, c, st, "5"), "clock regression"},
		{"clock infinite", AdvanceStateStrictAt(act, c, st, goAN("Infinity")), "clock regression"},
		{"action", AdvanceStateStrictAt(goAJ(`{"action":{"verb":"pay"}}`), c, st, goAN("1000000")), "malformed action"},
		{"state not an object", AdvanceStateStrict(act, c, "x"), "malformed monitor state"},
	}
	for _, r := range rows {
		if r.r["ok"] != false || r.r["reason"] != r.reason {
			t.Errorf("%s: %v", r.name, r.r)
		}
	}
	if r := AdvanceStateStrictAt(act, c, st, goAN("1000000")); r["ok"] != true {
		t.Errorf("the same time is not a regression: %v", r)
	}
}

func TestGoASafeStr(t *testing.T) {
	if got := safeStr(func() (string, error) { return "v", nil }); got != "v" {
		t.Errorf("value: %q", got)
	}
	if got := safeStr(func() (string, error) { return "v", errMalformed }); got != Unhashable {
		t.Errorf("error: %q", got)
	}
	if got := safeStr(func() (string, error) { panic("x") }); got != Unhashable {
		t.Errorf("panic: %q", got)
	}
}
