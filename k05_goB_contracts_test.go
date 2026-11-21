package pca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func goBJSON(t *testing.T, s string) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("bad test json %q: %v", s, err)
	}
	return v
}

func goBStrings(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
}

// goBNest is a list holding one "and" clause nested `levels` deep, with a plain clause at the bottom.
func goBNest(t *testing.T, levels int) []any {
	inner := goBJSON(t, `{"id":"leaf","kind":"never","p":{"verb":"x"}}`)
	for i := levels; i >= 1; i-- {
		inner = map[string]any{"id": fmt.Sprintf("and%d", i), "kind": "and", "clauses": []any{inner}}
	}
	return []any{inner}
}

func TestGoB_ValidateClauseShapes(t *testing.T) {
	v := func(s string) []string { return ValidateClause(goBJSON(t, s), map[string]bool{}, 1) }
	goBStrings(t, v(`{"kind":"never","p":{"verb":"x"}}`), "<no id>: missing clause id")
	goBStrings(t, v(`{"id":"","kind":"never","p":{"verb":"x"}}`), "<no id>: missing clause id")
	goBStrings(t, v(`{"id":5,"kind":"never","p":{"verb":"x"}}`), "<no id>: missing clause id")
	goBStrings(t, v(`"x"`), "clause not an object")
	long := strings.Repeat("a", 128)
	goBStrings(t, v(`{"id":"`+long+`","kind":"never","p":{"verb":"x"}}`))
	goBStrings(t, v(`{"id":"`+long+`a","kind":"never","p":{"verb":"x"}}`), long+"a: id too long")
	goBStrings(t, v(`{"id":"__proto__","kind":"never","p":{"verb":"x"}}`), "__proto__: forbidden id")
	goBStrings(t, v(`{"id":"c","kind":"nope"}`), "c: unknown clause kind nope")
	for _, kind := range []string{"always", "never"} {
		goBStrings(t, v(`{"id":"c","kind":"`+kind+`"}`), "c: p: not an object")
		goBStrings(t, v(`{"id":"c","kind":"`+kind+`","p":{"verb":"x"}}`))
	}
	for _, kind := range []string{"precedes", "requires_prior"} {
		goBStrings(t, v(`{"id":"c","kind":"`+kind+`","q":{"verb":"x"}}`), "c: p: not an object")
		goBStrings(t, v(`{"id":"c","kind":"`+kind+`","p":{"verb":"x"}}`), "c: q: not an object")
		goBStrings(t, v(`{"id":"c","kind":"`+kind+`","p":{"verb":"x"},"q":{"verb":"y"}}`))
	}
	goBStrings(t, v(`{"id":"c","kind":"responds_within","q":{"verb":"x"},"within":3}`), "c: p: not an object")
	goBStrings(t, v(`{"id":"c","kind":"responds_within","p":{"verb":"x"},"within":3}`), "c: q: not an object")
	within := "c: within must be an integer in [1, MAX_DEADLINE]"
	for _, w := range []string{"1", "2", "1000000"} {
		goBStrings(t, v(`{"id":"c","kind":"responds_within","p":{"verb":"x"},"q":{"verb":"y"},"within":`+w+`}`))
	}
	for _, w := range []string{"0", "-1", "1000001", "1.5", `"3"`} {
		goBStrings(t, v(`{"id":"c","kind":"responds_within","p":{"verb":"x"},"q":{"verb":"y"},"within":`+w+`}`), within)
	}
	goBStrings(t, v(`{"id":"c","kind":"and","clauses":[]}`), "c: and.clauses must be a non-empty array")
	goBStrings(t, v(`{"id":"c","kind":"and","clauses":"x"}`), "c: and.clauses must be a non-empty array")
	// an id used twice is refused
	seen := map[string]bool{}
	cl := goBJSON(t, `{"id":"c","kind":"never","p":{"verb":"x"}}`)
	goBStrings(t, ValidateClause(cl, seen, 1))
	goBStrings(t, ValidateClause(cl, seen, 1), "c: duplicate id")
	// nesting past the limit
	goBStrings(t, ValidateClause(cl, map[string]bool{}, ContractMaxClauseDeep), nil...)
	goBStrings(t, ValidateClause(cl, map[string]bool{}, ContractMaxClauseDeep+1), "clause nesting too deep")
}

func TestGoB_CountClauses(t *testing.T) {
	c := func(s string) int { return countClauses(goBJSON(t, s).([]any), 1) }
	if got := c(`[{"kind":"and","clauses":[{"kind":"never"},{"kind":"never"}]}]`); got != 3 {
		t.Errorf("an and counts itself and its children: %d", got)
	}
	// only an "and" nests
	if got := c(`[{"kind":"always","clauses":[{"kind":"never"},{"kind":"never"}]}]`); got != 1 {
		t.Errorf("a non-and with a clauses key: %d", got)
	}
	if got := c(`["x", 5, {"kind":"and","clauses":"x"}]`); got != 3 {
		t.Errorf("non-objects and an and without a list: %d", got)
	}
	if got := countClauses(goBNest(t, 3), 1); got != 4 {
		t.Errorf("three levels and a leaf: %d", got)
	}
	// past the depth bound the count is "too many" at once: 17 levels counted, then ContractMaxClauses+1
	if got := countClauses(goBNest(t, 20), 1); got != 17+ContractMaxClauses+1 {
		t.Errorf("deep nest: %d", got)
	}
	if got := countClauses(goBNest(t, 16), 1); got != 17 {
		t.Errorf("sixteen levels and a leaf: %d", got)
	}
}

func TestGoB_ValidateContractShapes(t *testing.T) {
	mk := func(s string) any { return goBJSON(t, s) }
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","invariants":"x"}`)), "invariants not an array")
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","clauses":"x"}`)), "clauses not an array")
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p"}`)))
	// invariants: 256 are allowed, 257 are too many (and nothing else is wrong)
	inv := func(n int) any {
		list := make([]any, n)
		for i := range list {
			list[i] = map[string]any{"id": fmt.Sprintf("i%d", i), "kind": "never", "when": map[string]any{"verb": "x"}}
		}
		return map[string]any{"version": json.Number("1"), "principal": "p", "invariants": list}
	}
	goBStrings(t, ValidateContract(inv(MaxInvariants)))
	goBStrings(t, ValidateContract(inv(MaxInvariants+1)), "too many invariants")
	// an invalid invariant is reported, an id-less pair is not a duplicate
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","invariants":[{}]}`)), "<no id>: missing id")
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","invariants":[{},{}]}`)), "<no id>: missing id", "<no id>: missing id")
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","invariants":[5,{"id":"a","kind":"never","when":{"verb":"x"}}]}`)), "invariant not an object")
	dup := `{"id":"a","kind":"never","when":{"verb":"x"}}`
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","invariants":[`+dup+`,`+dup+`]}`)), "a: duplicate id")
	// a clause id may not reuse an invariant id
	goBStrings(t, ValidateContract(mk(`{"version":1,"principal":"p","invariants":[`+dup+`],"clauses":[{"id":"a","kind":"never","p":{"verb":"x"}}]}`)), "a: duplicate id")
	// too many clauses: flat, and nested past the depth bound
	flat := make([]any, ContractMaxClauses+1)
	for i := range flat {
		flat[i] = map[string]any{"id": fmt.Sprintf("c%d", i), "kind": "never", "p": map[string]any{"verb": "x"}}
	}
	p := ValidateContract(map[string]any{"version": json.Number("1"), "principal": "p", "clauses": flat})
	goBStrings(t, p, "too many clauses")
	p = ValidateContract(map[string]any{"version": json.Number("1"), "principal": "p", "clauses": flat[:ContractMaxClauses]})
	goBStrings(t, p)
	p = ValidateContract(map[string]any{"version": json.Number("1"), "principal": "p", "clauses": goBNest(t, 17)})
	found := false
	for _, s := range p {
		if s == "too many clauses" {
			found = true
		}
	}
	if !found {
		t.Errorf("a 17-level nest must be too many clauses: %q", p)
	}
	goBStrings(t, ValidateContract(map[string]any{"version": json.Number("1"), "principal": "p", "clauses": goBNest(t, 15)}))
}

func TestGoB_ContractFromConstitutionAndID(t *testing.T) {
	c := ContractFromConstitution(map[string]any{"principal": "p", "invariants": []any{}})
	if c["version"] != any(json.Number("1")) {
		t.Errorf("version: %v", c["version"])
	}
	if got := ValidateContract(c); len(got) != 0 {
		t.Errorf("a contract from a constitution is well formed: %q", got)
	}
	if id, err := ContractID("x"); id != "" || err != errMalformed {
		t.Errorf("a non-object has no id: %q %v", id, err)
	}
	if id, err := ContractID(nil); id != "" || err == nil {
		t.Errorf("nil: %q %v", id, err)
	}
	id, err := ContractID(c)
	if err != nil || id == "" {
		t.Fatalf("id: %q %v", id, err)
	}
	c2 := copyObj(c)
	c2["principal"] = "q"
	if id2, _ := ContractID(c2); id2 == id {
		t.Error("the id depends on the content")
	}
	// the id and signature do not feed into the id
	c3 := copyObj(c)
	c3["id"], c3["sig"] = "x", "y"
	if id3, _ := ContractID(c3); id3 != id {
		t.Error("id and sig are not part of the content")
	}
}

func TestGoB_EmbeddedConstitutionDefaults(t *testing.T) {
	got := embeddedConstitution(map[string]any{"principal": "p"})
	if inv, ok := got["invariants"].([]any); !ok || inv == nil || len(inv) != 0 {
		t.Errorf("a missing invariants list becomes an empty (not nil) list: %#v", got["invariants"])
	}
	if got["version"] != any(json.Number("1")) || got["principal"] != any("p") {
		t.Errorf("%v", got)
	}
	got = embeddedConstitution(map[string]any{"principal": "p", "invariants": "x"})
	if inv, ok := got["invariants"].([]any); !ok || inv == nil {
		t.Errorf("a non-list becomes an empty list: %#v", got["invariants"])
	}
}

func TestGoB_SignAndVerifyContract(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	body := func() any {
		return goBJSON(t, `{"version":1,"principal":"`+kp.Public+`","invariants":[],"clauses":[{"id":"c1","kind":"never","p":{"verb":"delete"}}]}`)
	}
	// an invalid contract is not signed; the problems are named
	bad := goBJSON(t, `{"version":1,"invariants":[]}`)
	if out, err := SignContract(bad, seed); out != nil || err == nil || err.Error() != "signContract: principal missing" {
		t.Errorf("one problem: %v %v", out, err)
	}
	bad = goBJSON(t, `{"version":2,"invariants":[]}`)
	if out, err := SignContract(bad, seed); out != nil || err == nil || err.Error() != "signContract: unsupported version 2; principal missing" {
		t.Errorf("two problems: %v %v", out, err)
	}
	if out, err := SignContract(body(), []byte("short")); out != nil || err == nil {
		t.Errorf("a bad seed: %v %v", out, err)
	}
	out, err := SignContract(body(), seed)
	if err != nil || out == nil {
		t.Fatalf("sign: %v", err)
	}
	wantID, _ := ContractID(body())
	if out["id"] != any(wantID) || !isString(out["sig"]) {
		t.Errorf("id/sig: %v", out)
	}
	if r := VerifyContract(out, ""); r["ok"] != true {
		t.Errorf("verify: %v", r)
	}
	if r := VerifyContract(out, kp.Public); r["ok"] != true {
		t.Errorf("verify against the principal: %v", r)
	}
	if r := VerifyContract(out, "someone-else"); r["ok"] != false || r["reason"] != "principal mismatch" {
		t.Errorf("principal mismatch: %v", r)
	}
	tamper := func(mut func(map[string]any)) map[string]any {
		c := copyObj(out)
		mut(c)
		return VerifyContract(c, "")
	}
	if r := tamper(func(c map[string]any) { c["id"] = "AAAA" }); r["ok"] != false || r["reason"] != "id does not match content" {
		t.Errorf("wrong id: %v", r)
	}
	if r := tamper(func(c map[string]any) { delete(c, "id") }); r["ok"] != false || r["reason"] != "id does not match content" {
		t.Errorf("no id: %v", r)
	}
	if r := tamper(func(c map[string]any) { c["id"] = json.Number("5") }); r["ok"] != false || r["reason"] != "id does not match content" {
		t.Errorf("numeric id: %v", r)
	}
	if r := tamper(func(c map[string]any) { delete(c, "sig") }); r["ok"] != false || r["reason"] != "bad signature" {
		t.Errorf("no sig: %v", r)
	}
	if r := tamper(func(c map[string]any) { c["sig"] = strings.Repeat("A", 86) }); r["ok"] != false || r["reason"] != "bad signature" {
		t.Errorf("wrong sig: %v", r)
	}
	if r := VerifyContract(goBJSON(t, `{"version":1}`), ""); r["ok"] != false || r["reason"] != "principal missing" {
		t.Errorf("invalid: %v", r)
	}
}

// ---- clause transitions ---------------------------------------------------------------------------------------------

func goBAct(verb string) map[string]any {
	return map[string]any{"action": map[string]any{"verb": verb, "resource": "r"}}
}

func goBState(t *testing.T) map[string]any {
	return EmptyMonitorState(json.Number("1000"))
}

func TestGoB_ClauseBaseAndDesc(t *testing.T) {
	cl := map[string]any{"id": "c", "kind": "never"}
	if tr := clauseBase(cl, false, ""); tr.reason != nil {
		t.Errorf("an empty reason is no reason: %#v", tr.reason)
	} else if _, has := tr.rows[0].(map[string]any)["reason"]; has {
		t.Error("the row of an empty reason has no reason")
	}
	if tr := clauseBase(cl, false, "why"); tr.reason != any("why") || tr.rows[0].(map[string]any)["reason"] != any("why") || tr.ok {
		t.Errorf("a reason: %+v", tr)
	}
	if tr := clauseBase(cl, true, nil); !tr.ok || tr.reason != nil || tr.rows[0].(map[string]any)["result"] != "pass" {
		t.Errorf("pass: %+v", tr)
	}
	if got := clauseDesc(map[string]any{"description": "x"}, "def"); got != any("x") {
		t.Errorf("description: %v", got)
	}
	if got := clauseDesc(map[string]any{"description": nil}, "def"); got != any("def") {
		t.Errorf("null description: %v", got)
	}
	if got := clauseDesc(map[string]any{}, "def"); got != any("def") {
		t.Errorf("no description: %v", got)
	}
	if got := clauseDesc(map[string]any{"description": ""}, "def"); got != any("") {
		t.Errorf("an empty description is kept: %#v", got)
	}
}

func TestGoB_EvalClauseFailsClosed(t *testing.T) {
	// a clause without a string id panics inside evalClause: the verdict is a violation, never a panic
	tr := evalClause(map[string]any{"kind": "always", "p": map[string]any{"verb": "x"}}, goBAct("x"), goBState(t), json.Number("1000"), &regexBudget{})
	if tr.ok || tr.reason != any("clause evaluation error (fail closed)") || len(tr.rows) != 1 {
		t.Errorf("%+v", tr)
	}
	if r := tr.rows[0].(map[string]any); r["result"] != "violated" || r["reason"] != any("clause evaluation error (fail closed)") {
		t.Errorf("row: %v", r)
	}
}

func TestGoB_EvalClauseAnd(t *testing.T) {
	mkAnd := func(s string) map[string]any { return goBJSON(t, s).(map[string]any) }
	st := goBState(t)
	ev := func(cl map[string]any, verb string) clauseTrans {
		return evalClause(cl, goBAct(verb), st, json.Number("1000"), &regexBudget{})
	}
	pass := `{"id":"a","kind":"never","p":{"verb":"zzz"}}`
	v1 := `{"id":"b","kind":"never","p":{"verb":"pay"},"description":"R1"}`
	v2 := `{"id":"c","kind":"never","p":{"verb":"pay"},"description":"R2"}`
	all := ev(mkAnd(`{"id":"all","kind":"and","clauses":[`+pass+`,`+goBPass2(pass)+`]}`), "pay")
	if !all.ok || all.reason != nil || len(all.rows) != 2 {
		t.Errorf("all pass: %+v", all)
	}
	both := ev(mkAnd(`{"id":"all","kind":"and","clauses":[`+pass+`,`+v1+`,`+v2+`]}`), "pay")
	if both.ok || both.reason != any("R1") || len(both.rows) != 3 {
		t.Errorf("first failure names the reason: %+v", both)
	}
	ids := []any{}
	for _, r := range both.rows {
		ids = append(ids, r.(map[string]any)["id"])
	}
	if !reflect.DeepEqual(ids, []any{"a", "b", "c"}) {
		t.Errorf("rows in order: %v", ids)
	}
	one := ev(mkAnd(`{"id":"all","kind":"and","clauses":[`+v1+`,`+pass+`]}`), "pay")
	if one.ok || one.reason != any("R1") {
		t.Errorf("failure then pass: %+v", one)
	}
	two := ev(mkAnd(`{"id":"all","kind":"and","clauses":[`+pass+`,`+v2+`]}`), "pay")
	if two.ok || two.reason != any("R2") {
		t.Errorf("pass then failure: %+v", two)
	}
	// a failure without a reason leaves no reason
	quiet := ev(mkAnd(`{"id":"all","kind":"and","clauses":[{"id":"q","kind":"never","p":{"verb":"pay"},"description":""}]}`), "pay")
	if quiet.ok || quiet.reason != nil {
		t.Errorf("quiet: %+v", quiet)
	}
}

func goBPass2(s string) string { return strings.Replace(s, `"id":"a"`, `"id":"a2"`, 1) }

func TestGoB_EvalClauseRespondsWithin(t *testing.T) {
	cl := goBJSON(t, `{"id":"r1","kind":"responds_within","p":{"verb":"pay"},"q":{"verb":"ack"},"within":5}`).(map[string]any)
	state := func(left string) map[string]any {
		s := goBState(t)
		s["deadlines"] = map[string]any{"r1": json.Number(left)}
		return s
	}
	// an open obligation with 2 actions left, p again: the obligation keeps the SMALLER window
	tr := evalClause(cl, goBAct("pay"), state("2"), json.Number("1000"), &regexBudget{})
	if !tr.ok || !jeq(tr.deadlineSet["r1"], json.Number("1")) {
		t.Errorf("carried window: %+v", tr)
	}
	// no open obligation, p: the window opens at `within`
	tr = evalClause(cl, goBAct("pay"), goBState(t), json.Number("1000"), &regexBudget{})
	if !tr.ok || !jeq(tr.deadlineSet["r1"], json.Number("5")) {
		t.Errorf("new window: %+v", tr)
	}
	// a response discharges the obligation
	tr = evalClause(cl, goBAct("ack"), state("2"), json.Number("1000"), &regexBudget{})
	if v, has := tr.deadlineSet["r1"]; !tr.ok || !has || v != nil {
		t.Errorf("discharged: %+v", tr)
	}
	// an exhausted window is a violation
	tr = evalClause(cl, goBAct("other"), state("1"), json.Number("1000"), &regexBudget{})
	if tr.ok || len(tr.deadlineSet) != 0 {
		t.Errorf("exhausted: %+v", tr)
	}
}

// ---- the monitor ------------------------------------------------------------------------------------------------------

func goBNeverContract(t *testing.T, id string, desc string) map[string]any {
	d := ""
	if desc != "-" {
		d = `,"description":"` + desc + `"`
	}
	return goBJSON(t, `{"version":1,"principal":"p","clauses":[{"id":"`+id+`","kind":"never","p":{"verb":"delete"}`+d+`}]}`).(map[string]any)
}

func TestGoB_CheckContractReasonWithoutDescription(t *testing.T) {
	r := CheckContract(goBAct("delete"), goBNeverContract(t, "c1", ""), goBState(t))
	if r["ok"] != false || !reflect.DeepEqual(r["reasons"], []any{"c1: violated"}) {
		t.Errorf("%v", r)
	}
	r = CheckContract(goBAct("delete"), goBNeverContract(t, "c1", "no deletes"), goBState(t))
	if !reflect.DeepEqual(r["reasons"], []any{"c1: no deletes"}) {
		t.Errorf("%v", r)
	}
	r = CheckContract(goBAct("read"), goBNeverContract(t, "c1", "-"), goBState(t))
	if r["ok"] != true || len(r["violated"].([]any)) != 0 {
		t.Errorf("%v", r)
	}
	// a contract with no invariants and no clauses is checked (and passes)
	r = CheckContract(goBAct("read"), goBJSON(t, `{"version":1,"principal":"p"}`), goBState(t))
	if r["ok"] != true || len(r["evaluated"].([]any)) != 0 {
		t.Errorf("%v", r)
	}
}

func TestGoB_AdvanceContractRefusals(t *testing.T) {
	c := goBNeverContract(t, "c1", "no deletes")
	// a stale head: the contract's own violations stay and "<state>" is named once, last
	r := AdvanceContract(goBState(t), goBAct("delete"), c, map[string]any{"expectedSeq": json.Number("5")})
	if r["ok"] != false || r["decidedBy"] != "state" ||
		!reflect.DeepEqual(r["violated"], []any{"c1", "<state>"}) ||
		!reflect.DeepEqual(r["reasons"], []any{"c1: no deletes", "<state>: stale state head (seq)"}) {
		t.Errorf("stale seq: %v", r)
	}
	// a malformed state: "<state>" is not repeated
	r = AdvanceContract(map[string]any{}, goBAct("read"), c, map[string]any{"expectedSeq": json.Number("0")})
	if r["ok"] != false || !reflect.DeepEqual(r["violated"], []any{"<state>"}) ||
		!reflect.DeepEqual(r["reasons"], []any{"<state>: malformed monitor state", "<state>: stale state head (seq)"}) {
		t.Errorf("malformed state: %v", r)
	}
	// the digest head
	st := goBState(t)
	d, err := StateDigest(st)
	if err != nil {
		t.Fatal(err)
	}
	if r := AdvanceContract(st, goBAct("read"), c, map[string]any{"expectedStateDigest": d}); r["ok"] != true {
		t.Errorf("the right digest: %v", r)
	}
	for _, bad := range []any{"AAAA", json.Number("5"), nil, true} {
		r := AdvanceContract(st, goBAct("read"), c, map[string]any{"expectedStateDigest": bad})
		if r["ok"] != false || r["decidedBy"] != "state" || !reflect.DeepEqual(r["reasons"], []any{"<state>: stale state head (digest)"}) {
			t.Errorf("digest %v: %v", bad, r)
		}
	}
	// a null `now` option is the same as none
	r = AdvanceContract(st, goBAct("read"), c, map[string]any{"now": nil})
	if r["ok"] != true || !jeq(r["next"].(map[string]any)["now"], json.Number("1000")) {
		t.Errorf("null now: %v", r)
	}
	r = AdvanceContract(st, goBAct("read"), c, map[string]any{"now": json.Number("2000")})
	if r["ok"] != true || !jeq(r["next"].(map[string]any)["now"], json.Number("2000")) {
		t.Errorf("explicit now: %v", r)
	}
}

func TestGoB_AdvanceContractDecidedBy(t *testing.T) {
	st := goBState(t)
	r := AdvanceContract(st, goBAct("delete"), goBNeverContract(t, "c1", "x"), nil)
	if r["ok"] != false || r["decidedBy"] != "contract" {
		t.Errorf("a violation is decided by the contract: %v", r)
	}
	// ids that merely start or end like a structural marker are still clauses
	for _, id := range []string{"<x", "x>"} {
		r = AdvanceContract(st, goBAct("delete"), goBNeverContract(t, id, "x"), nil)
		if r["ok"] != false || r["decidedBy"] != "contract" {
			t.Errorf("id %q: %v", id, r)
		}
	}
	// a structural refusal is decided by the state
	r = AdvanceContract(st, map[string]any{"action": map[string]any{}}, goBNeverContract(t, "c1", "x"), nil)
	if r["ok"] != false || r["decidedBy"] != "state" || !reflect.DeepEqual(r["violated"], []any{"<action>"}) {
		t.Errorf("malformed action: %v", r)
	}
	r = AdvanceContract(st, goBAct("read"), goBNeverContract(t, "c1", "x"), nil)
	if r["ok"] != true || r["decidedBy"] != "none" {
		t.Errorf("allowed: %v", r)
	}
}

func TestGoB_AdvanceContractDeadlines(t *testing.T) {
	c := goBNeverContract(t, "c1", "x")
	// a deadline of a clause this contract does not name is carried over
	st := goBState(t)
	st["deadlines"] = map[string]any{"zz": json.Number("3")}
	r := AdvanceContract(st, goBAct("read"), c, nil)
	if r["ok"] != true {
		t.Fatalf("%v", r)
	}
	if dl, _ := r["next"].(map[string]any)["deadlines"].(map[string]any); len(dl) != 1 || !jeq(dl["zz"], json.Number("3")) {
		t.Errorf("carried deadlines: %v", r["next"])
	}
	// with no deadline at all the key is absent (an empty map would change the state digest)
	r = AdvanceContract(goBState(t), goBAct("read"), c, nil)
	if _, has := r["next"].(map[string]any)["deadlines"]; r["ok"] != true || has {
		t.Errorf("no deadlines: %v", r["next"])
	}
	// the obligation of a responds_within clause opens, shrinks, and is discharged
	rc := goBJSON(t, `{"version":1,"principal":"p","clauses":[{"id":"r1","kind":"responds_within","p":{"verb":"pay"},"q":{"verb":"ack"},"within":3}]}`)
	r = AdvanceContract(goBState(t), goBAct("pay"), rc, nil)
	if r["ok"] != true || !jeq(r["next"].(map[string]any)["deadlines"].(map[string]any)["r1"], json.Number("3")) {
		t.Fatalf("opened: %v", r)
	}
	r = AdvanceContract(r["next"], goBAct("pay"), rc, map[string]any{"now": json.Number("1001")})
	if r["ok"] != true || !jeq(r["next"].(map[string]any)["deadlines"].(map[string]any)["r1"], json.Number("2")) {
		t.Fatalf("shrunk to the smaller window: %v", r)
	}
	r = AdvanceContract(r["next"], goBAct("ack"), rc, map[string]any{"now": json.Number("1002")})
	if _, has := r["next"].(map[string]any)["deadlines"]; r["ok"] != true || has {
		t.Errorf("discharged: %v", r)
	}
}

func TestGoB_CheckAndAdvanceContractResult(t *testing.T) {
	c := goBNeverContract(t, "c1", "x")
	st := goBState(t)
	r := CheckAndAdvanceContract(true, st, goBAct("read"), c, nil)
	if r["permitted"] != true || r["allow"] != true || r["ok"] != true {
		t.Errorf("allowed: %v", r)
	}
	r = CheckAndAdvanceContract(false, st, goBAct("read"), c, nil)
	if r["permitted"] != false || r["allow"] != false || r["ok"] != false || r["decidedBy"] != "contract" ||
		!reflect.DeepEqual(r["reasons"], []any{"<permission>: not permitted"}) {
		t.Errorf("not permitted: %v", r)
	}
	r = CheckAndAdvanceContract(true, st, goBAct("delete"), c, nil)
	if r["permitted"] != true || r["allow"] != false || r["ok"] != false {
		t.Errorf("violation: %v", r)
	}
	r = CheckAndAdvanceContract("yes", st, goBAct("delete"), c, nil)
	if r["permitted"] != false || r["allow"] != false {
		t.Errorf("only true permits: %v", r)
	}
}
