package pca

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func goAJ(s string) any {
	v, err := StrictParse(s)
	if err != nil {
		panic(err)
	}
	return v
}

func goAN(s string) json.Number { return json.Number(s) }

func goAStrs(n int, s string) string { return strings.Repeat(s, n) }

func TestGoAProhibitionConstants(t *testing.T) {
	if ConstitutionVersion != 1 || EvidenceVersion != 1 || MaxLedger != 10000 || MaxInvariants != 256 || MaxDeadline != 1000000 ||
		maxStateEntries != 100000 || maxStateKeys != 1024 || maxIDLen != 128 || maxConditionDepth != 32 {
		t.Fatal("a published limit changed")
	}
}

func TestGoAProhibitionHelpers(t *testing.T) {
	if pHas("x", "k") || pHas(nil, "k") || !pHas(map[string]any{"k": nil}, "k") || pHas(map[string]any{}, "k") {
		t.Error("pHas")
	}
	for _, f := range []any{goAN("-Infinity"), goAN("Infinity"), math.NaN(), "x", nil} {
		if pFin(f) {
			t.Errorf("pFin(%v)", f)
		}
	}
	if !pFin(goAN("0")) || !pFin(goAN("-3.5")) {
		t.Error("pFin finite")
	}
	if pNegZero(goAN("-1")) || pNegZero(goAN("0")) || pNegZero(goAN("1")) || pNegZero("x") || !pNegZero(goAN("-0")) {
		t.Error("pNegZero")
	}
	if pNonEmptyStr("") || pNonEmptyStr(5) || pNonEmptyStr(nil) || !pNonEmptyStr("a") {
		t.Error("pNonEmptyStr")
	}
	truthy := []struct {
		v    any
		want bool
	}{
		{nil, false}, {false, false}, {true, true}, {"", false}, {"a", true}, {goAN("0"), false}, {goAN("1"), true}, {goAN("5"), true},
		{goAN("-2"), true}, {math.NaN(), false}, {map[string]any{}, true}, {[]any{}, true},
	}
	for _, c := range truthy {
		if got := pTruthy(c.v); got != c.want {
			t.Errorf("pTruthy(%#v) = %v", c.v, got)
		}
	}
	keys := map[string]any{}
	for _, k := range []string{"m", "c", "x", "a", "q", "b", "z", "d", "k", "e", "y", "f"} {
		keys[k] = true
	}
	if got := pSortedKeys(keys); !reflect.DeepEqual(got, []string{"a", "b", "c", "d", "e", "f", "k", "m", "q", "x", "y", "z"}) {
		t.Errorf("pSortedKeys %v", got)
	}
	if !jeq("a", "a") || jeq("a", "b") || !jeq(goAN("1"), goAN("1.0")) || jeq(goAN("1"), "1") || jeq(goAN("1"), goAN("2")) || !jeq(nil, nil) {
		t.Error("jeq")
	}
	if _, ok := pNorm(map[string]any{"a": goAN("1")}); !ok {
		t.Error("pNorm of valid input")
	}
	if _, ok := pNorm(math.NaN()); ok {
		t.Error("pNorm of NaN must fail")
	}
}

func goAChain(kind string, n int) any {
	cur := any(map[string]any{"field": "action.x", "op": "exists"})
	for i := 0; i < n; i++ {
		cur = map[string]any{kind: wrapKind(kind, cur)}
	}
	return cur
}

func wrapKind(kind string, v any) any {
	if kind == "not" {
		return v
	}
	return []any{v}
}

func TestGoAValidateCondition(t *testing.T) {
	leaf := `{"field":"action.x","op":"eq","value":1}`
	rows := []struct {
		name string
		c    any
		want string
	}{
		{"not an object", "x", "condition not an object"},
		{"nil", nil, "condition not an object"},
		{"leaf", goAJ(leaf), ""},
		{"all_of alone", goAJ(`{"all_of":[` + leaf + `]}`), ""},
		{"any_of alone", goAJ(`{"any_of":[` + leaf + `]}`), ""},
		{"not alone", goAJ(`{"not":` + leaf + `}`), ""},
		{"all_of empty", goAJ(`{"all_of":[]}`), "condition.all_of must be a non-empty array"},
		{"any_of empty", goAJ(`{"any_of":[]}`), "condition.any_of must be a non-empty array"},
		{"all_of not a list", goAJ(`{"all_of":"x"}`), "condition.all_of must be a non-empty array"},
		{"any_of not a list", goAJ(`{"any_of":{}}`), "condition.any_of must be a non-empty array"},
		{"all_of one valid child", goAJ(`{"all_of":[` + leaf + `]}`), ""},
		{"all_of bad child", goAJ(`{"all_of":[` + leaf + `,{"op":"eq"}]}`), "condition.field missing"},
		{"any_of bad child", goAJ(`{"any_of":[{"op":"eq"}]}`), "condition.field missing"},
		{"not bad child", goAJ(`{"not":{"op":"eq"}}`), "condition.field missing"},
		{"not of a non-object", goAJ(`{"not":5}`), "condition not an object"},
		{"all_of wins over any_of when not absent", goAJ(`{"all_of":[],"any_of":[` + leaf + `]}`), "condition.all_of must be a non-empty array"},
		{"not wins over all_of", goAJ(`{"not":` + leaf + `,"all_of":[]}`), ""},
		{"empty field", goAJ(`{"field":"","op":"eq"}`), "condition.field missing"},
		{"field not a string", goAJ(`{"field":5,"op":"eq"}`), "condition.field missing"},
		{"op missing", goAJ(`{"field":"a"}`), "unknown condition op undefined"},
		{"op number", goAJ(`{"field":"a","op":5}`), "unknown condition op 5"},
		{"op unknown", goAJ(`{"field":"a","op":"bogus"}`), "unknown condition op bogus"},
		{"op empty", goAJ(`{"field":"a","op":""}`), "unknown condition op "},
		{"ref ok", goAJ(`{"field":"a","op":"eq","ref":"action.y"}`), ""},
		{"ref empty", goAJ(`{"field":"a","op":"eq","ref":""}`), "bad condition.ref"},
		{"ref number", goAJ(`{"field":"a","op":"eq","ref":5}`), "bad condition.ref"},
		{"member_of ok", goAJ(`{"field":"a","op":"member_of","collection":"subject.g"}`), ""},
		{"member_of no collection", goAJ(`{"field":"a","op":"member_of"}`), ""},
		{"member_of empty collection", goAJ(`{"field":"a","op":"member_of","collection":""}`), "bad condition.collection"},
		{"member_of numeric collection", goAJ(`{"field":"a","op":"member_of","collection":3}`), "bad condition.collection"},
		{"other op ignores collection", goAJ(`{"field":"a","op":"eq","collection":""}`), ""},
	}
	for _, r := range rows {
		if got := ValidateCondition(r.c, 0); got != r.want {
			t.Errorf("%s: got %q want %q", r.name, got, r.want)
		}
	}
	// the depth bound: the leaf sits at depth n, and depth 32 is the last allowed
	for _, kind := range []string{"not", "all_of", "any_of"} {
		if got := ValidateCondition(goAChain(kind, 32), 0); got != "" {
			t.Errorf("%s nesting 32: %q", kind, got)
		}
		if got := ValidateCondition(goAChain(kind, 33), 0); got != "condition nesting too deep" {
			t.Errorf("%s nesting 33: %q", kind, got)
		}
	}
	if ValidateCondition(goAJ(leaf), 32) != "" || ValidateCondition(goAJ(leaf), 33) != "condition nesting too deep" {
		t.Error("depth argument boundary")
	}
}

func TestGoAValidateWhen(t *testing.T) {
	rows := []struct {
		name string
		w    any
		want string
	}{
		{"not an object", "x", "when: not an object"},
		{"verb ok", goAJ(`{"verb":"read"}`), ""},
		{"verb missing", goAJ(`{}`), "when: bad verb"},
		{"verb number", goAJ(`{"verb":5}`), "when: bad verb"},
		{"verb empty", goAJ(`{"verb":""}`), "when: bad verb"},
		{"verb list ok", goAJ(`{"verb":["a","b"]}`), ""},
		{"verb list of one", goAJ(`{"verb":["a"]}`), ""},
		{"verb list empty", goAJ(`{"verb":[]}`), "when: bad verb"},
		{"verb list with empty", goAJ(`{"verb":["a",""]}`), "when: bad verb"},
		{"verb list with empty first", goAJ(`{"verb":["","a"]}`), "when: bad verb"},
		{"verb list with number", goAJ(`{"verb":["a",5]}`), "when: bad verb"},
		{"resource number", goAJ(`{"verb":"a","resource":5}`), "when: bad resource"},
		{"resource plain", goAJ(`{"verb":"a","resource":"x"}`), ""},
		{"resource short plain", goAJ(`{"verb":"a","resource":"x*"}`), ""},
		{"resource regex ok", goAJ(`{"verb":"a","resource":"re:b"}`), ""},
		{"resource regex 200", goAJ(`{"verb":"a","resource":"re:` + goAStrs(200, "a") + `"}`), ""},
		{"resource regex 201", goAJ(`{"verb":"a","resource":"re:` + goAStrs(201, "a") + `"}`), "when: unsafe regex resource"},
		{"resource regex unsafe", goAJ(`{"verb":"a","resource":"re:\\1"}`), "when: unsafe regex resource"},
		{"where ok", goAJ(`{"verb":"a","where":[{"field":"action.x","op":"exists"}]}`), ""},
		{"where empty list", goAJ(`{"verb":"a","where":[]}`), ""},
		{"where not a list", goAJ(`{"verb":"a","where":{}}`), "when: where not an array"},
		{"where bad condition", goAJ(`{"verb":"a","where":[{"op":"eq"}]}`), "when: condition.field missing"},
		{"where deep ok", goAJ(`{"verb":"a","where":[]}`), ""},
	}
	for _, r := range rows {
		if got := ValidateWhen(r.w, "when"); got != r.want {
			t.Errorf("%s: got %q want %q", r.name, got, r.want)
		}
	}
	if got := ValidateWhen("x", "after"); got != "after: not an object" {
		t.Errorf("label: %q", got)
	}
	if got := ValidateWhen(map[string]any{"verb": "a", "where": []any{goAChain("not", 32)}}, "when"); got != "" {
		t.Errorf("a where condition may nest to depth 32: %q", got)
	}
	if got := ValidateWhen(map[string]any{"verb": "a", "where": []any{goAChain("not", 33)}}, "when"); got != "when: condition nesting too deep" {
		t.Errorf("a where condition nests to depth 32 at most: %q", got)
	}
}

func goAInv(kind, extra string) any {
	return goAJ(`{"id":"i1","kind":"` + kind + `"` + extra + `}`)
}

const goAWhenJ = `"when":{"verb":"pay"}`

func TestGoAValidateInvariant(t *testing.T) {
	cond := `[{"field":"action.params.ok","op":"eq","value":true}]`
	rows := []struct {
		name string
		inv  any
		want []string
	}{
		{"not an object", "x", []string{"invariant not an object"}},
		{"no id", goAJ(`{"kind":"never"}`), []string{"<no id>: missing id"}},
		{"empty id", goAJ(`{"id":"","kind":"never"}`), []string{"<no id>: missing id"}},
		{"numeric id", goAJ(`{"id":5,"kind":"never"}`), []string{"<no id>: missing id"}},
		{"id 128", goAJ(`{"id":"` + goAStrs(128, "a") + `","kind":"never",` + goAWhenJ + `}`), nil},
		{"id 129", goAJ(`{"id":"` + goAStrs(129, "a") + `","kind":"never",` + goAWhenJ + `}`), []string{goAStrs(129, "a") + ": id too long"}},
		{"forbidden proto", goAJ(`{"id":"__proto__","kind":"never",` + goAWhenJ + `}`), []string{"__proto__: forbidden id"}},
		{"forbidden constructor", goAJ(`{"id":"constructor","kind":"never",` + goAWhenJ + `}`), []string{"constructor: forbidden id"}},
		{"forbidden prototype", goAJ(`{"id":"prototype","kind":"never",` + goAWhenJ + `}`), []string{"prototype: forbidden id"}},
		{"unknown kind", goAInv("bogus", ""), []string{"i1: unknown invariant kind bogus"}},
		{"missing kind", goAJ(`{"id":"i1"}`), []string{"i1: unknown invariant kind undefined"}},
		{"never ok", goAInv("never", ","+goAWhenJ), nil},
		{"never bad when", goAInv("never", `,"when":{}`), []string{"i1: when: bad verb"}},
		{"never_unless ok", goAInv("never_unless", ","+goAWhenJ+`,"unless":`+cond), nil},
		{"never_unless bad when", goAInv("never_unless", `,"when":{},"unless":`+cond), []string{"i1: when: bad verb"}},
		{"never_unless no unless", goAInv("never_unless", ","+goAWhenJ), []string{"i1: unless must be a non-empty array"}},
		{"never_unless empty unless", goAInv("never_unless", ","+goAWhenJ+`,"unless":[]`), []string{"i1: unless must be a non-empty array"}},
		{"never_unless bad unless condition", goAInv("never_unless", ","+goAWhenJ+`,"unless":[{"op":"eq"}]`), []string{"i1: condition.field missing"}},
		{"cap ok", goAInv("cap", ","+goAWhenJ+`,"amount":"action.params.n","max":10`), nil},
		{"cap max 0 ok", goAInv("cap", ","+goAWhenJ+`,"amount":"action.params.n","max":0`), nil},
		{"cap window ok", goAInv("cap", ","+goAWhenJ+`,"amount":"action.params.n","max":1,"window_secs":1`), nil},
		{"cap bad when", goAInv("cap", `,"when":{},"amount":"action.params.n","max":1`), []string{"i1: when: bad verb"}},
		{"cap amount not action path", goAInv("cap", ","+goAWhenJ+`,"amount":"params.n","max":1`), []string{"i1: amount must be an action.* path"}},
		{"cap amount not a string", goAInv("cap", ","+goAWhenJ+`,"amount":5,"max":1`), []string{"i1: amount must be an action.* path"}},
		{"cap max missing", goAInv("cap", ","+goAWhenJ+`,"amount":"action.n"`), []string{"i1: max must be a finite number >= 0"}},
		{"cap max negative", goAInv("cap", ","+goAWhenJ+`,"amount":"action.n","max":-1`), []string{"i1: max must be a finite number >= 0"}},
		{"cap window zero", goAInv("cap", ","+goAWhenJ+`,"amount":"action.n","max":1,"window_secs":0`), []string{"i1: bad window_secs"}},
		{"cap window negative", goAInv("cap", ","+goAWhenJ+`,"amount":"action.n","max":1,"window_secs":-1`), []string{"i1: bad window_secs"}},
		{"cap window string", goAInv("cap", ","+goAWhenJ+`,"amount":"action.n","max":1,"window_secs":"x"`), []string{"i1: bad window_secs"}},
		{"rate ok", goAInv("rate", ","+goAWhenJ+`,"max":10000,"window_secs":1`), nil},
		{"rate max 0 ok", goAInv("rate", ","+goAWhenJ+`,"max":0,"window_secs":1`), nil},
		{"rate bad when", goAInv("rate", `,"when":{},"max":1,"window_secs":1`), []string{"i1: when: bad verb"}},
		{"rate max fraction", goAInv("rate", ","+goAWhenJ+`,"max":1.5,"window_secs":1`), []string{"i1: max must be an integer in [0,10000]"}},
		{"rate max negative", goAInv("rate", ","+goAWhenJ+`,"max":-1,"window_secs":1`), []string{"i1: max must be an integer in [0,10000]"}},
		{"rate max negative zero", map[string]any{"id": "i1", "kind": "rate", "when": goAJ(`{"verb":"pay"}`), "max": goAN("-0"), "window_secs": goAN("1")}, []string{"i1: max must be an integer in [0,10000]"}},
		{"rate max too big", goAInv("rate", ","+goAWhenJ+`,"max":10001,"window_secs":1`), []string{"i1: max must be an integer in [0,10000]"}},
		{"rate max missing", goAInv("rate", ","+goAWhenJ+`,"window_secs":1`), []string{"i1: max must be an integer in [0,10000]"}},
		{"rate window missing", goAInv("rate", ","+goAWhenJ+`,"max":1`), []string{"i1: window_secs must be > 0"}},
		{"rate window zero", goAInv("rate", ","+goAWhenJ+`,"max":1,"window_secs":0`), []string{"i1: window_secs must be > 0"}},
		{"rate window negative", goAInv("rate", ","+goAWhenJ+`,"max":1,"window_secs":-2`), []string{"i1: window_secs must be > 0"}},
		{"never_after ok", goAInv("never_after", `,"after":{"verb":"a"},"forbid":{"verb":"b"}`), nil},
		{"never_after bad after", goAInv("never_after", `,"after":{},"forbid":{"verb":"b"}`), []string{"i1: after: bad verb"}},
		{"never_after bad forbid", goAInv("never_after", `,"after":{"verb":"a"},"forbid":{}`), []string{"i1: forbid: bad verb"}},
		{"never_after both bad reports after", goAInv("never_after", `,"after":{},"forbid":{}`), []string{"i1: after: bad verb"}},
		{"require_prior ok", goAInv("require_prior", `,"when":{"verb":"a"},"prior":{"verb":"b"}`), nil},
		{"require_prior bad when", goAInv("require_prior", `,"when":{},"prior":{"verb":"b"}`), []string{"i1: when: bad verb"}},
		{"require_prior bad prior", goAInv("require_prior", `,"when":{"verb":"a"},"prior":{}`), []string{"i1: prior: bad verb"}},
		{"require_prior both bad reports when", goAInv("require_prior", `,"when":{},"prior":{}`), []string{"i1: when: bad verb"}},
		{"approval ok", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"action.n","threshold":0,"approved":`+cond), nil},
		{"approval bad when", goAInv("require_approval_over", `,"when":{},"amount":"action.n","threshold":1,"approved":`+cond), []string{"i1: when: bad verb"}},
		{"approval amount path", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"n","threshold":1,"approved":`+cond), []string{"i1: amount must be an action.* path"}},
		{"approval threshold missing", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"action.n","approved":`+cond), []string{"i1: threshold must be a finite number >= 0"}},
		{"approval threshold negative", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"action.n","threshold":-1,"approved":`+cond), []string{"i1: threshold must be a finite number >= 0"}},
		{"approval approved missing", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"action.n","threshold":1`), []string{"i1: approved must be a non-empty array"}},
		{"approval approved empty", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"action.n","threshold":1,"approved":[]`), []string{"i1: approved must be a non-empty array"}},
		{"approval approved bad condition", goAInv("require_approval_over", ","+goAWhenJ+`,"amount":"action.n","threshold":1,"approved":[{"op":"eq"}]`), []string{"i1: condition.field missing"}},
	}
	for _, r := range rows {
		if got := ValidateInvariant(r.inv); !reflect.DeepEqual(got, r.want) {
			t.Errorf("%s: got %q want %q", r.name, got, r.want)
		}
	}
	deep := func(n int) any {
		return map[string]any{"id": "i1", "kind": "never_unless", "when": map[string]any{"verb": "pay"}, "unless": []any{goAChain("not", n)}}
	}
	if got := ValidateInvariant(deep(32)); got != nil {
		t.Errorf("a condition nests to depth 32 from the invariant: %q", got)
	}
	if got := ValidateInvariant(deep(33)); !reflect.DeepEqual(got, []string{"i1: condition nesting too deep"}) {
		t.Errorf("nesting 33: %q", got)
	}
}

func goAConstitution(invs string) string {
	return `{"version":1,"principal":"P","invariants":[` + invs + `]}`
}

func TestGoAValidateConstitution(t *testing.T) {
	never := func(id string) string { return `{"id":"` + id + `","kind":"never",` + goAWhenJ + `}` }
	rows := []struct {
		name string
		c    any
		want []string
	}{
		{"not an object", "x", []string{"constitution not an object"}},
		{"ok", goAJ(goAConstitution(never("a"))), []string{}},
		{"empty ok", goAJ(goAConstitution("")), []string{}},
		{"version 2", goAJ(`{"version":2,"principal":"P","invariants":[]}`), []string{"unsupported version 2"}},
		{"version 0", goAJ(`{"version":0,"principal":"P","invariants":[]}`), []string{"unsupported version 0"}},
		{"version missing", goAJ(`{"principal":"P","invariants":[]}`), []string{"unsupported version undefined"}},
		{"principal missing", goAJ(`{"version":1,"invariants":[]}`), []string{"principal missing"}},
		{"principal empty", goAJ(`{"version":1,"principal":"","invariants":[]}`), []string{"principal missing"}},
		{"invariants missing", goAJ(`{"version":1,"principal":"P"}`), []string{"invariants not an array"}},
		{"both version and invariants wrong", goAJ(`{"version":3,"principal":"P"}`), []string{"unsupported version 3", "invariants not an array"}},
		{"duplicate id", goAJ(goAConstitution(never("a") + "," + never("a"))), []string{"a: duplicate id"}},
		{"distinct ids", goAJ(goAConstitution(never("a") + "," + never("b"))), []string{}},
		{"invariant problems come first", goAJ(goAConstitution(`{"id":"a","kind":"never"},` + never("a"))), []string{"a: when: not an object", "a: duplicate id"}},
		{"non-object invariant", goAJ(goAConstitution("5")), []string{"invariant not an object"}},
		{"id-less invariants do not collide", goAJ(goAConstitution(`{"kind":"never"},{"kind":"never"}`)), []string{"<no id>: missing id", "<no id>: missing id"}},
	}
	for _, r := range rows {
		if got := ValidateConstitution(r.c); !reflect.DeepEqual(got, r.want) {
			t.Errorf("%s: got %q want %q", r.name, got, r.want)
		}
	}
	mk := func(n int) any {
		invs := make([]any, n)
		for i := range invs {
			invs[i] = map[string]any{"id": "i" + pInt(i).String(), "kind": "never", "when": map[string]any{"verb": "pay"}}
		}
		return map[string]any{"version": goAN("1"), "principal": "P", "invariants": invs}
	}
	if got := ValidateConstitution(mk(256)); len(got) != 0 {
		t.Errorf("256 invariants: %q", got)
	}
	if got := ValidateConstitution(mk(257)); !reflect.DeepEqual(got, []string{"too many invariants"}) {
		t.Errorf("257 invariants: %q", got)
	}
}

func TestGoASignVerifyConstitution(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	c := goAJ(`{"version":1,"principal":"` + kp.Public + `","invariants":[{"id":"a","kind":"never","when":{"verb":"pay"}}]}`)
	sc, err := SignConstitution(c, seed)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ConstitutionID(c)
	if err != nil || sc["id"] != id || sc["sig"] == nil || sc["sig"] == "" {
		t.Fatalf("signed: %v id %q err %v", sc, id, err)
	}
	if id2, _ := ConstitutionID(sc); id2 != id {
		t.Error("the id covers the body without id and sig")
	}
	if v := VerifyConstitution(sc, ""); v["ok"] != true {
		t.Errorf("verify: %v", v)
	}
	if v := VerifyConstitution(sc, kp.Public); v["ok"] != true {
		t.Errorf("verify against the pinned principal: %v", v)
	}
	if v := VerifyConstitution(sc, "someone-else"); v["ok"] != false || v["reason"] != "principal mismatch" {
		t.Errorf("principal mismatch: %v", v)
	}
	// tampered content, tampered id, tampered or missing signature
	tamper := func(f func(m map[string]any)) any {
		m := copyObj(sc)
		f(m)
		return m
	}
	other := goAJ(`[{"id":"b","kind":"never","when":{"verb":"pay"}}]`)
	if v := VerifyConstitution(tamper(func(m map[string]any) { m["invariants"] = other }), ""); v["reason"] != "id does not match content" {
		t.Errorf("content: %v", v)
	}
	if v := VerifyConstitution(tamper(func(m map[string]any) { delete(m, "id") }), ""); v["reason"] != "id does not match content" {
		t.Errorf("no id: %v", v)
	}
	if v := VerifyConstitution(tamper(func(m map[string]any) { m["id"] = 5 }), ""); v["reason"] != "id does not match content" {
		t.Errorf("numeric id: %v", v)
	}
	if v := VerifyConstitution(tamper(func(m map[string]any) { delete(m, "sig") }), ""); v["reason"] != "bad signature" {
		t.Errorf("no sig: %v", v)
	}
	if v := VerifyConstitution(tamper(func(m map[string]any) { m["sig"] = "AAAA" }), ""); v["reason"] != "bad signature" {
		t.Errorf("bad sig: %v", v)
	}
	if v := VerifyConstitution(tamper(func(m map[string]any) { m["sig"] = 7 }), ""); v["reason"] != "bad signature" {
		t.Errorf("numeric sig: %v", v)
	}
	if v := VerifyConstitution(map[string]any{"version": goAN("2")}, ""); v["ok"] != false || v["reason"] != "unsupported version 2" {
		t.Errorf("malformed: %v", v)
	}
	// a key that did not sign it
	kp2, _ := NewKeyPair()
	forged := tamper(func(m map[string]any) { m["principal"] = kp2.Public })
	fid, _ := ConstitutionID(forged)
	forged.(map[string]any)["id"] = fid
	if v := VerifyConstitution(forged, ""); v["reason"] != "bad signature" {
		t.Errorf("wrong signer: %v", v)
	}

	if _, err := SignConstitution(goAJ(`{"version":2,"principal":"P","invariants":[]}`), seed); err == nil || err.Error() != "signConstitution: unsupported version 2" {
		t.Errorf("sign malformed: %v", err)
	}
	if _, err := SignConstitution(goAJ(`{"version":2,"principal":"","invariants":5}`), seed); err == nil || err.Error() != "signConstitution: unsupported version 2; principal missing; invariants not an array" {
		t.Errorf("problems are joined: %v", err)
	}
	if out, err := SignConstitution(c, []byte("short")); err == nil || out != nil {
		t.Errorf("a bad seed must not sign: %v %v", out, err)
	}
	if d, err := ConstitutionID("x"); d != "" || err != errMalformed {
		t.Errorf("ConstitutionID of a non-object: %q %v", d, err)
	}
}
