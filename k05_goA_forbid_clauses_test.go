package pca

import (
	"fmt"
	"strings"
	"testing"
)

func goAWhenHit() map[string]any  { return map[string]any{"verb": "read"} }
func goAWhenMiss() map[string]any { return map[string]any{"verb": "write"} }

// goAWhenUnknown matches in the veto reading (the field is missing) but never in the plain reading.
func goAWhenUnknown() map[string]any {
	return map[string]any{"verb": "read", "where": []any{map[string]any{"field": "subject.nope", "op": "eq", "value": "x"}}}
}

func goACl(id, kind, signer string, when map[string]any) map[string]any {
	c := map[string]any{"id": id, "kind": kind, "when": when}
	if signer != "" {
		c["signer"] = signer
	}
	return c
}

func goAClCtx() map[string]any {
	return map[string]any{"action": map[string]any{"verb": "read", "resource": "r"}}
}

func goASummary(res map[string]any) string {
	w := res["witness"].(map[string]any)
	win := w["winner"].(map[string]any)
	var vs []string
	for _, v := range res["values"].([]any) {
		m := v.(map[string]any)
		vs = append(vs, fmt.Sprintf("%v:%v:%v", m["id"], m["kind"], m["value"]))
	}
	return fmt.Sprintf("%v|%v|%v|%v|%s", res["decision"], win["kind"], win["id"], w["shadowed"], strings.Join(vs, ","))
}

func goAList(cs ...map[string]any) []any {
	out := make([]any, len(cs))
	for i, c := range cs {
		out[i] = c
	}
	return out
}

func TestGoADecideClauses(t *testing.T) {
	hit, miss, unk := goAWhenHit(), goAWhenMiss(), goAWhenUnknown()
	rows := []struct {
		name    string
		cl      []any
		prec    []string
		permits []string
		want    string
	}{
		{"forbid beats permit", goAList(goACl("f", "forbid", "", hit), goACl("p", "permit", "", hit)), nil, nil, "deny|forbid|f|[p]|f:forbid:true,p:permit:true"},
		{"unknown forbid still vetoes", goAList(goACl("f", "forbid", "", unk), goACl("p", "permit", "", hit)), nil, nil, "deny|forbid|f|[p]|f:forbid:unknown,p:permit:true"},
		{"missed forbid is false", goAList(goACl("f", "forbid", "", miss), goACl("p", "permit", "", hit)), nil, nil, "allow|permit|p|[]|f:forbid:false,p:permit:true"},
		{"permit uses the plain reading", goAList(goACl("p", "permit", "", unk)), nil, nil, "deny|none|<nil>|[]|p:permit:false"},
		{"no permit denies, naming escalates as shadowed", goAList(goACl("e", "escalate", "", hit)), nil, nil, "deny|none|<nil>|[e]|e:escalate:true"},
		{"single escalate", goAList(goACl("p", "permit", "", hit), goACl("e", "escalate", "", hit)), nil, nil, "escalate|escalate|e|[p]|p:permit:true,e:escalate:true"},
		{"first escalate wins", goAList(goACl("p", "permit", "", hit), goACl("e1", "escalate", "", hit), goACl("e2", "escalate", "", hit)), nil, nil, "escalate|escalate|e1|[p e2]|p:permit:true,e1:escalate:true,e2:escalate:true"},
		{"allow lists other permits", goAList(goACl("p1", "permit", "", hit), goACl("p2", "permit", "", hit)), nil, nil, "allow|permit|p1|[p2]|p1:permit:true,p2:permit:true"},
		{"empty list denies", goAList(), nil, nil, "deny|none|<nil>|[]|"},
		{"permit signer listed", goAList(goACl("p", "permit", "a", hit), goACl("q", "permit", "b", hit)), nil, []string{"a"}, "allow|permit|p|[]|p:permit:true,q:permit:false"},
		{"empty permit signers drop every permit", goAList(goACl("p", "permit", "a", hit)), nil, []string{}, "deny|none|<nil>|[]|p:permit:false"},
		{"unsigned permit is dropped even if empty signer listed", goAList(goACl("p", "permit", "", hit)), nil, []string{""}, "deny|none|<nil>|[]|p:permit:false"},
		{"signer not listed", goAList(goACl("p", "permit", "x", hit)), nil, []string{"y"}, "deny|none|<nil>|[]|p:permit:false"},
		{"forbid and escalate stay active under permit signers", goAList(goACl("f", "forbid", "x", hit)), nil, []string{"y"}, "deny|forbid|f|[]|f:forbid:true"},
		{"escalate stays active under permit signers", goAList(goACl("p", "permit", "a", hit), goACl("e", "escalate", "x", hit)), nil, []string{"a"}, "escalate|escalate|e|[p]|p:permit:true,e:escalate:true"},
		{"nil permit signers keep every permit", goAList(goACl("p", "permit", "x", hit)), nil, nil, "allow|permit|p|[]|p:permit:true"},
		{"more authoritative signer wins", goAList(goACl("a", "forbid", "lo", hit), goACl("b", "forbid", "hi", hit)), []string{"hi", "lo"}, nil, "deny|forbid|b|[a]|a:forbid:true,b:forbid:true"},
		{"more authoritative signer wins, other order", goAList(goACl("b", "forbid", "hi", hit), goACl("a", "forbid", "lo", hit)), []string{"hi", "lo"}, nil, "deny|forbid|b|[a]|b:forbid:true,a:forbid:true"},
		{"unlisted signer ranks last", goAList(goACl("a", "forbid", "zz", hit), goACl("b", "forbid", "lo", hit)), []string{"lo"}, nil, "deny|forbid|b|[a]|a:forbid:true,b:forbid:true"},
		{"unsigned ranks last, not at the empty signer", goAList(goACl("a", "forbid", "", hit), goACl("b", "forbid", "x", hit)), []string{"", "x"}, nil, "deny|forbid|b|[a]|a:forbid:true,b:forbid:true"},
		{"equal ranks tie by id", goAList(goACl("b", "forbid", "", hit), goACl("a", "forbid", "", hit)), nil, nil, "deny|forbid|a|[b]|b:forbid:true,a:forbid:true"},
		{"equal ranks tie by id, other order", goAList(goACl("a", "forbid", "", hit), goACl("b", "forbid", "", hit)), nil, nil, "deny|forbid|a|[b]|a:forbid:true,b:forbid:true"},
	}
	for _, r := range rows {
		if got := goASummary(DecideClauses(r.cl, goAClCtx(), r.prec, r.permits)); got != r.want {
			t.Errorf("%s:\n got  %s\n want %s", r.name, got, r.want)
		}
	}
}

func TestGoADecideClausesMalformed(t *testing.T) {
	const want = "deny|malformed|<nil>|[]|"
	cl := goAList(goACl("p", "permit", "", goAWhenHit()), goACl("f", "forbid", "", goAWhenHit()))
	for name, ctx := range map[string]any{
		"verb not a string":     map[string]any{"action": map[string]any{"verb": 1, "resource": "r"}},
		"resource not a string": map[string]any{"action": map[string]any{"verb": "read", "resource": 1}},
		"no resource":           map[string]any{"action": map[string]any{"verb": "read"}},
		"no verb":               map[string]any{"action": map[string]any{"resource": "r"}},
		"no action":             map[string]any{},
	} {
		if got := goASummary(DecideClauses(cl, ctx, nil, nil)); got != want {
			t.Errorf("%s: got %s", name, got)
		}
	}
	if got := goASummary(DecideClauses("nope", goAClCtx(), nil, nil)); got != want {
		t.Errorf("clauses not an array: got %s", got)
	}
	if got := goASummary(DecideClauses(goAList(goACl("p", "permit", "", goAWhenHit()), goACl("p", "permit", "", goAWhenHit())), goAClCtx(), nil, nil)); got != want {
		t.Errorf("duplicate ids: got %s", got)
	}
}

func TestGoACertifyAndCheck(t *testing.T) {
	cl := goAList(goACl("f", "forbid", "", goAWhenMiss()), goACl("p", "permit", "s", goAWhenHit()))
	cert, err := Certify(cl, goAClCtx(), []string{"s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows := cert["clauses"].([]any)
	if r := rows[0].(map[string]any); len(r) != 3 || r["id"] != "f" || r["kind"] != "forbid" || r["value"] != "false" {
		t.Errorf("unsigned row must carry no signer: %v", r)
	}
	if r := rows[1].(map[string]any); len(r) != 4 || r["signer"] != "s" || r["value"] != "true" {
		t.Errorf("signed row: %v", r)
	}
	if cert["decision"] != "allow" || cert["kind"] != "forbid-wins" {
		t.Errorf("certificate: %v", cert)
	}
	if res := CheckForbidCertificate(cert, cl, goAClCtx(), []string{"s"}, nil); res["ok"] != true {
		t.Errorf("a fresh certificate must check: %v", res)
	}
	bad := map[string]any{}
	for k, v := range cert {
		bad[k] = v
	}
	bad["action"] = "AAAA"
	if res := CheckForbidCertificate(bad, cl, goAClCtx(), []string{"s"}, nil); res["ok"] != false || res["reason"] != "certificate does not match the recomputed decision" {
		t.Errorf("tampered action hash: %v", res)
	}
	if res := CheckForbidCertificate(cert, "nope", goAClCtx(), nil, nil); res["ok"] != false || res["reason"] != "malformed clauses" {
		t.Errorf("malformed clauses: %v", res)
	}
	bad2 := map[string]any{}
	for k, v := range cert {
		bad2[k] = v
	}
	bad2["decision"] = "deny"
	if res := CheckForbidCertificate(bad2, cl, goAClCtx(), []string{"s"}, nil); res["ok"] != false || res["reason"] != "certificate table does not entail its decision" {
		t.Errorf("inconsistent table: %v", res)
	}
}
