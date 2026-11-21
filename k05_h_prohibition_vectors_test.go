package pca

import (
	"strings"
	"testing"
)

// Replay of every row of prohibition-vectors.json (clauses, check, constitution, monitor, evidence) and contracts-vectors.json
// (validate, check, advance, verify, enforcer) against the reference.

func vecRows(t *testing.T, doc map[string]any, key string) []map[string]any {
	t.Helper()
	list, ok := doc[key].([]any)
	if !ok || len(list) < 5 {
		t.Fatalf("%s: table missing or too small", key)
	}
	out := make([]map[string]any, len(list))
	for i, x := range list {
		out[i] = x.(map[string]any)
	}
	return out
}

func vecSame(t *testing.T, name string, got, want any) {
	t.Helper()
	g, err1 := NormalizeJSON(got)
	w, err2 := NormalizeJSON(want)
	if err1 != nil || err2 != nil {
		t.Fatalf("%s: not JSON: %v %v", name, err1, err2)
	}
	gs, _ := Canonicalize(g)
	ws, _ := Canonicalize(w)
	if gs != ws {
		t.Errorf("%s:\n got  %s\n want %s", name, gs, ws)
	}
}

func strSlice(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(l))
	for i, x := range l {
		out[i], _ = x.(string)
	}
	return out
}

func optsOf(r map[string]any) (prec, permit []string) {
	o, _ := r["options"].(map[string]any)
	if p, has := o["precedence"]; has {
		prec = strSlice(p)
	}
	if p, has := o["permitSigners"]; has {
		permit = strSlice(p)
		if permit == nil {
			permit = []string{}
		}
	}
	return
}

func TestProhibitionVectors(t *testing.T) {
	pv := load(t, "prohibition-vectors.json")
	for _, key := range []string{"clauses", "check", "constitution", "monitor", "evidence"} {
		vecRows(t, pv, key)
	}
	for _, v := range vecRows(t, pv, "clauses") {
		name := "clauses/" + v["name"].(string)
		e := v["expect"].(map[string]any)
		want, _ := e["error"].(string)
		if got := ClausesError(v["clauses"]); got != want {
			t.Errorf("%s: error %q want %q", name, got, want)
		}
		prec, permit := optsOf(v)
		d := DecideClauses(v["clauses"], v["action"], prec, permit)
		w := d["witness"].(map[string]any)
		vecSame(t, name, map[string]any{"decision": d["decision"], "winner": w["winner"], "shadowed": w["shadowed"], "values": d["values"]},
			map[string]any{"decision": e["decision"], "winner": e["winner"], "shadowed": e["shadowed"], "values": e["values"]})
	}
	for _, v := range vecRows(t, pv, "check") {
		name := "check/" + v["name"].(string)
		prec, permit := optsOf(v)
		got := CheckForbidCertificate(v["certificate"], v["clauses"], v["action"], prec, permit)
		vecSame(t, name, got, v["expect"])
		if v["expect"].(map[string]any)["ok"] == true {
			c, err := Certify(v["clauses"], v["action"], prec, permit)
			if err != nil {
				t.Fatal(err)
			}
			vecSame(t, name+"/certify", c, v["certificate"])
		}
	}
	for _, v := range vecRows(t, pv, "constitution") {
		name := "constitution/" + v["name"].(string)
		e := v["expect"].(map[string]any)
		probs := ValidateConstitution(v["constitution"])
		pl := make([]any, len(probs))
		for i, p := range probs {
			pl[i] = p
		}
		vecSame(t, name+"/problems", pl, e["problems"])
		vecSame(t, name, CheckProhibitions(v["action"], v["constitution"], v["state"]), e["result"])
	}
	for _, v := range vecRows(t, pv, "monitor") {
		name := "monitor/" + v["name"].(string)
		st := EmptyMonitorState(v["genesis_now"])
		for i, stepv := range v["steps"].([]any) {
			step := stepv.(map[string]any)
			cur := any(st)
			if now, has := step["now"]; has {
				tk := TickState(st, now)
				if tk["ok"] != true {
					vecSame(t, name, map[string]any{"allow": false, "decidedBy": "clock", "reason": tk["reason"]}, step["expect"])
					continue
				}
				cur = tk["state"]
			}
			r := CheckAndAdvance(true, step["action"], v["constitution"], cur, nil)
			if r["allow"] == true {
				st = r["next"].(map[string]any)
			} else {
				st = cur.(map[string]any)
			}
			vecSame(t, name+"/"+pInt(i).String(), map[string]any{"allow": r["allow"], "decidedBy": r["decidedBy"],
				"violated": r["prohibition"].(map[string]any)["violated"], "seq": r["next"].(map[string]any)["seq"]}, step["expect"])
		}
	}
	for _, v := range vecRows(t, pv, "evidence") {
		vecSame(t, "evidence/"+v["name"].(string), VerifySignedSafetyEvidence(v["signed"], v["expected"]), v["expect"])
	}
}

func TestContractVectors(t *testing.T) {
	cv := load(t, "contracts-vectors.json")
	for _, v := range vecRows(t, cv, "validate") {
		probs := ValidateContract(v["contract"])
		pl := make([]any, len(probs))
		for i, p := range probs {
			pl[i] = p
		}
		vecSame(t, "validate/"+v["name"].(string), pl, v["expect"].(map[string]any)["problems"])
	}
	for _, v := range vecRows(t, cv, "check") {
		vecSame(t, "check/"+v["name"].(string), CheckContract(v["action"], v["contract"], v["state"]), v["expect"])
	}
	for _, v := range vecRows(t, cv, "verify") {
		principal, _ := v["principal"].(string)
		vecSame(t, "verify/"+v["name"].(string), VerifyContract(v["contract"], principal), v["expect"])
	}
	for _, v := range vecRows(t, cv, "advance") {
		name := "advance/" + v["name"].(string)
		st := any(EmptyMonitorState(v["genesis_now"]))
		for i, stepv := range v["steps"].([]any) {
			step := stepv.(map[string]any)
			op, _ := step["options"].(map[string]any)
			o := map[string]any{}
			for _, k := range []string{"now", "expectedSeq"} {
				if x, has := op[k]; has {
					o[k] = x
				}
			}
			if op["stale_digest_of_genesis"] == true {
				d, err := StateDigest(EmptyMonitorState(v["genesis_now"]))
				if err != nil {
					t.Fatal(err)
				}
				o["expectedStateDigest"] = d
			}
			r := AdvanceContract(st, step["action"], v["contract"], o)
			if r["ok"] == true {
				st = r["next"]
			}
			next := r["next"].(map[string]any)
			deadlines, has := next["deadlines"]
			if !has {
				deadlines = map[string]any{}
			}
			latched := []any{}
			for _, k := range pSortedKeys(next["latched"].(map[string]any)) {
				latched = append(latched, k)
			}
			dg, err := StateDigest(next)
			if err != nil {
				t.Fatal(err)
			}
			vecSame(t, name+"/"+pInt(i).String(), map[string]any{"ok": r["ok"], "decidedBy": r["decidedBy"], "violated": r["violated"], "reasons": r["reasons"],
				"seq": next["seq"], "deadlines": deadlines, "latched": latched, "state_digest": dg}, step["expect"])
		}
	}
	enf := vecRows(t, cv, "enforcer")
	head, scenarios := enf[0], enf[1:]
	for _, v := range scenarios {
		name := "enforcer/" + v["name"].(string)
		kv := NewMemoryAtomicKV()
		wall := pNum(head["clock"])
		o := ContractEnforcerOptions{Now: func() float64 { return wall }}
		if op, _ := v["options"].(map[string]any); op["latchOnViolation"] == false {
			o.NoLatch = true
		}
		e, err := OpenContractEnforcer(kv, head["contract"], head["principal"].(string), o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc, has := v["stored_document"]; has {
			s, cerr := Canonicalize(doc)
			if cerr != nil {
				t.Fatal(cerr)
			}
			_ = kv.Update("contract/"+head["contract"].(map[string]any)["id"].(string), func([]byte) []byte { return []byte(s) })
		}
		for i, stv := range v["steps"].([]any) {
			st := stv.(map[string]any)
			var got any
			switch st["op"] {
			case "check":
				wall = pNum(head["clock"])
				if w, has := st["wall"]; has {
					wall = pNum(w)
				}
				permitted := true
				if p, has := st["permitted"]; has {
					permitted = p == true
				}
				got = e.Check(st["action"], permitted)
			case "peek":
				got = e.Peek(st["action"])
			case "state":
				r, serr := e.State()
				switch {
				case serr != nil:
					t.Fatalf("%s: %v", name, serr)
				case r == nil:
					got = nil
				default:
					sm := r["state"].(map[string]any)
					dg, _ := StateDigest(sm)
					got = map[string]any{"seq": sm["seq"], "now": sm["now"], "latched": r["latched"], "state_digest": dg}
				}
			default:
				got = map[string]any{"cleared": e.Reset(st["sig"])}
			}
			vecSame(t, name+"/"+pInt(i).String(), got, st["expect"])
		}
	}
}

func TestF3_ForbidAndContractsAuthorizeRefusals(t *testing.T) {
	refusal := contractRefusal(map[string]any{"allow": false, "reason": "violated", "violated": []any{"a", "b"}})
	if refusal == nil || refusal.Reason != "contract: violated (a,b)" || refusal.Status != 403 {
		t.Fatalf("contract refusal: %+v", refusal)
	}
	if contractRefusal(map[string]any{"allow": true}) != nil {
		t.Fatal("allow is no refusal")
	}
	op := Operation{Verb: "pay", Resource: "/r", Params: map[string]any{}}
	forbidIn := func(f *ForbidPolicy, cert any) AuthorizeInput {
		return AuthorizeInput{Forbid: f, ForbidCertificate: cert}
	}
	clauses := []any{
		map[string]any{"id": "ok", "kind": "permit", "when": map[string]any{"verb": "pay"}},
		map[string]any{"id": "no-big", "kind": "forbid", "when": map[string]any{"verb": "wire"}},
	}
	f := &ForbidPolicy{Clauses: func(Operation, map[string]any) any { return clauses }}
	if r := forbidRefusal(nil, forbidIn(f, nil), op); r != nil {
		t.Fatalf("allowed operation refused: %+v", r)
	}
	if r := forbidRefusal(nil, forbidIn(f, nil), Operation{Verb: "wire", Resource: "/r", Params: map[string]any{}}); r == nil ||
		r.Reason != "forbid: deny by forbid no-big" {
		t.Fatalf("forbid must win: %+v", r)
	}
	if r := forbidRefusal(nil, forbidIn(&ForbidPolicy{Clauses: f.Clauses, RequireCertificate: true}, nil), op); r == nil ||
		r.Reason != "forbid: the call carries no certificate (fail closed)" {
		t.Fatalf("certificate required: %+v", r)
	}
	cert, err := Certify(clauses, map[string]any{"action": map[string]any{"verb": "pay", "resource": "/r", "params": map[string]any{}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := forbidRefusal(nil, forbidIn(&ForbidPolicy{Clauses: f.Clauses, RequireCertificate: true}, cert), op); r != nil {
		t.Fatalf("matching certificate refused: %+v", r)
	}
	bad := copyObj(cert)
	bad["decision"] = "deny"
	if r := forbidRefusal(nil, forbidIn(&ForbidPolicy{Clauses: f.Clauses, RequireCertificate: true}, bad), op); r == nil ||
		!strings.HasPrefix(r.Reason, "forbid: certificate refused (") {
		t.Fatalf("tampered certificate: %+v", r)
	}
	panicking := &ForbidPolicy{Clauses: func(Operation, map[string]any) any { panic("x") }}
	if r := forbidRefusal(nil, forbidIn(panicking, nil), op); r == nil || r.Reason != "forbid: deny by malformed" {
		t.Fatalf("a failing clause source denies: %+v", r)
	}
}
