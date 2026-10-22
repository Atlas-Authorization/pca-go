package pca

// Mutation-kill tests for the Intent Layer v2 verifier rules (intent_v2.go and the files it calls): every boundary is
// pinned on both sides and the check order is pinned (first failure inside a check; checks 1-4 independent; the W-B
// unit ends at its first failure; a rule-17 question fails `provenance`). Fixture: intent_v2_fixture_test.go.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMutV2Allow(t *testing.T) {
	f := newV2Fx(t)
	expectV2(t, "g0", f.verify(), v2Base)
}

func TestMutV2BackCompatAndPolicies(t *testing.T) {
	f := newV2Fx(t)
	delete(f.p, "intent_session")
	f.resign()
	v := f.verify()
	if _, has := v.Checks["schema"]; has {
		t.Fatalf("no member, no policy: no v2 check (%v)", v.Checks)
	}
	if v.Checks["intent"] {
		t.Fatal("the v1 goal does not open a v2 grant")
	}
	// session.require without the member: intent_session reported and failed
	f.ctx["policy"] = map[string]any{"session": map[string]any{"require": true}}
	v = f.verify()
	if ok, has := v.Checks["intent_session"]; !has || ok {
		t.Fatalf("require: %v", v.Checks)
	}
	if _, has := v.Checks["schema"]; has {
		t.Fatal("require does not run schema")
	}
	// closed world without the member: schema runs against the first schema
	f.ctx["policy"] = map[string]any{"schema": map[string]any{"closed_world": true}}
	v = f.verify()
	if ok, has := v.Checks["schema"]; !has || !ok {
		t.Fatalf("closed world: %v (%s)", v.Checks, v.Reason)
	}
	if _, has := v.Checks["intent_session"]; has {
		t.Fatal("closed world does not run intent_session")
	}
	// false flags: inactive
	f.ctx["policy"] = map[string]any{"schema": map[string]any{"closed_world": false}, "session": map[string]any{"require": false}}
	v = f.verify()
	if _, has := v.Checks["schema"]; has {
		t.Fatal("closed_world false is inactive")
	}
	if _, has := v.Checks["intent_session"]; has {
		t.Fatal("require false is inactive")
	}
	// the policy is CLOSED and TYPED: a non-boolean / null flag, a bad age or an unknown member is a malformed context
	// (schema and intent_session fail even without intent_session)
	for name, pol := range map[string]any{
		"flags-1":         map[string]any{"schema": map[string]any{"closed_world": json.Number("1")}},
		"flags-string":    map[string]any{"session": map[string]any{"require": "true"}},
		"require-null":    map[string]any{"session": map[string]any{"require": nil}},
		"closed-null":     map[string]any{"schema": map[string]any{"closed_world": nil}},
		"age-null":        map[string]any{"session": map[string]any{"max_revocation_age_s": nil}},
		"age-negative":    map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(-1)}},
		"age-fraction":    map[string]any{"session": map[string]any{"max_revocation_age_s": json.Number("1.5")}},
		"age-string":      map[string]any{"session": map[string]any{"max_revocation_age_s": "60"}},
		"policy-unknown":  map[string]any{"layers": map[string]any{}},
		"session-unknown": map[string]any{"session": map[string]any{"required": true}},
		"schema-unknown":  map[string]any{"schema": map[string]any{"closed": true}},
	} {
		f.ctx["policy"] = pol
		expectCtxFail(t, name, f.verify(), false)
	}
	// age 0 and 2^53-1 are well typed
	for _, age := range []json.Number{jnum(0), jnum(9_007_199_254_740_991)} {
		f.ctx["policy"] = map[string]any{"session": map[string]any{"max_revocation_age_s": age}}
		if _, has := f.verify().Checks["schema"]; has {
			t.Fatalf("age %s: no check reported without the member", age)
		}
	}
	// a null or non-object policy / policy.session / policy.schema is a malformed context: schema and intent_session
	// are REPORTED and FAILED (accumulators too when the PCActn carries intent_session)
	for name, pol := range map[string]any{
		"members-null":   map[string]any{"schema": nil, "session": nil},
		"members-string": map[string]any{"schema": "x", "session": "x"},
		"policy-null":    nil,
		"policy-array":   []any{},
	} {
		f.ctx["policy"] = pol
		v = f.verify()
		for _, c := range []string{"schema", "intent_session"} {
			if ok, has := v.Checks[c]; !has || ok {
				t.Fatalf("%s: %s must be reported and failed: %v", name, c, v.Checks)
			}
		}
	}
}

// expectCtxFail: a malformed verifier context fails closed with every v2 check that could be reported (schema,
// intent_session, and accumulators when the PCActn carries intent_session); layers and W-B are not reported.
func expectCtxFail(t *testing.T, name string, v Verdict, present bool) {
	t.Helper()
	fails := []string{"schema", "intent_session"}
	if present {
		fails = append(fails, "accumulators")
	} else {
		// without the member the v1 goal does not open the fixture's v2 session grant, so intent fails first (the
		// reference's back-compat test); the malformed context still fails schema and intent_session
		fails = append([]string{"intent"}, fails...)
	}
	expectV2(t, name, v, nil, fails...)
	if present && !strings.Contains(v.Reason, "malformed v2 context") {
		t.Fatalf("%s: reason %q", name, v.Reason)
	}
}

// NULL vs ABSENT (README "strict values, absent vs null"): an absent optional member is empty / default; a member present
// with JSON null (or of the wrong JSON type) is malformed. A malformed TOP-LEVEL member fails every reportable v2
// check; a malformed member below it fails the check that reads it.
func TestMutV2NullVsAbsent(t *testing.T) {
	top := map[string]func(f *v2fx){
		"params-null":            func(f *v2fx) { f.ctx["params"] = nil },
		"params-array":           func(f *v2fx) { f.ctx["params"] = []any{} },
		"schema-null":            func(f *v2fx) { f.ctx["schema"] = nil },
		"session-null":           func(f *v2fx) { f.ctx["session"] = nil },
		"acc-null":               func(f *v2fx) { f.ctx["acc"] = nil },
		"acc-array":              func(f *v2fx) { f.ctx["acc"] = []any{} },
		"policy-null":            func(f *v2fx) { f.ctx["policy"] = nil },
		"policy.session-null":    func(f *v2fx) { f.ctx["policy"] = map[string]any{"session": nil} },
		"policy.schema-string":   func(f *v2fx) { f.ctx["policy"] = map[string]any{"schema": "x"} },
		"wb-null":                func(f *v2fx) { f.ctx["wb"] = nil },
		"wb-string":              func(f *v2fx) { f.ctx["wb"] = "x" },
		"wb.artifacts-null":      func(f *v2fx) { f.ctx["wb"] = map[string]any{"artifacts": nil} },
		"wb.artifacts-array":     func(f *v2fx) { f.ctx["wb"] = map[string]any{"artifacts": []any{}} },
		"wb.artifacts.facts":     func(f *v2fx) { f.ctx["wb"] = map[string]any{"artifacts": map[string]any{"facts": nil}} },
		"wb.artifacts.labels":    func(f *v2fx) { f.ctx["wb"] = map[string]any{"artifacts": map[string]any{"labels": "x"}} },
		"wb.artifacts.verdicts":  func(f *v2fx) { f.ctx["wb"] = map[string]any{"artifacts": map[string]any{"verdicts": map[string]any{}}} },
		"wb.artifacts.offer_set": func(f *v2fx) { f.ctx["wb"] = map[string]any{"artifacts": map[string]any{"offer_set": nil}} },
		"wb.policy-null":         func(f *v2fx) { f.ctx["wb"] = map[string]any{"policy": nil} },
		"wb.policy-false":        func(f *v2fx) { f.ctx["wb"] = map[string]any{"policy": false} },
		"wb.policy.world":        func(f *v2fx) { f.ctx["wb"] = map[string]any{"policy": map[string]any{"world": nil}} },
		"wb.policy.provenance":   func(f *v2fx) { f.ctx["wb"] = map[string]any{"policy": map[string]any{"provenance": []any{}}} },
		"wb.policy.classifiers":  func(f *v2fx) { f.ctx["wb"] = map[string]any{"policy": map[string]any{"classifiers": nil}} },
		"wb.policy.classifiers-o": func(f *v2fx) {
			f.ctx["wb"] = map[string]any{"policy": map[string]any{"classifiers": map[string]any{"length": jnum(1)}}}
		},
	}
	for name, mut := range top {
		f := newV2Fx(t)
		mut(f)
		expectCtxFail(t, name, f.verify(), true)
	}
	// without intent_session only schema and intent_session are reported
	f := newV2Fx(t)
	delete(f.p, "intent_session")
	f.resign()
	f.ctx["params"] = nil
	expectCtxFail(t, "params-null-no-member", f.verify(), false)

	// below the top level: the check that reads the member fails
	cases := []struct {
		name  string
		mut   func(f *v2fx)
		fails []string
	}{
		{"session.grants-null", func(f *v2fx) { f.ctx["session"].(map[string]any)["grants"] = nil }, []string{"intent_session"}},
		{"session.grants-object", func(f *v2fx) { f.ctx["session"].(map[string]any)["grants"] = map[string]any{} }, []string{"intent_session"}},
		{"session.revocation-null", func(f *v2fx) { f.ctx["session"].(map[string]any)["revocation"] = nil }, []string{"intent_session"}},
		{"session.root-null", func(f *v2fx) { f.ctx["session"].(map[string]any)["root"] = nil }, []string{"intent_session", "accumulators"}},
		{"schema.docs-null", func(f *v2fx) { f.ctx["schema"].(map[string]any)["docs"] = nil }, []string{"schema", "accumulators"}},
		{"schema.keys-null", func(f *v2fx) { f.ctx["schema"].(map[string]any)["keys"] = nil }, []string{"schema", "accumulators"}},
		{"schema.keys-absent", func(f *v2fx) { delete(f.ctx["schema"].(map[string]any), "keys") }, []string{"schema", "accumulators"}},
		{"acc.state-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["state"] = nil }, []string{"accumulators"}},
		{"acc.state-array", func(f *v2fx) { f.ctx["acc"].(map[string]any)["state"] = []any{} }, []string{"accumulators"}},
		{"acc.monitors-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["monitors"] = nil }, []string{"accumulators"}},
		{"acc.monitors-string", func(f *v2fx) { f.ctx["acc"].(map[string]any)["monitors"] = "x" }, []string{"accumulators"}},
		{"acc.receipts-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["receipts"] = nil }, []string{"accumulators"}},
		{"acc.receipts-object", func(f *v2fx) { f.ctx["acc"].(map[string]any)["receipts"] = map[string]any{} }, []string{"accumulators"}},
		{"acc.last_seq-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["last_seq"] = nil }, []string{"accumulators"}},
		{"acc.last_seq-array", func(f *v2fx) { f.ctx["acc"].(map[string]any)["last_seq"] = []any{} }, []string{"accumulators"}},
		{"acc.last_seq-value-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["last_seq"] = map[string]any{"x": nil} }, []string{"accumulators"}},
		{"acc.last_seq-value-string", func(f *v2fx) { f.ctx["acc"].(map[string]any)["last_seq"] = map[string]any{"x": "1"} }, []string{"accumulators"}},
		{"acc.sequencer_keys-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["sequencer_keys"] = nil }, []string{"accumulators"}},
		{"acc.sequencer_keys-string", func(f *v2fx) { f.ctx["acc"].(map[string]any)["sequencer_keys"] = "ab" }, []string{"accumulators"}},
		{"acc.state.trip_spend-null", func(f *v2fx) { f.ctx["acc"].(map[string]any)["state"] = map[string]any{"trip_spend": nil} }, []string{"accumulators"}},
		{"acc.state.trip_spend-string", func(f *v2fx) {
			f.ctx["acc"].(map[string]any)["state"] = map[string]any{"trip_spend": map[string]any{"sum": "0"}}
		}, []string{"accumulators"}},
	}
	for _, c := range cases {
		f := newV2Fx(t)
		c.mut(f)
		expectV2(t, c.name, f.verify(), minus(v2Base, c.fails...), c.fails...)
	}
	// absent containers are empty
	f = newV2Fx(t)
	f.ctx["acc"].(map[string]any)["receipts"] = []any{}
	f.ctx["acc"].(map[string]any)["sequencer_keys"] = []any{}
	f.ctx["acc"].(map[string]any)["last_seq"] = map[string]any{}
	f.ctx["session"].(map[string]any)["grants"] = []any{}
	f.ctx["wb"] = map[string]any{"artifacts": map[string]any{}, "policy": map[string]any{}}
	expectV2(t, "empty containers", f.verify(), v2Base)
	f = newV2Fx(t)
	delete(f.ctx["session"].(map[string]any), "grants")
	delete(f.ctx["acc"].(map[string]any), "monitors")
	expectV2(t, "absent grants / monitors", f.verify(), v2Base)
	// own reads: an inherited or prototype-named key is just absent / ordinary data
	f = newV2Fx(t)
	f.ctx["acc"].(map[string]any)["state"] = map[string]any{"constructor": map[string]any{"sum": jnum(0)}}
	expectV2(t, "state-proto-name", f.verify(), minus(v2Base, "accumulators"), "accumulators")
}

// Rules 16-18 inputs: every optional member null fails; absent is empty / default.
func TestMutV2WBNullVsAbsent(t *testing.T) {
	ks := []fxKey{newKey(t)}
	world := func(mut func(in map[string]any)) any {
		in := worldInput(t, ks, nil, map[string]any{})
		mut(in)
		return worldP(normalizeJSON(in))["ok"]
	}
	if world(func(map[string]any) {}) != true {
		t.Fatal("empty world")
	}
	for name, mut := range map[string]func(in map[string]any){
		"committed":           func(in map[string]any) { in["committed"] = nil },
		"committed.facts":     func(in map[string]any) { in["committed"] = map[string]any{"facts": nil} },
		"committed.offer_set": func(in map[string]any) { in["committed"] = map[string]any{"offer_set": nil} },
		"facts":               func(in map[string]any) { in["facts"] = nil },
		"policy":              func(in map[string]any) { in["policy"] = nil },
		"worlds":              func(in map[string]any) { in["policy"] = map[string]any{"worlds": nil} },
		"relational":          func(in map[string]any) { in["policy"] = map[string]any{"relational": nil} },
		"skew_ms":             func(in map[string]any) { in["policy"] = map[string]any{"skew_ms": nil} },
		"offers":              func(in map[string]any) { in["policy"] = map[string]any{"offers": nil} },
		"action":              func(in map[string]any) { in["action"] = nil },
		"action.params":       func(in map[string]any) { in["action"].(map[string]any)["params"] = nil },
	} {
		if world(mut) != false {
			t.Fatalf("world %s null must fail", name)
		}
	}
	for name, mut := range map[string]func(in map[string]any){
		"committed": func(in map[string]any) { delete(in, "committed") },
		"facts":     func(in map[string]any) { delete(in, "facts") },
		"policy":    func(in map[string]any) { delete(in, "policy") },
		"params":    func(in map[string]any) { delete(in["action"].(map[string]any), "params") },
	} {
		if world(mut) != true {
			t.Fatalf("world %s absent must pass", name)
		}
	}
	prov := func(mut func(in, pol map[string]any)) any {
		pol := map[string]any{"params": map[string]any{}}
		in := map[string]any{"aud": v2Aud, "session": dg("session"), "action": map[string]any{"params": map[string]any{"a": "x"}},
			"prov": map[string]any{}, "committed_labels": []any{}, "labels": []any{}, "policy": pol}
		mut(in, pol)
		return provP(normalizeJSON(in))["outcome"]
	}
	if prov(func(_, _ map[string]any) {}) != "pass" {
		t.Fatal("empty provenance")
	}
	for name, mut := range map[string]func(in, pol map[string]any){
		"prov":             func(in, _ map[string]any) { in["prov"] = nil },
		"committed_labels": func(in, _ map[string]any) { in["committed_labels"] = nil },
		"labels":           func(in, _ map[string]any) { in["labels"] = nil },
		"action.params":    func(in, _ map[string]any) { in["action"] = map[string]any{"params": nil} },
		"action":           func(in, _ map[string]any) { in["action"] = nil },
		"policy":           func(in, _ map[string]any) { in["policy"] = nil },
		"params":           func(_, pol map[string]any) { pol["params"] = nil },
		"registry":         func(_, pol map[string]any) { pol["registry"] = nil },
		"label_keys":       func(_, pol map[string]any) { pol["label_keys"] = nil },
		"critical_max":     func(_, pol map[string]any) { pol["critical_max"] = nil },
		"material_tainted": func(_, pol map[string]any) { pol["material_tainted"] = nil },
		"critical_tainted": func(_, pol map[string]any) { pol["critical_tainted"] = nil },
		"flows":            func(_, pol map[string]any) { pol["flows"] = nil },
	} {
		if prov(mut) != "deny" {
			t.Fatalf("provenance %s null must deny", name)
		}
	}
	for name, mut := range map[string]func(in, pol map[string]any){
		"prov":             func(in, _ map[string]any) { delete(in, "prov") },
		"committed_labels": func(in, _ map[string]any) { delete(in, "committed_labels") },
		"labels":           func(in, _ map[string]any) { delete(in, "labels") },
	} {
		if prov(mut) != "pass" {
			t.Fatalf("provenance %s absent must pass", name)
		}
	}
	j := newKey(t)
	cls := func(mut func(in, c map[string]any)) any {
		c := map[string]any{"id": "tone", "param": "action.params.body", "labels": []any{"a"}, "keys": []any{j.id}, "k": jnum(1), "measurements": []any{"m"}}
		cd, _ := hashCanonicalV("x")
		v := signArt(t, j, classifierDomain, map[string]any{"v": jnum(1), "kind": "pca-intent-classification", "classifier": "tone", "session": dg("session"),
			"content_digest": cd, "label": "a", "measurement": "m", "judge": j.id})
		in := map[string]any{"session": dg("session"), "action": map[string]any{"params": map[string]any{"body": "x"}},
			"committed": []any{refOf(t, classifierRefDomain, "c", v)}, "verdicts": []any{v}, "policy": map[string]any{"classifiers": []any{c}}}
		mut(in, c)
		return clsP(normalizeJSON(in))["ok"]
	}
	if cls(func(_, _ map[string]any) {}) != true {
		t.Fatal("classifier base")
	}
	for name, mut := range map[string]func(in, c map[string]any){
		"committed":     func(in, _ map[string]any) { in["committed"] = nil },
		"verdicts":      func(in, _ map[string]any) { in["verdicts"] = nil },
		"measurements":  func(_, c map[string]any) { c["measurements"] = nil },
		"classifiers":   func(in, _ map[string]any) { in["policy"] = map[string]any{"classifiers": nil} },
		"action.params": func(in, _ map[string]any) { in["action"] = map[string]any{"params": nil} },
		"action":        func(in, _ map[string]any) { in["action"] = nil },
	} {
		if cls(mut) != false {
			t.Fatalf("classifier %s null must fail", name)
		}
	}
	if cls(func(_, c map[string]any) { delete(c, "measurements") }) != true {
		t.Fatal("measurements absent = any")
	}
}

// ---- rule 13 wire ------------------------------------------------------------------------------------------------

func TestMutV2SessionWire(t *testing.T) {
	ids := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"id": "a" + string(rune('A'+i%26)) + strings.Repeat("x", i/26), "post": jnum(0)}
		}
		return out
	}
	dgs := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = dg("d" + string(rune('a'+i)))
		}
		return out
	}
	prov := func(n, refs int, refLen int) map[string]any {
		m := map[string]any{}
		for i := 0; i < n; i++ {
			rs := make([]any, refs)
			for j := range rs {
				rs[j] = strings.Repeat("r", refLen)
			}
			m["action.params.p"+string(rune('a'+i%26))+strings.Repeat("z", i/26)] = rs
		}
		return m
	}
	accept := map[string]func(m map[string]any){
		"seq-2^31-1": func(m map[string]any) { m["seq"] = jnum(2_147_483_647) },
		"acc-16":     func(m map[string]any) { m["acc"] = ids(16) },
		"acc-id-64": func(m map[string]any) {
			m["acc"] = []any{map[string]any{"id": strings.Repeat("a", 64), "post": jnum(0)}}
		},
		"facts-16":     func(m map[string]any) { m["facts"] = dgs(16) },
		"classes-8":    func(m map[string]any) { m["classes"] = dgs(8) },
		"labels-16":    func(m map[string]any) { m["labels"] = dgs(16) },
		"prov-32":      func(m map[string]any) { m["prov"] = prov(32, 1, 1) },
		"prov-refs-8":  func(m map[string]any) { m["prov"] = prov(1, 8, 1) },
		"prov-ref-256": func(m map[string]any) { m["prov"] = prov(1, 1, 256) },
		"receipt": func(m map[string]any) {
			m["acc"] = []any{map[string]any{"id": "a", "post": jnum(0), "receipt": dg("r")}}
		},
		"offer-set": func(m map[string]any) { m["offer_set"] = dg("o") },
	}
	refuse := map[string]func(m map[string]any){
		"seq-2^31":    func(m map[string]any) { m["seq"] = jnum(2_147_483_648) },
		"seq-minus-1": func(m map[string]any) { m["seq"] = jnum(-1) },
		"acc-17":      func(m map[string]any) { m["acc"] = ids(17) },
		"acc-id-65": func(m map[string]any) {
			m["acc"] = []any{map[string]any{"id": strings.Repeat("a", 65), "post": jnum(0)}}
		},
		"acc-id-dash": func(m map[string]any) { m["acc"] = []any{map[string]any{"id": "a-b", "post": jnum(0)}} },
		"acc-dup": func(m map[string]any) {
			m["acc"] = []any{map[string]any{"id": "a", "post": jnum(0)}, map[string]any{"id": "a", "post": jnum(1)}}
		},
		"acc-post-neg": func(m map[string]any) { m["acc"] = []any{map[string]any{"id": "a", "post": jnum(-1)}} },
		"acc-extra":    func(m map[string]any) { m["acc"] = []any{map[string]any{"id": "a", "post": jnum(0), "x": "y"}} },
		"acc-receipt-31": func(m map[string]any) {
			m["acc"] = []any{map[string]any{"id": "a", "post": jnum(0), "receipt": b64.EncodeToString(make([]byte, 31))}}
		},
		"facts-17":       func(m map[string]any) { m["facts"] = dgs(17) },
		"facts-dup":      func(m map[string]any) { m["facts"] = []any{dg("x"), dg("x")} },
		"classes-9":      func(m map[string]any) { m["classes"] = dgs(9) },
		"labels-17":      func(m map[string]any) { m["labels"] = dgs(17) },
		"prov-33":        func(m map[string]any) { m["prov"] = prov(33, 1, 1) },
		"prov-refs-9":    func(m map[string]any) { m["prov"] = prov(1, 9, 1) },
		"prov-refs-0":    func(m map[string]any) { m["prov"] = prov(1, 0, 1) },
		"prov-ref-257":   func(m map[string]any) { m["prov"] = prov(1, 1, 257) },
		"prov-ref-empty": func(m map[string]any) { m["prov"] = prov(1, 1, 0) },
		"prov-bad-path":  func(m map[string]any) { m["prov"] = map[string]any{"env.x": []any{"r"}} },
		"prov-nested":    func(m map[string]any) { m["prov"] = map[string]any{"action.params.a.b": []any{"r"}} },
		"offer-set-31":   func(m map[string]any) { m["offer_set"] = b64.EncodeToString(make([]byte, 31)) },
		"unknown":        func(m map[string]any) { m["note"] = "x" },
		"no-schema":      func(m map[string]any) { delete(m, "schema") },
		"no-seq":         func(m map[string]any) { delete(m, "seq") },
		"root-33":        func(m map[string]any) { m["root"] = b64.EncodeToString(make([]byte, 33)) },
	}
	for name, mut := range accept {
		m := newV2Fx(t).is()
		mut(m)
		if e := validateIntentSessionWire(deep(t, m)); e != "" {
			t.Fatalf("%s: refused: %s", name, e)
		}
	}
	for name, mut := range refuse {
		m := newV2Fx(t).is()
		mut(m)
		if e := validateIntentSessionWire(deep(t, m)); e == "" {
			t.Fatalf("%s: accepted", name)
		}
	}
	for _, bad := range []any{nil, []any{}, "x", jnum(1)} {
		if validateIntentSessionWire(bad) == "" {
			t.Fatalf("%v accepted", bad)
		}
	}
	// end to end: a wire refusal is the terminal wire failure
	f := newV2Fx(t)
	f.is()["seq"] = jnum(2_147_483_648)
	f.resign()
	mustWire(t, "seq-over", f.verify())
}

// ---- rule 13 check ------------------------------------------------------------------------------------------------

func TestMutV2SessionRootBounds(t *testing.T) {
	// now < expires_at: equal fails (intent_session AND accumulators), +1 passes
	for _, c := range []struct {
		exp  int64
		pass bool
	}{{v2Now, false}, {v2Now + 1, true}} {
		f := newV2Fx(t)
		f.S["expires_at"] = jnum(c.exp)
		f.signRoot()
		f.rebind()
		if c.pass {
			expectV2(t, "expires+1", f.verify(), v2Base)
		} else {
			expectV2(t, "expires==now", f.verify(), []string{"schema"}, "intent_session", "accumulators")
		}
	}
	f := newV2Fx(t)
	delete(f.ctx["session"].(map[string]any), "root")
	expectV2(t, "root-missing", f.verify(), []string{"schema"}, "intent_session", "accumulators")
	// a root signed by a non-principal
	f = newV2Fx(t)
	f.signRootWith(newKey(t))
	f.rebind()
	expectV2(t, "root-foreign-signer", f.verify(), []string{"schema"}, "intent_session", "accumulators")
	// the root names another session
	f = newV2Fx(t)
	f.S["session"] = dg("other")
	f.signRoot()
	f.rebind()
	expectV2(t, "root-other-session", f.verify(), []string{"schema"}, "intent_session", "accumulators")
	// a tampered root (digest no longer the committed one)
	f = newV2Fx(t)
	f.ctx["session"].(map[string]any)["root"].(map[string]any)["question_uri"] = "https://other"
	expectV2(t, "root-tampered", f.verify(), []string{"schema"}, "intent_session", "accumulators")
}

func TestMutV2SessionBinding(t *testing.T) {
	f := newV2Fx(t)
	f.S["intent_ref"] = dg("other-ref")
	f.signRoot()
	f.rebind()
	expectV2(t, "ref", f.verify(), minus(v2Base, "intent_session"), "intent_session")

	f = newV2Fx(t)
	f.S["schema"] = map[string]any{"aud": "other.example", "digest": f.schemaD}
	f.signRoot()
	f.rebind()
	expectV2(t, "schema-aud", f.verify(), minus(v2Base, "intent_session"), "intent_session")

	f = newV2Fx(t)
	f.S["layers"] = map[string]any{"task": map[string]any{"map_digest": dg("map-other")}}
	f.signRoot()
	f.rebind()
	expectV2(t, "seq0-map", f.verify(), minus(v2Base, "intent_session"), "intent_session")

	// no intent: the member needs the binding (and wire allows intent_session alone)
	f = newV2Fx(t)
	delete(f.p, "intent")
	f.resign()
	v := f.verify()
	if v.Checks["intent_session"] || v.Allow {
		t.Fatalf("no intent: %v", v.Checks)
	}

	// an admitting root signed by a non-principal (an agent can never mint a grant)
	f = newV2Fx(t)
	f.grant = f.sessionGrant(f.agent, 0, "", f.mapD, f.salt)
	f.build()
	expectV2(t, "agent-grant", f.verify(), minus(v2Base, "intent_session"), "intent_session")

	// caveat seq differs from the PCActn seq
	f = newV2Fx(t)
	f.is()["seq"] = jnum(1)
	f.resign()
	f.ctx["session"].(map[string]any)["grants"] = []any{f.grant}
	v = f.verify()
	if v.Checks["intent_session"] {
		t.Fatal("seq mismatch must fail")
	}
}

func TestMutV2DeltaChain(t *testing.T) {
	f := newV2Fx(t)
	g0 := f.grant
	g0id := g0["id"].(string)
	f.grant = f.sessionGrant(f.principal, 1, g0id, f.mapD, f.salt)
	f.build()
	f.is()["seq"] = jnum(1)
	f.resign()
	f.ctx["session"].(map[string]any)["grants"] = []any{g0}
	expectV2(t, "d1", f.verify(), v2Base)

	f.ctx["session"].(map[string]any)["grants"] = []any{}
	expectV2(t, "d1-unheld", f.verify(), minus(v2Base, "intent_session"), "intent_session")

	f.ctx["session"].(map[string]any)["grants"] = []any{g0}
	f.grant = f.sessionGrant(f.principal, 1, dg("not-g0"), f.mapD, f.salt)
	f.build()
	expectV2(t, "d1-broken-prev", f.verify(), minus(v2Base, "intent_session"), "intent_session")

	// a held grant at seq 0 signed by a non-principal
	f.grant = f.sessionGrant(f.principal, 1, g0id, f.mapD, f.salt)
	f.build()
	f.ctx["session"].(map[string]any)["grants"] = []any{f.sessionGrant(f.agent, 0, "", f.mapD, f.salt)}
	v := f.verify()
	if v.Checks["intent_session"] {
		t.Fatal("a held grant by a non-principal must fail")
	}
}

func TestMutV2Revocation(t *testing.T) {
	setup := func(maxAge int64) *v2fx {
		f := newV2Fx(t)
		f.withRevocation(maxAge)
		return f
	}
	withEv := func(f *v2fx, ev map[string]any, policy map[string]any) Verdict {
		f.ctx["session"].(map[string]any)["revocation"] = ev
		if policy != nil {
			f.ctx["policy"] = policy
		}
		return f.verify()
	}
	ok := func(name string, v Verdict) { t.Helper(); expectV2(t, name, v, v2Base) }
	bad := func(name string, v Verdict) {
		t.Helper()
		expectV2(t, name, v, minus(v2Base, "intent_session"), "intent_session")
	}
	other := func() *revSet { return newRevSet(t, "pca-intent:session:zz") }
	f := setup(60)
	A := f.revAuth
	ok("fresh", withEv(f, f.evidence(A, other(), v2Now-30_000, v2Now+300_000), nil))
	ok("age==max", withEv(f, f.evidence(A, other(), v2Now-60_000, v2Now+300_000), nil))
	bad("age==max+1", withEv(f, f.evidence(A, other(), v2Now-60_001, v2Now+300_000), nil))
	ok("not_after==now", withEv(f, f.evidence(A, other(), v2Now-1_000, v2Now), nil))
	bad("not_after==now-1", withEv(f, f.evidence(A, other(), v2Now-1_000, v2Now-1), nil))
	ok("issued==now+60000", withEv(f, f.evidence(A, other(), v2Now+60_000, v2Now+300_000), nil))
	bad("issued==now+60001", withEv(f, f.evidence(A, other(), v2Now+60_001, v2Now+300_000), nil))
	ok("empty-set", withEv(f, f.evidence(A, newRevSet(t), v2Now-1_000, v2Now+300_000), nil))
	bad("absent", withEv(f, nil, nil))
	bad("principal-signed", withEv(f, f.evidence(f.principal, other(), v2Now-1_000, v2Now+300_000), nil))
	bad("foreign-signer", withEv(f, f.evidence(newKey(t), other(), v2Now-1_000, v2Now+300_000), nil))
	for i, id := range f.revIDs() {
		bad("revoked-"+string(rune('0'+i)), withEv(f, f.evidence(A, newRevSet(t, id, "pca-intent:session:zz"), v2Now-1_000, v2Now+300_000), nil))
	}
	// the revoked list must be exactly the signed set
	for name, mut := range map[string]func(ev map[string]any){
		"list-missing":   func(ev map[string]any) { delete(ev, "revoked") },
		"list-null":      func(ev map[string]any) { ev["revoked"] = nil },
		"list-string":    func(ev map[string]any) { ev["revoked"] = "pca-intent:session:zz" },
		"list-number":    func(ev map[string]any) { ev["revoked"] = []any{jnum(1)} },
		"list-shorter":   func(ev map[string]any) { ev["revoked"] = []any{} },
		"list-other-id":  func(ev map[string]any) { ev["revoked"] = []any{"pca-intent:session:zy"} },
		"list-unsorted":  func(ev map[string]any) { ev["revoked"] = []any{"b", "a"} },
		"list-duplicate": func(ev map[string]any) { ev["revoked"] = []any{"a", "a"} },
		"evidence-extra": func(ev map[string]any) { ev["proofs"] = map[string]any{} },
	} {
		ev := f.evidence(A, other(), v2Now-1_000, v2Now+300_000)
		mut(ev)
		bad(name, withEv(f, ev, nil))
	}
	// epoch must equal set_size (re-signed so only that rule fails)
	ep := f.evidence(A, other(), v2Now-1_000, v2Now+300_000)
	body := withoutKeys(ep["epoch"].(map[string]any), "guardian", "sig")
	body["epoch"] = jnum(2)
	e2 := withoutKeys(body)
	e2["guardian"], e2["sig"] = A.id, signDomain(t, A, revEpochDomain, body)
	ep["epoch"] = e2
	bad("epoch!=set_size", withEv(f, ep, nil))

	// APPEND-ONLY against the tracked last epoch
	last := f.evidence(A, newRevSet(t, "a", "b"), v2Now-5_000, v2Now+300_000)
	track := func(ev map[string]any) Verdict {
		f.ctx["session"].(map[string]any)["revocation_last"] = last
		return withEv(f, ev, nil)
	}
	ok("superset", track(f.evidence(A, newRevSet(t, "a", "b", "c"), v2Now-1_000, v2Now+300_000)))
	ok("same-epoch-same-set", track(f.evidence(A, newRevSet(t, "a", "b"), v2Now-1_000, v2Now+300_000)))
	bad("rollback", track(f.evidence(A, newRevSet(t, "a"), v2Now-1_000, v2Now+300_000)))
	bad("drop", track(f.evidence(A, newRevSet(t, "a", "c", "d"), v2Now-1_000, v2Now+300_000)))
	bad("equivocation", track(f.evidence(A, newRevSet(t, "a", "z"), v2Now-1_000, v2Now+300_000)))
	last = map[string]any{"epoch": last["epoch"], "revoked": []any{"a"}}
	bad("tracked-last-malformed", track(f.evidence(A, newRevSet(t, "a", "b", "c"), v2Now-1_000, v2Now+300_000)))
	last = f.evidence(A, newRevSet(t, "a", "b"), v2Now-5_000, v2Now+300_000)
	last["note"] = "x"
	bad("tracked-last-extra-member", track(f.evidence(A, newRevSet(t, "a", "b", "c"), v2Now-1_000, v2Now+300_000)))
	delete(f.ctx["session"].(map[string]any), "revocation_last")
	f.ctx["session"].(map[string]any)["revocation_last"] = nil
	expectV2(t, "tracked-last-null", withEv(f, f.evidence(A, other(), v2Now-1_000, v2Now+300_000), nil), minus(v2Base, "intent_session"), "intent_session")
	delete(f.ctx["session"].(map[string]any), "revocation_last")

	// the stricter of S and policy applies
	f = setup(60)
	A = f.revAuth
	bad("policy-stricter", withEv(f, f.evidence(A, other(), v2Now-20_000, v2Now+300_000), map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(10)}}))
	ok("policy-at-bound", withEv(f, f.evidence(A, other(), v2Now-10_000, v2Now+300_000), map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(10)}}))
	// a malformed age is a malformed context (every reportable check fails), never only intent_session
	expectCtxFail(t, "policy-misconfigured", withEv(f, f.evidence(A, other(), v2Now-1_000, v2Now+300_000), map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(-1)}}), true)
	expectCtxFail(t, "policy-fraction", withEv(f, f.evidence(A, other(), v2Now-1_000, v2Now+300_000), map[string]any{"session": map[string]any{"max_revocation_age_s": json.Number("1.5")}}), true)
	// a policy bound without an authority in S fails closed
	g := newV2Fx(t)
	bad("policy-without-authority", withEv(g, g.evidence(g.revAuth, other(), v2Now-1_000, v2Now+300_000), map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(300)}}))
	// S: the authority is required and is not a principal
	for _, name := range []string{"key-absent", "key-principal", "pq_pk-null"} {
		h := newV2Fx(t)
		rev := map[string]any{"epoch_uri": "u", "max_age_s": jnum(60), "key": h.revAuth.id}
		switch name {
		case "key-absent":
			delete(rev, "key")
		case "key-principal":
			rev["key"] = h.principal.id
		case "pq_pk-null":
			rev["pq_pk"] = nil
		}
		h.S["revocation"] = rev
		h.signRoot()
		h.rebind()
		expectV2(t, "S-"+name, h.verify(), []string{"schema"}, "intent_session", "accumulators")
	}
}

// ---- rule 14 --------------------------------------------------------------------------------------------------

func TestMutV2Schema(t *testing.T) {
	run := func(name string, params map[string]any, pass bool) {
		t.Helper()
		f := newV2Fx(t)
		f.params = params
		f.build()
		f.ctx["params"] = params
		v := f.verify()
		if v.Checks["schema"] != pass {
			t.Fatalf("%s: schema = %v, want %v (%s)", name, v.Checks["schema"], pass, v.Reason)
		}
	}
	base := func(k string, x any) map[string]any {
		p := map[string]any{"offer_id": "OF-1", "total": jnum(38_900), "add_ons": []any{"none"}, "refundable": false}
		if x == nil {
			delete(p, k)
		} else {
			p[k] = x
		}
		return p
	}
	run("note-16-bytes", base("note", strings.Repeat("é", 8)), true)
	run("note-17-bytes", base("note", strings.Repeat("é", 8)+"a"), false)
	run("total-min", base("total", jnum(0)), true)
	run("total-below-min", base("total", jnum(-1)), false)
	run("total-max", base("total", jnum(5_000_000)), true)
	run("total-above-max", base("total", jnum(5_000_001)), false)
	run("total-fraction", base("total", json.Number("1.5")), false)
	run("set-3", base("add_ons", []any{"none", "tripshield", "seat_plus"}), true)
	run("set-dup", base("add_ons", []any{"none", "none"}), false)
	run("set-other", base("add_ons", []any{"bag"}), false)
	run("set-empty", base("add_ons", []any{}), true)
	run("bool-string", base("refundable", "false"), false)
	run("missing-required", base("offer_id", nil), false)
	run("undeclared", base("reseller", "x"), false)

	// conformance order: params_not_object, unknown_verb, undeclared (UTF-8 order) before missing, then declared paths
	doc := deep(t, newV2Fx(t).schema)
	for _, c := range []struct {
		verb   string
		params any
		code   string
		path   string
	}{
		{"air.book", []any{}, "params_not_object", ""},
		{"air.cancel", map[string]any{}, "unknown_verb", ""},
		{"air.book", map[string]any{"zz": jnum(1), "aa": jnum(1)}, "undeclared_param", "action.params.aa"},
		{"air.book", map[string]any{"offer_id": "x", "extra": jnum(1)}, "undeclared_param", "action.params.extra"},
		{"air.book", map[string]any{}, "missing_param", "action.params.add_ons"},
		{"air.book", map[string]any{"offer_id": jnum(1), "total": "x", "add_ons": []any{}, "refundable": true}, "bad_type", "action.params.offer_id"},
	} {
		got := conformAction(doc, c.verb, normalizeJSON(c.params))
		if got.OK || got.Code != c.code || got.Path != c.path {
			t.Fatalf("conform %v: got %+v, want %s %s", c.params, got, c.code, c.path)
		}
	}
	// dates: leap rules
	for d, ok := range map[string]bool{"2028-02-29": true, "2026-02-29": false, "1900-02-29": false, "2000-02-29": true, "2026-1-05": false, "0000-01-01": false, "2026-12-31": true, "2026-13-01": false} {
		if isCalendarDate(d) != ok {
			t.Fatalf("date %s", d)
		}
	}
	// the schema signature: forged key, alg mismatch, tamper
	f := newV2Fx(t)
	f.ctx["schema"].(map[string]any)["keys"] = []any{map[string]any{"kid": "k1", "alg": "ed25519", "pk": newKey(t).id}}
	expectV2(t, "forged", f.verify(), minus(v2Base, "schema"), "schema")
	f = newV2Fx(t)
	f.ctx["schema"].(map[string]any)["keys"] = []any{map[string]any{"kid": "k1", "alg": "ml-dsa-65", "pk": f.site.id}}
	expectV2(t, "alg-mismatch", f.verify(), minus(v2Base, "schema"), "schema")
	f = newV2Fx(t)
	f.ctx["schema"].(map[string]any)["keys"] = []any{map[string]any{"kid": "k2", "alg": "ed25519", "pk": f.site.id}}
	expectV2(t, "kid-unknown", f.verify(), minus(v2Base, "schema"), "schema")
	// schema check is independent: a schema failure leaves intent_session and accumulators passing
	f = newV2Fx(t)
	delete(f.ctx, "params")
	expectV2(t, "no-params", f.verify(), []string{"intent_session"}, "schema", "accumulators")
	// env.canon feeds the layers check
	f = newV2Fx(t)
	f.ctx["layers"] = map[string]any{"site": map[string]any{"predicates": []any{map[string]any{"verb": "air.book", "where": []any{
		map[string]any{"field": "env.canon.add_ons", "op": "eq", "value": `["none"]`},
		map[string]any{"field": "env.canon.refundable", "op": "eq", "value": "false"}}}}}}
	expectV2(t, "layers-canon", f.verify(), append(append([]string{}, v2Base...), "layers"))
}

// ---- layers (V5) ------------------------------------------------------------------------------------------------

func TestMutV2Layers(t *testing.T) {
	ceiling := func(max int64) map[string]any {
		return map[string]any{"predicates": []any{map[string]any{"verb": "air.book", "where": []any{map[string]any{"field": "action.params.total", "op": "lte", "value": jnum(max)}}}}}
	}
	withL := append(append([]string{}, v2Base...), "layers")
	for _, c := range []struct {
		name   string
		layers map[string]any
		pass   bool
	}{
		{"org-at-bound", map[string]any{"org": ceiling(38_900)}, true},
		{"org-below", map[string]any{"org": ceiling(38_899)}, false},
		{"site-below", map[string]any{"site": ceiling(38_899)}, false},
		{"std-below", map[string]any{"std": ceiling(38_899)}, false},
		{"empty-predicates", map[string]any{"site": map[string]any{"predicates": []any{}}}, false},
		{"other-verb", map[string]any{"org": map[string]any{"predicates": []any{map[string]any{"verb": "air.search"}}}}, false},
		{"wildcard", map[string]any{"org": map[string]any{"predicates": []any{map[string]any{"verb": "*", "resource": "skyair.example/*"}}}}, true},
	} {
		f := newV2Fx(t)
		f.ctx["layers"] = c.layers
		if c.pass {
			expectV2(t, c.name, f.verify(), withL)
		} else {
			expectV2(t, c.name, f.verify(), minus(withL, "layers"), "layers")
		}
	}
	// a malformed layers member is a malformed context (layers itself is then not reported)
	for name, l := range map[string]any{"null": nil, "string": "x", "ceiling-null": map[string]any{"org": nil},
		"no-predicates": map[string]any{"site": map[string]any{}}, "primitive-ceiling": map[string]any{"org": jnum(5)},
		"predicates-object": map[string]any{"org": map[string]any{"predicates": map[string]any{}}}, "unknown-ceiling": map[string]any{"task": ceiling(1)}} {
		f := newV2Fx(t)
		f.ctx["layers"] = l
		expectCtxFail(t, "layers-"+name, f.verify(), true)
	}
	// no member: layers not reported even when configured
	f := newV2Fx(t)
	f.ctx["layers"] = map[string]any{"org": ceiling(1)}
	delete(f.p, "intent_session")
	f.resign()
	if _, has := f.verify().Checks["layers"]; has {
		t.Fatal("layers needs the member")
	}
}

// ---- rule 15 ----------------------------------------------------------------------------------------------------

func TestMutV2AccumulatorsSiteLocal(t *testing.T) {
	bad := func(name string, f *v2fx) {
		t.Helper()
		expectV2(t, name, f.verify(), minus(v2Base, "accumulators"), "accumulators")
	}
	setPre := func(f *v2fx, pre any) { f.ctx["acc"].(map[string]any)["state"] = map[string]any{"trip_spend": pre} }
	// domain_max 500000: post 500000 passes, 500001 fails
	f := newV2Fx(t)
	setPre(f, map[string]any{"sum": jnum(461_100)})
	f.setClaim(500_000)
	expectV2(t, "at-domain-max", f.verify(), v2Base)
	f = newV2Fx(t)
	setPre(f, map[string]any{"sum": jnum(461_101)})
	f.setClaim(500_001)
	bad("over-domain-max", f)
	f = newV2Fx(t)
	f.setClaim(38_899)
	bad("claim-off-by-one", f)
	f = newV2Fx(t)
	f.is()["acc"] = []any{}
	f.resign()
	bad("claim-missing", f)
	f = newV2Fx(t)
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(38_900)}, map[string]any{"id": "nope", "post": jnum(0)}}
	f.resign()
	bad("claim-unknown", f)
	f = newV2Fx(t)
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(38_900), "receipt": dg("r")}}
	f.resign()
	bad("site-local-with-receipt", f)
	for name, pre := range map[string]any{"count-shape": map[string]any{"count": jnum(0)}, "two-keys": map[string]any{"sum": jnum(0), "x": jnum(0)},
		"negative": map[string]any{"sum": jnum(-1)}, "fraction": map[string]any{"sum": json.Number("0.5")}, "null": nil} {
		f = newV2Fx(t)
		setPre(f, pre)
		bad("pre-"+name, f)
	}
	f = newV2Fx(t)
	f.ctx["acc"].(map[string]any)["state"] = map[string]any{}
	bad("no-state", f)
	// overflow: pre 2^53-1 - 38899 + 38900 leaves the safe range
	f = newV2Fx(t)
	f.S["accumulators"].([]any)[0].(map[string]any)["domain_max"] = jnum(9_007_199_254_740_991)
	f.signRoot()
	f.rebind()
	setPre(f, map[string]any{"sum": jnum(9_007_199_254_740_991 - 38_899)})
	f.setClaim(9_007_199_254_740_991)
	bad("overflow", f)
	// the schema that drives accumulates_into must be the session schema
	f = newV2Fx(t)
	f.ctx["schema"].(map[string]any)["docs"] = []any{}
	expectV2(t, "no-schema", f.verify(), []string{"intent_session"}, "schema", "accumulators")
}

func TestMutV2Monitors(t *testing.T) {
	mon := func(kind string, within int64) map[string]any {
		m := map[string]any{"id": "m", "kind": kind, "p": map[string]any{"verb": "air.book"}}
		if kind == "requires_prior" || kind == "precedes" || kind == "responds_within" {
			m["q"] = map[string]any{"verb": "hotel.book"}
		}
		if within > 0 {
			m["within"] = jnum(within)
		}
		return m
	}
	for _, c := range []struct {
		kind   string
		within int64
		state  any
		ok     bool
	}{
		{"requires_prior", 0, "unmet", true}, {"precedes", 0, "met", true}, {"never", 0, "seen", true}, {"always", 0, "broken", true},
		{"responds_within", 3, "pending:3", true}, {"responds_within", 3, "pending:4", false}, {"responds_within", 3, "pending:0", false},
		{"responds_within", 64, "missed", true}, {"never", 0, "unmet", false}, {"always", 0, nil, false}, {"never", 0, jnum(1), false},
	} {
		f := newV2Fx(t)
		f.S["monitors"] = []any{mon(c.kind, c.within)}
		f.signRoot()
		f.rebind()
		mons := map[string]any{}
		if c.state != nil {
			mons["m"] = c.state
		}
		f.ctx["acc"].(map[string]any)["monitors"] = mons
		if c.ok {
			expectV2(t, c.kind, f.verify(), v2Base)
		} else {
			expectV2(t, c.kind, f.verify(), minus(v2Base, "accumulators"), "accumulators")
		}
	}
	// within bounds of the declaration (1..64)
	for w, ok := range map[int64]bool{1: true, 64: true, 65: false} {
		if (monitorDeclError(deep(t, mon("responds_within", w))) == "") != ok {
			t.Fatalf("within %d", w)
		}
	}
	if monitorDeclError(deep(t, map[string]any{"id": "m", "kind": "never", "p": map[string]any{"verb": "x"}, "q": map[string]any{"verb": "y"}})) == "" {
		t.Fatal("never takes no q")
	}
}

func TestMutV2AccumulatorsSequenced(t *testing.T) {
	ok := func(name string, f *v2fx) { t.Helper(); expectV2(t, name, f.verify(), v2Base) }
	bad := func(name string, f *v2fx) {
		t.Helper()
		expectV2(t, name, f.verify(), minus(v2Base, "accumulators"), "accumulators")
	}
	type tc struct {
		name    string
		kid     string
		nb      int64
		na      *int64
		issued  int64
		mutKeys func(f *v2fx, ks map[string]any) []any
		mutR    func(r map[string]any)
		last    any
		pass    bool
	}
	cases := []tc{
		{name: "current", kid: "s2", nb: v2Now - 1_000, pass: true},
		{name: "not_before==issued", kid: "s2", nb: v2Now, pass: true},
		{name: "not_before==issued+1", kid: "s2", nb: v2Now + 1, pass: false},
		{name: "not_after==issued", kid: "s2", nb: v2Now - 1_000, na: i64(v2Now), pass: true},
		{name: "not_after==issued-1 (retired)", kid: "s2", nb: v2Now - 100_000, na: i64(v2Now - 1), pass: false},
		{name: "issued==now+60000", kid: "s2", nb: 0, issued: v2Now + 60_000, pass: true},
		{name: "issued==now+60001", kid: "s2", nb: 0, issued: v2Now + 60_001, pass: false},
		{name: "kid-unlisted", kid: "s9", nb: 0, pass: false},
		{name: "no-key-set", kid: "s2", nb: 0, mutKeys: func(*v2fx, map[string]any) []any { return []any{} }, pass: false},
		{name: "foreign-key-set", kid: "s2", nb: 0, mutKeys: func(f *v2fx, _ map[string]any) []any {
			return []any{f.keySet(newKey(t), keyEntry("s2", f.seqKey, 0, nil))}
		}, pass: false},
		{name: "second-set-verifies", kid: "s2", nb: 0, mutKeys: func(f *v2fx, ks map[string]any) []any {
			return []any{f.keySet(newKey(t), keyEntry("s2", f.seqKey, 0, nil)), ks}
		}, pass: true},
		{name: "entry-suite-differs", kid: "s2", nb: 0, mutKeys: func(f *v2fx, _ map[string]any) []any {
			e := keyEntry("s2", f.seqKey, 0, nil)
			e["alg"] = "ml-dsa-65"
			e["pq_pk"] = b64.EncodeToString(make([]byte, 1952))
			return []any{f.keySet(f.seqRoot, e)}
		}, pass: false},
		{name: "expires==now", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["expires_at"] = jnum(v2Now) }, pass: true},
		{name: "expires==now-1", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["expires_at"] = jnum(v2Now - 1) }, pass: false},
		{name: "last-seq-2", kid: "s2", nb: 0, last: jnum(2), pass: true},
		{name: "last-seq-3", kid: "s2", nb: 0, last: jnum(3), pass: false},
		{name: "last-seq-null", kid: "s2", nb: 0, last: "null", pass: false},
		{name: "last-seq-string", kid: "s2", nb: 0, last: "2", pass: false},
		{name: "last-seq-fraction", kid: "s2", nb: 0, last: json.Number("2.5"), pass: false},
		{name: "other-aud", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["aud"] = "hotel.example" }, pass: false},
		{name: "other-session", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["session"] = dg("s-other") }, pass: false},
		{name: "other-acc", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["acc"] = "other" }, pass: false},
		{name: "other-action", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["pcactn_digest"] = dg("other-action") }, pass: false},
		{name: "arithmetic", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["post"] = jnum(48_901) }, pass: false},
		{name: "delta-not-val", kid: "s2", nb: 0, mutR: func(r map[string]any) { r["delta"] = jnum(38_901); r["post"] = jnum(48_901) }, pass: false},
	}
	for _, c := range cases {
		f := newV2Fx(t)
		f.useSequenced()
		issued := v2Now
		if c.issued != 0 {
			issued = c.issued
		}
		r := f.receipt(f.seqKey, c.kid, func(r map[string]any) {
			r["issued_at"] = jnum(issued)
			if c.mutR != nil {
				c.mutR(r)
			}
		})
		ks := f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, c.nb, c.na))
		sets := []any{ks}
		if c.mutKeys != nil {
			sets = c.mutKeys(f, ks)
		}
		f.claimReceipt(r, jsInt(r["post"]), sets, r)
		if c.last != nil {
			lv := c.last
			if lv == "null" {
				lv = nil
			}
			f.ctx["acc"].(map[string]any)["last_seq"] = map[string]any{"trip_spend": lv}
		}
		if c.pass {
			ok(c.name, f)
		} else {
			bad(c.name, f)
		}
	}
	// a receipt signed by another key than the listed entry
	f := newV2Fx(t)
	f.useSequenced()
	r := f.receipt(newKey(t), "s2", nil)
	f.claimReceipt(r, 48_900, []any{f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, 0, nil))}, r)
	bad("foreign-signer", f)
	// the claim names a receipt that is not presented
	f = newV2Fx(t)
	f.useSequenced()
	r = f.receipt(f.seqKey, "s2", nil)
	f.claimReceipt(r, 48_900, []any{f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, 0, nil))})
	bad("not-presented", f)
	// no receipt on a sequenced claim
	f = newV2Fx(t)
	f.useSequenced()
	f.setClaim(48_900)
	bad("no-receipt", f)
}

func jsInt(v any) int64 { return int64(jsF(v)) }

// ---- the check order of the whole pipeline --------------------------------------------------------------------

func TestMutV2PipelineOrder(t *testing.T) {
	// independent checks: schema and accumulators fail together, intent_session still passes; schema is the reason
	f := newV2Fx(t)
	f.ctx["params"] = map[string]any{"offer_id": "OF-1", "total": jnum(1), "add_ons": []any{"none"}, "refundable": false}
	expectV2(t, "schema+acc", f.verify(), []string{"intent_session"}, "schema", "accumulators")
	// intent_session and accumulators both fail on a missing root; schema passes; intent_session is first
	f = newV2Fx(t)
	delete(f.ctx["session"].(map[string]any), "root")
	expectV2(t, "session+acc", f.verify(), []string{"schema"}, "intent_session", "accumulators")
	// layers between intent_session and accumulators
	f = newV2Fx(t)
	f.ctx["layers"] = map[string]any{"org": map[string]any{"predicates": []any{}}}
	f.setClaim(1)
	expectV2(t, "layers+acc", f.verify(), []string{"schema", "intent_session"}, "layers", "accumulators")
}

// ---- W-B unit inside the pipeline --------------------------------------------------------------------------------

func TestMutV2WBUnit(t *testing.T) {
	judge := newKey(t)
	// a classifier policy with no committed verdict: classes reported and failed (no quorum)
	f := newV2Fx(t)
	f.ctx["wb"] = map[string]any{"policy": map[string]any{"classifiers": []any{map[string]any{"id": "tone", "param": "action.params.offer_id",
		"labels": []any{"a"}, "keys": []any{judge.id}, "k": jnum(1)}}}}
	expectV2(t, "classes-no-quorum", f.verify(), v2Base, "classes")
	// a provenance policy that makes the material offer_id tainted (no prov): question -> provenance FAILED with
	// intent_required, and the later classes check is still reported (a question does not end the unit)
	f = newV2Fx(t)
	f.ctx["wb"] = map[string]any{"policy": map[string]any{"provenance": map[string]any{"params": map[string]any{"action.params.offer_id": "material"}},
		"classifiers": []any{map[string]any{"id": "tone", "param": "action.params.offer_id", "labels": []any{"a"}, "keys": []any{judge.id}, "k": jnum(1)}}}}
	v := f.verify()
	if ok, has := v.Checks["provenance"]; !has || ok || !strings.Contains(v.Reason, "intent_required: ") {
		t.Fatalf("question: %v (%s)", v.Checks, v.Reason)
	}
	if ok, has := v.Checks["classes"]; !has || ok {
		t.Fatalf("classes after a question: %v", v.Checks)
	}
	// deny ends the unit: material_tainted deny -> provenance failed, classes NOT reported
	f.ctx["wb"].(map[string]any)["policy"].(map[string]any)["provenance"].(map[string]any)["material_tainted"] = "deny"
	v = f.verify()
	if ok, has := v.Checks["provenance"]; !has || ok {
		t.Fatalf("deny: %v", v.Checks)
	}
	if _, has := v.Checks["classes"]; has {
		t.Fatal("a deny ends the W-B unit")
	}
	// facts first: a world policy with no facts fails facts; provenance and classes not reported
	f = newV2Fx(t)
	f.ctx["wb"] = map[string]any{"policy": map[string]any{"world": map[string]any{"worlds": []any{map[string]any{"name": "fare", "subject_path": "action.params.offer_id",
		"oracles": []any{map[string]any{"kid": "o1", "pk": judge.id}}, "freshness_ms": jnum(1000), "min_oracles": jnum(1), "max_faulty": jnum(0)}}},
		"provenance": map[string]any{"params": map[string]any{}}}}
	v = f.verify()
	if ok, has := v.Checks["facts"]; !has || ok {
		t.Fatalf("facts: %v", v.Checks)
	}
	if _, has := v.Checks["provenance"]; has {
		t.Fatal("a facts failure ends the W-B unit")
	}
}

// ---- rules 16-18 function level ---------------------------------------------------------------------------------

func worldInput(t *testing.T, oracles []fxKey, facts []map[string]any, policy map[string]any) map[string]any {
	refs := []any{}
	fs := []any{}
	for _, f := range facts {
		refs = append(refs, refOf(t, factRefDomain, "f", f))
		fs = append(fs, f)
	}
	return map[string]any{"now": jnum(v2Now), "aud": v2Aud, "session": dg("session"),
		"action":    map[string]any{"verb": "air.book", "resource": "r", "params": map[string]any{"offer_id": "OF-2", "quote": jnum(38_900), "total": jnum(77_800)}},
		"committed": map[string]any{"facts": refs}, "facts": fs, "policy": policy}
}

func fact(t *testing.T, k fxKey, kid string, value any, tObs int64) map[string]any {
	return signArt(t, k, factDomain, map[string]any{"v": jnum(1), "kind": "pca-fact", "name": "fare", "subject": "OF-2", "value": value, "t_obs": jnum(tObs), "oracle": kid})
}

func farePolicy(oracles []fxKey, min, faulty, fresh int64, extra map[string]any) map[string]any {
	os := []any{}
	for i, o := range oracles {
		os = append(os, map[string]any{"kid": "o" + string(rune('0'+i)), "pk": o.id})
	}
	p := map[string]any{"worlds": []any{map[string]any{"name": "fare", "subject_path": "action.params.offer_id", "oracles": os,
		"freshness_ms": jnum(fresh), "min_oracles": jnum(min), "max_faulty": jnum(faulty)}}}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestMutV2World(t *testing.T) {
	ks := []fxKey{newKey(t), newKey(t), newKey(t), newKey(t)}
	w := func(facts []map[string]any, pol map[string]any) map[string]any {
		return worldP(deep(t, worldInput(t, ks, facts, pol)))
	}
	f3 := func(a, b, c int64, tObs int64) []map[string]any {
		return []map[string]any{fact(t, ks[0], "o0", jnum(a), tObs), fact(t, ks[1], "o1", jnum(b), tObs), fact(t, ks[2], "o2", jnum(c), tObs)}
	}
	// lower median of three (odd) and of four (even: index 1)
	if got := w(f3(30, 10, 20, v2Now), farePolicy(ks, 3, 1, 1000, nil)); got["ok"] != true || !sameJSON(got["world"], map[string]any{"fare": jnum(20)}) {
		t.Fatalf("median3: %v", got)
	}
	four := append(f3(40, 10, 30, v2Now), fact(t, ks[3], "o3", jnum(20), v2Now))
	if got := w(four, farePolicy(ks, 4, 1, 1000, nil)); !sameJSON(got["world"], map[string]any{"fare": jnum(20)}) {
		t.Fatalf("median4 lower: %v", got)
	}
	// freshness inclusive: now - t_obs == freshness_ms counted, +1 not counted
	if got := w(f3(1, 1, 1, v2Now-1000), farePolicy(ks, 3, 1, 1000, nil)); got["ok"] != true {
		t.Fatalf("fresh at bound: %v", got)
	}
	if got := w(f3(1, 1, 1, v2Now-1001), farePolicy(ks, 3, 1, 1000, nil)); got["ok"] != false {
		t.Fatalf("stale: %v", got)
	}
	// skew inclusive: t_obs == now + skew counted, +1 not
	if got := w(f3(1, 1, 1, v2Now+60_000), farePolicy(ks, 3, 1, 1000, nil)); got["ok"] != true {
		t.Fatalf("skew at bound: %v", got)
	}
	if got := w(f3(1, 1, 1, v2Now+60_001), farePolicy(ks, 3, 1, 1000, nil)); got["ok"] != false {
		t.Fatalf("future: %v", got)
	}
	// min_oracles >= 2f+1 (policy) and enough fresh facts
	if got := w(f3(1, 1, 1, v2Now), farePolicy(ks, 2, 1, 1000, nil)); got["ok"] != false {
		t.Fatalf("min < 2f+1: %v", got)
	}
	if got := w(f3(1, 1, 1, v2Now)[:2], farePolicy(ks, 3, 1, 1000, nil)); got["ok"] != false {
		t.Fatalf("2 of 3: %v", got)
	}
	// single source reported
	if got := w(f3(5, 5, 5, v2Now)[:1], farePolicy(ks, 1, 0, 1000, nil)); !sameJSON(got["single_source"], []any{"fare"}) {
		t.Fatalf("single: %v", got)
	}
	// relational: ratio_ppm floor and the safe-integer bound, sub negative
	rel := func(fn, a, b string) map[string]any {
		return map[string]any{"relational": []any{map[string]any{"name": "x", "fn": fn, "a": a, "b": b}}}
	}
	if got := w(f3(3, 3, 3, v2Now), farePolicy(ks, 3, 1, 1000, rel("ratio_ppm", "action.params.quote", "env.world.fare"))); !sameJSON(got["world"], map[string]any{"fare": jnum(3), "x": jnum(12_966_666_666)}) {
		t.Fatalf("ratio floor: %v", got)
	}
	if got := w(f3(0, 0, 0, v2Now), farePolicy(ks, 3, 1, 1000, rel("ratio_ppm", "action.params.quote", "env.world.fare"))); got["ok"] != false {
		t.Fatalf("ratio by zero: %v", got)
	}
	if got := w(f3(1, 1, 1, v2Now), farePolicy(ks, 3, 1, 1000, rel("ratio_ppm", "action.params.big", "env.world.fare"))); got["ok"] != false {
		t.Fatalf("ratio missing operand: %v", got)
	}
	if got := w(f3(40_000, 40_000, 40_000, v2Now), farePolicy(ks, 3, 1, 1000, rel("sub", "action.params.quote", "env.world.fare"))); !sameJSON(got["world"], map[string]any{"fare": jnum(40_000), "x": jnum(-1_100)}) {
		t.Fatalf("sub negative: %v", got)
	}
	big := worldInput(t, ks, f3(1, 1, 1, v2Now), farePolicy(ks, 3, 1, 1000, rel("ratio_ppm", "action.params.quote", "env.world.fare")))
	// floor(a * 1e6 / 1) <= 2^53-1 iff a <= 9007199254
	big["action"].(map[string]any)["params"].(map[string]any)["quote"] = jnum(9_007_199_255)
	if got := worldP(deep(t, big)); got["ok"] != false {
		t.Fatalf("ratio overflow: %v", got)
	}
	big["action"].(map[string]any)["params"].(map[string]any)["quote"] = jnum(9_007_199_254)
	if got := worldP(deep(t, big)); got["ok"] != true {
		t.Fatalf("ratio at bound: %v", got)
	}
	// duplicate oracle, unpinned kid, tamper, uncommitted ignored, mixed values
	dup := []map[string]any{fact(t, ks[0], "o0", jnum(1), v2Now), fact(t, ks[0], "o0", jnum(2), v2Now), fact(t, ks[1], "o1", jnum(1), v2Now)}
	if got := w(dup, farePolicy(ks, 2, 0, 1000, nil)); got["ok"] != false {
		t.Fatalf("duplicate oracle: %v", got)
	}
	mixed := []map[string]any{fact(t, ks[0], "o0", jnum(1), v2Now), fact(t, ks[1], "o1", "gold", v2Now)}
	if got := w(mixed, farePolicy(ks, 2, 0, 1000, nil)); got["ok"] != false {
		t.Fatalf("mixed: %v", got)
	}
	strs := []map[string]any{fact(t, ks[0], "o0", "gold", v2Now), fact(t, ks[1], "o1", "gold", v2Now)}
	if got := w(strs, farePolicy(ks, 2, 0, 1000, nil)); !sameJSON(got["world"], map[string]any{"fare": "gold"}) {
		t.Fatalf("strings agree: %v", got)
	}
	in := worldInput(t, ks, f3(1, 1, 1, v2Now), farePolicy(ks, 3, 1, 1000, nil))
	in["facts"] = append(in["facts"].([]any), fact(t, ks[3], "o3", jnum(99), v2Now))
	if got := worldP(deep(t, in)); !sameJSON(got["world"], map[string]any{"fare": jnum(1)}) {
		t.Fatalf("uncommitted ignored: %v", got)
	}
	in = worldInput(t, ks, f3(1, 1, 1, v2Now), farePolicy(ks, 3, 1, 1000, nil))
	in["facts"].([]any)[0].(map[string]any)["t_obs"] = jnum(v2Now - 1)
	if got := worldP(deep(t, in)); got["ok"] != false {
		t.Fatalf("tampered (ref no longer matches): %v", got)
	}
	// committed digest count bound 16 / 17
	in = worldInput(t, ks, nil, map[string]any{})
	refs := []any{}
	for i := 0; i < 17; i++ {
		refs = append(refs, dg("c"+string(rune('a'+i))))
	}
	in["committed"] = map[string]any{"facts": refs}
	if got := worldP(deep(t, in)); got["ok"] != false {
		t.Fatalf("17 commitments: %v", got)
	}
}

func TestMutV2Provenance(t *testing.T) {
	site := newKey(t)
	params := map[string]any{"offer_id": "OF-1", "payment_ref": "pm_1"}
	labels := func(fields map[string]any, siteName string) map[string]any {
		return signArt(t, site, labelsDomain, map[string]any{"v": jnum(1), "kind": "pca-labels", "site": siteName, "session": dg("session"),
			"response_digest": dg("resp"), "fields": fields, "issued_at": jnum(v2Now), "kid": "k1"})
	}
	digestOf := func(v any) string { h, _ := hashCanonicalV(deep(t, v)); return h }
	run := func(prov map[string]any, committed []any, rcs []any, policy map[string]any) map[string]any {
		in := map[string]any{"aud": v2Aud, "session": dg("session"), "action": map[string]any{"params": params}, "prov": prov,
			"policy": policy}
		// nil = ABSENT (a present JSON null is malformed and denies, like the reference)
		if committed != nil {
			in["committed_labels"] = committed
		}
		if rcs != nil {
			in["labels"] = rcs
		}
		return provP(deep(t, in))
	}
	pol := func(extra map[string]any) map[string]any {
		p := map[string]any{"params": map[string]any{"action.params.offer_id": "material", "action.params.payment_ref": "critical"},
			"registry":   map[string]any{"wallet:ana": "trusted", "web:x": "web", "tool:fx": "tool"},
			"label_keys": []any{map[string]any{"site": v2Aud, "kid": "k1", "pk": site.id}, map[string]any{"site": "gov.example", "kid": "k1", "pk": site.id}}}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	clean := map[string]any{"action.params.offer_id": []any{"wallet:ana"}, "action.params.payment_ref": []any{"wallet:ana"}}
	if got := run(clean, nil, nil, pol(nil)); got["outcome"] != "pass" {
		t.Fatalf("clean: %v", got)
	}
	// a material web value: question (tap); question_typed mode: typed; deny mode: deny; allow: pass
	web := map[string]any{"action.params.offer_id": []any{"web:x"}, "action.params.payment_ref": []any{"wallet:ana"}}
	for mode, want := range map[string][2]string{"": {"question", "tap"}, "question_typed": {"question", "typed"}, "deny": {"deny", ""}, "allow": {"pass", ""}} {
		extra := map[string]any{}
		if mode != "" {
			extra["material_tainted"] = mode
		}
		got := run(web, nil, nil, pol(extra))
		if got["outcome"] != want[0] || (want[1] != "" && got["friction"] != want[1]) {
			t.Fatalf("material %q: %v", mode, got)
		}
	}
	// a tool value is tainted (rank 2), first_party is not (rank 1)
	if got := run(map[string]any{"action.params.offer_id": []any{"tool:fx"}}, nil, nil, pol(nil)); got["outcome"] != "question" {
		t.Fatalf("tool: %v", got)
	}
	// undeclared but policy-listed params the action carries get agent; critical default question_typed
	if got := run(map[string]any{}, nil, nil, pol(nil)); got["outcome"] != "question" || got["friction"] != "typed" {
		t.Fatalf("undeclared critical: %v", got)
	}
	// critical_max: trusted cap refuses a first_party critical value
	rc := labels(map[string]any{"pay": map[string]any{"class": "payment.instrument_meta", "value_digest": digestOf("pm_1")}}, v2Aud)
	ref := refOf(t, labelsRefDomain, "l", rc)
	lp := map[string]any{"action.params.offer_id": []any{"wallet:ana"}, "action.params.payment_ref": []any{labelRefPrefix + ref + "#pay"}}
	if got := run(lp, []any{ref}, []any{rc}, pol(nil)); got["outcome"] != "pass" || !sameJSON(got["labels"].(map[string]any)["action.params.payment_ref"], "first_party") {
		t.Fatalf("first-party label: %v", got)
	}
	if got := run(lp, []any{ref}, []any{rc}, pol(map[string]any{"critical_max": "trusted"})); got["outcome"] != "deny" {
		t.Fatalf("critical_max trusted: %v", got)
	}
	if got := run(lp, []any{ref}, []any{rc}, pol(map[string]any{"critical_max": "first_party"})); got["outcome"] != "pass" {
		t.Fatalf("critical_max first_party: %v", got)
	}
	// value mismatch -> agent; uncommitted receipt -> deny; foreign site without a flow rule -> deny
	bad := labels(map[string]any{"pay": map[string]any{"class": "payment.instrument_meta", "value_digest": digestOf("pm_2")}}, v2Aud)
	bref := refOf(t, labelsRefDomain, "l", bad)
	if got := run(map[string]any{"action.params.payment_ref": []any{labelRefPrefix + bref + "#pay"}}, []any{bref}, []any{bad}, pol(nil)); !sameJSON(got["labels"].(map[string]any)["action.params.payment_ref"], "agent") {
		t.Fatalf("value mismatch: %v", got)
	}
	if got := run(lp, []any{}, []any{rc}, pol(nil)); got["outcome"] != "deny" {
		t.Fatalf("uncommitted: %v", got)
	}
	gov := labels(map[string]any{"pay": map[string]any{"class": "pii.passport", "value_digest": digestOf("pm_1")}}, "gov.example")
	gref := refOf(t, labelsRefDomain, "l", gov)
	gp := map[string]any{"action.params.payment_ref": []any{labelRefPrefix + gref + "#pay"}}
	if got := run(gp, []any{gref}, []any{gov}, pol(nil)); got["outcome"] != "deny" {
		t.Fatalf("flow without rule: %v", got)
	}
	// most specific pattern wins: pii.* allows, pii.passport (exact) forbids
	flows := map[string]any{"pii.*": []any{v2Aud}, "pii.passport": []any{"other"}}
	if got := run(gp, []any{gref}, []any{gov}, pol(map[string]any{"flows": flows})); got["outcome"] != "deny" {
		t.Fatalf("exact beats prefix: %v", got)
	}
	if got := run(gp, []any{gref}, []any{gov}, pol(map[string]any{"flows": map[string]any{"pii.*": []any{v2Aud}, "*": []any{}}})); got["outcome"] == "deny" {
		t.Fatalf("prefix beats *: %v", got)
	}
	// prov wire bounds inside the rule: 32 / 33 paths, 8 / 9 refs
	many := map[string]any{}
	for i := 0; i < 33; i++ {
		many["action.params.p"+string(rune('a'+i%26))+strings.Repeat("z", i/26)] = []any{"wallet:ana"}
	}
	if got := run(many, nil, nil, pol(nil)); got["outcome"] != "deny" {
		t.Fatalf("33 prov paths: %v", got)
	}
}

func TestMutV2Classifier(t *testing.T) {
	js := []fxKey{newKey(t), newKey(t), newKey(t)}
	content := "We are sorry."
	cd, _ := hashCanonicalV(content)
	verdict := func(j fxKey, label string) map[string]any {
		return signArt(t, j, classifierDomain, map[string]any{"v": jnum(1), "kind": "pca-intent-classification", "classifier": "tone", "session": dg("session"),
			"content_digest": cd, "label": label, "measurement": "m1", "judge": j.id})
	}
	run := func(k int64, vs []map[string]any, labels []any) map[string]any {
		refs, all := []any{}, []any{}
		for _, v := range vs {
			refs = append(refs, refOf(t, classifierRefDomain, "c", v))
			all = append(all, v)
		}
		keys := []any{js[0].id, js[1].id, js[2].id}
		in := map[string]any{"session": dg("session"), "action": map[string]any{"params": map[string]any{"body": content}}, "committed": refs, "verdicts": all,
			"policy": map[string]any{"classifiers": []any{map[string]any{"id": "tone", "param": "action.params.body", "labels": labels, "keys": keys, "k": jnum(k), "measurements": []any{"m1"}}}}}
		return clsP(deep(t, in))
	}
	ls := []any{"neutral", "apologetic"}
	two := []map[string]any{verdict(js[0], "apologetic"), verdict(js[1], "apologetic"), verdict(js[2], "neutral")}
	if got := run(2, two, ls); got["ok"] != true || !sameJSON(got["classes"], map[string]any{"tone": "apologetic"}) {
		t.Fatalf("k=2: %v", got)
	}
	if got := run(3, two, ls); got["ok"] != false {
		t.Fatalf("k=3 no quorum: %v", got)
	}
	if got := run(1, two, ls); got["ok"] != false {
		t.Fatalf("k=1 ambiguous: %v", got)
	}
	if got := run(4, two, ls); got["ok"] != false {
		t.Fatalf("k > |keys|: %v", got)
	}
	if got := run(1, []map[string]any{verdict(js[0], "apologetic"), verdict(js[0], "apologetic")}, ls); got["ok"] != false {
		t.Fatalf("one judge twice: %v", got)
	}
	if got := run(1, []map[string]any{verdict(js[0], "hostile")}, ls); got["ok"] != false {
		t.Fatalf("label outside the set: %v", got)
	}
	if got := run(1, []map[string]any{verdict(newKey(t), "neutral")}, ls); got["ok"] != false {
		t.Fatalf("judge not allowlisted: %v", got)
	}
	// KEYS: labels spelled like Object.prototype members are ordinary keys of a prototype-free tally
	for _, l := range []string{"toString", "constructor", "__proto__", "valueOf", "hasOwnProperty"} {
		if got := run(1, []map[string]any{verdict(js[0], l)}, []any{"neutral", l}); got["ok"] != true || !sameJSON(got["classes"], map[string]any{"tone": l}) {
			t.Fatalf("label %s: %v", l, got)
		}
		// an unvoted proto-named label is 0 votes, never a winner
		if got := run(1, []map[string]any{verdict(js[0], "neutral")}, []any{"neutral", l}); !sameJSON(got["classes"], map[string]any{"tone": "neutral"}) {
			t.Fatalf("unvoted label %s: %v", l, got)
		}
	}
}

func TestMutV2ClassifierProtoID(t *testing.T) {
	j := newKey(t)
	cd, _ := hashCanonicalV("x")
	v := signArt(t, j, classifierDomain, map[string]any{"v": jnum(1), "kind": "pca-intent-classification", "classifier": "constructor", "session": dg("session"),
		"content_digest": cd, "label": "length", "measurement": "m1", "judge": j.id})
	in := map[string]any{"session": dg("session"), "action": map[string]any{"params": map[string]any{"body": "x"}}, "committed": []any{refOf(t, classifierRefDomain, "c", v)},
		"verdicts": []any{v}, "policy": map[string]any{"classifiers": []any{map[string]any{"id": "constructor", "param": "action.params.body",
			"labels": []any{"length", "name"}, "keys": []any{j.id}, "k": jnum(1)}}}}
	if got := clsP(deep(t, in)); got["ok"] != true || !sameJSON(got["classes"], map[string]any{"constructor": "length"}) {
		t.Fatalf("classifier id constructor: %v", got)
	}
	// with no verdict, no label (not even `length`) reaches the quorum
	in["committed"], in["verdicts"] = []any{}, []any{}
	if got := clsP(deep(t, in)); got["ok"] != false {
		t.Fatalf("no verdict: %v", got)
	}
}

func TestMutV2WBClock(t *testing.T) {
	ks := []fxKey{newKey(t), newKey(t), newKey(t)}
	facts := []map[string]any{fact(t, ks[0], "o0", jnum(5), v2Now), fact(t, ks[1], "o1", jnum(5), v2Now), fact(t, ks[2], "o2", jnum(5), v2Now)}
	for name, now := range map[string]any{"string": "1800000000000", "float": json.Number("1800000000000.5"), "null": nil, "neg-zero": json.Number("-0"), "unsafe": json.Number("9007199254740992")} {
		in := worldInput(t, ks, facts, farePolicy(ks, 3, 1, 1000, nil))
		in["now"] = now
		if got := worldP(normalizeJSON(in)); got["ok"] != false {
			t.Fatalf("now %s: every fact must be stale: %v", name, got)
		}
		// a relational dimension needs no clock
		rel := worldInput(t, ks, nil, map[string]any{"relational": []any{map[string]any{"name": "d", "fn": "sub", "a": "action.params.total", "b": "action.params.quote"}}})
		rel["now"] = now
		if got := worldP(normalizeJSON(rel)); got["ok"] != true || !sameJSON(got["world"], map[string]any{"d": jnum(38_900)}) {
			t.Fatalf("now %s, relational: %v", name, got)
		}
	}
	in := worldInput(t, ks, facts, farePolicy(ks, 3, 1, 1000, nil))
	delete(in, "now")
	if got := worldP(normalizeJSON(in)); got["ok"] != false {
		t.Fatalf("absent now: %v", got)
	}
	// offers: a valid, fresh offer set is stale without a usable clock
	site := newKey(t)
	os := signArt(t, site, offerSetDomain, map[string]any{"v": jnum(1), "kind": "pca-offer-set", "site": v2Aud, "session": dg("session"), "query": map[string]any{},
		"rank": "price_asc", "complete": true, "offers": []any{map[string]any{"offer_id": "OF-2", "price": jnum(100)}, map[string]any{"offer_id": "OF-3", "price": jnum(90)}},
		"issued_at": jnum(v2Now), "kid": "s1"})
	offers := map[string]any{"offers": map[string]any{"name": "excess", "site_keys": []any{map[string]any{"kid": "s1", "pk": site.id}}, "max_age_ms": jnum(1000),
		"offer_param": "action.params.offer_id", "filter": map[string]any{"query": map[string]any{}, "offer": map[string]any{}}}}
	mk := func(now any) map[string]any {
		in := worldInput(t, ks, nil, offers)
		in["committed"] = map[string]any{"offer_set": refOf(t, offerSetRefDomain, "o", os)}
		in["offer_set"] = os
		in["now"] = now
		return normalizeJSON(in).(map[string]any)
	}
	if got := worldP(mk(jnum(v2Now))); got["ok"] != true || !sameJSON(got["world"], map[string]any{"excess": jnum(10)}) {
		t.Fatalf("offers with a clock: %v", got)
	}
	if got := worldP(mk(jnum(v2Now + 1000))); got["ok"] != true {
		t.Fatalf("offers at max age: %v", got)
	}
	if got := worldP(mk(jnum(v2Now + 1001))); got["ok"] != false {
		t.Fatalf("offers stale: %v", got)
	}
	if got := worldP(mk(jnum(v2Now - 60_000))); got["ok"] != true {
		t.Fatalf("offers at skew: %v", got)
	}
	if got := worldP(mk(jnum(v2Now - 60_001))); got["ok"] != false {
		t.Fatalf("offers future: %v", got)
	}
	if got := worldP(mk("1800000000000")); got["ok"] != false {
		t.Fatalf("offers, string now: %v", got)
	}
}

func TestMutV2WBActive(t *testing.T) {
	d := dg("x")
	for _, c := range []struct {
		is, pol map[string]any
		want    [3]bool
	}{
		{map[string]any{}, map[string]any{}, [3]bool{}},
		{map[string]any{"facts": []any{d}}, map[string]any{}, [3]bool{true, false, false}},
		{map[string]any{"facts": []any{}}, map[string]any{}, [3]bool{}},
		{map[string]any{"facts": map[string]any{"0": d, "length": jnum(1)}}, map[string]any{}, [3]bool{}},
		{map[string]any{"offer_set": d}, map[string]any{}, [3]bool{true, false, false}},
		{map[string]any{"offer_set": map[string]any{"length": jnum(43)}}, map[string]any{}, [3]bool{}},
		{map[string]any{"offer_set": nil}, map[string]any{}, [3]bool{}},
		{map[string]any{}, map[string]any{"world": map[string]any{"worlds": []any{map[string]any{}}}}, [3]bool{true, false, false}},
		{map[string]any{}, map[string]any{"world": map[string]any{"relational": []any{map[string]any{}}}}, [3]bool{true, false, false}},
		{map[string]any{}, map[string]any{"world": map[string]any{"worlds": map[string]any{"length": jnum(2)}, "relational": "ab"}}, [3]bool{}},
		{map[string]any{}, map[string]any{"world": map[string]any{"offers": map[string]any{}}}, [3]bool{true, false, false}},
		{map[string]any{}, map[string]any{"world": map[string]any{"offers": []any{}}}, [3]bool{}},
		{map[string]any{}, map[string]any{"world": map[string]any{"offers": nil}}, [3]bool{}},
		{map[string]any{"prov": map[string]any{}}, map[string]any{}, [3]bool{false, true, false}},
		{map[string]any{"prov": nil}, map[string]any{}, [3]bool{false, true, false}},
		{map[string]any{"labels": []any{d}}, map[string]any{}, [3]bool{false, true, false}},
		{map[string]any{"labels": map[string]any{"length": jnum(1)}}, map[string]any{}, [3]bool{}},
		{map[string]any{}, map[string]any{"provenance": map[string]any{"params": map[string]any{}}}, [3]bool{false, true, false}},
		{map[string]any{}, map[string]any{"provenance": []any{}}, [3]bool{}},
		{map[string]any{}, map[string]any{"provenance": nil}, [3]bool{}},
		{map[string]any{"classes": []any{d}}, map[string]any{}, [3]bool{false, false, true}},
		{map[string]any{"classes": map[string]any{"length": jnum(1)}}, map[string]any{}, [3]bool{}},
		{map[string]any{}, map[string]any{"classifiers": []any{map[string]any{}}}, [3]bool{false, false, true}},
		{map[string]any{}, map[string]any{"classifiers": "abc"}, [3]bool{}},
	} {
		got := IntentWBActivePrimitive(normalizeJSON(map[string]any{"intent_session": c.is, "policy": c.pol}))
		if got["facts"] != c.want[0] || got["provenance"] != c.want[1] || got["classes"] != c.want[2] {
			t.Fatalf("%v %v: got %v, want %v", c.is, c.pol, got, c.want)
		}
	}
}

// Every v2 signature check routes through the SDK suite dispatch and reports unsupported_suite for an alg it refuses.
func TestMutV2UnsupportedSuite(t *testing.T) {
	f := newV2Fx(t)
	f.S["alg"] = "x-unregistered"
	f.signRoot()
	f.rebind()
	v := f.verify()
	if v.Checks["intent_session"] || !strings.Contains(v.Reason, "unsupported_suite") {
		t.Fatalf("session root: %v (%s)", v.Checks, v.Reason)
	}
	f = newV2Fx(t)
	f.ctx["schema"].(map[string]any)["keys"] = []any{map[string]any{"kid": "k1", "alg": "x-unregistered", "pk": f.site.id}}
	v = f.verify()
	if v.Checks["schema"] || !strings.Contains(v.Reason, "schema does not verify: schema key: unsupported_suite") {
		t.Fatalf("schema: %v (%s)", v.Checks, v.Reason)
	}
	f = newV2Fx(t)
	f.useSequenced()
	r := f.receipt(f.seqKey, "s2", func(r map[string]any) { r["alg"] = "x-unregistered" })
	f.claimReceipt(r, 48_900, []any{f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, 0, nil))}, r)
	v = f.verify()
	if v.Checks["accumulators"] || !strings.Contains(v.Reason, "unsupported_suite") {
		t.Fatalf("receipt: %v (%s)", v.Checks, v.Reason)
	}
	if suiteSupported("x-unregistered", true) || !suiteSupported(nil, false) {
		t.Fatal("dispatch")
	}
}

// ---- strict rules 13-15 (README "strict values, absent vs null, suite capability") ------------------------------

func TestMutV2StrictClock(t *testing.T) {
	f := newV2Fx(t)
	v, err := VerifyPCActnCoreWith(f.p2(), deepM(t, f.grant), maxSafeInt+1, v2Aud, VerifyOptions{IntentV2: IntentV2ContextFromJSON(normalizeJSON(f.ctx))})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v2Base {
		if v.Checks[c] {
			t.Fatalf("clock 2^53: %s must fail (%v)", c, v.Checks)
		}
	}
	if decideIntentV2(f.p2(), deepM(t, f.grant), IntentV2ContextFromJSON(normalizeJSON(f.ctx)), maxSafeInt).checks[0].why != "" {
		t.Fatal("clock 2^53-1 is a safe integer")
	}
}

func TestMutV2StrictHeldGrants(t *testing.T) {
	setup := func(held any) *v2fx {
		f := newV2Fx(t)
		g0id := f.grant["id"].(string)
		f.grant = f.sessionGrant(f.principal, 1, g0id, f.mapD, f.salt)
		f.build()
		f.is()["seq"] = jnum(1)
		f.resign()
		f.ctx["session"].(map[string]any)["grants"] = []any{held}
		return f
	}
	base := newV2Fx(t).grant
	_ = base
	for name, mut := range map[string]func(g map[string]any) any{
		"string":      func(map[string]any) any { return "g0" },
		"null":        func(map[string]any) any { return nil },
		"id-number":   func(g map[string]any) any { g["id"] = jnum(1); return g },
		"issuer-null": func(g map[string]any) any { g["issuer"] = nil; return g },
		"alg-number":  func(g map[string]any) any { g["alg"] = jnum(1); return g },
	} {
		f := newV2Fx(t)
		g := deepM(t, f.grant)
		f2 := setup(mut(g))
		_ = f
		v := f2.verify()
		if v.Checks["intent_session"] {
			t.Fatalf("held grant %s must fail", name)
		}
	}
	f := newV2Fx(t)
	g := deepM(t, f.grant)
	g["alg"] = "x-unregistered"
	f2 := setup(g)
	v := f2.verify()
	if v.Checks["intent_session"] || !strings.Contains(v.Reason, "unsupported_suite") {
		t.Fatalf("held grant suite: %v (%s)", v.Checks, v.Reason)
	}
}

func TestMutV2StrictSessionRoot(t *testing.T) {
	bad := func(name string, mut func(f *v2fx)) {
		t.Helper()
		f := newV2Fx(t)
		mut(f)
		f.signRoot()
		f.rebind()
		expectV2(t, name, f.verify(), []string{"schema"}, "intent_session", "accumulators")
	}
	bad("layers.org-null", func(f *v2fx) { f.S["layers"].(map[string]any)["org"] = nil })
	bad("layers.std-null", func(f *v2fx) { f.S["layers"].(map[string]any)["std"] = nil })
	bad("revocation.pq_pk-without-key", func(f *v2fx) {
		f.S["revocation"] = map[string]any{"epoch_uri": "u", "max_age_s": jnum(60), "pq_pk": dg("pq")}
	})
	bad("revocation-null", func(f *v2fx) { f.S["revocation"] = nil })
	bad("acc-id-constructor", func(f *v2fx) {
		a := tripAcc()
		a["id"] = "constructor"
		f.S["accumulators"] = []any{a}
	})
	bad("monitor-id-proto", func(f *v2fx) {
		f.S["monitors"] = []any{map[string]any{"id": "__proto__", "kind": "never", "p": map[string]any{"verb": "x"}}}
	})
	bad("principal-alg-number", func(f *v2fx) { f.S["principals"].([]any)[0].(map[string]any)["alg"] = jnum(1) })
	bad("holder-root_alg-unsupported", func(f *v2fx) {
		a := tripAcc()
		a["holder"] = map[string]any{"kind": "sequenced", "uri": "u", "root": f.seqRoot.id, "root_alg": "x-unregistered"}
		f.S["accumulators"] = []any{a}
	})
	// revocation.key + pq_pk is well formed
	f := newV2Fx(t)
	k := newKey(t)
	f.S["revocation"] = map[string]any{"epoch_uri": "u", "max_age_s": jnum(60), "key": k.id, "pq_pk": dg("pq")}
	f.signRoot()
	if r := sessionRootShape(deep(t, f.S)); r != "" {
		t.Fatalf("revocation key + pq_pk: %s", r)
	}
}

func TestMutV2StrictRevocationEvidence(t *testing.T) {
	f := newV2Fx(t)
	f.withRevocation(60)
	set := newRevSet(t, "pca-intent:session:zz")
	run := func(mut func(ev map[string]any)) bool {
		ev := f.evidence(f.revAuth, set, v2Now-1_000, v2Now+300_000)
		mut(ev)
		f.ctx["session"].(map[string]any)["revocation"] = ev
		return f.verify().Checks["intent_session"]
	}
	if !run(func(map[string]any) {}) {
		t.Fatal("well-formed evidence")
	}
	ep := func(k string, v any) func(ev map[string]any) {
		return func(ev map[string]any) { ev["epoch"].(map[string]any)[k] = v }
	}
	for name, mut := range map[string]func(ev map[string]any){
		"not_after-string":      ep("not_after", "1800000300000"),
		"issued_at-null":        ep("issued_at", nil),
		"set_size-fraction":     ep("set_size", json.Number("1.5")),
		"instance_id-number":    ep("instance_id", jnum(1)),
		"guardian_epoch-null":   ep("guardian_epoch", nil),
		"alg-number":            ep("alg", jnum(1)),
		"alg-unsupported":       ep("alg", "x-unregistered"),
		"pq_pk-null":            ep("pq_pk", nil),
		"evidence-epoch-absent": func(ev map[string]any) { delete(ev, "epoch") },
		"evidence-epoch-null":   func(ev map[string]any) { ev["epoch"] = nil },
	} {
		if run(mut) {
			t.Fatalf("%s must fail", name)
		}
	}
	// a PQ epoch verifies only under S.revocation.pq_pk (S pins none here)
	if run(func(ev map[string]any) {
		e := ev["epoch"].(map[string]any)
		e["alg"], e["pq_pk"] = "ml-dsa-65", b64.EncodeToString(make([]byte, 1952))
	}) {
		t.Fatal("unpinned PQ epoch")
	}
}

func TestMutV2StrictSchemaNames(t *testing.T) {
	sch := func(mut func(params map[string]any)) bool {
		d := v2Schema()
		mut(d["verbs"].([]any)[0].(map[string]any)["params"].(map[string]any))
		return actionSchemaShapeOK(deep(t, withoutKeys(d)), false)
	}
	if !sch(func(map[string]any) {}) {
		t.Fatal("base schema")
	}
	for _, n := range []string{"constructor", "__proto__", "prototype"} {
		if sch(func(p map[string]any) {
			p["action.params."+n] = map[string]any{"type": "string", "semantic": "x", "sensitivity": "free"}
		}) {
			t.Fatalf("reserved parameter name %s", n)
		}
	}
	if !sch(func(p map[string]any) {
		p["action.params.toString"] = map[string]any{"type": "string", "semantic": "x", "sensitivity": "free", "required": false}
	}) {
		t.Fatal("toString is an ordinary parameter name")
	}
	if sch(func(p map[string]any) { p["action.params.offer_id"].(map[string]any)["default"] = nil }) {
		t.Fatal("default null is malformed")
	}
	if !sch(func(p map[string]any) { p["action.params.offer_id"].(map[string]any)["default"] = "OF-1" }) {
		t.Fatal("a string default")
	}
	// own reads of params: a params key named like an inherited member is ordinary data (undeclared here)
	got := conformAction(deep(t, newV2Fx(t).schema), "air.book", normalizeJSON(map[string]any{"offer_id": "x", "total": jnum(1), "add_ons": []any{}, "refundable": true, "constructor": "x"}))
	if got.OK || got.Code != "undeclared_param" || got.Path != "action.params.constructor" {
		t.Fatalf("own params read: %+v", got)
	}
}

func worldP(in any) map[string]any { r, _ := IntentWorldPrimitive(in); return r }
func provP(in any) map[string]any  { r, _ := IntentProvenancePrimitive(in); return r }
func clsP(in any) map[string]any   { r, _ := IntentClassifierPrimitive(in); return r }

func TestMutV2ReadPurpose(t *testing.T) {
	rp := func(in map[string]any) map[string]any { return IntentReadPurposePrimitive(in) }
	fields := []any{
		map[string]any{"path": "b", "class": "pii.contact"},
		map[string]any{"path": "a", "class": "pii.passport", "optional": true},
		map[string]any{"path": "c", "class": "public"},
		map[string]any{"path": "b", "class": "pii.contact"},
	}
	got := rp(map[string]any{"fields": fields, "purpose": "booking", "coverage": map[string]any{"booking": []any{"travel.*"}}})
	if !sameJSON(got, map[string]any{"outcome": "question", "minimise": []any{"a"}, "uncovered": []any{"b"}}) {
		t.Fatalf("uncovered: %v", got)
	}
	got = rp(map[string]any{"fields": fields, "purpose": "booking", "coverage": map[string]any{"booking": []any{"pii.*"}}, "on_uncovered": "deny"})
	if !sameJSON(got, map[string]any{"outcome": "allow", "minimise": []any{}, "uncovered": []any{}}) {
		t.Fatalf("covered by prefix: %v", got)
	}
	got = rp(map[string]any{"fields": fields, "purpose": "x", "coverage": map[string]any{"booking": []any{"*"}}, "on_uncovered": "deny"})
	if got["outcome"] != "deny" || !sameJSON(got["uncovered"], []any{"b"}) {
		t.Fatalf("unknown purpose: %v", got)
	}
	// an inherited purpose name is not covered
	got = rp(map[string]any{"fields": fields, "purpose": "constructor", "coverage": map[string]any{}})
	if got["outcome"] != "question" {
		t.Fatalf("constructor purpose: %v", got)
	}
	// UTF-8 byte order: U+FFFD sorts before U+1F600
	got = rp(map[string]any{"fields": []any{map[string]any{"path": "\U0001F600", "class": "x"}, map[string]any{"path": "\uFFFD", "class": "x"}}, "purpose": "p", "coverage": map[string]any{}})
	if !sameJSON(got["uncovered"], []any{"\uFFFD", "\U0001F600"}) {
		t.Fatalf("utf-8 order: %v", got["uncovered"])
	}
	malformed := map[string]any{"outcome": "deny", "minimise": []any{}, "uncovered": []any{}}
	for name, in := range map[string]map[string]any{
		"fields-null":      {"fields": nil, "purpose": "p", "coverage": map[string]any{}},
		"purpose-null":     {"fields": fields, "purpose": nil, "coverage": map[string]any{}},
		"coverage-null":    {"fields": fields, "purpose": "p", "coverage": nil},
		"coverage-entry":   {"fields": fields, "purpose": "p", "coverage": map[string]any{"p": "x"}},
		"pattern-number":   {"fields": fields, "purpose": "p", "coverage": map[string]any{"p": []any{jnum(1)}}},
		"field-no-class":   {"fields": []any{map[string]any{"path": "a"}}, "purpose": "p", "coverage": map[string]any{}},
		"optional-null":    {"fields": []any{map[string]any{"path": "a", "class": "x", "optional": nil}}, "purpose": "p", "coverage": map[string]any{}},
		"on_uncovered-bad": {"fields": fields, "purpose": "p", "coverage": map[string]any{}, "on_uncovered": "allow"},
		"on_uncovered-nil": {"fields": fields, "purpose": "p", "coverage": map[string]any{}, "on_uncovered": nil},
	} {
		if got := rp(in); !sameJSON(got, malformed) {
			t.Fatalf("%s: %v", name, got)
		}
	}
}

// In the pipeline (follows intentV2ContextError at HEAD): a ceiling with an extra member passes the context check and
// fails `layers` as that ceiling; an unknown wb.artifacts / wb.policy member fails `facts` (intentWBContextError).
func TestMutV2ClosedPoliciesInPipeline(t *testing.T) {
	withL := append(append([]string{}, v2Base...), "layers")
	f := newV2Fx(t)
	f.ctx["layers"] = map[string]any{"site": map[string]any{"predicates": []any{map[string]any{"verb": "*"}}, "note": "x"}}
	expectV2(t, "ceiling-extra-member", f.verify(), minus(withL, "layers"), "layers")
	f = newV2Fx(t)
	f.ctx["layers"] = map[string]any{"task": map[string]any{"predicates": []any{}}}
	expectCtxFail(t, "layers-unknown-member", f.verify(), true)
	for name, wb := range map[string]any{
		"artifacts-unknown": map[string]any{"artifacts": map[string]any{"receipts": []any{}}},
		"policy-unknown":    map[string]any{"policy": map[string]any{"layers": map[string]any{}}},
	} {
		f = newV2Fx(t)
		f.ctx["wb"] = wb
		expectV2(t, name, f.verify(), v2Base, "facts")
	}
}

// Rule 15 freshness (5e718f47): receipt lifetime <= 15 min and age <= A_r, key-set version / age, retired keys.
func TestMutV2ReceiptFreshness(t *testing.T) {
	type tc struct {
		name             string
		issued, expires  int64
		ksIssued         int64
		ksVersion        int64
		na               *int64
		policy, versions map[string]any
		pass             bool
	}
	cases := []tc{
		{name: "base", issued: v2Now, expires: v2Now + 60_000, ksIssued: v2Now - 100, ksVersion: 1, pass: true},
		{name: "lifetime==15min", issued: v2Now - 1_000, expires: v2Now - 1_000 + 900_000, ksIssued: v2Now - 100, ksVersion: 1, pass: true},
		{name: "lifetime>15min", issued: v2Now - 1_000, expires: v2Now - 1_000 + 900_001, ksIssued: v2Now - 100, ksVersion: 1},
		{name: "age==default", issued: v2Now - 900_000, expires: v2Now, ksIssued: v2Now - 100, ksVersion: 1, pass: true},
		{name: "age==policy", issued: v2Now - 10_000, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 1,
			policy: map[string]any{"acc": map[string]any{"max_receipt_age_s": jnum(10)}}, pass: true},
		{name: "age>policy", issued: v2Now - 10_001, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 1,
			policy: map[string]any{"acc": map[string]any{"max_receipt_age_s": jnum(10)}}},
		{name: "keyset-age==default", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 3_600_000, ksVersion: 1, pass: true},
		{name: "keyset-age>default", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 3_600_001, ksVersion: 1},
		{name: "keyset-age>policy", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 2_001, ksVersion: 1,
			policy: map[string]any{"acc": map[string]any{"max_keyset_age_s": jnum(2)}}},
		{name: "keyset-future==60s", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now + 60_000, ksVersion: 1, pass: true},
		{name: "keyset-future>60s", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now + 60_001, ksVersion: 1},
		// tracked {version, digest}: "SAME" = the presented set's digest
		{name: "version==tracked-same-digest", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 2, versions: map[string]any{"version": jnum(2), "digest": "SAME"}, pass: true},
		{name: "version==tracked-other-digest (equivocation)", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 2, versions: map[string]any{"version": jnum(2), "digest": dg("other-set")}},
		{name: "version<tracked (rollback)", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 1, versions: map[string]any{"version": jnum(2), "digest": "SAME"}},
		{name: "version>tracked", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 3, versions: map[string]any{"version": jnum(2), "digest": dg("older-set")}, pass: true},
		{name: "version-0", issued: v2Now, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 0},
		{name: "retired-not_after==now-60s", issued: v2Now - 70_000, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 1, na: i64(v2Now - 60_000), pass: true},
		{name: "retired-not_after==now-60001", issued: v2Now - 70_000, expires: v2Now + 1_000, ksIssued: v2Now - 100, ksVersion: 1, na: i64(v2Now - 60_001)},
	}
	for _, c := range cases {
		f := newV2Fx(t)
		f.useSequenced()
		r := f.receipt(f.seqKey, "s2", func(r map[string]any) {
			r["issued_at"], r["expires_at"] = jnum(c.issued), jnum(c.expires)
		})
		ks := []any{map[string]any{"kid": "s2", "pk": f.seqKey.id, "not_before": jnum(0)}}
		if c.na != nil {
			ks[0].(map[string]any)["not_after"] = jnum(*c.na)
		}
		body := map[string]any{"v": jnum(1), "kind": "pca-sequencer-keys", "sequencer": f.seqRoot.id, "version": jnum(c.ksVersion), "issued_at": jnum(c.ksIssued), "keys": ks}
		set := withoutKeys(body)
		set["sig"] = signDomain(t, f.seqRoot, sequencerKeysDomain, body)
		f.claimReceipt(r, 48_900, []any{set}, r)
		if c.policy != nil {
			f.ctx["policy"] = c.policy
		}
		if c.versions != nil {
			tracked := withoutKeys(c.versions)
			if tracked["digest"] == "SAME" {
				d, _ := sequencerKeySetDigest(deep(t, set))
				tracked["digest"] = d
			}
			f.ctx["acc"].(map[string]any)["keyset_versions"] = map[string]any{f.seqRoot.id: tracked}
		}
		if c.pass {
			expectV2(t, c.name, f.verify(), v2Base)
		} else {
			expectV2(t, c.name, f.verify(), minus(v2Base, "accumulators"), "accumulators")
		}
	}
	// policy.acc and acc.keyset_versions are typed: a malformed context
	for name, mut := range map[string]func(f *v2fx){
		"policy.acc-null":         func(f *v2fx) { f.ctx["policy"] = map[string]any{"acc": nil} },
		"policy.acc-unknown":      func(f *v2fx) { f.ctx["policy"] = map[string]any{"acc": map[string]any{"max_age_s": jnum(1)}} },
		"policy.acc-age-string":   func(f *v2fx) { f.ctx["policy"] = map[string]any{"acc": map[string]any{"max_receipt_age_s": "10"}} },
		"policy.acc-age-negative": func(f *v2fx) { f.ctx["policy"] = map[string]any{"acc": map[string]any{"max_keyset_age_s": jnum(-1)}} },
	} {
		f := newV2Fx(t)
		mut(f)
		expectCtxFail(t, name, f.verify(), true)
	}
	for name, kv := range map[string]any{"null": nil, "array": []any{}, "value-null": map[string]any{"r": nil}, "value-string": map[string]any{"r": "1"},
		"value-bare-number":    map[string]any{"r": jnum(1)},
		"value-unknown-member": map[string]any{"r": map[string]any{"version": jnum(1), "digest": dg("d"), "note": "x"}},
		"value-bad-digest":     map[string]any{"r": map[string]any{"version": jnum(1), "digest": "abc"}},
		"value-version-0":      map[string]any{"r": map[string]any{"version": jnum(0), "digest": dg("d")}},
		"value-no-digest":      map[string]any{"r": map[string]any{"version": jnum(1)}},
		"value-digest-null":    map[string]any{"r": map[string]any{"version": jnum(1), "digest": nil}},
	} {
		f := newV2Fx(t)
		f.ctx["acc"].(map[string]any)["keyset_versions"] = kv
		expectV2(t, "keyset_versions-"+name, f.verify(), minus(v2Base, "accumulators"), "accumulators")
	}
}

// The SDK parser keeps a JSON -0 as negative zero: it is never a non-negative safe integer (raw `input_json` members).
func TestMutV2NegativeZeroSurvivesParsing(t *testing.T) {
	v, err := ParseJSONLenient([]byte(`{"total": -0, "z": -0.0}`))
	if err != nil {
		t.Fatal(err)
	}
	m := normalizeJSON(v).(map[string]any)
	for _, k := range []string{"total", "z"} {
		if jsIsInt(m[k]) || jsIsNonNeg(m[k]) || m[k] != jsNumber(negZero()) {
			t.Fatalf("%s: %v", k, m[k])
		}
	}
	c := conformAction(deep(t, newV2Fx(t).schema), "air.book", normalizeJSON(map[string]any{"offer_id": "x", "total": json.Number("-0"), "add_ons": []any{}, "refundable": true}))
	if c.OK || c.Code != "bad_type" || c.Path != "action.params.total" {
		t.Fatalf("total -0: %+v", c)
	}
}

func negZero() float64 { z := 0.0; return -z }
