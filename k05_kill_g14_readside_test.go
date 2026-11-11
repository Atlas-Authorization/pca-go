package pca

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// g14: read-side validation boundaries (read grant bodies, entries, read receipts), RedactRead's request checks and
// redaction edges, read-receipt chains, the mode ranks and CheckSink's fail-closed catch.

const g14rsKey = "F8t5-ytBIPKx7GXkGY1uCLKOgT_rAeSkAIObheGAgM4" // any 32-byte base64url value

func g14rsN(s string) json.Number { return json.Number(s) }

func g14rsLabels(prefix string, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%02d", prefix, i)
	}
	return out
}

func g14rsObj(prefix string, n int, v func() any) map[string]any {
	out := map[string]any{}
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("%s%02d", prefix, i)] = v()
	}
	return out
}

func g14rsEntry() map[string]any {
	return map[string]any{"verb": "customers.get", "resource_prefix": "customers/", "purposes": []any{"support"},
		"modes": map[string]any{"pii": "last4"}, "default_mode": "drop"}
}

func TestK05KillG14ReadModeRank(t *testing.T) {
	for m, want := range map[string]int{"show": 0, "last4": 1, "bucket:7": 2, "bucket:100": 2, "token": 3, "hash": 4, "drop": 5} {
		if got := k5ModeRank(m); got != want {
			t.Errorf("k5ModeRank(%q) = %d, want %d", m, got, want)
		}
	}
}

func TestK05KillG14ReadIsBMP(t *testing.T) {
	for s, want := range map[string]bool{"": true, "abc": true, "\uffff": true, "a\U00010000": false, "\U0010ffff": false} {
		if got := k5IsBMP(s); got != want {
			t.Errorf("k5IsBMP(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestK05KillG14ReadEntry(t *testing.T) {
	cases := []struct {
		name string
		mut  func(e map[string]any)
		want bool
	}{
		{"base", func(map[string]any) {}, true},
		{"extra key", func(e map[string]any) { e["zzz"] = g14rsN("1") }, false},
		{"missing key", func(e map[string]any) { delete(e, "default_mode") }, false},
		{"verb empty", func(e map[string]any) { e["verb"] = "" }, false},
		{"verb 128", func(e map[string]any) { e["verb"] = strings.Repeat("v", 128) }, true},
		{"verb 129", func(e map[string]any) { e["verb"] = strings.Repeat("v", 129) }, false},
		{"prefix 512", func(e map[string]any) { e["resource_prefix"] = strings.Repeat("r", 512) }, true},
		{"prefix 513", func(e map[string]any) { e["resource_prefix"] = strings.Repeat("r", 513) }, false},
		{"purposes unsorted", func(e map[string]any) { e["purposes"] = []any{"b", "a"} }, false},
		{"purposes 16", func(e map[string]any) { e["purposes"] = g14rsLabels("p", 16) }, true},
		{"purposes 17", func(e map[string]any) { e["purposes"] = g14rsLabels("p", 17) }, false},
		{"purposes empty", func(e map[string]any) { e["purposes"] = []any{} }, false},
		{"modes not an object", func(e map[string]any) { e["modes"] = "x" }, false},
		{"modes 32", func(e map[string]any) { e["modes"] = g14rsObj("m", 32, func() any { return "show" }) }, true},
		{"modes 33", func(e map[string]any) { e["modes"] = g14rsObj("m", 33, func() any { return "show" }) }, false},
		{"default mode unknown", func(e map[string]any) { e["default_mode"] = "bogus" }, false},
		{"mode key not a label", func(e map[string]any) { e["modes"] = map[string]any{"BAD": "show"} }, false},
		{"mode value unknown", func(e map[string]any) { e["modes"] = map[string]any{"pii": "bogus"} }, false},
	}
	for _, c := range cases {
		e := g14rsEntry()
		c.mut(e)
		if got := k5ValidEntry(e); got != c.want {
			t.Errorf("%s: k5ValidEntry = %v, want %v", c.name, got, c.want)
		}
	}
	if k5ValidEntry("x") {
		t.Error("a non-object entry is accepted")
	}
}

func g14rsBody() map[string]any {
	return map[string]any{"v": g14rsN("1"), "id": "rg-1", "principal": g14rsKey, "issued_at": g14rsN("1"), "expires_at": g14rsN("2"),
		"reads": []any{g14rsEntry()}, "caps": map[string]any{"pii": g14rsN("3")},
		"sinks": map[string]any{"ext": map[string]any{"allow": []any{"public"}, "escalate": []any{"pii"}}}}
}

func TestK05KillG14ReadGrantBody(t *testing.T) {
	sink := func(allow, esc []any) map[string]any {
		return map[string]any{"ext": map[string]any{"allow": allow, "escalate": esc}}
	}
	entries := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = g14rsEntry()
		}
		return out
	}
	emptySink := func() any { return map[string]any{"allow": []any{}, "escalate": []any{}} }
	cases := []struct {
		name string
		mut  func(b map[string]any)
		want bool
	}{
		{"base", func(map[string]any) {}, true},
		{"extra key", func(b map[string]any) { b["zzz"] = g14rsN("1") }, false},
		{"v 2", func(b map[string]any) { b["v"] = g14rsN("2") }, false},
		{"v string", func(b map[string]any) { b["v"] = "1" }, false},
		{"id invalid", func(b map[string]any) { b["id"] = "bad id" }, false},
		{"principal invalid", func(b map[string]any) { b["principal"] = "x" }, false},
		{"issued_at negative", func(b map[string]any) { b["issued_at"] = g14rsN("-1") }, false},
		{"expires_at string", func(b map[string]any) { b["expires_at"] = "x" }, false},
		{"reads not an array", func(b map[string]any) { b["reads"] = "x" }, false},
		{"reads empty", func(b map[string]any) { b["reads"] = []any{} }, false},
		{"reads 32", func(b map[string]any) { b["reads"] = entries(32) }, true},
		{"reads 33", func(b map[string]any) { b["reads"] = entries(33) }, false},
		{"reads bad entry", func(b map[string]any) { b["reads"] = []any{"x"} }, false},
		{"caps not an object", func(b map[string]any) { b["caps"] = "x" }, false},
		{"caps 32", func(b map[string]any) { b["caps"] = g14rsObj("c", 32, func() any { return g14rsN("1") }) }, true},
		{"caps 33", func(b map[string]any) { b["caps"] = g14rsObj("c", 33, func() any { return g14rsN("1") }) }, false},
		{"caps key not a label", func(b map[string]any) { b["caps"] = map[string]any{"BAD": g14rsN("1")} }, false},
		{"caps value negative", func(b map[string]any) { b["caps"] = map[string]any{"pii": g14rsN("-1")} }, false},
		{"sinks not an object", func(b map[string]any) { b["sinks"] = "x" }, false},
		{"sinks 16", func(b map[string]any) { b["sinks"] = g14rsObj("s", 16, emptySink) }, true},
		{"sinks 17", func(b map[string]any) { b["sinks"] = g14rsObj("s", 17, emptySink) }, false},
		{"sink key invalid", func(b map[string]any) { b["sinks"] = map[string]any{"bad key": emptySink()} }, false},
		{"sink not an object", func(b map[string]any) { b["sinks"] = map[string]any{"ext": "x"} }, false},
		{"sink extra key", func(b map[string]any) {
			b["sinks"] = map[string]any{"ext": map[string]any{"allow": []any{}, "escalate": []any{}, "z": []any{}}}
		}, false},
		{"allow unsorted", func(b map[string]any) { b["sinks"] = sink([]any{"b", "a"}, []any{}) }, false},
		{"escalate unsorted", func(b map[string]any) { b["sinks"] = sink([]any{}, []any{"b", "a"}) }, false},
		{"allow 16", func(b map[string]any) { b["sinks"] = sink(g14rsLabels("l", 16), []any{}) }, true},
		{"allow 17", func(b map[string]any) { b["sinks"] = sink(g14rsLabels("l", 17), []any{}) }, false},
		{"escalate 16", func(b map[string]any) { b["sinks"] = sink([]any{}, g14rsLabels("l", 16)) }, true},
		{"escalate 17", func(b map[string]any) { b["sinks"] = sink([]any{}, g14rsLabels("l", 17)) }, false},
		{"allow and escalate overlap", func(b map[string]any) { b["sinks"] = sink([]any{"a"}, []any{"a"}) }, false},
	}
	for _, c := range cases {
		b := g14rsBody()
		c.mut(b)
		if got := k5ValidReadGrantBody(b); got != c.want {
			t.Errorf("%s: k5ValidReadGrantBody = %v, want %v", c.name, got, c.want)
		}
	}
	if k5ValidReadGrantBody("x") {
		t.Error("a non-object body is accepted")
	}
}

func g14rsRcpt() map[string]any {
	return map[string]any{"v": g14rsN("1"), "grant": g14rsKey, "verb": "customers.get", "resource": "customers/77", "purpose": "support",
		"seq": g14rsN("0"), "prev": nil,
		"fields":    map[string]any{"name": map[string]any{"class": "public", "action": "shown", "kind": nil, "vd": g14rsKey}},
		"labels":    []any{"public"},
		"issued_at": g14rsN("1"), "signer": g14rsKey, "sig": "s"}
}

func TestK05KillG14ReadReceiptShape(t *testing.T) {
	field := func(f map[string]any) func(r map[string]any) {
		return func(r map[string]any) {
			base := map[string]any{"class": "public", "action": "shown", "kind": nil, "vd": g14rsKey}
			for k, v := range f {
				base[k] = v
			}
			r["fields"] = map[string]any{"name": base}
		}
	}
	shown := func() any { return map[string]any{"class": "public", "action": "shown", "kind": nil, "vd": g14rsKey} }
	cases := []struct {
		name string
		mut  func(r map[string]any)
		want bool
	}{
		{"base", func(map[string]any) {}, true},
		{"extra key", func(r map[string]any) { r["zzz"] = g14rsN("1") }, false},
		{"missing sig", func(r map[string]any) { delete(r, "sig") }, false},
		{"v 2", func(r map[string]any) { r["v"] = g14rsN("2") }, false},
		{"grant invalid", func(r map[string]any) { r["grant"] = "x" }, false},
		{"verb empty", func(r map[string]any) { r["verb"] = "" }, false},
		{"verb 128", func(r map[string]any) { r["verb"] = strings.Repeat("v", 128) }, true},
		{"verb 129", func(r map[string]any) { r["verb"] = strings.Repeat("v", 129) }, false},
		{"resource 512", func(r map[string]any) { r["resource"] = strings.Repeat("r", 512) }, true},
		{"resource 513", func(r map[string]any) { r["resource"] = strings.Repeat("r", 513) }, false},
		{"purpose invalid", func(r map[string]any) { r["purpose"] = "bad purpose" }, false},
		{"seq negative", func(r map[string]any) { r["seq"] = g14rsN("-1") }, false},
		{"seq 1 prev invalid", func(r map[string]any) { r["seq"], r["prev"] = g14rsN("1"), "x" }, false},
		{"seq 1 prev digest", func(r map[string]any) { r["seq"], r["prev"] = g14rsN("1"), g14rsKey }, true},
		{"seq 0 prev digest", func(r map[string]any) { r["prev"] = g14rsKey }, false},
		{"seq 1 prev null", func(r map[string]any) { r["seq"] = g14rsN("1") }, false},
		{"issued_at negative", func(r map[string]any) { r["issued_at"] = g14rsN("-1") }, false},
		{"signer invalid", func(r map[string]any) { r["signer"] = "x" }, false},
		{"labels unsorted", func(r map[string]any) { r["labels"] = []any{"ref", "public"} }, false},
		{"labels 32", func(r map[string]any) { r["labels"] = g14rsLabels("l", 32) }, true},
		{"labels 33", func(r map[string]any) { r["labels"] = g14rsLabels("l", 33) }, false},
		{"sig not a string", func(r map[string]any) { r["sig"] = g14rsN("1") }, false},
		{"fields not an object", func(r map[string]any) { r["fields"] = "x" }, false},
		{"fields 64", func(r map[string]any) { r["fields"] = g14rsObj("f", 64, shown) }, true},
		{"fields 65", func(r map[string]any) { r["fields"] = g14rsObj("f", 65, shown) }, false},
		{"field name invalid", func(r map[string]any) { r["fields"] = map[string]any{"bad key": shown()} }, false},
		{"field not an object", func(r map[string]any) { r["fields"] = map[string]any{"name": "x"} }, false},
		{"field extra key", field(map[string]any{"z": g14rsN("1")}), false},
		{"class not a string", field(map[string]any{"class": g14rsN("1")}), false},
		{"class not a label", field(map[string]any{"class": "BAD"}), false},
		{"class unclassified", field(map[string]any{"class": "unclassified", "action": "dropped"}), true},
		{"action unknown", field(map[string]any{"action": "other"}), false},
		{"action masked", field(map[string]any{"action": "masked", "kind": "token"}), true},
		{"kind not a string", field(map[string]any{"kind": g14rsN("1")}), false},
		{"vd invalid", field(map[string]any{"vd": "x"}), false},
	}
	for _, c := range cases {
		r := g14rsRcpt()
		c.mut(r)
		if got := k5ValidReadReceipt(r); got != c.want {
			t.Errorf("%s: k5ValidReadReceipt = %v, want %v", c.name, got, c.want)
		}
	}
	if k5ValidReadReceipt("x") {
		t.Error("a non-object receipt is accepted")
	}
}

// g14rsVectors: the shared read-side vectors (fresh decode each call, so tests may edit what they get).
func g14rsVectors(t *testing.T) (R map[string]any, sinks map[string][]any) {
	t.Helper()
	R = load(t, "readside-vectors.json")
	sinks = map[string][]any{}
	for _, x := range R["sinks"].([]any) {
		c := x.(map[string]any)
		sinks[c["name"].(string)], _ = c["receipts"].([]any)
	}
	return R, sinks
}

func g14rsInput(t *testing.T) ReadInput {
	t.Helper()
	R, _ := g14rsVectors(t)
	for _, x := range R["redact"].([]any) {
		c := x.(map[string]any)
		if c["name"] != "support-view" {
			continue
		}
		i := c["input"].(map[string]any)
		return ReadInput{Grant: R["grants"].(map[string]any)["main"], Principal: i["principal"].(string), Now: i["now"], Verb: i["verb"].(string),
			Resource: i["resource"].(string), Purpose: i["purpose"].(string), Schema: i["schema"], Record: i["record"], Tighten: i["tighten"],
			Salt: i["salt"].(string), Counts: i["counts"]}
	}
	t.Fatal("support-view vector missing")
	return ReadInput{}
}

func TestK05KillG14RedactRequest(t *testing.T) {
	cases := []struct {
		name     string
		mut      func(in *ReadInput)
		decision string
		code     string
	}{
		{"base", func(*ReadInput) {}, "allow", ""},
		{"salt 15", func(in *ReadInput) { in.Salt = strings.Repeat("s", 15) }, "deny", "bad_request"},
		{"salt 16", func(in *ReadInput) { in.Salt = strings.Repeat("s", 16) }, "allow", ""},
		{"now == issued_at", func(in *ReadInput) { in.Now = g14rsN("1799996400000") }, "allow", ""},
		// a lone surrogate in the salt makes the value digest non-canonical: the panic is caught, deny bad_request
		{"salt with a lone surrogate", func(in *ReadInput) { in.Salt = "\xed\xa0\x80" + "0123456789abcdef" }, "deny", "bad_request"},
		{"verb 128", func(in *ReadInput) { in.Verb = strings.Repeat("v", 128) }, "deny", "no_read_scope"},
		{"verb 129", func(in *ReadInput) { in.Verb = strings.Repeat("v", 129) }, "deny", "bad_request"},
		{"resource 512", func(in *ReadInput) { in.Resource = "customers/" + strings.Repeat("r", 502) }, "allow", ""},
		{"resource 513", func(in *ReadInput) { in.Resource = "customers/" + strings.Repeat("r", 503) }, "deny", "bad_request"},
		{"purpose invalid", func(in *ReadInput) { in.Purpose = "bad purpose" }, "deny", "bad_request"},
		{"schema fields not an object", func(in *ReadInput) { in.Schema = map[string]any{"fields": "x", "required": []any{}} }, "deny", "bad_request"},
		{"schema required not an array", func(in *ReadInput) {
			in.Schema = map[string]any{"fields": map[string]any{"name": "public"}, "required": "x"}
		}, "deny", "bad_request"},
		{"schema field name invalid", func(in *ReadInput) {
			in.Schema = map[string]any{"fields": map[string]any{"name": "public", "bad key": "public"}, "required": []any{}}
		}, "deny", "bad_request"},
		{"schema field class invalid", func(in *ReadInput) {
			in.Schema = map[string]any{"fields": map[string]any{"name": "BAD"}, "required": []any{}}
		}, "deny", "bad_request"},
		{"required names an unknown field", func(in *ReadInput) {
			in.Schema = map[string]any{"fields": map[string]any{"name": "public"}, "required": []any{"missing"}}
		}, "deny", "bad_request"},
		{"tighten not an object", func(in *ReadInput) { in.Tighten = "x" }, "deny", "bad_request"},
		{"record of 33 members", func(in *ReadInput) { in.Record = g14rsObj("k", 33, func() any { return g14rsN("1") }) }, "deny", "bad_request"},
		{"counts key invalid", func(in *ReadInput) { in.Counts = map[string]any{"BAD": g14rsN("1")} }, "deny", "bad_request"},
		{"counts value negative", func(in *ReadInput) { in.Counts = map[string]any{"pii": g14rsN("-1")} }, "deny", "bad_request"},
		{"grant with an extra member", func(in *ReadInput) {
			g := map[string]any{"z": g14rsN("1")}
			for k, v := range in.Grant.(map[string]any) {
				g[k] = v
			}
			in.Grant = g
		}, "deny", "bad_grant"},
	}
	for _, c := range cases {
		in := g14rsInput(t)
		c.mut(&in)
		if r := RedactRead(in); r.Decision != c.decision || r.Code != c.code || r.Counts == nil {
			t.Errorf("%s: %s/%s counts %v, want %s/%s", c.name, r.Decision, r.Code, r.Counts, c.decision, c.code)
		}
	}
}

func TestK05KillG14RedactModes(t *testing.T) {
	// support entry: pii last4, financial bucket:100
	in := g14rsInput(t)
	in.Tighten = map[string]any{"financial": "bucket:10"} // the same rank as bucket:100: not stricter, ignored
	if r := RedactRead(in); r.Decision != "allow" || r.View["balance"] != g14rsN("12300") {
		t.Errorf("equal-rank tighten: %s %v", r.Decision, r.View["balance"])
	}
	in = g14rsInput(t)
	rec := in.Record.(map[string]any)
	rec["ssn"] = "abcde" // five scalars: more than four, so last4 shows
	rec["balance"] = g14rsN("0")
	r := RedactRead(in)
	if r.Decision != "allow" || r.View["ssn"] != "****bcde" || r.View["balance"] != g14rsN("0") {
		t.Errorf("edges: %s ssn=%v balance=%v", r.Decision, r.View["ssn"], r.View["balance"])
	}
	if f := r.Fields["balance"]; f.Action != "masked" || f.Kind != "bucket" {
		t.Errorf("balance field %+v", f)
	}
}

func TestK05KillG14ReadChain(t *testing.T) {
	R, sinks := g14rsVectors(t)
	rs := R["keys"].(map[string]any)["rs"].(string)
	gd := R["digests"].(map[string]any)["grant"].(string)
	chain := sinks["chain-of-two-public-reads"]
	other := sinks["pii-may-not-leave"]
	if len(chain) != 2 || len(other) != 1 {
		t.Fatalf("vectors: chain %d, other %d", len(chain), len(other))
	}
	const now = 1_800_000_000_000
	check := func(name string, receipts any, at int64, wantLabels []string, wantCode string, wantAt int) {
		t.Helper()
		l, code, i := ReadChainLabels(receipts, rs, gd, at)
		if code != wantCode || i != wantAt || !reflect.DeepEqual(l, wantLabels) {
			t.Errorf("%s: %v %q %d, want %v %q %d", name, l, code, i, wantLabels, wantCode, wantAt)
		}
	}
	check("not an array", "x", now, nil, "bad_receipt", 0)
	check("not an object", []any{"x"}, now, nil, "bad_receipt", 0)
	check("issued exactly now", []any{chain[0]}, 1_799_999_980_000, []string{"public", "ref"}, "", -1)
	check("chain of two", chain, now, []string{"public", "ref"}, "", -1)
	// a validly signed receipt 1 whose prev is the digest of a different receipt 0
	check("broken link", []any{other[0], chain[1]}, now, nil, "bad_receipt", 1)
	forged := map[string]any{}
	for k, v := range chain[0].(map[string]any) {
		forged[k] = v
	}
	forged["sig"] = chain[1].(map[string]any)["sig"] // well-formed, but not this receipt's signature
	check("wrong signature", []any{forged}, now, nil, "bad_receipt", 0)
}

func TestK05KillG14SinkFailClosed(t *testing.T) {
	res := func() (res SinkResult) {
		defer k5SinkFailClosed(&res)
		res = SinkResult{"allow", "", nil}
		panic("boom")
	}()
	if res.Decision != "deny" || res.Code != "bad_request" || res.Labels == nil || len(res.Labels) != 0 {
		t.Fatalf("caught panic: %+v", res)
	}
	res = func() (res SinkResult) {
		defer k5SinkFailClosed(&res)
		return SinkResult{"allow", "", []string{"a"}}
	}()
	if res.Decision != "allow" || len(res.Labels) != 1 {
		t.Fatalf("no panic: %+v", res)
	}
}
