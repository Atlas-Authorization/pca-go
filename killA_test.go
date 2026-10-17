package pca

// Mutation kill tests for intent_acc.go (rule 15: accumulator / monitor declarations, reservation receipts, sequencer
// key sets, receipt freshness and arithmetic). Oracle: packages/pca/src/intent-acc.ts (ACC_ID_RE, KID_RE, UNIT_RE,
// MAX_SESSION_ACCUMULATORS / MONITORS = 16, MAX_MONITOR_WITHIN = 64, MAX_RECEIPT_LIFETIME_MS = 900_000,
// DEFAULT_MAX_RECEIPT_AGE_MS = 900_000, accReceiptShapeError, sequencerKeySetShapeError, verifyReceiptAgainstHolder,
// receiptArithmeticOk). Each case pins one boundary or one disjunct of a rule.

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func killACopy(m map[string]any) map[string]any {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if err := d.Decode(&out); err != nil {
		panic(err)
	}
	return out
}

func killAWith(base map[string]any, k string, v any) map[string]any {
	m := killACopy(base)
	m[k] = v
	return m
}

func killAWithout(base map[string]any, k string) map[string]any {
	m := killACopy(base)
	delete(m, k)
	return m
}

// ---- matchKid (KID_RE = ^[A-Za-z0-9_.:-]{1,64}$) -------------------------------------------------------------------

func TestKillAMatchKid(t *testing.T) {
	cases := map[string]bool{
		"": false, "a": true, "ab": true, strings.Repeat("k", 64): true, strings.Repeat("k", 65): false, strings.Repeat("k", 63): true,
		"z": true, "A": true, "Z": true, "0": true, "9": true, "_": true, ".": true, ":": true, "-": true,
		"`": false, "{": false, "@": false, "[": false, "/": false, ";": false, " ": false, "!a": false, "a!": false, "s2": true,
		"m": true, "M": true, "5": true, "a b": false, "é": false,
	}
	for s, want := range cases {
		if got := matchKid(s); got != want {
			t.Errorf("matchKid(%q) = %v, want %v", s, got, want)
		}
	}
	// every byte outside the class is refused alone and as a second character
	for c := 0; c < 256; c++ {
		in := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-'
		if got := matchKid(string([]byte{byte(c)})); got != in {
			t.Errorf("matchKid(byte %d) = %v, want %v", c, got, in)
		}
		if got := matchKid(string([]byte{'a', byte(c)})); got != in {
			t.Errorf("matchKid(a+byte %d) = %v, want %v", c, got, in)
		}
	}
}

// ---- predicateShapeOK --------------------------------------------------------------------------------------------

func TestKillAPredicateShape(t *testing.T) {
	cases := []struct {
		p    any
		want bool
	}{
		{"x", false}, {nil, false}, {map[string]any{}, false}, {map[string]any{"verb": "a"}, true},
		{map[string]any{"verb": []any{}}, false}, {map[string]any{"verb": []any{"a"}}, true}, {map[string]any{"verb": []any{"a", "b"}}, true},
		{map[string]any{"verb": []any{"a", jnum(1)}}, false}, {map[string]any{"verb": []any{jnum(1)}}, false}, {map[string]any{"verb": jnum(1)}, false},
	}
	for i, c := range cases {
		if got := predicateShapeOK(c.p); got != c.want {
			t.Errorf("case %d %v: got %v want %v", i, c.p, got, c.want)
		}
	}
}

// ---- accumulatorDeclError -----------------------------------------------------------------------------------------

func killAAcc() map[string]any {
	return map[string]any{"id": "trip_spend", "agg": "sum", "unit": "usd_cents", "sel": map[string]any{"accumulates_into": "spend.usd_cents"},
		"win": map[string]any{"kind": "task"}, "key": nil, "domain_max": jnum(500_000), "holder": map[string]any{"kind": "site_local"}}
}

func killASeqHolder() map[string]any {
	return map[string]any{"kind": "sequenced", "uri": "https://atlas.example/seq", "root": dg("seqroot")}
}

func TestKillAAccumulatorDecl(t *testing.T) {
	base := killAAcc()
	verbsSel := map[string]any{"verbs": []any{"air.book"}}
	n := func(xs ...string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	many := func(k int) []any {
		out := make([]any, k)
		for i := range out {
			out[i] = fmt.Sprintf("v%d", i)
		}
		return out
	}
	walletAcc := func(agg string) map[string]any {
		a := killAWith(base, "agg", agg)
		a["sel"] = map[string]any{"event": "question"}
		a["holder"] = map[string]any{"kind": "wallet"}
		delete(a, "unit")
		return a
	}
	type c struct {
		name string
		a    any
		want string
	}
	cases := []c{
		{"valid", base, ""},
		{"not-object", "x", "accumulator: not an object / unknown member"},
		{"unknown-member", killAWith(base, "extra", jnum(1)), "accumulator: not an object / unknown member"},
		{"id-non-string", killAWith(base, "id", jnum(1)), "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"},
		{"id-dash", killAWith(base, "id", "a-b"), "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"},
		{"id-proto", killAWith(base, "id", "__proto__"), "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"},
		{"id-constructor", killAWith(base, "id", "constructor"), "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"},
		{"id-64", killAWith(base, "id", strings.Repeat("a", 64)), ""},
		{"id-65", killAWith(base, "id", strings.Repeat("a", 65)), "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"},
		{"agg-bad", killAWith(base, "agg", "avg"), "accumulator agg"},
		{"val-bad-path", killAWith(base, "val", "foo"), "accumulator val"},
		{"val-non-string", killAWith(base, "val", jnum(1)), "accumulator val"},
		{"val-ok", killAWith(base, "val", "action.params.total"), ""},
		{"unit-bad", killAWith(base, "unit", "Bad!"), "accumulator unit"},
		{"unit-non-string", killAWith(base, "unit", jnum(1)), "accumulator unit"},
		{"unit-64", killAWith(base, "unit", strings.Repeat("u", 64)), ""},
		{"unit-65", killAWith(base, "unit", strings.Repeat("u", 65)), "accumulator unit"},
		{"unit-63", killAWith(base, "unit", strings.Repeat("u", 63)), ""},
		{"sel-not-object", killAWith(base, "sel", "x"), "accumulator sel"},
		{"sel-unknown", killAWith(base, "sel", map[string]any{"accumulates_into": "spend.usd_cents", "foo": jnum(1)}), "accumulator sel"},
		{"verbs-ok", killAWith(killAWith(base, "sel", verbsSel), "val", "action.params.total"), ""},
		{"verbs-empty", killAWith(killAWith(base, "sel", map[string]any{"verbs": []any{}}), "val", "action.params.total"), "accumulator sel.verbs"},
		{"verbs-not-array", killAWith(killAWith(base, "sel", map[string]any{"verbs": "air.book"}), "val", "action.params.total"), "accumulator sel.verbs"},
		{"verbs-64", killAWith(killAWith(base, "sel", map[string]any{"verbs": many(64)}), "val", "action.params.total"), ""},
		{"verbs-63", killAWith(killAWith(base, "sel", map[string]any{"verbs": many(63)}), "val", "action.params.total"), ""},
		{"verbs-65", killAWith(killAWith(base, "sel", map[string]any{"verbs": many(65)}), "val", "action.params.total"), "accumulator sel.verbs"},
		{"verbs-empty-string", killAWith(killAWith(base, "sel", map[string]any{"verbs": n("a", "")}), "val", "action.params.total"), "accumulator sel.verbs"},
		{"verbs-non-string", killAWith(killAWith(base, "sel", map[string]any{"verbs": []any{"a", jnum(1)}}), "val", "action.params.total"), "accumulator sel.verbs"},
		{"ai-bad", killAWith(base, "sel", map[string]any{"accumulates_into": "Bad!"}), "accumulator sel.accumulates_into"},
		{"ai-non-string", killAWith(base, "sel", map[string]any{"accumulates_into": jnum(1)}), "accumulator sel.accumulates_into"},
		{"win-not-object", killAWith(base, "win", "task"), "accumulator win"},
		{"win-task-extra", killAWith(base, "win", map[string]any{"kind": "task", "ms": jnum(1)}), "accumulator win task"},
		{"win-kind-bad", killAWith(base, "win", map[string]any{"kind": "forever"}), "accumulator win kind"},
		{"sliding-ok", killAWith(base, "win", map[string]any{"kind": "sliding", "ms": jnum(5)}), ""},
		{"sliding-ms-1", killAWith(base, "win", map[string]any{"kind": "sliding", "ms": jnum(1)}), ""},
		{"sliding-ms-0", killAWith(base, "win", map[string]any{"kind": "sliding", "ms": jnum(0)}), "accumulator win sliding"},
		{"sliding-ms-frac", killAWith(base, "win", map[string]any{"kind": "sliding", "ms": json.Number("1.5")}), "accumulator win sliding"},
		{"sliding-extra", killAWith(base, "win", map[string]any{"kind": "sliding", "ms": jnum(5), "t0": jnum(0)}), "accumulator win sliding"},
		{"period-ok", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(1), "t0": jnum(0)}), ""},
		{"period-ok2", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(7), "t0": jnum(3)}), ""},
		{"period-no-t0", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(7)}), "accumulator win period"},
		{"period-extra", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(7), "t0": jnum(3), "x": jnum(1)}), "accumulator win period"},
		{"period-ms-0", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(0), "t0": jnum(3)}), "accumulator win period"},
		{"period-ms-frac", killAWith(base, "win", map[string]any{"kind": "period", "ms": json.Number("1.5"), "t0": jnum(3)}), "accumulator win period"},
		{"period-ms-neg", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(-2), "t0": jnum(3)}), "accumulator win period"},
		{"period-t0-neg", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(7), "t0": jnum(-1)}), "accumulator win period"},
		{"period-t0-frac", killAWith(base, "win", map[string]any{"kind": "period", "ms": jnum(7), "t0": json.Number("0.5")}), "accumulator win period"},
		{"key-missing", killAWithout(base, "key"), "accumulator key"},
		{"key-bad", killAWith(base, "key", "foo"), "accumulator key"},
		{"key-non-string", killAWith(base, "key", jnum(1)), "accumulator key"},
		{"key-ok", killAWith(base, "key", "action.params.offer_id"), ""},
		{"domain-neg", killAWith(base, "domain_max", jnum(-1)), "accumulator domain_max"},
		{"cap-neg", killAWith(base, "cap", jnum(-1)), "accumulator cap"},
		{"holder-not-object", killAWith(base, "holder", "site_local"), "accumulator holder"},
		{"holder-kind-bad", killAWith(base, "holder", map[string]any{"kind": "cloud"}), "accumulator holder kind"},
		{"site-local-extra", killAWith(base, "holder", map[string]any{"kind": "site_local", "uri": "x"}), "accumulator holder members"},
		{"seq-ok", killAWith(base, "holder", killASeqHolder()), ""},
		{"seq-unknown", killAWith(base, "holder", killAWith(killASeqHolder(), "foo", "x")), "accumulator holder sequenced member"},
		{"seq-uri-empty", killAWith(base, "holder", killAWith(killASeqHolder(), "uri", "")), "accumulator holder uri"},
		{"seq-uri-missing", killAWith(base, "holder", killAWithout(killASeqHolder(), "uri")), "accumulator holder uri"},
		{"seq-root-bad", killAWith(base, "holder", killAWith(killASeqHolder(), "root", "x")), "accumulator holder root"},
		{"seq-root-pq-ok", killAWith(base, "holder", killAWith(killAWith(killASeqHolder(), "root_pq_pk", "AAAA"), "root_alg", "ml-dsa-65")), ""},
		{"seq-root-pq-bad", killAWith(base, "holder", killAWith(killAWith(killASeqHolder(), "root_pq_pk", "!!"), "root_alg", "ml-dsa-65")), "accumulator holder root_pq_pk"},
		{"seq-keys-uri-empty", killAWith(base, "holder", killAWith(killASeqHolder(), "keys_uri", "")), "accumulator holder keys_uri"},
		{"seq-keys-uri-non-string", killAWith(base, "holder", killAWith(killASeqHolder(), "keys_uri", jnum(1))), "accumulator holder keys_uri"},
		{"seq-keys-uri-ok", killAWith(base, "holder", killAWith(killASeqHolder(), "keys_uri", "https://atlas.example/keys")), ""},
		{"wallet-without-event", killAWith(base, "holder", map[string]any{"kind": "wallet"}), "accumulator wallet"},
		{"event-without-wallet", killAWithout(killAWith(base, "sel", map[string]any{"event": "question"}), "unit"), "accumulator wallet"},
		{"wallet-event-sum-ok", walletAcc("sum"), ""},
		{"wallet-event-max-ok", walletAcc("max"), ""},
		{"event-bad", killAWith(walletAcc("sum"), "sel", map[string]any{"event": "lunch"}), "accumulator sel.event"},
		{"event-and-verbs", killAWith(walletAcc("sum"), "sel", map[string]any{"event": "question", "verbs": n("a")}), "accumulator sel kind"},
		{"sum-verbs-no-val", killAWith(base, "sel", verbsSel), "accumulator needs val"},
		{"max-ai-no-val", killAWith(base, "agg", "max"), "accumulator needs val"},
		{"max-val-ok", killAWith(killAWith(base, "agg", "max"), "val", "action.params.total"), ""},
		{"count-ok", killAWith(base, "agg", "count"), ""},
		{"count-with-val", killAWith(killAWith(base, "agg", "count"), "val", "action.params.total"), "count takes no val"},
	}
	for _, c := range cases {
		if got := accumulatorDeclError(c.a); got != c.want {
			t.Errorf("%s: accumulatorDeclError = %q, want %q", c.name, got, c.want)
		}
	}
}

// ---- monitorDeclError / monitorStates ------------------------------------------------------------------------------

func TestKillAMonitorDecl(t *testing.T) {
	base := map[string]any{"id": "m", "kind": "never", "p": map[string]any{"verb": "x"}}
	rw := map[string]any{"id": "m", "kind": "responds_within", "p": map[string]any{"verb": "x"}, "q": map[string]any{"verb": "y"}, "within": jnum(3)}
	idErr := "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
	cases := []struct {
		name string
		m    any
		want string
	}{
		{"valid", base, ""},
		{"not-object", "x", "monitor shape"},
		{"unknown", killAWith(base, "foo", jnum(1)), "monitor shape"},
		{"id-dash", killAWith(base, "id", "a-b"), idErr},
		{"id-num", killAWith(base, "id", jnum(1)), idErr},
		{"id-proto", killAWith(base, "id", "__proto__"), idErr},
		{"id-prototype", killAWith(base, "id", "prototype"), idErr},
		{"id-64", killAWith(base, "id", strings.Repeat("m", 64)), ""},
		{"id-65", killAWith(base, "id", strings.Repeat("m", 65)), idErr},
		{"kind-bad", killAWith(base, "kind", "sometimes"), "monitor kind"},
		{"p-bad", killAWith(base, "p", "x"), "monitor p"},
		{"never-with-q", killAWith(base, "q", map[string]any{"verb": "y"}), "monitor q"},
		{"precedes-no-q", killAWith(base, "kind", "precedes"), "monitor q"},
		{"precedes-bad-q", killAWith(killAWith(base, "kind", "precedes"), "q", "y"), "monitor q"},
		{"status-admitted", killAWith(base, "status", "admitted"), ""},
		{"status-committed", killAWith(base, "status", "committed"), ""},
		{"status-bad", killAWith(base, "status", "pending"), "monitor status"},
		{"never-with-within", killAWith(base, "within", jnum(3)), "monitor within"},
		{"rw-ok", rw, ""},
		{"rw-no-within", killAWithout(rw, "within"), "monitor within"},
		{"rw-within-0", killAWith(rw, "within", jnum(0)), "monitor within range"},
		{"rw-within-1", killAWith(rw, "within", jnum(1)), ""},
		{"rw-within-64", killAWith(rw, "within", jnum(64)), ""},
		{"rw-within-65", killAWith(rw, "within", jnum(65)), "monitor within range"},
		{"rw-within-frac", killAWith(rw, "within", json.Number("1.5")), "monitor within range"},
	}
	for _, c := range cases {
		if got := monitorDeclError(c.m); got != c.want {
			t.Errorf("%s: monitorDeclError = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestKillAMonitorStates(t *testing.T) {
	cases := []struct {
		m    map[string]any
		want []string
	}{
		{map[string]any{"kind": "responds_within"}, []string{"idle", "missed"}},
		{map[string]any{"kind": "responds_within", "within": json.Number("1.5")}, []string{"idle", "missed"}},
		{map[string]any{"kind": "responds_within", "within": jnum(1)}, []string{"idle", "pending:1", "missed"}},
		{map[string]any{"kind": "responds_within", "within": jnum(2)}, []string{"idle", "pending:1", "pending:2", "missed"}},
		{map[string]any{"kind": "never"}, []string{"clean", "seen"}},
		{map[string]any{"kind": "always"}, []string{"ok", "broken"}},
		{map[string]any{"kind": "precedes"}, []string{"unmet", "met"}},
	}
	for i, c := range cases {
		if got := monitorStates(c.m); !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: monitorStates = %v, want %v", i, got, c.want)
		}
	}
}

// ---- session-root caps (MAX_SESSION_ACCUMULATORS / MAX_SESSION_MONITORS = 16) --------------------------------------

func TestKillASessionCaps(t *testing.T) {
	f := newV2Fx(t)
	if e := sessionRootShape(deep(t, f.S)); e != "" {
		t.Fatalf("fixture root: %s", e)
	}
	accs := func(k int) []any {
		out := make([]any, k)
		for i := range out {
			a := tripAcc()
			a["id"] = fmt.Sprintf("a%d", i)
			out[i] = a
		}
		return out
	}
	mons := func(k int) []any {
		out := make([]any, k)
		for i := range out {
			out[i] = map[string]any{"id": fmt.Sprintf("m%d", i), "kind": "never", "p": map[string]any{"verb": "x"}}
		}
		return out
	}
	for _, c := range []struct {
		k, v string
		n    int
		want string
	}{
		{"accumulators", "", 16, ""}, {"accumulators", "", 15, ""}, {"accumulators", "", 17, "accumulators must be an array of at most 16"},
		{"monitors", "", 16, ""}, {"monitors", "", 15, ""}, {"monitors", "", 17, "monitors must be an array of at most 16"},
	} {
		S := deepM(t, f.S)
		if c.k == "accumulators" {
			S["accumulators"] = deep(t, accs(c.n))
		} else {
			S["monitors"] = deep(t, mons(c.n))
		}
		if got := sessionRootShape(S); got != c.want {
			t.Errorf("%s x%d: %q, want %q", c.k, c.n, got, c.want)
		}
	}
}

// ---- accSelects / accValueOf / distinctKey -------------------------------------------------------------------------

func killASchemaDoc() map[string]any {
	acc := func() map[string]any {
		return map[string]any{"type": "integer", "accumulates_into": []any{"spend.usd_cents"}}
	}
	return map[string]any{"verbs": []any{
		map[string]any{"verb": "air.book", "params": map[string]any{"action.params.total": acc(), "action.params.fee": acc(),
			"action.params.offer_id": map[string]any{"type": "string"}}},
		map[string]any{"verb": "air.noparams"},
	}}
}

func TestKillAAccSelects(t *testing.T) {
	doc := killASchemaDoc()
	throwing := map[string]any{"verbs": []any{nil}}
	ai := map[string]any{"agg": "sum", "sel": map[string]any{"accumulates_into": "spend.usd_cents"}}
	aiOther := map[string]any{"agg": "sum", "sel": map[string]any{"accumulates_into": "miles"}}
	verbs := map[string]any{"agg": "sum", "sel": map[string]any{"verbs": []any{"air.search"}}}
	ev := map[string]any{"agg": "sum", "sel": map[string]any{"event": "question"}}
	cases := []struct {
		name        string
		a           map[string]any
		verb        string
		schema      any
		have        bool
		sel, throws bool
	}{
		{"event", ev, "air.book", doc, true, false, false},
		{"verbs-hit", verbs, "air.search", doc, true, true, false},
		{"verbs-miss", verbs, "air.book", doc, true, false, false},
		{"ai-no-schema", ai, "air.book", doc, false, false, false},
		{"ai-hit", ai, "air.book", doc, true, true, false},
		{"ai-throwing-schema", ai, "air.book", throwing, true, false, true},
		{"ai-unknown-verb", ai, "air.cancel", doc, true, false, false},
		{"ai-other-unit", aiOther, "air.book", doc, true, false, false},
		{"ai-verb-without-params", ai, "air.noparams", doc, true, false, true},
	}
	for _, c := range cases {
		s, th := accSelects(c.a, c.verb, c.schema, c.have)
		if s != c.sel || th != c.throws {
			t.Errorf("%s: accSelects = (%v, %v), want (%v, %v)", c.name, s, th, c.sel, c.throws)
		}
	}
}

func TestKillADistinctKey(t *testing.T) {
	for _, c := range []struct {
		x  any
		k  string
		ok bool
	}{
		{"a", `"a"`, true}, {jnum(7), "7", true}, {true, "", false}, {json.Number("1.5"), "", false}, {nil, "", false},
	} {
		k, ok := distinctKey(c.x)
		if k != c.k || ok != c.ok {
			t.Errorf("distinctKey(%v) = (%q, %v), want (%q, %v)", c.x, k, ok, c.k, c.ok)
		}
	}
}

func TestKillAAccValueOf(t *testing.T) {
	doc := killASchemaDoc()
	throwing := map[string]any{"verbs": []any{nil}}
	sum := map[string]any{"agg": "sum", "sel": map[string]any{"accumulates_into": "spend.usd_cents"}}
	sumVal := map[string]any{"agg": "sum", "val": "action.params.total", "sel": map[string]any{"verbs": []any{"air.book"}}}
	count := map[string]any{"agg": "count", "sel": map[string]any{"verbs": []any{"air.book"}}}
	dist := map[string]any{"agg": "distinct", "val": "action.params.offer_id", "sel": map[string]any{"verbs": []any{"air.book"}}}
	big := json.Number("9007199254740991")
	type want struct {
		v          accValue
		ok, throws bool
	}
	cases := []struct {
		name   string
		a      map[string]any
		verb   string
		params map[string]any
		schema any
		have   bool
		w      want
	}{
		{"count", count, "air.book", map[string]any{}, doc, true, want{accValue{val: 1}, true, false}},
		{"distinct", dist, "air.book", map[string]any{"offer_id": "OF-1"}, doc, true, want{accValue{val: 1, key: `"OF-1"`}, true, false}},
		{"distinct-bad", dist, "air.book", map[string]any{"offer_id": true}, doc, true, want{accValue{val: 1}, false, false}},
		{"val-ok", sumVal, "air.book", map[string]any{"total": jnum(5)}, doc, true, want{accValue{val: 5}, true, false}},
		{"val-neg", sumVal, "air.book", map[string]any{"total": jnum(-1)}, doc, true, want{accValue{}, false, false}},
		{"val-missing", sumVal, "air.book", map[string]any{}, doc, true, want{accValue{}, false, false}},
		{"ai-no-schema", sum, "air.book", map[string]any{"total": jnum(5)}, doc, false, want{accValue{}, false, false}},
		{"ai-throwing", sum, "air.book", map[string]any{"total": jnum(5)}, throwing, true, want{accValue{}, false, true}},
		{"ai-unknown-verb", sum, "air.cancel", map[string]any{"total": jnum(5)}, doc, true, want{accValue{}, false, false}},
		{"ai-no-params", sum, "air.noparams", map[string]any{"total": jnum(5)}, doc, true, want{accValue{}, false, true}},
		{"ai-sum", sum, "air.book", map[string]any{"total": jnum(5), "fee": jnum(2)}, doc, true, want{accValue{val: 7}, true, false}},
		{"ai-one", sum, "air.book", map[string]any{"total": jnum(5)}, doc, true, want{accValue{val: 5}, true, false}},
		{"ai-neg", sum, "air.book", map[string]any{"total": jnum(5), "fee": jnum(-2)}, doc, true, want{accValue{}, false, false}},
		{"ai-overflow", sum, "air.book", map[string]any{"total": big, "fee": big}, doc, true, want{accValue{}, false, false}},
		{"ai-at-max", sum, "air.book", map[string]any{"total": big, "fee": jnum(0)}, doc, true, want{accValue{val: 9007199254740991}, true, false}},
	}
	for _, c := range cases {
		v, ok, th := accValueOf(c.a, c.verb, c.params, c.schema, c.have)
		if v != c.w.v || ok != c.w.ok || th != c.w.throws {
			t.Errorf("%s: accValueOf = (%+v, %v, %v), want (%+v, %v, %v)", c.name, v, ok, th, c.w.v, c.w.ok, c.w.throws)
		}
	}
}

// ---- pre-state / combine ---------------------------------------------------------------------------------------------

func TestKillAPreState(t *testing.T) {
	cases := []struct {
		agg  string
		s    any
		want bool
	}{
		{"sum", "x", false}, {"sum", map[string]any{"sum": jnum(3)}, true}, {"sum", map[string]any{"sum": jnum(-3)}, false},
		{"distinct", map[string]any{"values": "x"}, false}, {"distinct", map[string]any{"values": []any{jnum(1)}}, false},
		{"distinct", map[string]any{"values": []any{"a", jnum(1)}}, false}, {"distinct", map[string]any{"values": []any{"a", "b"}}, true},
		{"distinct", map[string]any{"values": []any{"a", "a"}}, false}, {"count", map[string]any{"count": jnum(0), "x": jnum(1)}, false},
	}
	for i, c := range cases {
		if got := preStateOK(c.agg, c.s); got != c.want {
			t.Errorf("case %d preStateOK(%s, %v) = %v, want %v", i, c.agg, c.s, got, c.want)
		}
	}
	if v := preValue("distinct", map[string]any{"values": []any{"a", "b"}}); v != 2 {
		t.Errorf("preValue distinct = %v", v)
	}
	if v := preValue("sum", map[string]any{"sum": jnum(5)}); v != 5 {
		t.Errorf("preValue sum = %v", v)
	}
	if v := preValue("max", map[string]any{"max": jnum(9)}); v != 9 {
		t.Errorf("preValue max = %v", v)
	}
	if p, ok := combineAcc("distinct", map[string]any{"values": []any{"a"}}, accValue{val: 1, key: "b"}); p != 2 || !ok {
		t.Errorf("combineAcc distinct new = %v %v", p, ok)
	}
	if p, ok := combineAcc("distinct", map[string]any{"values": []any{"a"}}, accValue{val: 1, key: "a"}); p != 1 || !ok {
		t.Errorf("combineAcc distinct seen = %v %v", p, ok)
	}
}

// ---- receipts ------------------------------------------------------------------------------------------------------

func killAReceipt(signer string) map[string]any {
	return map[string]any{"v": jnum(1), "kind": "pca-acc-receipt", "session": dg("session"), "acc": "trip_spend", "seq": jnum(3), "pre": jnum(10_000),
		"delta": jnum(38_900), "post": jnum(48_900), "pcactn_digest": dg("pd"), "aud": v2Aud, "issued_at": jnum(v2Now), "expires_at": jnum(v2Now + 60_000),
		"kid": "s2", "ledger": map[string]any{"index": jnum(7), "head": dg("head")}, "signer": signer, "sig": "AAAA"}
}

func TestKillAReceiptShape(t *testing.T) {
	base := killAReceipt(dg("signer"))
	if !accReceiptShapeOK(base) {
		t.Fatal("base receipt refused")
	}
	ok := map[string]map[string]any{
		"acc-64":       killAWith(base, "acc", strings.Repeat("a", 64)),
		"seq-1":        killAWith(base, "seq", jnum(1)),
		"zero-amounts": killAWith(killAWith(killAWith(base, "pre", jnum(0)), "delta", jnum(0)), "post", jnum(0)),
		"lifetime-max": killAWith(base, "expires_at", jnum(v2Now+900_000)),
		"issued-zero":  killAWith(killAWith(base, "issued_at", jnum(0)), "expires_at", jnum(1)),
		"alg-ed25519":  killAWith(base, "alg", "ed25519"),
		"pq-suite":     killAWith(killAWith(killAWith(base, "alg", "ml-dsa-65"), "pq_pk", "AAAA"), "pq_sig", "AAAA"),
	}
	bad := map[string]any{
		"not-object":          "x",
		"unknown":             killAWith(base, "extra", jnum(1)),
		"v-2":                 killAWith(base, "v", jnum(2)),
		"v-string":            killAWith(base, "v", "1"),
		"kind":                killAWith(base, "kind", "pca-acc-receipt2"),
		"session":             killAWith(base, "session", "x"),
		"acc-num":             killAWith(base, "acc", jnum(1)),
		"acc-dash":            killAWith(base, "acc", "a-b"),
		"acc-65":              killAWith(base, "acc", strings.Repeat("a", 65)),
		"seq-0":               killAWith(base, "seq", jnum(0)),
		"seq-frac":            killAWith(base, "seq", json.Number("1.5")),
		"seq-string":          killAWith(base, "seq", "3"),
		"pre-neg":             killAWith(base, "pre", jnum(-1)),
		"delta-neg":           killAWith(base, "delta", jnum(-1)),
		"post-neg":            killAWith(base, "post", jnum(-1)),
		"pcactn-digest":       killAWith(base, "pcactn_digest", "x"),
		"aud-empty":           killAWith(base, "aud", ""),
		"aud-num":             killAWith(base, "aud", jnum(1)),
		"issued-neg":          killAWith(killAWith(base, "issued_at", jnum(-1)), "expires_at", jnum(0)),
		"expires-neg":         killAWith(killAWith(base, "issued_at", jnum(-2)), "expires_at", jnum(-1)),
		"expires-before":      killAWith(base, "expires_at", jnum(v2Now-1)),
		"lifetime-over":       killAWith(base, "expires_at", jnum(v2Now+900_001)),
		"kid-space":           killAWith(base, "kid", "s 2"),
		"kid-num":             killAWith(base, "kid", jnum(2)),
		"ledger-not-object":   killAWith(base, "ledger", "x"),
		"ledger-extra":        killAWith(base, "ledger", map[string]any{"index": jnum(7), "head": dg("head"), "x": jnum(1)}),
		"ledger-index-neg":    killAWith(base, "ledger", map[string]any{"index": jnum(-1), "head": dg("head")}),
		"ledger-head":         killAWith(base, "ledger", map[string]any{"index": jnum(7), "head": "x"}),
		"signer":              killAWith(base, "signer", "x"),
		"alg-unknown":         killAWith(base, "alg", "rsa"),
		"alg-num":             killAWith(base, "alg", jnum(1)),
		"ed-with-pq-pk":       killAWith(base, "pq_pk", "AAAA"),
		"ed-with-pq-sig":      killAWith(base, "pq_sig", "AAAA"),
		"ed-named-with-pq-pk": killAWith(killAWith(base, "alg", "ed25519"), "pq_pk", "AAAA"),
		"no-sig":              killAWithout(base, "sig"),
		"sig-num":             killAWith(base, "sig", jnum(1)),
	}
	for name, r := range ok {
		if !accReceiptShapeOK(r) {
			t.Errorf("%s: refused", name)
		}
	}
	for name, r := range bad {
		if accReceiptShapeOK(r) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func killASignReceipt(t *testing.T, k fxKey, r map[string]any) map[string]any {
	r["sig"] = signDomain(t, k, accReceiptDomain, receiptBody(r))
	return r
}

func TestKillAReceiptSignature(t *testing.T) {
	k := newKey(t)
	r := killASignReceipt(t, k, killAReceipt(k.id))
	if !verifyAccReceiptSignature(r, k.id, nil) {
		t.Fatal("valid receipt refused")
	}
	// a correctly signed receipt with an unknown member (outside the signed body) is refused by the shape rule
	if verifyAccReceiptSignature(killAWith(r, "extra", "x"), k.id, nil) {
		t.Error("unknown member accepted")
	}
	// a forged signature (one bit flipped, still canonical base64url of 64 bytes)
	forged := killACopy(r)
	sig, _ := DecodeB64uStrict(forged["sig"].(string), -1)
	sig[5] ^= 1
	forged["sig"] = b64.EncodeToString(sig)
	if verifyAccReceiptSignature(forged, k.id, nil) {
		t.Error("forged signature accepted")
	}
	// a body field changed after signing
	if verifyAccReceiptSignature(killAWith(r, "post", jnum(48_901)), k.id, nil) {
		t.Error("tampered body accepted")
	}
	// another expected signer
	other := newKey(t)
	if verifyAccReceiptSignature(r, other.id, nil) {
		t.Error("foreign expected signer accepted")
	}
}

// ---- sequencer key sets --------------------------------------------------------------------------------------------

func killAKeySet(t *testing.T, root fxKey, sequencer string, version, issued int64, keys ...map[string]any) map[string]any {
	ks := make([]any, len(keys))
	for i, k := range keys {
		ks[i] = k
	}
	body := map[string]any{"v": jnum(1), "kind": "pca-sequencer-keys", "sequencer": sequencer, "version": jnum(version), "issued_at": jnum(issued), "keys": ks}
	out := withoutKeys(body)
	out["sig"] = signDomain(t, root, sequencerKeysDomain, body)
	return out
}

func TestKillAKeySetShape(t *testing.T) {
	entry := map[string]any{"kid": "s2", "pk": dg("k"), "not_before": jnum(10)}
	base := map[string]any{"v": jnum(1), "kind": "pca-sequencer-keys", "sequencer": dg("root"), "version": jnum(1), "issued_at": jnum(v2Now - 100),
		"keys": []any{entry}, "sig": "AAAA"}
	withEntry := func(e map[string]any) map[string]any { return killAWith(base, "keys", []any{e}) }
	keysN := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"kid": fmt.Sprintf("k%d", i), "pk": dg("k"), "not_before": jnum(0)}
		}
		return out
	}
	ok := map[string]map[string]any{
		"base":            base,
		"keys-256":        killAWith(base, "keys", keysN(256)),
		"keys-255":        killAWith(base, "keys", keysN(255)),
		"keys-2":          killAWith(base, "keys", keysN(2)),
		"not-after-equal": withEntry(killAWith(entry, "not_after", jnum(10))),
		"not-after-later": withEntry(killAWith(entry, "not_after", jnum(11))),
		"entry-alg":       withEntry(killAWith(entry, "alg", "ed25519")),
		"entry-pq":        withEntry(killAWith(killAWith(entry, "alg", "ml-dsa-65"), "pq_pk", "AAAA")),
		"pq-suite":        killAWith(killAWith(killAWith(base, "alg", "ml-dsa-65"), "pq_pk", "AAAA"), "pq_sig", "AAAA"),
		"version-2":       killAWith(base, "version", jnum(2)),
	}
	bad := map[string]any{
		"not-object":       "x",
		"unknown":          killAWith(base, "extra", jnum(1)),
		"v-2":              killAWith(base, "v", jnum(2)),
		"kind":             killAWith(base, "kind", "pca-sequencer-key"),
		"sequencer":        killAWith(base, "sequencer", "x"),
		"issued-neg":       killAWith(base, "issued_at", jnum(-1)),
		"version-0":        killAWith(base, "version", jnum(0)),
		"version-frac":     killAWith(base, "version", json.Number("1.5")),
		"version-missing":  killAWithout(base, "version"),
		"keys-not-array":   killAWith(base, "keys", "x"),
		"keys-empty":       killAWith(base, "keys", []any{}),
		"keys-257":         killAWith(base, "keys", keysN(257)),
		"entry-not-object": killAWith(base, "keys", []any{"x"}),
		"entry-unknown":    withEntry(killAWith(entry, "foo", jnum(1))),
		"entry-kid-space":  withEntry(killAWith(entry, "kid", "s 2")),
		"entry-kid-num":    withEntry(killAWith(entry, "kid", jnum(2))),
		"entry-dup-kid":    killAWith(base, "keys", []any{entry, killACopy(entry)}),
		"entry-pk":         withEntry(killAWith(entry, "pk", "x")),
		"entry-alg":        withEntry(killAWith(entry, "alg", "rsa")),
		"entry-pq-pk":      withEntry(killAWith(entry, "pq_pk", "!!")),
		"entry-nb-neg":     withEntry(killAWith(entry, "not_before", jnum(-1))),
		"entry-nb-missing": withEntry(killAWithout(entry, "not_before")),
		"entry-na-before":  withEntry(killAWith(entry, "not_after", jnum(9))),
		"entry-na-neg":     withEntry(killAWith(entry, "not_after", jnum(-1))),
		"alg-unknown":      killAWith(base, "alg", "rsa"),
		"ed-with-pq-pk":    killAWith(base, "pq_pk", "AAAA"),
		"ed-with-pq-sig":   killAWith(base, "pq_sig", "AAAA"),
		"ed-named-pq-pk":   killAWith(killAWith(base, "alg", "ed25519"), "pq_pk", "AAAA"),
		"no-sig":           killAWithout(base, "sig"),
	}
	for name, k := range ok {
		if !sequencerKeySetShapeOK(k) {
			t.Errorf("%s: refused", name)
		}
	}
	for name, k := range bad {
		if sequencerKeySetShapeOK(k) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKillAKeySetSignature(t *testing.T) {
	root, sk := newKey(t), newKey(t)
	ks := killAKeySet(t, root, root.id, 1, v2Now-100, keyEntry("s2", sk, 0, nil))
	if !verifySequencerKeySet(ks, root.id, nil, false) {
		t.Fatal("valid key set refused")
	}
	// signed by the root but naming another sequencer
	other := killAKeySet(t, root, dg("other-root"), 1, v2Now-100, keyEntry("s2", sk, 0, nil))
	if verifySequencerKeySet(other, root.id, nil, false) {
		t.Error("key set for another sequencer accepted")
	}
	if verifySequencerKeySet(ks, nil, nil, false) {
		t.Error("non-string root accepted")
	}
	forged := killACopy(ks)
	sig, _ := DecodeB64uStrict(forged["sig"].(string), -1)
	sig[0] ^= 1
	forged["sig"] = b64.EncodeToString(sig)
	if verifySequencerKeySet(forged, root.id, nil, false) {
		t.Error("forged key-set signature accepted")
	}
}

func TestKillATrackedKeySet(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{map[string]any{"version": jnum(1), "digest": dg("d")}, ""},
		{map[string]any{"version": jnum(2), "digest": dg("d")}, ""},
		{map[string]any{"version": jnum(0), "digest": dg("d")}, "a tracked key set version must be a safe integer >= 1"},
		{map[string]any{"version": json.Number("1.5"), "digest": dg("d")}, "a tracked key set version must be a safe integer >= 1"},
	} {
		if got := trackedKeySetError(c.v); got != c.want {
			t.Errorf("trackedKeySetError(%v) = %q, want %q", c.v, got, c.want)
		}
	}
}

// ---- verifyReceiptAgainstHolder --------------------------------------------------------------------------------------

func TestKillAReceiptAgainstHolder(t *testing.T) {
	root, sk := newKey(t), newKey(t)
	holder := map[string]any{"kind": "sequenced", "uri": "https://atlas.example/seq", "root": root.id}
	def := receiptFreshness{maxReceiptAgeMs: defaultMaxReceiptAgeMs, maxKeySetAgeMs: defaultMaxKeySetAgeMs}
	rcpt := func(issued int64) map[string]any {
		r := killAReceipt(sk.id)
		r["issued_at"], r["expires_at"] = jnum(issued), jnum(issued+60_000)
		return killASignReceipt(t, sk, r)
	}
	set := func(issued int64, nb int64) []any {
		return []any{killAKeySet(t, root, root.id, 1, issued, keyEntry("s2", sk, nb, nil))}
	}
	now := float64(v2Now)
	if !verifyReceiptAgainstHolder(rcpt(v2Now), holder, set(v2Now-100, 0), now, def) {
		t.Fatal("valid receipt refused")
	}
	// now must be a safe integer
	if verifyReceiptAgainstHolder(rcpt(v2Now), holder, set(v2Now-100, 0), now+0.5, def) {
		t.Error("fractional now accepted")
	}
	// negative bounds are refused even when the ages would satisfy them (receipt / set issued in the future skew)
	if verifyReceiptAgainstHolder(rcpt(v2Now+1_000), holder, set(v2Now-100, 0), now, receiptFreshness{maxReceiptAgeMs: -1, maxKeySetAgeMs: defaultMaxKeySetAgeMs}) {
		t.Error("negative receipt-age bound accepted")
	}
	if verifyReceiptAgainstHolder(rcpt(v2Now), holder, set(v2Now+1_000, 0), now, receiptFreshness{maxReceiptAgeMs: defaultMaxReceiptAgeMs, maxKeySetAgeMs: -1}) {
		t.Error("negative key-set-age bound accepted")
	}
	// a malformed tracked entry fails closed
	bad := receiptFreshness{maxReceiptAgeMs: defaultMaxReceiptAgeMs, maxKeySetAgeMs: defaultMaxKeySetAgeMs, tracked: map[string]any{"version": jnum(0), "digest": dg("d")}}
	if verifyReceiptAgainstHolder(rcpt(v2Now), holder, set(v2Now-100, 0), now, bad) {
		t.Error("malformed tracked key set accepted")
	}
	// the receipt was issued before the key's not_before
	if verifyReceiptAgainstHolder(rcpt(v2Now), holder, set(v2Now-100, v2Now+1), now, def) {
		t.Error("receipt before the key's not_before accepted")
	}
	// at not_before exactly: accepted
	if !verifyReceiptAgainstHolder(rcpt(v2Now), holder, set(v2Now-100, v2Now), now, def) {
		t.Error("receipt at the key's not_before refused")
	}
	// the receipt's age bound (default 15 min): exactly at the bound / one past
	if !verifyReceiptAgainstHolder(rcpt(v2Now-900_000), holder, set(v2Now-100, 0), now, def) {
		t.Error("receipt at the age bound refused")
	}
	if verifyReceiptAgainstHolder(rcpt(v2Now-900_001), holder, set(v2Now-100, 0), now, def) {
		t.Error("receipt past the age bound accepted")
	}
}

// The DEFAULT receipt-age bound (900 000 ms, no policy) end to end: a receipt issued 900 001 ms ago is refused by the
// holder check ("not signed by a key ..."), not merely as expired.
func TestKillADefaultReceiptAge(t *testing.T) {
	f := newV2Fx(t)
	f.useSequenced()
	issued := v2Now - 900_001
	r := f.receipt(f.seqKey, "s2", func(r map[string]any) {
		r["issued_at"], r["expires_at"] = jnum(issued), jnum(issued+900_000)
	})
	f.claimReceipt(r, 48_900, []any{f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, 0, nil))}, r)
	v := f.verify()
	if v.Allow || !strings.Contains(v.Reason, "the reservation receipt for 'trip_spend' is not signed by a key") {
		t.Fatalf("reason %q", v.Reason)
	}
	// one ms younger: the holder check passes and the receipt is refused as expired
	f = newV2Fx(t)
	f.useSequenced()
	issued = v2Now - 900_000
	r = f.receipt(f.seqKey, "s2", func(r map[string]any) {
		r["issued_at"], r["expires_at"] = jnum(issued), jnum(issued+899_999)
	})
	f.claimReceipt(r, 48_900, []any{f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, 0, nil))}, r)
	if v := f.verify(); v.Allow || !strings.Contains(v.Reason, "the reservation receipt for 'trip_spend' has expired") {
		t.Fatalf("reason %q", v.Reason)
	}
}

// ---- receiptArithmeticOk ---------------------------------------------------------------------------------------------

func TestKillAReceiptArithmetic(t *testing.T) {
	r := func(pre, delta, post int64) map[string]any {
		return map[string]any{"pre": jnum(pre), "delta": jnum(delta), "post": jnum(post)}
	}
	cases := []struct {
		agg  string
		r    map[string]any
		val  float64
		want bool
	}{
		{"sum", r(5, 3, 8), 3, true}, {"sum", r(5, 3, 9), 3, false}, {"sum", r(5, 4, 9), 3, false},
		{"count", r(5, 1, 6), 7, true}, {"count", r(0, 1, 1), 1, true}, {"count", r(5, 0, 5), 7, false}, {"count", r(5, 2, 7), 7, false},
		{"count", r(5, 1, 7), 7, false}, {"count", r(5, 1, 5), 7, false}, {"count", r(5, 1, 4), 7, false},
		{"max", r(5, 3, 5), 3, true}, {"max", r(5, 9, 9), 9, true}, {"max", r(5, 3, 3), 3, false}, {"max", r(5, 4, 5), 3, false},
		{"distinct", r(5, 1, 6), 1, true}, {"distinct", r(5, 0, 5), 1, true}, {"distinct", r(5, 2, 7), 1, false},
		{"distinct", r(5, 0, 6), 1, false}, {"distinct", r(5, 1, 5), 1, false}, {"distinct", r(5, 1, 4), 1, false},
		{"avg", r(5, 1, 6), 1, false},
	}
	for _, c := range cases {
		if got := receiptArithmeticOk(c.agg, c.r, c.val); got != c.want {
			t.Errorf("receiptArithmeticOk(%s, %v, %v) = %v, want %v", c.agg, c.r, c.val, got, c.want)
		}
	}
}
