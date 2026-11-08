package pca

import (
	"errors"
	"strings"
	"testing"
)

// ---- aggregate grant validators

func g12AggRule() map[string]any {
	return map[string]any{"verb": "orders.stats", "resource_prefix": "orders/", "purposes": []any{"analytics"}, "fns": []any{"count", "sum"},
		"min_group": jnum(1), "clamp": jnum(10), "epsilon_micro": jnum(5), "dp": false}
}

func g12AggBody(principal string, rules ...map[string]any) map[string]any {
	rs := []any{}
	for _, r := range rules {
		rs = append(rs, r)
	}
	return map[string]any{"v": jnum(1), "id": "g1", "principal": principal, "issued_at": jnum(1000), "expires_at": jnum(5000), "rules": rs,
		"epsilon_budget_micro": jnum(100), "max_queries": jnum(5)}
}

func g12With(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = v
	return out
}

func g12Seq(prefix string, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = prefix + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	return out
}

func TestG12AggRuleBounds(t *testing.T) {
	base := g12AggRule()
	cases := []struct {
		name string
		r    any
		want bool
	}{
		{"base", base, true},
		{"not an object", "x", false},
		{"extra key", g12With(base, "x", true), false},
		{"empty verb", g12With(base, "verb", ""), false},
		{"verb 128", g12With(base, "verb", strings.Repeat("v", 128)), true},
		{"verb 129", g12With(base, "verb", strings.Repeat("v", 129)), false},
		{"prefix 512", g12With(base, "resource_prefix", strings.Repeat("r", 512)), true},
		{"prefix 513", g12With(base, "resource_prefix", strings.Repeat("r", 513)), false},
		{"purposes unsorted", g12With(base, "purposes", []any{"b", "a"}), false},
		{"purposes empty", g12With(base, "purposes", []any{}), false},
		{"purposes 16", g12With(base, "purposes", g12Seq("p", 16)), true},
		{"purposes 17", g12With(base, "purposes", g12Seq("p", 17)), false},
		{"fns unsorted", g12With(base, "fns", []any{"sum", "count"}), false},
		{"fns empty", g12With(base, "fns", []any{}), false},
		{"min_group string", g12With(base, "min_group", "1"), false},
		{"min_group 0", g12With(base, "min_group", jnum(0)), false},
		{"clamp string", g12With(base, "clamp", "1"), false},
		{"clamp 1000000", g12With(base, "clamp", jnum(1000000)), true},
		{"clamp 1000001", g12With(base, "clamp", jnum(1000001)), false},
		{"eps string", g12With(base, "epsilon_micro", "1"), false},
		{"eps 1073741824", g12With(base, "epsilon_micro", jnum(1073741824)), true},
		{"eps 1073741825", g12With(base, "epsilon_micro", jnum(1073741825)), false},
		{"dp not a boolean", g12With(base, "dp", "yes"), false},
		{"dp eps 1", g12With(g12With(base, "dp", true), "epsilon_micro", jnum(1)), true},
		{"dp eps 0", g12With(g12With(base, "dp", true), "epsilon_micro", jnum(0)), false},
	}
	for _, c := range cases {
		if got := k5ValidAggRule(c.r); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestG12AggGrantBodyBounds(t *testing.T) {
	p := b64.EncodeToString(make([]byte, 32))
	base := g12AggBody(p, g12AggRule())
	rules := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = g12AggRule()
		}
		return out
	}
	bad := g12With(g12AggRule(), "verb", "")
	cases := []struct {
		name string
		b    any
		want bool
	}{
		{"base", base, true},
		{"not an object", "x", false},
		{"extra key", g12With(base, "x", true), false},
		{"v string", g12With(base, "v", "1"), false},
		{"v 2", g12With(base, "v", jnum(2)), false},
		{"id", g12With(base, "id", ""), false},
		{"principal", g12With(base, "principal", "x"), false},
		{"issued_at", g12With(base, "issued_at", "x"), false},
		{"expires_at", g12With(base, "expires_at", "x"), false},
		{"budget", g12With(base, "epsilon_budget_micro", "x"), false},
		{"max_queries", g12With(base, "max_queries", "x"), false},
		{"rules not a list", g12With(base, "rules", "x"), false},
		{"no rules", g12With(base, "rules", []any{}), false},
		{"16 rules", g12With(base, "rules", rules(16)), true},
		{"17 rules", g12With(base, "rules", rules(17)), false},
		{"a bad rule", g12With(base, "rules", []any{g12AggRule(), bad}), false},
	}
	for _, c := range cases {
		if got := k5ValidAggGrantBody(c.b); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

// ---- AggregateRead

func g12AggGrant(t *testing.T, k fxKey, rule map[string]any) map[string]any {
	body := g12AggBody(k.id, rule)
	return map[string]any{"body": body, "sig": signDomain(t, k, k5AggregateDomain, body)}
}

func g12AggIn(k fxKey, g any) AggregateInput {
	return AggregateInput{Grant: g, Principal: k.id, Now: jnum(2000), Verb: "orders.stats", Resource: "orders/eu", Purpose: "analytics", Fn: "count",
		Values: []any{jnum(1), jnum(2)}, Salt: "0123456789abcdef", Noise: "seeded"}
}

func g12IsEmptyFail(r AggregateResult) bool {
	return r.Decision == "deny" && r.Code == "bad_request" && r.Value == 0 && r.ChargedMicro == 0 && r.State.SpentMicro == 0 && r.State.Queries == 0 && len(r.State.Answered) == 0
}

func TestG12AggregateStateBounds(t *testing.T) {
	const mx = maxSafeIntI
	for name, st := range map[string]AggregateState{
		"spent -1":        {SpentMicro: -1, Queries: 3},
		"spent max+1":     {SpentMicro: mx + 1, Queries: 3},
		"queries -1":      {SpentMicro: 3, Queries: -1},
		"queries max+1":   {SpentMicro: 3, Queries: mx + 1},
		"answered max+1":  {SpentMicro: 3, Queries: 3, Answered: map[string]int64{"q": mx + 1}},
		"answered -max-1": {SpentMicro: 3, Queries: 3, Answered: map[string]int64{"q": -mx - 1}},
	} {
		if r := AggregateRead(AggregateInput{Principal: "x", State: st}); !g12IsEmptyFail(r) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// in range: the state is kept (cloned) on the refusal that follows (a malformed principal)
	for name, st := range map[string]AggregateState{
		"spent max":    {SpentMicro: mx, Queries: 2},
		"queries max":  {SpentMicro: 2, Queries: mx},
		"answered max": {SpentMicro: 2, Queries: 2, Answered: map[string]int64{"q": mx, "r": -mx}},
		"no answered":  {SpentMicro: 5, Queries: 2},
	} {
		r := AggregateRead(AggregateInput{Principal: "x", Now: jnum(1), State: st})
		if r.Decision != "deny" || r.Code != "bad_request" || r.State.SpentMicro != st.SpentMicro || r.State.Queries != st.Queries || len(r.State.Answered) != len(st.Answered) {
			t.Errorf("%s: %+v", name, r)
			continue
		}
		for k, v := range st.Answered {
			if r.State.Answered[k] != v {
				t.Errorf("%s: answered[%s] = %d", name, k, r.State.Answered[k])
			}
		}
	}
}

func TestG12AggregateRequestRefusals(t *testing.T) {
	k := newKey(t)
	g := g12AggGrant(t, k, g12AggRule())
	run := func(name string, in AggregateInput, want string) AggregateResult {
		t.Helper()
		r := AggregateRead(in)
		if (r.Decision == "allow") != (want == "allow") || (want != "allow" && r.Code != want) {
			t.Errorf("%s: %+v, want %s", name, r, want)
		}
		return r
	}
	base := g12AggIn(k, g)
	r := run("base", base, "allow")
	if r.Value != 2 || r.ChargedMicro != 0 || r.State.SpentMicro != 0 || r.State.Queries != 1 {
		t.Errorf("base: %+v", r)
	}
	mod := func(f func(*AggregateInput)) AggregateInput { in := base; f(&in); return in }
	run("bad now", mod(func(in *AggregateInput) { in.Now = "x" }), "bad_request")
	run("bad principal", mod(func(in *AggregateInput) { in.Principal = "x" }), "bad_request")
	run("grant not an object", mod(func(in *AggregateInput) { in.Grant = "x" }), "bad_grant")
	run("grant extra member", mod(func(in *AggregateInput) { in.Grant = g12With(g, "x", true) }), "bad_grant")
	run("now == issued_at", mod(func(in *AggregateInput) { in.Now = jnum(1000); in.Verb = "" }), "bad_request")
	run("verb 128", mod(func(in *AggregateInput) { in.Verb = strings.Repeat("v", 128) }), "no_read_scope")
	run("verb 129", mod(func(in *AggregateInput) { in.Verb = strings.Repeat("v", 129) }), "bad_request")
	run("resource 512", mod(func(in *AggregateInput) { in.Resource = "orders/" + strings.Repeat("r", 505) }), "allow")
	run("resource 513", mod(func(in *AggregateInput) { in.Resource = "orders/" + strings.Repeat("r", 506) }), "bad_request")
	run("purpose", mod(func(in *AggregateInput) { in.Purpose = "" }), "bad_request")
	run("fn", mod(func(in *AggregateInput) { in.Fn = "avg" }), "bad_request")
	run("noise", mod(func(in *AggregateInput) { in.Noise = "x" }), "bad_request")
	run("salt 15", mod(func(in *AggregateInput) { in.Salt = "0123456789abcde" }), "bad_request")
	run("values not a list", mod(func(in *AggregateInput) { in.Values = "x" }), "bad_request")
	million := func(n int) []any {
		v := make([]any, n)
		for i := range v {
			v[i] = 1
		}
		return v
	}
	if r := run("1000000 values", mod(func(in *AggregateInput) { in.Values = million(1000000) }), "allow"); r.Value != 1000000 {
		t.Errorf("1000000 values: %d", r.Value)
	}
	run("1000001 values", mod(func(in *AggregateInput) { in.Values = million(1000001) }), "bad_request")
}

func TestG12AggregateFailClosedPaths(t *testing.T) {
	k := newKey(t)
	g := g12AggGrant(t, k, g12AggRule())
	in := g12AggIn(k, g)
	in.State = AggregateState{SpentMicro: 7, Queries: 1}
	// a query digest that cannot be made (a lone surrogate in the resource) is the catch-all with an EMPTY state
	lone := in
	lone.Resource = "orders/\xed\xa0\x80"
	if r := AggregateRead(lone); !g12IsEmptyFail(r) {
		t.Errorf("lone surrogate: %+v", r)
	}
	// so is a grant digest that cannot be made
	old := k5GrantDigestFn
	k5GrantDigestFn = func(map[string]any) (string, bool) { return "", false }
	r := AggregateRead(in)
	k5GrantDigestFn = old
	if !g12IsEmptyFail(r) {
		t.Errorf("grant digest: %+v", r)
	}
	// a sampler RangeError (dp sum with clamp 0: a zero noise scale) is recovered into the same
	rule := g12With(g12AggRule(), "dp", true)
	rule["clamp"] = jnum(0)
	dp := g12AggIn(k, g12AggGrant(t, k, rule))
	dp.Fn = "sum"
	dp.State = AggregateState{SpentMicro: 7, Queries: 1}
	if r := AggregateRead(dp); !g12IsEmptyFail(r) {
		t.Errorf("sampler panic: %+v", r)
	}
}

// ---- vault

type g12VaultStore struct {
	puts               map[string]VaultEntry
	panicPut, panicGet bool
	entry              VaultEntry
	has                bool
}

func (s *g12VaultStore) Put(tok string, e VaultEntry) {
	if s.panicPut {
		panic("g12 put")
	}
	if s.puts == nil {
		s.puts = map[string]VaultEntry{}
	}
	s.puts[tok] = e
}

func (s *g12VaultStore) Get(string) (VaultEntry, bool) {
	if s.panicGet {
		panic("g12 get")
	}
	return s.entry, s.has
}

func g12VaultRead(t *testing.T) (map[string]any, ReadInput) {
	V := load(t, "vault-aggregate-vectors.json")
	grant := V["grants"].(map[string]any)["vault"].(map[string]any)["main"].(map[string]any)
	r := V["vault"].([]any)[0].(map[string]any)["redact"].(map[string]any)
	return grant, ReadInput{Grant: grant, Principal: r["principal"].(string), Now: r["now"], Verb: r["verb"].(string), Resource: r["resource"].(string),
		Purpose: r["purpose"].(string), Schema: r["schema"], Record: map[string]any{"cust": "c_77", "tax": "123-45", "zz": "q"},
		Tighten: map[string]any{"ssn": "hash"}, Salt: r["salt"].(string), Counts: r["counts"]}
}

func TestG12VaultMintsOnlyTokens(t *testing.T) {
	_, in := g12VaultRead(t)
	st := &g12VaultStore{}
	r := RedactReadWithVault(in, st)
	if r.Decision != "allow" || r.Fields["tax"].Kind != "hash" || r.Fields["tax"].Action != "masked" || r.Fields["zz"].Action != "dropped" {
		t.Fatalf("premise: %+v", r)
	}
	tok, _ := r.View["cust"].(string)
	if e, has := st.puts[tok]; len(st.puts) != 1 || !has || e.Cls != "ref" || e.Value != "c_77" {
		t.Fatalf("puts: %v", st.puts)
	}
	if r := RedactReadWithVault(in, &g12VaultStore{panicPut: true}); r.Decision != "deny" || r.Code != "bad_request" {
		t.Errorf("panicking store: %+v", r)
	}
	if r := RedactReadWithVault(in, nil); r.Decision != "allow" || len(r.View) != 2 {
		t.Errorf("no store: %+v", r)
	}
}

func TestG12DetokenizeStoreAndExpiry(t *testing.T) {
	grant, in := g12VaultRead(t)
	gd, ok := ReadGrantDigest(grant["body"].(map[string]any))
	if !ok {
		t.Fatal("digest")
	}
	now := int64(k5F(in.Now))
	run := func(st VaultStore) DetokenizeResult {
		return Detokenize(DetokenizeInput{Grant: grant, Principal: in.Principal, Now: in.Now, Sink: "payments", Token: "tok", Store: st})
	}
	if r := run(&g12VaultStore{panicGet: true}); r.Decision != "deny" || r.Code != "bad_request" || r.Value != nil {
		t.Errorf("panicking store: %+v", r)
	}
	if r := run(&g12VaultStore{entry: VaultEntry{Cls: "ref", Value: "v", Grant: gd, Exp: now + 1}, has: true}); r.Decision != "allow" || r.Value != "v" {
		t.Errorf("live: %+v", r)
	}
	for _, exp := range []int64{now, now - 1} {
		if r := run(&g12VaultStore{entry: VaultEntry{Cls: "ref", Value: "v", Grant: gd, Exp: exp}, has: true}); r.Decision != "deny" || r.Code != "expired" {
			t.Errorf("exp %d: %+v", exp-now, r)
		}
	}
}

// ---- the sampler

func g12Panic(f func()) (v any) {
	defer func() { v = recover() }()
	f()
	return nil
}

func TestG12SamplerConstants(t *testing.T) {
	if k5MaxSteps != 100000 || k5Steps != 100000 || k5Two48 != 1<<48 {
		t.Fatalf("%d %d %d", k5MaxSteps, k5Steps, k5Two48)
	}
}

func TestG12SamplerBoundsAndRejection(t *testing.T) {
	if v := g12Panic(func() { k5SeededDraws("x").uniform(0) }); v != k5RangeError("uniform: bad bound") {
		t.Errorf("uniform(0): %v", v)
	}
	if v := g12Panic(func() { k5SeededDraws("x").uniform(1<<47 + 1) }); v != k5RangeError("uniform: bad bound") {
		t.Errorf("uniform(2^47+1): %v", v)
	}
	if v := g12Panic(func() { k5SeededDraws("x").uniform(1 << 47) }); v != nil {
		t.Errorf("uniform(2^47): %v", v)
	}
	if got := k5SeededDraws("x").uniform(1); got != 0 {
		t.Errorf("uniform(1) = %d", got)
	}
	// the first 48-bit draw of seed g12s0 lies at or above the rejection limit for n = floor(2^48/3)+1: the second is used
	if got := k5SeededDraws("g12s0").uniform(93824992236886); got != 58251862805297 {
		t.Errorf("rejection: %d", got)
	}
	// n = draw/2 makes the limit exactly the first draw: rejected (r < limit is strict)
	if got := k5SeededDraws("g12s0").uniform(140088566478607); got != 51976260205246 {
		t.Errorf("limit draw: %d", got)
	}
	if v := g12Panic(func() { k5SeededDraws("\xed\xa0\x80").next48() }); v != k5RangeError("draws: bad block") {
		t.Errorf("bad seed: %v", v)
	}
	if v := g12Panic(func() { k5DiscreteLaplace(k5SeededDraws("x"), 0, 1) }); v != k5RangeError("laplace: bad rate") {
		t.Errorf("rate 0: %v", v)
	}
}

func TestG12SecureDrawsSeedAndEntropyFailure(t *testing.T) {
	if s := k5SecureDraws().seed; len(s) != 43 {
		t.Errorf("seed %q", s)
	}
	old := k5RandRead
	defer func() { k5RandRead = old }()
	k5RandRead = func([]byte) (int, error) { return 0, errors.New("g12 no entropy") }
	if v := g12Panic(func() { k5SecureDraws() }); v != k5RangeError("secure: no entropy") {
		t.Errorf("entropy: %v", v)
	}
}

// With the loop bound shrunk, seeds (found offline against the shared sampler vectors' stream) reach every bound exactly.
func TestG12SamplerStepBounds(t *testing.T) {
	old := k5Steps
	defer func() { k5Steps = old }()
	k5Steps = 2
	const n = 93824992236886
	if v := g12Panic(func() {
		if got := k5SeededDraws("g12s3").uniform(n); got != 73698542607184 {
			t.Errorf("uniform 2nd draw: %d", got)
		}
	}); v != nil {
		t.Errorf("uniform 2nd draw panicked: %v", v)
	}
	if v := g12Panic(func() { k5SeededDraws("g12s1").uniform(n) }); v != k5RangeError("uniform: no draw") {
		t.Errorf("uniform 2 rejections: %v", v)
	}
	if v := g12Panic(func() {
		if k5SeededDraws("g12s0").bernExpSmall(1, 1) {
			t.Error("bernExpSmall: want false at k = 2")
		}
	}); v != nil {
		t.Errorf("bernExpSmall panicked: %v", v)
	}
	if v := g12Panic(func() {
		if got := k5DiscreteLaplace(k5SeededDraws("g12s4"), 1, 1); got != 0 {
			t.Errorf("laplace 2nd round: %d", got)
		}
	}); v != nil {
		t.Errorf("laplace 2nd round panicked: %v", v)
	}
	if v := g12Panic(func() { k5DiscreteLaplace(k5SeededDraws("g12s18"), 1, 1) }); v != k5RangeError("laplace: no sample") {
		t.Errorf("laplace no sample: %v", v)
	}
	k5Steps = 3
	if v := g12Panic(func() {
		if got := k5DiscreteLaplace(k5SeededDraws("g12s1"), 1, 1); got != 3 {
			t.Errorf("laplace v = 3: %d", got)
		}
	}); v != nil {
		t.Errorf("laplace v = 3 panicked: %v", v)
	}
	if v := g12Panic(func() { k5DiscreteLaplace(k5SeededDraws("g12s6"), 1, 1) }); v != k5RangeError("laplace: no termination") {
		t.Errorf("laplace v = 4: %v", v)
	}
}
