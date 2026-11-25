package pca

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// ---- MemoryStateStore

func TestG01ConsumeOnceRefusesEmptyKey(t *testing.T) {
	s := NewMemoryStateStore()
	ok, err := s.ConsumeOnce("", 1, 0)
	if ok || err != ErrConsumeOnce {
		t.Fatalf("ConsumeOnce(\"\") = %v, %v", ok, err)
	}
}

func g01OnceStore(n int, retain int64) *MemoryStateStore {
	s := NewMemoryStateStore()
	s.once = map[string]int64{}
	for i := 0; i < n; i++ {
		s.once["old"+strconv.Itoa(i)] = retain
	}
	return s
}

func TestG01ConsumeOncePruneBoundary(t *testing.T) {
	// 1023 expired records: no prune
	s := g01OnceStore(1023, 5)
	if len(s.once) != 1023 {
		t.Fatalf("setup: %d", len(s.once))
	}
	if ok, err := s.ConsumeOnce("new", 100, 10); !ok || err != nil || len(s.once) != 1024 {
		t.Fatalf("1023: ok=%v err=%v len=%d", ok, err, len(s.once))
	}
	// 1024 expired records: pruned before the insert
	s = g01OnceStore(1024, 5)
	if ok, err := s.ConsumeOnce("new", 100, 10); !ok || err != nil || len(s.once) != 1 {
		t.Fatalf("1024: ok=%v err=%v len=%d", ok, err, len(s.once))
	}
	// 1024 records whose horizon is now: still live, kept
	s = g01OnceStore(1024, 10)
	if ok, err := s.ConsumeOnce("new", 100, 10); !ok || err != nil || len(s.once) != 1025 {
		t.Fatalf("1024 live: ok=%v err=%v len=%d", ok, err, len(s.once))
	}
}

func TestG01ConsumeOnceExtendsHorizon(t *testing.T) {
	s := NewMemoryStateStore()
	if ok, err := s.ConsumeOnce("k", 100, 0); !ok || err != nil {
		t.Fatalf("first: %v %v", ok, err)
	}
	if ok, err := s.ConsumeOnce("k", 200, 50); ok || err != nil {
		t.Fatalf("live: %v %v", ok, err)
	}
	// the live record was extended to 200: at 150 it is still live
	if ok, err := s.ConsumeOnce("k", 300, 150); ok || err != nil {
		t.Fatalf("extended: %v %v", ok, err)
	}
}

func TestG01ClaimKeepsOtherStreams(t *testing.T) {
	s := NewMemoryStateStore()
	for _, k := range []string{"a", "b"} {
		if r, err := s.Claim(k, 1); !r.OK || err != nil {
			t.Fatalf("claim %s: %+v %v", k, r, err)
		}
	}
	r, err := s.Claim("a", 1)
	if r.OK || err != nil || r.LastCounter == nil || *r.LastCounter != 1 {
		t.Fatalf("replayed claim: %+v %v", r, err)
	}
}

// ---- small helpers

func TestG01RootCaveatsSkipsOnlyTheFirstEnvelope(t *testing.T) {
	ms := map[string]any{"type": "max_spend", "amount": 1.0}
	env := map[string]any{"type": envelopeCaveat, "n": 1.0}
	env2 := map[string]any{"type": envelopeCaveat, "n": 2.0}
	got := RootCaveats(map[string]any{"caveats": []any{ms, env, env2}})
	if want := []any{ms, env2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RootCaveats = %v", got)
	}
}

func TestG01ReversibilityRank(t *testing.T) {
	for c, want := range map[string]int{"irreversible": 2, "unknown": 2, "costly": 1, "rate_limited": 1, "reversible": 0} {
		if got := reversibilityRank(c); got != want {
			t.Fatalf("rank(%s) = %d, want %d", c, got, want)
		}
	}
	if got := reversibilityRank(nil); got != 2 {
		t.Fatalf("rank(nil) = %d", got)
	}
}

func TestG01MissingResolveGrant(t *testing.T) {
	in := AuthorizeInput{Risk: InsecureCalmRisk, Audience: "a", StateStore: NewMemoryStateStore(),
		IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }}
	if got := MissingAuthorizeComponents(in); !reflect.DeepEqual(got, []string{"ResolveGrant"}) {
		t.Fatalf("missing = %v", got)
	}
}

func TestG01HostCallbacksRecover(t *testing.T) {
	boom := func() { panic("g01 boom") }
	if st, failed := callRevocationState(func(_, _ map[string]any) (*RevocationState, error) { boom(); return nil, nil }, nil, nil); st != nil || !failed {
		t.Fatalf("callRevocationState: %v %v", st, failed)
	}
	if g, failed := callResolve(func(string) (map[string]any, error) { boom(); return nil, nil }, "r"); g != nil || !failed {
		t.Fatalf("callResolve: %v %v", g, failed)
	}
	if c, failed := callContext(func(map[string]any) (*AuthorizeContext, error) { boom(); return nil, nil }, nil); c != nil || !failed {
		t.Fatalf("callContext: %v %v", c, failed)
	}
	if c, failed := callIntentV2(func(map[string]any) (*IntentV2Context, error) { boom(); return nil, nil }, nil); c != nil || !failed {
		t.Fatalf("callIntentV2: %v %v", c, failed)
	}
	if r, failed := callRevoked(func(_, _ map[string]any) (bool, error) { boom(); return true, nil }, nil, nil); r || !failed {
		t.Fatalf("callRevoked: %v %v", r, failed)
	}
	if r, failed := callClaim(g01PanicStore{}, "k", 1); r.OK || !failed {
		t.Fatalf("callClaim: %+v %v", r, failed)
	}
	if ki := callK1(func(map[string]any) (*K1Input, error) { boom(); return nil, nil }, nil); ki != nil {
		t.Fatalf("callK1: %v", ki)
	}
	if g, failed := callResolve(func(string) (map[string]any, error) { return map[string]any{"id": "x"}, errors.New("e") }, "r"); g != nil || !failed {
		t.Fatalf("callResolve error: %v %v", g, failed)
	}
}

type g01PanicStore struct{}

func (g01PanicStore) Claim(string, int64) (ClaimResult, error) { panic("g01 store") }

func TestG01Decisive(t *testing.T) {
	c := &orderedChecks{order: []string{"a", "b"}, st: map[string]string{"a": "pass", "b": "fail"}}
	if got := decisive(c, []string{"x: 0", "a: stale", "b: why"}); got != "b: why" {
		t.Fatalf("decisive = %q", got)
	}
	if got := decisive(c, nil); got != "denied" {
		t.Fatalf("no reasons: %q", got)
	}
	if got := decisive(c, []string{"only"}); got != "only" {
		t.Fatalf("one reason: %q", got)
	}
	none := &orderedChecks{order: []string{"a"}, st: map[string]string{"a": "pass"}}
	if got := decisive(none, []string{"first", "second"}); got != "first" {
		t.Fatalf("nothing failing: %q", got)
	}
	// operation first, then plan_state, then insertion order
	all := &orderedChecks{order: []string{"a", "plan_state", "operation"},
		st: map[string]string{"a": "fail", "plan_state": "fail", "operation": "fail"}}
	rs := []string{"a: 1", "plan_state: 2", "operation: 3"}
	if got := decisive(all, rs); got != "operation: 3" {
		t.Fatalf("operation first: %q", got)
	}
	all.st["operation"] = "pass"
	if got := decisive(all, rs); got != "plan_state: 2" {
		t.Fatalf("plan_state second: %q", got)
	}
	all.st["plan_state"] = "pass"
	if got := decisive(all, rs); got != "a: 1" {
		t.Fatalf("insertion order: %q", got)
	}
	// a failing check with no reason of its own is skipped
	if got := decisive(&orderedChecks{order: []string{"a", "b"}, st: map[string]string{"a": "fail", "b": "fail"}},
		[]string{"z: 0", "b: 1"}); got != "b: 1" {
		t.Fatalf("reasonless failure: %q", got)
	}
}

// ---- jsonValue / safeIntNumber / copyParams

func g01Arr(n int, leaf any) any {
	v := leaf
	for i := 0; i < n; i++ {
		v = []any{v}
	}
	return v
}

type g01DupJSON struct{}

func (g01DupJSON) MarshalJSON() ([]byte, error) { return []byte(`{"a":1,"a":2}`), nil }

type g01PanicJSON struct{}

func (g01PanicJSON) MarshalJSON() ([]byte, error) { panic("g01 marshal") }

func g01JV(t *testing.T, name string, v any, wantOK bool) any {
	t.Helper()
	got, ok := jsonValue(v, 1)
	if ok != wantOK {
		t.Fatalf("%s: ok = %v, want %v (%v)", name, ok, wantOK, got)
	}
	if !ok && got != nil {
		t.Fatalf("%s: a refusal carries %v", name, got)
	}
	return got
}

func TestG01JSONValueDepth(t *testing.T) {
	g01JV(t, "arrays 32", g01Arr(32, 1.0), true)
	g01JV(t, "arrays 33", g01Arr(33, 1.0), false)
	g01JV(t, "maps 32", g01Nest(32, 1.0), true)
	g01JV(t, "maps 33", g01Nest(33, 1.0), false)
}

func TestG01JSONValueScalars(t *testing.T) {
	g01JV(t, "abc", json.Number("abc"), false)
	g01JV(t, "-1e400", json.Number("-1e400"), false)
	if got := g01JV(t, "1.5", json.Number("1.5"), true); got != json.Number("1.5") {
		t.Fatalf("1.5 -> %v", got)
	}
	if got := g01JV(t, "float 1.5", 1.5, true); got != json.Number("1.5") {
		t.Fatalf("float 1.5 -> %v", got)
	}
	g01JV(t, "NaN", math.NaN(), false)
	g01JV(t, "-Inf", math.Inf(-1), false)
	safe := uint64(maxSafeInt)
	if got := g01JV(t, "uint 5", uint(5), true); got != json.Number("5") {
		t.Fatalf("uint 5 -> %v", got)
	}
	if got := g01JV(t, "uint max", uint(safe), true); got != json.Number("9007199254740991") {
		t.Fatalf("uint max -> %v", got)
	}
	g01JV(t, "uint huge", ^uint(0), false)
	if got := g01JV(t, "uint64 5", uint64(5), true); got != json.Number("5") {
		t.Fatalf("uint64 5 -> %v", got)
	}
	if got := g01JV(t, "uint64 max", safe, true); got != json.Number("9007199254740991") {
		t.Fatalf("uint64 max -> %v", got)
	}
	g01JV(t, "uint64 max+1", safe+1, false)
	g01JV(t, "uint64 huge", uint64(math.MaxUint64), false)
	if got := g01JV(t, "struct", struct{ A int }{1}, true); !reflect.DeepEqual(got, map[string]any{"A": json.Number("1")}) {
		t.Fatalf("struct -> %#v", got)
	}
	g01JV(t, "chan", make(chan int), false)
	g01JV(t, "duplicate keys", g01DupJSON{}, false)
}

func TestG01SafeIntNumber(t *testing.T) {
	for _, c := range []struct {
		i    int64
		ok   bool
		want any
	}{{maxSafeInt, true, json.Number("9007199254740991")}, {-maxSafeInt, true, json.Number("-9007199254740991")},
		{maxSafeInt + 1, false, nil}, {-maxSafeInt - 1, false, nil}} {
		got, ok := safeIntNumber(c.i)
		if ok != c.ok || got != c.want {
			t.Fatalf("safeIntNumber(%d) = %v, %v", c.i, got, ok)
		}
	}
}

func TestG01CopyParams(t *testing.T) {
	m, ok := copyParams(map[string]any{"a": g01Arr(31, 1.0)})
	if !ok || m == nil {
		t.Fatal("31 nested arrays with a scalar: refused")
	}
	for name, p := range map[string]map[string]any{
		"NaN":       {"a": math.NaN()},
		"too deep":  {"a": g01Arr(32, []any{})},
		"bad utf-8": {"s": "\xff"},
	} {
		if m, ok := copyParams(p); ok || m != nil {
			t.Fatalf("%s: accepted %v", name, m)
		}
	}
}

// ---- coercePCActn / coreCheckOrder / planRoot

func TestG01CoercePCActn(t *testing.T) {
	var typedNil map[string]any
	if p, why := coercePCActn(typedNil); p != nil || why != "absent" {
		t.Fatalf("typed nil: %v %q", p, why)
	}
	want := map[string]any{"a": json.Number("1")}
	for _, in := range []any{`{"a":1}`, []byte(`{"a":1}`)} {
		if p, why := coercePCActn(in); why != "" || !reflect.DeepEqual(p, want) {
			t.Fatalf("%T: %v %q", in, p, why)
		}
	}
	for _, in := range []any{"{", []byte("{")} {
		if p, why := coercePCActn(in); p != nil || why != "undecodable" {
			t.Fatalf("%T {: %v %q", in, p, why)
		}
	}
	padded := []byte(`{"a":1}` + strings.Repeat(" ", MaxArtifactBytes-7))
	if len(padded) != MaxArtifactBytes {
		t.Fatalf("setup: %d", len(padded))
	}
	if p, why := coercePCActn(padded); why != "" || !reflect.DeepEqual(p, want) {
		t.Fatalf("padded to the limit: %v %q", p, why)
	}
}

func TestG01CoreCheckOrder(t *testing.T) {
	got := coreCheckOrder(map[string]bool{"wire": true, "zzz": false, "aaa": true})
	if want := []string{"wire", "aaa", "zzz"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v", got)
	}
}

func TestG01PlanRoot(t *testing.T) {
	if r, ok := planRoot([]map[string]any{nil}); ok || r != "" {
		t.Fatalf("nil node: %q %v", r, ok)
	}
	if r, ok := planRoot([]map[string]any{{"id": "n1", "pre": make(chan int)}}); ok || r != "" {
		t.Fatalf("chan pre: %q %v", r, ok)
	}
	if r, ok := planRoot([]map[string]any{{"verb": "v"}}); ok || r != "" {
		t.Fatalf("no id: %q %v", r, ok)
	}
	node := map[string]any{"id": "n1", "verb": "v", "resource": "r", "params_digest": "d", "reversibility_class": "reversible"}
	r, ok := planRoot([]map[string]any{node})
	pc, err := CommitPlan([]map[string]any{node})
	if !ok || err != nil || r != pc.Root || r == "" {
		t.Fatalf("valid node: %q %v vs %v %v", r, ok, pc, err)
	}
}

// ---- policyStep / envelopePredicates / k1StockList

func TestG01PolicyStep(t *testing.T) {
	inner := map[string]any{"verb": "v", "resource": "r", "params": map[string]any{}}
	actionCtx := map[string]any{"action": inner}
	cctx := map[string]any{"now": int64(1), "action": inner, "delegation_depth": 0}
	env := map[string]any{"predicates": []any{map[string]any{"verb": "v", "resource": "r"}}, "caveats": []any{}}
	grant := map[string]any{"caveats": []any{map[string]any{"type": envelopeCaveat}, SealedCaveat()}}
	tc := &ToolCall{Tool: "v", Args: map[string]any{}}
	if why := policyStep(env, grant, cctx, actionCtx, tc, true); len(why) != 0 {
		t.Fatalf("k1 on: %v", why)
	}
	if why := policyStep(env, grant, cctx, actionCtx, tc, false); !reflect.DeepEqual(why, []string{"root caveat(s) not satisfied: sealed"}) {
		t.Fatalf("k1 off: %q", why)
	}
	if why := policyStep(nil, grant, cctx, actionCtx, tc, true); !reflect.DeepEqual(why, []string{"grant carries no valid envelope"}) {
		t.Fatalf("no envelope: %q", why)
	}
}

func TestG01EnvelopePredicatesRecovers(t *testing.T) {
	ctx := map[string]any{"action": map[string]any{"verb": "v", "resource": "abc", "params": map[string]any{}}}
	ok, why := envelopePredicates([]any{map[string]any{"verb": "v", "resource": "re:abc"}}, ctx, nil)
	if ok || why != "predicate evaluation error (fail closed)" {
		t.Fatalf("nil budget: %v %q", ok, why)
	}
}

func TestG01K1StockListEmpty(t *testing.T) {
	if got := k1StockList([]any{}, []any{"x"}); !reflect.DeepEqual(got, []any{"x"}) {
		t.Fatalf("k1StockList = %v", got)
	}
}

// ---- IsAuthorizedFor

func TestG01IsAuthorizedFor(t *testing.T) {
	params := map[string]any{"a": 1.0}
	cp, _ := copyParams(params)
	d, _ := ParamsDigest(cp)
	res := AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "v", Resource: "r", ParamsDigest: d}}
	op := func(v, r string, p map[string]any) *Operation { return &Operation{Verb: v, Resource: r, Params: p} }
	if !IsAuthorizedFor(res, op("v", "r", params)) {
		t.Fatal("the exact operation is not authorized")
	}
	for name, o := range map[string]*Operation{
		"verb": op("w", "r", params), "resource": op("v", "s", params), "params": op("v", "r", map[string]any{"a": 2.0}),
		"empty verb": op("", "r", params), "nil op": nil,
	} {
		if IsAuthorizedFor(res, o) {
			t.Fatalf("%s: authorized", name)
		}
	}
	denied := res
	denied.Allow = false
	if IsAuthorizedFor(denied, op("v", "r", params)) {
		t.Fatal("a denied result authorizes")
	}
	if IsAuthorizedFor(AuthorizeResult{Allow: true}, op("v", "r", params)) {
		t.Fatal("a result without an operation authorizes")
	}
	empty, _ := ParamsDigest(map[string]any{})
	e := AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "v", Resource: "r", ParamsDigest: empty}}
	if IsAuthorizedFor(e, op("v", "r", map[string]any{"a": math.NaN()})) {
		t.Fatal("NaN params authorized")
	}
	if IsAuthorizedFor(e, op("v", "r", map[string]any{"a": g01PanicJSON{}})) {
		t.Fatal("panicking params authorized")
	}
}

// ---- v2Env

func TestG01V2EnvMalformed(t *testing.T) {
	host := map[string]any{"host": 1.0}
	for _, k := range []string{"acc", "mon", "canon", "world", "prov", "class"} {
		host[k] = "reserved"
	}
	got := v2Env(map[string]any{"intent_session": map[string]any{}}, map[string]any{}, &IntentV2Context{malformed: true}, 0, host)
	if want := map[string]any{"host": 1.0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("v2Env = %v", got)
	}
}

func TestG01V2EnvComputed(t *testing.T) {
	f := newV2Fx(t)
	ctx := IntentV2ContextFromJSON(f.ctx)
	want := decideIntentV2(f.p2(), f.grant, ctx, float64(f.now)).env
	if len(want) == 0 {
		t.Fatal("setup: the fixture computes no v2 env")
	}
	if got := v2Env(f.p2(), f.grant, ctx, f.now, nil); !reflect.DeepEqual(got, any(want)) {
		t.Fatalf("v2Env = %v, want %v", got, want)
	}
}
