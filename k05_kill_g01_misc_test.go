package pca

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// ---- missingcontext.go

var g01Untrusted = map[string]string{"subject": "agent_declared_untrusted", "action.params": "agent_declared_untrusted"}

// g01Nest wraps leaf in n maps keyed "a" (g01Nest(1, x) = {"a": x}).
func g01Nest(n int, leaf any) any {
	v := leaf
	for i := 0; i < n; i++ {
		v = map[string]any{"a": v}
	}
	return v
}

func g01Group(n int, leaf any) any {
	v := leaf
	for i := 0; i < n; i++ {
		v = map[string]any{"all_of": []any{v}}
	}
	return v
}

func g01Strs(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %q, want %q", what, got, want)
	}
}

func TestG01BindContextLeafDepth(t *testing.T) {
	// maps at depth 0..16 are expanded, the 18th level (depth 17) is a leaf
	b := BindContext(map[string]any{}, map[string]any{"subject": g01Nest(18, 1)}, g01Untrusted)
	g01Strs(t, "dropped", b.Dropped, []string{"subject" + strings.Repeat(".a", 17)})
	b = BindContext(map[string]any{}, map[string]any{"action": map[string]any{"params": g01Nest(18, 1)}}, g01Untrusted)
	g01Strs(t, "dropped", b.Dropped, []string{"action.params" + strings.Repeat(".a", 17)})
	// 17 levels end in the scalar leaf exactly at depth 17
	b = BindContext(map[string]any{}, map[string]any{"subject": g01Nest(17, 1)}, g01Untrusted)
	g01Strs(t, "dropped", b.Dropped, []string{"subject" + strings.Repeat(".a", 17)})
}

func TestG01BindContextLeaves(t *testing.T) {
	b := BindContext(map[string]any{}, map[string]any{"subject": map[string]any{"__proto__": 1, "x": 2}}, g01Untrusted)
	g01Strs(t, "dropped", b.Dropped, []string{"subject.x"})
	b = BindContext(map[string]any{}, map[string]any{"subject": map[string]any{"x": 2}}, g01Untrusted)
	g01Strs(t, "dropped", b.Dropped, []string{"subject.x"})
	// an empty object is a leaf, not an expanded (vanishing) node
	b = BindContext(map[string]any{}, map[string]any{"subject": map[string]any{"e": map[string]any{}}}, g01Untrusted)
	g01Strs(t, "dropped", b.Dropped, []string{"subject.e"})
	g01Strs(t, "conflicts", b.Conflicts, []string{})
}

func TestG01BindContextMerge(t *testing.T) {
	// a differing bound value is a conflict, an equal one is not
	// (JSON numbers: a Go float64 does not canonicalize, and a value that cannot be digested is itself a conflict)
	one, two := json.Number("1"), json.Number("2")
	b := BindContext(map[string]any{"action": map[string]any{}, "subject": map[string]any{"x": one}},
		map[string]any{"subject": map[string]any{"x": two}}, nil)
	g01Strs(t, "conflicts", b.Conflicts, []string{"subject.x"})
	b = BindContext(map[string]any{"action": map[string]any{}, "subject": map[string]any{"x": one}},
		map[string]any{"subject": map[string]any{"x": one}}, nil)
	g01Strs(t, "conflicts", b.Conflicts, []string{})

	// a supplied subject value never creates an action
	b = BindContext(map[string]any{}, map[string]any{"subject": map[string]any{"x": 1.0}}, nil)
	g01Strs(t, "conflicts", b.Conflicts, []string{})
	if want := map[string]any{"subject": map[string]any{"x": 1.0}}; !reflect.DeepEqual(b.Context, want) {
		t.Fatalf("context = %v, want %v", b.Context, want)
	}

	// supplied params into an empty bound context create the action shell
	b = BindContext(map[string]any{}, map[string]any{"action": map[string]any{"params": map[string]any{"x": 1.0}}}, nil)
	g01Strs(t, "conflicts", b.Conflicts, []string{})
	shell := map[string]any{"action": map[string]any{"verb": "", "resource": "", "params": map[string]any{"x": 1.0}}}
	if !reflect.DeepEqual(b.Context, shell) {
		t.Fatalf("context = %v, want %v", b.Context, shell)
	}

	// a bound null action is never replaced: the supplied params conflict and the null stays (shared vector
	// a-bound-action-null-is-not-replaced-by-params)
	b = BindContext(map[string]any{"action": nil}, map[string]any{"action": map[string]any{"params": map[string]any{"x": 1.0}}}, nil)
	g01Strs(t, "conflicts", b.Conflicts, []string{"action.params.x"})
	if want := map[string]any{"action": nil}; !reflect.DeepEqual(b.Context, want) {
		t.Fatalf("context = %v, want %v", b.Context, want)
	}

	// bound params are kept and merged
	b = BindContext(map[string]any{"action": map[string]any{"verb": "v", "resource": "r", "params": map[string]any{"a": 1.0}}},
		map[string]any{"action": map[string]any{"params": map[string]any{"b": 2.0}}}, nil)
	g01Strs(t, "conflicts", b.Conflicts, []string{})
	want := map[string]any{"action": map[string]any{"verb": "v", "resource": "r", "params": map[string]any{"a": 1.0, "b": 2.0}}}
	if !reflect.DeepEqual(b.Context, want) {
		t.Fatalf("context = %v, want %v", b.Context, want)
	}

	b = BindContext(nil, nil, nil)
	if b.Context == nil || len(b.Context) != 0 {
		t.Fatalf("context = %#v, want an empty non-nil map", b.Context)
	}
}

func TestG01BindContextPanicFailsClosed(t *testing.T) {
	mcPanicHook = func(where string) {
		if where == "bind" {
			panic("g01 bind")
		}
	}
	defer func() { mcPanicHook = nil }()
	sub := map[string]any{}
	want := []string{"?"}
	for i := 0; i < 10; i++ {
		sub[fmt.Sprintf("k%d", i)] = 1.0
		want = append(want, fmt.Sprintf("subject.k%d", i))
	}
	b := BindContext(map[string]any{"action": map[string]any{}}, map[string]any{"subject": sub}, nil)
	g01Strs(t, "conflicts", b.Conflicts, want)
}

func g01Collect(c any, ctx map[string]any, depth int) (map[string]bool, bool) {
	out := map[string]bool{}
	ill := false
	mcCollect(c, ctx, out, &ill, depth)
	return out, ill
}

func g01CollectIs(t *testing.T, name string, c any, ctx map[string]any, depth int, wantOut map[string]bool, wantIll bool) {
	t.Helper()
	out, ill := g01Collect(c, ctx, depth)
	if ill != wantIll || !reflect.DeepEqual(out, wantOut) {
		t.Fatalf("%s: out=%v ill=%v, want out=%v ill=%v", name, out, ill, wantOut, wantIll)
	}
}

func TestG01McCollect(t *testing.T) {
	leaf := map[string]any{"field": "subject.x", "op": "eq", "value": 1.0}
	bare := map[string]any{"action": map[string]any{}}
	none := map[string]bool{}
	sx := map[string]bool{"subject.x": true}
	g01CollectIs(t, "string", "x", bare, 0, none, true)
	g01CollectIs(t, "depth 64", leaf, bare, 64, sx, false)
	g01CollectIs(t, "depth 65", leaf, bare, 65, none, true)
	g01CollectIs(t, "empty all_of", map[string]any{"all_of": []any{}}, bare, 0, none, true)
	g01CollectIs(t, "group at 63", map[string]any{"all_of": []any{leaf}}, bare, 63, sx, false)
	g01CollectIs(t, "group at 64", map[string]any{"all_of": []any{leaf}}, bare, 64, none, true)
	present := map[string]any{"action": map[string]any{}, "subject": map[string]any{"x": 1.0}}
	g01CollectIs(t, "decided", leaf, present, 0, none, false)
	g01CollectIs(t, "present but undecidable", map[string]any{"field": "subject.x"}, present, 0, none, true)
	g01CollectIs(t, "params not an object", map[string]any{"field": "action.params", "op": "eq", "value": 1.0},
		map[string]any{"action": map[string]any{"params": 5.0}}, 0, map[string]bool{"action.params": true}, false)
}

func TestG01DecideWithMissing(t *testing.T) {
	leaf := map[string]any{"field": "subject.x", "op": "eq", "value": 1.0}
	bound := map[string]any{"action": map[string]any{}}
	got := DecideWithMissing([]any{g01Group(64, leaf)}, bound, nil, nil)
	want := TypedDecision{Decision: "escalate", Reason: "escalate: missing_context principal:subject.x",
		Missing: []MissingContext{{Path: "subject.x", Supplier: "principal"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("64 groups: %#v", got)
	}
	ill := TypedDecision{Decision: "deny", Reason: "ill_typed_context", Missing: []MissingContext{}}
	if got := DecideWithMissing([]any{leaf, "y"}, bound, nil, nil); !reflect.DeepEqual(got, ill) {
		t.Fatalf("missing + ill: %#v", got)
	}
	bad := TypedDecision{Decision: "deny", Reason: "bad_context", Missing: []MissingContext{}}
	if got := DecideWithMissing([]any{leaf}, "x", nil, nil); !reflect.DeepEqual(got, bad) {
		t.Fatalf("bad bound: %#v", got)
	}
}

func TestG01DecideWithMissingPanicFailsClosed(t *testing.T) {
	mcPanicHook = func(where string) {
		if where == "decide" {
			panic("g01 decide")
		}
	}
	defer func() { mcPanicHook = nil }()
	got := DecideWithMissing([]any{}, map[string]any{"action": map[string]any{}}, nil, nil)
	want := TypedDecision{Decision: "deny", Reason: "evaluation error (fail closed)", Missing: []MissingContext{}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestG01SupplierOfLongest(t *testing.T) {
	for i := 0; i < 50; i++ {
		table := map[string]string{"subject": "principal", "subject.x": "rs_observation", "env": "discharge_issuer", "subject.xy": "agent_declared_untrusted"}
		if got := SupplierOf("subject.x.y", table); got != "rs_observation" {
			t.Fatalf("SupplierOf = %q", got)
		}
	}
}

// ---- obligations.go

func g01ObErr(t *testing.T, o map[string]any, want string) {
	t.Helper()
	if got := ObligationError(o); got != want {
		t.Fatalf("ObligationError(%v) = %q, want %q", o, got, want)
	}
}

func TestG01ObligationBounds(t *testing.T) {
	if got := ObligationError("x"); got != "an obligation must be an object" {
		t.Fatalf("got %q", got)
	}
	g01ObErr(t, map[string]any{"kind": "require_receipt", "params": "x"}, "params must be an object")
	sinkErr := "log.sink must be a non-empty string of at most 128 characters"
	g01ObErr(t, map[string]any{"kind": "log", "params": map[string]any{"sink": ""}}, sinkErr)
	g01ObErr(t, map[string]any{"kind": "log", "params": map[string]any{"sink": strings.Repeat("s", 128)}}, "")
	g01ObErr(t, map[string]any{"kind": "log", "params": map[string]any{"sink": strings.Repeat("s", 129)}}, sinkErr)
	g01ObErr(t, map[string]any{"kind": "notify", "params": map[string]any{"to": strings.Repeat("t", 256)}}, "")
	g01ObErr(t, map[string]any{"kind": "notify", "params": map[string]any{"to": strings.Repeat("t", 257)}}, "notify.to is required")
	g01ObErr(t, map[string]any{"kind": "watermark", "params": map[string]any{"id": strings.Repeat("w", 128)}}, "")
	g01ObErr(t, map[string]any{"kind": "watermark", "params": map[string]any{"id": strings.Repeat("w", 129)}}, "watermark.id is required")
	fields := func(n int) []any {
		f := make([]any, n)
		for i := range f {
			f[i] = fmt.Sprintf("f%d", i)
		}
		return f
	}
	g01ObErr(t, map[string]any{"kind": "redact", "params": map[string]any{"fields": fields(32)}}, "")
	g01ObErr(t, map[string]any{"kind": "redact", "params": map[string]any{"fields": fields(33)}}, "redact.fields must be 1..32 dotted field paths")
}

func TestG01MergeObligationsSixteen(t *testing.T) {
	wm := func(from int) []any {
		l := []any{}
		for i := from; i < from+8; i++ {
			l = append(l, map[string]any{"kind": "watermark", "params": map[string]any{"id": fmt.Sprintf("w%02d", i)}})
		}
		return l
	}
	merged, ok := MergeObligations(wm(0), wm(8))
	if !ok || len(merged) != 16 {
		t.Fatalf("merge of 16: ok=%v len=%d", ok, len(merged))
	}
	if _, ok := MergeObligations(wm(0), wm(8), wm(9)); ok {
		t.Fatal("merge of 17 accepted")
	}
}

// ---- ed25519strict.go

func g01MemoSwap(m map[[32]byte]bool) map[[32]byte]bool {
	edPointMemo.Lock()
	defer edPointMemo.Unlock()
	old := edPointMemo.m
	edPointMemo.m = m
	return old
}

func g01MemoFill(n int) map[[32]byte]bool {
	m := make(map[[32]byte]bool, n+1)
	for i := 0; i < n; i++ {
		var k [32]byte
		k[0], k[1], k[2], k[31] = byte(i), byte(i>>8), byte(i>>16), 0xAA
		m[k] = false
	}
	return m
}

func g01MemoLen() int {
	edPointMemo.Lock()
	defer edPointMemo.Unlock()
	return len(edPointMemo.m)
}

func TestG01EdStrictPointShort(t *testing.T) {
	if edStrictPoint([]byte{1, 2, 3}) {
		t.Fatal("a 3-byte encoding was accepted")
	}
	if edStrictPoint(nil) {
		t.Fatal("an empty encoding was accepted")
	}
}

func TestG01EdPointMemoBound(t *testing.T) {
	probe := make([]byte, 32)
	probe[5] = 0x77
	old := g01MemoSwap(g01MemoFill(1 << 14))
	defer g01MemoSwap(old)
	edStrictPoint(probe)
	if n := g01MemoLen(); n != 1 {
		t.Fatalf("a full memo (16384) was not emptied before the insert: len %d", n)
	}
	g01MemoSwap(g01MemoFill(1 << 13))
	edStrictPoint(probe)
	if n := g01MemoLen(); n != 1<<13+1 {
		t.Fatalf("a memo of 8192 was emptied or not extended: len %d", n)
	}
}
