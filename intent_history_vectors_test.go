package pca

import "testing"

// Replay of the session-history surface against the reference (base-intenthistory), every case: windows, grouping keys,
// pre-states, post values, monitor steps and folds. Where the reference throws, AccPreState / AccPost report ok = false, InWindow
// answers false (no window holds) and the monitor functions answer "" (no state); where the reference returns nothing (a window or
// a monitor of an unknown kind) the answers are the same false and "", and AccKeyOf reports ok = false for its null.
func TestSessionHistoryMatchesTheReference(t *testing.T) {
	refused := map[string]any{"refused": true}
	state := func(s string) any {
		if s == "" {
			return refused
		}
		return s
	}
	fns := map[string]vecFn{
		"inWindow": func(a []any) (any, error) {
			if InWindow(vecObj(a[0]), a[1], a[2]) {
				return true, nil
			}
			return refused, nil
		},
		"accKeyOf": func(a []any) (any, error) {
			if k, ok := AccKeyOf(vecObj(a[0]), vecObj(a[1])); ok {
				return k, nil
			}
			return refused, nil
		},
		"accPreState": func(a []any) (any, error) {
			cand := vecObj(a[2])
			hist, _ := a[1].([]any)
			schema := vecArg(a, 3)
			if pre, ok := AccPreState(vecObj(a[0]), hist, vecObj(cand["params"]), cand["t"], schema, schema != nil); ok {
				return pre, nil
			}
			return refused, nil
		},
		"accPost": func(a []any) (any, error) {
			cand := vecObj(a[2])
			hist, _ := a[1].([]any)
			schema := vecArg(a, 3)
			if post, ok := AccPost(vecObj(a[0]), hist, vecStr(cand, "verb"), vecObj(cand["params"]), cand["t"], schema, schema != nil); ok {
				return jsNumber(post), nil
			}
			return refused, nil
		},
		"monitorStep": func(a []any) (any, error) {
			q, _ := a[1].(string)
			return state(MonitorStep(vecObj(a[0]), q, vecObj(a[2]))), nil
		},
		"monitorState": func(a []any) (any, error) {
			hist, _ := a[1].([]any)
			return state(MonitorState(vecObj(a[0]), hist)), nil
		},
	}
	// the reference's throw, its null and (for a window) its false are this surface's one refusal
	same := func(want, got any) bool {
		if _, throws := vecObj(want)["$throws"]; throws || want == nil || want == false {
			return baseCanon(got) == baseCanon(refused)
		}
		return baseCanon(want) == baseCanon(got)
	}
	n := 0
	var k baseTally
	baseEachOrdered(t, "base-intenthistory.json.gz", func(c *baseCase) {
		n++
		f, ok := fns[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		k.run(c.Fn)
		var got any
		if p := baseCall(func() { got, _ = f(c.Args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		if !same(normalizeJSON(c.Out), vecJSON(got)) {
			k.fail(c, "want %s got %s", baseCanon(c.Out), baseCanon(vecJSON(got)))
		}
	})
	k.finish(t)
	if n != 29179 {
		t.Fatalf("the corpus holds %d cases, 29179 are expected", n)
	}
}
