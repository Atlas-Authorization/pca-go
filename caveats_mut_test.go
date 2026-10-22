package pca

import (
	"math"
	"reflect"
	"testing"
)

// Mutation-kill tests for caveats.go (0.4.1 mutation run) and the threshold share pq_pk guard. Semantics mirror the TS
// reference: envelopeCaveatEvaluator (packages/pca/src/predicates.ts) and policyCaveats (policy-vm.ts).

func cavOne(cv map[string]any, ctx map[string]any) bool {
	ok, _ := EvaluateCaveats([]any{cv}, ctx)
	return ok
}

// A non-finite Go float `now` (not reachable through JSON, but EvaluateCaveats takes any Go number) is not a time:
// every time-dependent caveat is unsatisfied, whichever side of the bound the infinity sits on.
func TestMutCaveatNonFiniteNow(t *testing.T) {
	for _, now := range []any{math.Inf(1), math.Inf(-1), math.NaN(), float32(math.Inf(-1)), float32(math.Inf(1))} {
		for _, cv := range []map[string]any{
			{"type": "expires", "at": 5.0},         // -Inf < 5 would hold
			{"type": "not_before", "at": 0.0},      // +Inf >= 0 would hold
			{"type": "budget_alloc", "limit": 1.0}, // needs only a finite now
		} {
			if cavOne(cv, map[string]any{"now": now}) {
				t.Fatalf("now=%v satisfied %v", now, cv)
			}
		}
	}
	// a non-finite caveat bound is refused too
	if cavOne(map[string]any{"type": "expires", "at": math.Inf(1)}, map[string]any{"now": 0.0}) {
		t.Fatal("expires at +Inf satisfied")
	}
	if cavOne(map[string]any{"type": "not_before", "at": math.Inf(-1)}, map[string]any{"now": 0.0}) {
		t.Fatal("not_before at -Inf satisfied")
	}
	if !cavOne(map[string]any{"type": "expires", "at": 5.0}, map[string]any{"now": 4.0}) {
		t.Fatal("finite baseline refused")
	}
}

// reversibility_max: the full 3x3 order reversible < rate_limited < irreversible, cur <= lim (equal is satisfied).
func TestMutCaveatReversibilityMatrix(t *testing.T) {
	cls := []string{"reversible", "rate_limited", "irreversible"}
	for li, lim := range cls {
		for ci, cur := range cls {
			got := cavOne(map[string]any{"type": "reversibility_max", "class": lim}, map[string]any{"now": 1.0, "reversibility_class": cur})
			if want := ci <= li; got != want {
				t.Fatalf("reversibility_max{class:%s} with %s: got %v want %v", lim, cur, got, want)
			}
		}
	}
	for _, bad := range [][2]any{{"costly", "reversible"}, {"reversible", "costly"}, {[]any{"irreversible"}, "reversible"}, {"irreversible", nil}} {
		if cavOne(map[string]any{"type": "reversibility_max", "class": bad[0]}, map[string]any{"now": 1.0, "reversibility_class": bad[1]}) {
			t.Fatalf("reversibility_max %v satisfied", bad)
		}
	}
}

// rate: per_secs must be > 0 (0 / negative is refused, not an empty window), and recent_action_times must be an array.
func TestMutCaveatRateGuards(t *testing.T) {
	now := 10_000.0
	ctx := func(times any) map[string]any {
		m := map[string]any{"now": now}
		if times != nil {
			m["recent_action_times"] = times
		}
		return m
	}
	for _, per := range []any{0.0, -1.0, -0.5} {
		if cavOne(map[string]any{"type": "rate", "max": 1.0, "per_secs": per}, ctx([]any{})) {
			t.Fatalf("rate per_secs=%v satisfied", per)
		}
	}
	if cavOne(map[string]any{"type": "rate", "max": 1.0, "per_secs": 1.0}, ctx(nil)) {
		t.Fatal("rate without recent_action_times satisfied")
	}
	if cavOne(map[string]any{"type": "rate", "max": 1.0, "per_secs": 1.0}, ctx("x")) {
		t.Fatal("rate with non-array recent_action_times satisfied")
	}
	if cavOne(map[string]any{"type": "rate", "max": 1.0}, ctx([]any{})) || cavOne(map[string]any{"type": "rate", "per_secs": 1.0}, ctx([]any{})) {
		t.Fatal("rate with a missing bound satisfied")
	}
	if !cavOne(map[string]any{"type": "rate", "max": 1.0, "per_secs": 0.001}, ctx([]any{})) {
		t.Fatal("rate with a tiny positive window and no actions refused")
	}
}

// budget_alloc: satisfied iff limit is finite and >= 0 (0 and fractions included).
func TestMutCaveatBudgetAllocBoundary(t *testing.T) {
	for _, c := range []struct {
		lim  any
		want bool
	}{{0.0, true}, {0.5, true}, {1.0, true}, {-0.0001, false}, {-1.0, false}, {"1", false}, {nil, false}} {
		if got := cavOne(map[string]any{"type": "budget_alloc", "limit": c.lim}, map[string]any{"now": 1.0}); got != c.want {
			t.Fatalf("budget_alloc limit=%v: got %v want %v", c.lim, got, c.want)
		}
	}
}

// PolicyCaveats: a ONE-element chain is a chain; its (only) hop's appended caveats are evaluated.
func TestMutPolicyCaveatsSingleHopChain(t *testing.T) {
	root := map[string]any{"type": "note"}
	hop := map[string]any{"type": "expires", "at": 9.0}
	grant := map[string]any{"caveats": []any{root}}
	chain := []any{map[string]any{"caveats": []any{root, hop}}}
	if got := PolicyCaveats(grant, chain); !reflect.DeepEqual(got, []any{root, hop}) {
		t.Fatalf("single-hop chain: %#v", got)
	}
	if got := PolicyCaveats(grant, []any{}); !reflect.DeepEqual(got, []any{root}) {
		t.Fatalf("empty chain: %#v", got)
	}
}

// A share that NAMES pq_pk for a role registering none is refused, even the empty string and even though the
// signature (which does not cover share.pq_pk) is valid.
func TestMutShareEmptyPqPkForEdRole(t *testing.T) {
	e, _ := signedShare(t, "agent", []byte("m"))
	for _, v := range []any{"", "x", nil, 5} {
		e["share"].(map[string]any)["pq_pk"] = v
		if VerifyThresholdShare(e) {
			t.Fatalf("ed25519-role share naming pq_pk %#v accepted", v)
		}
	}
	delete(e["share"].(map[string]any), "pq_pk")
	if !VerifyThresholdShare(e) {
		t.Fatal("baseline refused after removing pq_pk")
	}
}
