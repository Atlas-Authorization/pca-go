package pca

import (
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// r5n3Within runs f on its own goroutine: a panic or a run past the deadline fails this test instead of ending the binary.
func r5n3Within(t *testing.T, name string, f func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("%s: panicked: %v", name, r)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: did not terminate", name)
	}
}

func r5n3U16(s string) []uint16 { return utf16.Encode([]rune(s)) }

func TestR5N3GlobMatchTerminatesAndBacktracks(t *testing.T) {
	for _, c := range []struct {
		glob, s string
		want    bool
	}{
		{"*b", "ab", true},
		{"*b", "ac", false},
		{"a*c", "abxc", true},
		{"a*c", "abxd", false},
		{"*", "", true},
		{"*", "abc", true},
		{"a**b", "axb", true},
		{"?*", "z", true},
		{"a?c", "abc", true},
		{"*a*b", "xaxb", true},
		{"*ab", "aab", true},
	} {
		c := c
		r5n3Within(t, c.glob+" vs "+c.s, func() {
			m, ok := globMatch(r5n3U16(c.glob), r5n3U16(c.s))
			if !ok || m != c.want {
				t.Errorf("globMatch(%q, %q) = %v, %v; want %v", c.glob, c.s, m, ok, c.want)
			}
		})
	}
}

func r5n3Ctx() map[string]any {
	return map[string]any{
		"action":  map[string]any{"verb": "v", "resource": "r"},
		"subject": map[string]any{"n": jnum(1), "s": "a"},
	}
}

func TestR5N3PredicateLeafUnknownsAndMembership(t *testing.T) {
	ctx := r5n3Ctx()
	leaf := func(field, op string, value any) int {
		return evaluateConditionTri(map[string]any{"field": field, "op": op, "value": value}, ctx, &regexBudget{})
	}
	for _, op := range []string{"lt", "lte", "gt", "gte"} { // a number and a string have no order
		if got := leaf("subject.n", op, "x"); got != triUnknown {
			t.Errorf("%s over unordered operands: %d", op, got)
		}
	}
	if got := leaf("subject.s", "like", `a\`); got != triUnknown { // a trailing escape is an invalid glob
		t.Errorf("like with a trailing backslash: %d", got)
	}
	if leaf("subject.s", "in", []any{"b", "a"}) != triTrue || leaf("subject.s", "in", []any{"b"}) != triFalse ||
		leaf("subject.s", "nin", []any{"b", "a"}) != triFalse || leaf("subject.s", "nin", []any{"b"}) != triTrue {
		t.Error("in / nin")
	}
}

func TestR5N3ResourceMatchesNeedsAStringPattern(t *testing.T) {
	// an empty resource must not equal a pattern that is not a string
	for _, p := range []any{5, nil, []any{"r"}} {
		if resourceMatches(p, true, "", &regexBudget{}) {
			t.Errorf("resource pattern %v matched the empty resource", p)
		}
	}
}

func TestR5N3PredicateMatchesFaultIsNoMatch(t *testing.T) {
	// a nil budget makes the regex charge fault: that is a non-match, never a panic
	r5n3Recover(t, "predicateMatches", func() {
		pred := map[string]any{"verb": "v", "resource": "re:r"}
		if predicateMatches(pred, r5n3Ctx(), nil) {
			t.Error("a faulting predicate matched")
		}
		if !predicateMatches(pred, r5n3Ctx(), &regexBudget{}) {
			t.Error("the same predicate with a budget must match")
		}
	})
}

func TestR5N3FirstUnmetLimit(t *testing.T) {
	ctx := r5n3Ctx()
	unmet := map[string]any{"field": "subject.n", "op": "gt", "value": jnum(5)}
	want := describeCondition(unmet, 0)
	if want == "" {
		t.Fatal("no description")
	}
	preds := []any{
		map[string]any{"verb": "x"},                      // another verb
		map[string]any{"verb": "v", "resource": "other"}, // another resource
		map[string]any{"verb": "v", "resource": "r"},     // no where
		map[string]any{"verb": "v", "resource": "r", "where": []any{unmet}},
	}
	if got, ok := firstUnmetLimit(preds, ctx, &regexBudget{}); !ok || got != want {
		t.Errorf("firstUnmetLimit = %q, %v; want %q", got, ok, want)
	}
	if got, ok := firstUnmetLimit(preds[:3], ctx, &regexBudget{}); ok || got != "" {
		t.Errorf("no limit in scope: %q, %v", got, ok)
	}
	met := map[string]any{"field": "subject.n", "op": "eq", "value": jnum(1)}
	if got, ok := firstUnmetLimit([]any{map[string]any{"verb": "v", "where": []any{met}}}, ctx, &regexBudget{}); ok || got != "" {
		t.Errorf("all limits met: %q, %v", got, ok)
	}
}

// A `matches` pattern whose program and subject together exceed the per-match budget (the document budget still admits it)
// is unknown, not false.
func TestR5N3MatchesOverTheMatchBudgetIsUnknown(t *testing.T) {
	pat := "(" + strings.Repeat("a", 62) + "){64}" // 62*64+1 = 3969 instructions
	subj := strings.Repeat("a", 510)               // 3969 * 511 > 2,000,000 and < the 5,000,000 document budget
	ctx := map[string]any{"subject": map[string]any{"s": subj}}
	cond := map[string]any{"field": "subject.s", "op": "matches", "value": pat}
	r5n3Within(t, "matches", func() {
		if got := evaluateConditionTri(cond, ctx, &regexBudget{}); got != triUnknown {
			t.Errorf("matches over the match budget: %d", got)
		}
	})
	for _, c := range []any{nil, "x", []any{}, 5} {
		if got := evaluateConditionTri(c, ctx, &regexBudget{}); got != triUnknown {
			t.Errorf("non-object condition %v: %d", c, got)
		}
	}
}
