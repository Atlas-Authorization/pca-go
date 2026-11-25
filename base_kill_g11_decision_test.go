package pca

import (
	"fmt"
	"reflect"
	"testing"
)

func TestG11MeetUnknown(t *testing.T) {
	if Meet("bogus", "allow") != "deny" || Meet("allow", "bogus") != "deny" || Meet("escalate", "allow") != "escalate" {
		t.Fatal("an unknown decision is deny")
	}
}

func TestG11DecisionOfEmptyChecks(t *testing.T) {
	if got := DecisionOf(map[string]any{"checks": map[string]any{}}); got != "deny" {
		t.Fatal(got)
	}
}

func TestG11IsModelDerivedPath(t *testing.T) {
	one := []string{"a"}
	for i, tc := range []struct {
		path   string
		single []string
		want   bool
	}{
		{"env", one, false},
		{"x.class", one, false},
		{"env.class", nil, true},
		{"env.foo", one, false},
		{"env.world", one, true},
		{"env.world", nil, false},
		{"env.world.x", one, false},
		{"env.world.a", one, true},
	} {
		if got := isModelDerivedPath(tc.path, tc.single); got != tc.want {
			t.Errorf("case %d %s: %v", i, tc.path, got)
		}
	}
}

func TestG11CollectCondPathsDepth(t *testing.T) {
	nest := func(d int) any {
		var c any = map[string]any{"field": "f"}
		for i := 0; i < d; i++ {
			c = map[string]any{"all_of": []any{c}}
		}
		return c
	}
	out := map[string]bool{}
	collectCondPaths(nest(64), out, 0)
	if !reflect.DeepEqual(out, map[string]bool{"f": true}) {
		t.Fatalf("depth 64: %v", out)
	}
	out = map[string]bool{}
	collectCondPaths(nest(65), out, 0)
	if len(out) != 0 {
		t.Fatalf("depth 65: %v", out)
	}
}

func TestG11UnitTagsBound(t *testing.T) {
	units := func(n int) map[string]any {
		m := map[string]any{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("action.params.p%d", i)] = map[string]any{"kind": "k"}
		}
		return m
	}
	if got := unitTagsError(units(64)); got != "" {
		t.Fatal(got)
	}
	if got := unitTagsError(units(65)); got != "units has more than 64 entries" {
		t.Fatal(got)
	}
}

func TestG11UnitTagTextNullKind(t *testing.T) {
	if got := unitTagText(map[string]any{"kind": nil, "currency": "USD"}); got != "?/USD" {
		t.Fatal(got)
	}
}

func TestG11FailClosedVerdict(t *testing.T) {
	ok, reason := func() (ok bool, reason string) {
		defer failClosedVerdict(&ok, &reason)
		ok = true
		panic("x")
	}()
	if ok || reason != "evaluation error (fail closed): x" {
		t.Fatal(ok, reason)
	}
	ok, reason = func() (ok bool, reason string) {
		defer failClosedVerdict(&ok, &reason)
		return true, ""
	}()
	if !ok || reason != "" {
		t.Fatal(ok, reason)
	}
}
