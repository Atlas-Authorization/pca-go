package pca

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Mutation kills for actions_traits.go.

func TestG13TraitsJoinRev(t *testing.T) {
	for _, c := range []struct{ p, q, want string }{
		{"rate_limited", "irreversible", "irreversible"},
		{"irreversible", "rate_limited", "irreversible"},
		{"rate_limited", "rate_limited", "rate_limited"},
		// as TS (REV_RANK[p] >= REV_RANK[q] ? p : q): any comparison with an unknown class is false, so q wins
		{"x", "reversible", "reversible"},
		{"irreversible", "x", "x"},
		{"x", "y", "y"},
	} {
		if got := joinProfile(Profile{Rev: c.p}, Profile{Rev: c.q}).Rev; got != c.want {
			t.Fatalf("join(%s, %s).Rev = %s", c.p, c.q, got)
		}
	}
}

func TestG13TraitsClosure(t *testing.T) {
	dag := Registry{"a": {ID: "a", Implies: []string{"b"}}, "b": {ID: "b"}}
	if got, err := dag.closure([]string{"a"}); err != nil || !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("closure: %v %v", got, err)
	}
	cyc := Registry{"a": {ID: "a", Implies: []string{"b"}}, "b": {ID: "b", Implies: []string{"a"}}}
	done := make(chan []string, 1)
	go func() { got, _ := cyc.closure([]string{"a"}); done <- got }()
	select {
	case got := <-done:
		if !reflect.DeepEqual(got, []string{"a", "b"}) {
			t.Fatalf("cyclic closure: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closure does not terminate on an implies cycle")
	}
}

func TestG13TraitsBuildCoreRegistry(t *testing.T) {
	if got := len(buildCoreRegistry(coreTable)); got != 22 {
		t.Fatalf("core registry has %d traits", got)
	}
	defer func() {
		if r := recover(); r != "core trait registry: trait 'pca.a' implies unknown trait 'pca.zz'" {
			t.Fatalf("panic %v", r)
		}
	}()
	buildCoreRegistry([]coreTraitRow{{name: "a", implies: []string{"zz"}, phrase: "p"}})
	t.Fatal("an invalid core table did not panic")
}

func TestG13TraitsSmallHelpers(t *testing.T) {
	if got := trimParamsPrefix("action.params.x"); got != "x" {
		t.Fatalf("trim %q", got)
	}
	if got := trimParamsPrefix("action"); got != "" {
		t.Fatalf("trim short %q", got)
	}
	for in, want := range map[string]string{"abc": "abc", ": x": "", "code: reason": "code", "a b": "a"} {
		if got := errCode(errors.New(in)); got != want {
			t.Fatalf("errCode(%q) = %q", in, got)
		}
	}
	run := func(f func()) (res string) {
		res = "untouched"
		defer recoverTo(&res, "p: ")
		f()
		return res
	}
	if got := run(func() { panic("boom") }); got != "p: boom" {
		t.Fatalf("recovered %q", got)
	}
	if got := run(func() {}); got != "untouched" {
		t.Fatalf("no panic %q", got)
	}
	if got := schemaFloorError(map[string]any{}, nil); !strings.HasPrefix(got, "bad_registry: ") {
		t.Fatalf("a document without verbs: %q", got)
	}
}

func TestG13TraitsSchemaVerbShape(t *testing.T) {
	for _, c := range []struct {
		name string
		v    map[string]any
		want string
	}{
		{"unknown class", map[string]any{"params": map[string]any{}, "reversibility": "bogus"}, "reversibility must be a reversibility class"},
		{"valid default", map[string]any{"params": map[string]any{}, "reversibility": map[string]any{"by": "x", "map": map[string]any{}, "default": "reversible"}}, ""},
		{"bad default", map[string]any{"params": map[string]any{}, "reversibility": map[string]any{"by": "x", "map": map[string]any{}, "default": "bogus"}}, "the reversibility default must be a reversibility class"},
		{"null tags", map[string]any{"params": map[string]any{"action.params.a": map[string]any{"type": "string", "tags": nil}}}, ""},
	} {
		if got := schemaVerbShapeError(c.v); got != c.want {
			t.Fatalf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestG13TraitsRegistryOfSchema(t *testing.T) {
	reg, err := registryOfSchema(map[string]any{"trait_defs": []any{}})
	if err != nil || reflect.ValueOf(reg).Pointer() != reflect.ValueOf(coreRegistry).Pointer() {
		t.Fatalf("an empty trait_defs must reuse the core registry: %v", err)
	}
}

func g13trVerb(kind string, traits []any) map[string]any {
	return map[string]any{"verb": "a.b", "kind": kind, "params": map[string]any{}, "effects": []any{}, "traits": traits, "floors": map[string]any{}}
}

func TestG13TraitsSchemaVerbFloor(t *testing.T) {
	const firstTop = "schema_traits_forged: unconfirmed action must carry every trait (missing pca.agent_spawning)"
	if got := schemaVerbFloorError(g13trVerb("write", []any{}), coreRegistry, nil); got != "schema_traits_forged: missing implied trait pca.irreversible" {
		t.Fatalf("write verb with no reversibility: %q", got)
	}
	if got := schemaVerbFloorError(g13trVerb("read", []any{}), coreRegistry, nil); got != firstTop {
		t.Fatalf("read verb with no reversibility: %q", got)
	}
	by := g13trVerb("write", []any{})
	by["params"] = map[string]any{"action.params.flag": map[string]any{"type": "boolean"}}
	by["reversibility_by"] = map[string]any{"param": "action.params.flag", "map": map[string]any{"true": "reversible", "false": "reversible"}}
	if got := schemaVerbFloorError(by, coreRegistry, nil); got != firstTop {
		t.Fatalf("reversibility_by covering every value: %q", got)
	}
	all := anyStrs(topTraits(coreRegistry))
	first := g13trVerb("read", append([]any{json.Number("5")}, all...))
	last := g13trVerb("read", append(append([]any{}, all...), json.Number("6")))
	if got := schemaVerbFloorError(first, coreRegistry, nil); got != "unknown_trait: unknown trait '5'" {
		t.Fatalf("non-string first trait: %q", got)
	}
	if got := schemaVerbFloorError(last, coreRegistry, nil); got != "unknown_trait: unknown trait '6'" {
		t.Fatalf("non-string last trait: %q", got)
	}
}

func TestG13TraitsEffectiveDanglingRegistry(t *testing.T) {
	reg := Registry{"x.a": {ID: "x.a", Implies: []string{"x.zz"}}}
	d := map[string]any{"verb": "a.b", "kind": "read", "resource": map[string]any{"type": "doc", "scope": "one"}, "params": map[string]any{}, "effects": []any{"read"}}
	if _, err := effective(d, reg, nil); err == nil || err.Error() != "unknown_trait: unknown trait 'x.zz'" {
		t.Fatalf("a registry with a dangling implies: %v", err)
	}
}
