package pca

// Replay of the reference corpus for the intent ontology: verb resolution, IR projection, the well-formedness checker, template
// instantiation, slot typing, locale-aware amount parsing and the shipped ontology data. The corpus is read here (not through
// the shared loader) so that object member order survives: the checker reports defects in member order.

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

func goalOntologyEach(t *testing.T, file string, f func(c *baseCase)) {
	t.Helper()
	fh, err := os.Open("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, raw := range doc.Cases {
		v, err := ParseJSONLenient(raw)
		if err != nil {
			t.Fatal(err)
		}
		m := v.(map[string]any)
		args, _ := m["args"].([]any)
		f(&baseCase{Fn: m["fn"].(string), Name: m["name"].(string), Args: args, Out: normalizeJSON(m["out"]), C: m})
	}
}

func goalOntologyArgInt(v any) int {
	f, _ := jsNum(v)
	return int(f)
}

func TestGoalOntologyVectors(t *testing.T) {
	o := func(x any) any {
		if s, ok := x.(string); ok {
			if shipped := goalShippedOntology(s); shipped != nil {
				return shipped
			}
		}
		return x
	}
	try := func(f func(a []any) any) vecFn {
		return func(a []any) (any, error) { return anlTry(func() any { return f(a) }) }
	}
	fns := map[string]vecFn{
		"shippedOntology": try(func(a []any) any { return goalShippedOntology(vecArg(a, 0)) }),
		"shippedCatalog":  try(func(a []any) any { return goalShippedCatalog(vecArg(a, 0)) }),
		"ontologyDigest":  try(func(a []any) any { return goalOntologyDigest(o(vecArg(a, 0))) }),
		"resolveVerb":     try(func(a []any) any { return goalResolveVerb(o(vecArg(a, 0)), vecArg(a, 1)) }),
		"goalCcy":         try(func(a []any) any { return goalGoalCcy(vecArg(a, 0)) }),
		"goalAnchors":     try(func(a []any) any { return goalGoalAnchors(vecArg(a, 0)) }),
		"toIrOntology":    try(func(a []any) any { return goalToIrOntology(o(vecArg(a, 0)), vecArg(a, 1)) }),
		"ontologyForGoal": try(func(a []any) any { return goalOntologyForGoal(o(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2)) }),
		"checkOntology":   try(func(a []any) any { return goalCheckOntology(o(vecArg(a, 0))) }),
		"instantiateTemplate": try(func(a []any) any {
			return goalInstantiateTemplate(o(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3))
		}),
		"slotLits": try(func(a []any) any {
			v := vecArg(a, 2)
			if v == nil {
				v = anlUndef
			}
			return goalSlotLits(o(vecArg(a, 0)), vecArg(a, 1), v)
		}),
		"parseHumanAmount": try(func(a []any) any {
			return goalParseHumanAmount(vecArg(a, 0), goalOntologyArgInt(vecArg(a, 1)), vecArg(a, 2))
		}),
		"parseMoney": try(func(a []any) any { return goalParseMoney(vecArg(a, 0), goalOntologyArgInt(vecArg(a, 1)), vecArg(a, 2)) }),
	}
	var k baseTally
	goalOntologyEach(t, "ref-goal-ontology.json.gz", func(c *baseCase) {
		f, ok := fns[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		k.run(c.Fn)
		var got any
		var err error
		if p := baseCall(func() { got, err = f(c.Args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		if throws, _ := baseThrows(c.Out); throws {
			if err == nil && !(vecEngineCrash(c.Out) && vecRefusalValue(vecJSON(got))) {
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(vecJSON(got)))
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(vecJSON(got)); w != g {
			k.fail(c, "want %s got %s", w, g)
		}
	})
	k.finish(t)
	if len(k.ran) != len(fns) {
		t.Fatalf("corpus covers %d of %d entry points", len(k.ran), len(fns))
	}
}
