package pca

import "testing"

// revKeys is a deep copy of v whose objects remember their members in the REVERSE of the order they had: the same value, written
// with every key order flipped (a stored jsonb copy against a fresh pack).
func revKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		keys := jsKeys(t)
		rev := make([]string, len(keys))
		for i, k := range keys {
			out[k] = revKeys(t[k])
			rev[len(keys)-1-i] = k
		}
		recordKeyOrder(out, rev)
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = revKeys(x)
		}
		return out
	}
	return v
}

// The version diff compares definitions by value: key order is not meaning.
func TestActionDiffIgnoresKeyOrder(t *testing.T) {
	a := map[string]any{"b": map[string]any{"y": jnum(1), "x": []any{map[string]any{"q": "1", "p": "2"}}}, "a": jnum(2)}
	if !adSameJSON(a, true, revKeys(a), true) || !adSameJSON(revKeys(a), true, a, true) {
		t.Fatal("the same value with reversed keys must compare equal")
	}
	if adSameJSON(a, true, map[string]any{"a": jnum(2), "b": jnum(3)}, true) {
		t.Fatal("a different value must not compare equal")
	}
	if adSameJSON([]any{jnum(1), jnum(2)}, true, []any{jnum(2), jnum(1)}, true) {
		t.Fatal("array order is meaning")
	}
	var def map[string]any
	baseEachOrdered(t, "ref-actions-diff.json.gz", func(c *baseCase) {
		if def == nil && c.Fn == "diffDefs" {
			def = vecObj(vecArg(c.Args, 0))
		}
	})
	if def == nil {
		t.Fatal("no definition in the corpus")
	}
	for _, pair := range [][2]map[string]any{{def, revKeys(def).(map[string]any)}, {revKeys(def).(map[string]any), def}} {
		r, err := ActionDiffDefs(pair[0], pair[1], coreRegistry, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r["class"] != "equal" {
			t.Fatalf("a definition against itself with reversed keys: %v", r)
		}
	}
}
