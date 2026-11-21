package pca

// Replay helpers for the YAML / authoring corpora. Unlike replayVectors they keep the member order of every object in the case
// arguments (the reference reports the first of several defects in `Object.keys` order, and the YAML writer emits members in
// that order), so the arguments are NOT passed through normalizeJSON; the expected output is normalized as usual.

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func orderedEach(t *testing.T, file string, f func(c *baseCase)) {
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
		t.Fatalf("no cases in %s", file)
	}
	for i, raw := range doc.Cases {
		v, err := ParseJSONLenient(raw)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		m, _ := v.(map[string]any)
		args, _ := m["args"].([]any)
		fn, _ := m["fn"].(string)
		name, _ := m["name"].(string)
		f(&baseCase{Fn: fn, Name: name, Args: args, Out: normalizeJSON(m["out"]), C: m})
	}
}

func replayOrdered(t *testing.T, file string, fns map[string]vecFn) {
	t.Helper()
	var k baseTally
	orderedEach(t, file, func(c *baseCase) {
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
		var skip vecSkip
		if errors.As(err, &skip) {
			k.skip(c.Fn, string(skip))
			return
		}
		if throws, code := baseThrows(c.Out); throws {
			var ce *CodedError
			switch {
			case err == nil:
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(vecJSON(got)))
			case code != "" && !strings.HasPrefix(code, "ERR_") && (!errors.As(err, &ce) || ce.Code != code):
				k.fail(c, "reference refuses with code %s, Go with %v", code, err)
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
}
