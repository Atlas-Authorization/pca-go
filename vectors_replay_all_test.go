package pca

import (
	"errors"
	"strings"
	"testing"
)

// replayAll replays EVERY case of a reference corpus and asserts the case total: an fn without a Go entry point fails, a case may
// not be skipped, a reference refusal requires a Go refusal (with the same stable code when it carries one), and for the fns named
// in text the Go error text must equal the reference refusal text. cmp gives per-fn comparators (want, got as canonical-JSON values).
func replayAll(t *testing.T, file string, total int, fns map[string]vecFn, cmp map[string]func(want, got any) bool, text map[string]bool) {
	t.Helper()
	var k baseTally
	n := 0
	baseEachOrdered(t, file, func(c *baseCase) {
		n++
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
			k.fail(c, "skipped (%s): every case of this corpus is compared", string(skip))
			return
		}
		replayRan(c.Fn)
		if throws, code := baseThrows(c.Out); throws {
			var ce *CodedError
			want, _ := vecObj(c.Out)["$throws"].(string)
			switch {
			case err == nil && vecEngineCrash(c.Out) && vecRefusalValue(vecJSON(got)):
			case err == nil:
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(vecJSON(got)))
			case code != "" && !strings.HasPrefix(code, "ERR_") && (!errors.As(err, &ce) || ce.Code != code): // ERR_* are JS-runtime codes
				k.fail(c, "reference refuses with code %s, Go with %v", code, err)
			case text[c.Fn] && !vecEngineCrash(c.Out) && err.Error() != want:
				k.fail(c, "reference refuses with %q, Go with %q", want, err.Error())
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		if f := cmp[c.Fn]; f != nil {
			if !f(normalizeJSON(c.Out), vecJSON(got)) {
				k.fail(c, "want %s got %s", baseCanon(c.Out), baseCanon(vecJSON(got)))
			}
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(vecJSON(got)); w != g {
			k.fail(c, "want %s got %s", w, g)
		}
	})
	k.finish(t)
	if n != total {
		t.Fatalf("%s: the corpus holds %d cases, %d are expected", file, n, total)
	}
}
