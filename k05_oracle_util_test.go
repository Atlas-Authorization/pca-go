package pca

// Shared harness for the k05 differential oracles: testdata/k05-<module>.json.gz come from tools/pca-audit/k05-oracles
// (the TypeScript reference over generated boundary inputs). A file is {about, generator, count, cases: [{fn, name, args,
// out, textPrefix?, cmp?}]}; bytes are {"$bytes": b64url}; a throw is {"$throws": message, "code"?}. The files are large
// (up to ~170 MB inflated), so cases are STREAMED one at a time (never the whole document in memory) and each module test
// walks its file exactly once, dispatching on fn.

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
)

type k05Case struct {
	Fn, Name string
	Args     []any
	Out      any
	C        map[string]any // the whole case (textPrefix, cmp, ...)
}

// k05Each streams testdata/<file> and calls f for every case, in file order.
func k05Each(t *testing.T, file string, f func(c *k05Case)) int {
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
	dec := json.NewDecoder(zr)
	tok := func() json.Token {
		x, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if d, _ := tok().(json.Delim); d != '{' {
		t.Fatal("k05: not an object")
	}
	n := 0
	for dec.More() {
		key, _ := tok().(string)
		if key != "cases" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if d, _ := tok().(json.Delim); d != '[' {
			t.Fatal("k05: cases is not an array")
		}
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.Fatal(err)
			}
			v, err := ParseJSONLenient(raw)
			if err != nil {
				t.Fatalf("k05 case %d: %v", n, err)
			}
			m := normalizeJSON(v).(map[string]any)
			args, _ := m["args"].([]any)
			c := &k05Case{Fn: m["fn"].(string), Name: m["name"].(string), Args: args, Out: m["out"], C: m}
			f(c)
			n++
		}
		tok()
	}
	if n == 0 {
		t.Fatalf("k05: no cases in %s", file)
	}
	return n
}

// k05Throws reports whether out is a reference throw, and its stable code ("" when it carried none).
func k05Throws(out any) (bool, string) {
	m, ok := out.(map[string]any)
	if !ok {
		return false, ""
	}
	if _, ok := m["$throws"]; !ok {
		return false, ""
	}
	code, _ := m["code"].(string)
	return true, code
}

// k05Bytes decodes {"$bytes": b64url} (nil when v is not that shape).
func k05Bytes(v any) []byte {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// k05Canon is the canonical (lenient) JSON of v, for whole-value equality.
func k05Canon(v any) string {
	s, ok := canonicalLenient(v)
	if !ok {
		return fmt.Sprintf("<uncanonical %#v>", v)
	}
	return s
}

// k05Tally collects divergences per fn; finish fails the test with the first few and logs ran / skipped counts.
type k05Tally struct {
	ran, skipped map[string]int
	why          map[string]string
	bad          []string
	nbad         int
	badFn        map[string]int
	badKind      map[string]int
}

func (k *k05Tally) run(fn string) {
	if k.ran == nil {
		k.ran = map[string]int{}
	}
	k.ran[fn]++
}

// skip records a case not compared, with the reason (one reason per fn is kept for the log).
func (k *k05Tally) skip(fn, why string) {
	if k.skipped == nil {
		k.skipped, k.why = map[string]int{}, map[string]string{}
	}
	key := fn + "\x00" + why // one line per distinct reason
	k.skipped[key]++
	k.why[key] = fn
}

func (k *k05Tally) fail(c *k05Case, format string, a ...any) {
	k.nbad++
	if k.badFn == nil {
		k.badFn = map[string]int{}
	}
	k.badFn[c.Fn]++
	// a few per fn AND per kind of difference (the tail of the message, where the native's answer is), each clipped, so one CI
	// run shows every failing fn and every distinct way it fails
	msg := fmt.Sprintf(format, a...)
	kind := msg
	if len(kind) > 120 {
		kind = kind[len(kind)-120:]
	}
	if k.badKind == nil {
		k.badKind = map[string]int{}
	}
	k.badKind[c.Fn+"|"+kind]++
	if k.badFn[c.Fn] <= 4 || (k.badKind[c.Fn+"|"+kind] <= 1 && len(k.bad) < 300) {
		line := c.Name + ": " + msg
		if len(line) > 2500 {
			line = line[:1200] + " ... " + line[len(line)-1200:]
		}
		k.bad = append(k.bad, line)
	}
}

func (k *k05Tally) finish(t *testing.T) {
	t.Helper()
	fns := make([]string, 0, len(k.ran))
	for f := range k.ran {
		fns = append(fns, f)
	}
	sort.Strings(fns)
	for _, f := range fns {
		t.Logf("%s: %d compared", f, k.ran[f])
	}
	for key, n := range k.skipped {
		t.Logf("%s: %d skipped (%s)", k.why[key], n, key[len(k.why[key])+1:])
	}
	for f, n := range k.badFn {
		t.Logf("%s: %d DIVERGE", f, n)
	}
	if k.nbad > 0 {
		t.Fatalf("%d cases diverge from the reference:\n  %s", k.nbad, strings.Join(k.bad, "\n  "))
	}
}

// k05SameUnknown: both are the same "<prefix>unknown member '<name>'" refusal, naming possibly different members. With several
// unknown members the reference names the first in insertion order, which a Go map does not keep (Go names the least).
func k05SameUnknown(want, got string) bool {
	const m = "unknown member '"
	i, j := strings.LastIndex(want, m), strings.LastIndex(got, m)
	return i >= 0 && i == j && want[:i] == got[:j] && strings.HasSuffix(want, "'") && strings.HasSuffix(got, "'")
}

// k05I64 reads any integral JSON number below 2^63 as an int64 (2^53 and above included, so a native must refuse them as the
// reference does; -0 is 0).
func k05I64(v any) (int64, bool) {
	f, ok := jsNum(v)
	return int64(f), ok && f == math.Trunc(f) && math.Abs(f) < 1<<63
}

// k05Call runs f, turning a panic into an error string (a native that panics on hostile input is a divergence, not a crash).
func k05Call(f func()) (panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}
