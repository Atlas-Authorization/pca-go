package pca

// Shared harness for the base differential oracles: testdata/base-<module>.json.gz come from tools/pca-audit/oracles-base
// (the TypeScript reference over generated boundary inputs). A file is {about, generator, count, cases: [{fn, name, args,
// out, textPrefix?, cmp?}]}; bytes are {"$bytes": b64url}; a throw is {"$throws": message, "code"?}. The files are large
// (up to ~170 MB inflated), so cases are STREAMED one at a time (never the whole document in memory) and each module test
// walks its file exactly once, dispatching on fn.

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	unicodeutf8 "unicode/utf8"
	"testing"
)

type baseCase struct {
	Fn, Name string
	Args     []any
	Out      any
	C        map[string]any // the whole case (textPrefix, cmp, ...)
}

// baseEach streams testdata/<file> and calls f for every case, in file order.
func baseEach(t *testing.T, file string, f func(c *baseCase)) int {
	t.Helper()
	return baseEachWith(t, file, normalizeJSON, f)
}

// baseEachSeeded is baseEach with the corpus seed objects in args resolved to base64url keys (expected outputs untouched).
func baseEachSeeded(t *testing.T, file string, f func(c *baseCase)) int {
	t.Helper()
	return baseEach(t, file, func(c *baseCase) {
		c.Args, _ = vecResolveSeeds(c.Args).([]any)
		f(c)
	})
}

// baseEachOrdered is baseEach that keeps the text order of every object's members (the reference reports violations and emits
// members in Object.keys order, which jsKeys reads back from the parse-time side table).
func baseEachOrdered(t *testing.T, file string, f func(c *baseCase)) int {
	t.Helper()
	return baseEachWith(t, file, normalizeJSONOrdered, f)
}

// normalizeJSONOrdered is normalizeJSON, recording each rebuilt object's member order so jsKeys still sees the reference order.
func normalizeJSONOrdered(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = normalizeJSONOrdered(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = normalizeJSONOrdered(x)
		}
		return a
	}
	return normalizeJSON(v)
}

func baseEachWith(t *testing.T, file string, norm func(any) any, f func(c *baseCase)) int {
	t.Helper()
	fh, err := os.Open(vecCorpusPath(file))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	return baseEachStream(t, file, zr, norm, f)
}

// vecFallbackClockMs is the contract's default generator clock, used by a corpus whose header carries no `clockMs`.
const vecFallbackClockMs = 1_700_000_000_000

// vecCorpusClockCases is the header's `clockCases` of the corpus being replayed: the names of the cases whose expected result depends
// on the clock. Every other case is clock-independent.
var vecCorpusClockCases = map[string]bool{}

// vecIsClockCase reports whether the case's result depends on the generator clock (it must then run under vecOracleNow()).
func vecIsClockCase(name string) bool { return vecCorpusClockCases[name] }

// vecCorpusClockMs is the clock of the corpus being replayed: its header's `clockMs`, else the fallback. Replays run one at a time.
var vecCorpusClockMs float64 = vecFallbackClockMs

// vecOracleNow is the one clock accessor: the instant (ms since the epoch) the reference generator's frozen clock started at.
func vecOracleNow() float64 { return vecCorpusClockMs }

// baseEachStream walks one corpus document from r; the header's `clockMs` (read before `cases`) becomes vecOracleNow().
func baseEachStream(t *testing.T, file string, r io.Reader, norm func(any) any, f func(c *baseCase)) int {
	t.Helper()
	vecCorpusClockMs = vecFallbackClockMs
	vecCorpusClockCases = map[string]bool{}
	dec := json.NewDecoder(r)
	tok := func() json.Token {
		x, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if d, _ := tok().(json.Delim); d != '{' {
		t.Fatal("base: not an object")
	}
	n := 0
	for dec.More() {
		key, _ := tok().(string)
		if key == "clockMs" {
			var ms float64
			if err := dec.Decode(&ms); err != nil {
				t.Fatalf("base: clockMs of %s: %v", file, err)
			}
			vecCorpusClockMs = ms
			continue
		}
		if key == "clockCases" {
			var names []string
			if err := dec.Decode(&names); err != nil {
				t.Fatalf("base: clockCases of %s: %v", file, err)
			}
			for _, nm := range names {
				vecCorpusClockCases[nm] = true
			}
			continue
		}
		if key != "cases" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if d, _ := tok().(json.Delim); d != '[' {
			t.Fatal("base: cases is not an array")
		}
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.Fatal(err)
			}
			v, err := ParseJSONLenient(raw)
			if err != nil {
				t.Fatalf("base case %d: %v", n, err)
			}
			v = baseUTF16(v)
			m := norm(v).(map[string]any)
			args, _ := m["args"].([]any)
			c := &baseCase{Fn: m["fn"].(string), Name: m["name"].(string), Args: args, Out: m["out"], C: m}
			f(c)
			n++
		}
		tok()
	}
	if n == 0 {
		t.Fatalf("base: no cases in %s", file)
	}
	return n
}

// baseThrows reports whether out is a reference throw, and its stable code ("" when it carried none).
func baseThrows(out any) (bool, string) {
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

// baseBytes decodes {"$bytes": b64url} (nil when v is not that shape).
func baseBytes(v any) []byte {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	if sm, isMap := m["$bytes"].(map[string]any); isMap { // {"$bytes": {"$seed": label}}: sha256("atlas-pca-conformance/" + label)
		if label, ok := sm["$seed"].(string); ok && len(sm) == 1 {
			d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			return d[:]
		}
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

// baseCanon is the canonical (lenient) JSON of v, for whole-value equality.
func baseCanon(v any) string {
	v = baseSeedBytes(v)
	s, ok := canonicalLenient(v)
	if !ok {
		return fmt.Sprintf("<uncanonical %#v>", v)
	}
	return s
}

// baseTally collects divergences per fn; finish fails the test with the first few and logs ran / skipped counts.
type baseTally struct {
	ran, skipped map[string]int
	why          map[string]string
	bad          []string
	nbad         int
	badFn        map[string]int
	badKind      map[string]int
}

func (k *baseTally) run(fn string) {
	if k.ran == nil {
		k.ran = map[string]int{}
	}
	k.ran[fn]++
}

// skip records a case not compared, with the reason (one reason per fn is kept for the log).
func (k *baseTally) skip(fn, why string) {
	if k.skipped == nil {
		k.skipped, k.why = map[string]int{}, map[string]string{}
	}
	key := fn + "\x00" + why // one line per distinct reason
	k.skipped[key]++
	k.why[key] = fn
}

func (k *baseTally) fail(c *baseCase, format string, a ...any) {
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

func (k *baseTally) finish(t *testing.T) {
	t.Helper()
	fns := make([]string, 0, len(k.ran))
	for f := range k.ran {
		fns = append(fns, f)
	}
	sort.Strings(fns)
	for _, f := range fns {
		t.Logf("%s: %d compared", f, k.ran[f])
		// every replay through this tally counts for the accounting test, minus its skipped cases
		skipped := 0
		for key, n := range k.skipped {
			if k.why[key] == f {
				skipped += n
			}
		}
		if k.ran[f] > skipped {
			replayRan(f)
		}
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

// baseSameUnknown: both are the same "<prefix>unknown member '<name>'" refusal, naming possibly different members. With several
// unknown members the reference names the first in insertion order, which a Go map does not keep (Go names the least).
func baseSameUnknown(want, got string) bool {
	const m = "unknown member '"
	i, j := strings.LastIndex(want, m), strings.LastIndex(got, m)
	return i >= 0 && i == j && want[:i] == got[:j] && strings.HasSuffix(want, "'") && strings.HasSuffix(got, "'")
}

// baseI64 reads any integral JSON number below 2^63 as an int64 (2^53 and above included, so a native must refuse them as the
// reference does; -0 is 0).
func baseI64(v any) (int64, bool) {
	f, ok := jsNum(v)
	return int64(f), ok && f == math.Trunc(f) && math.Abs(f) < 1<<63
}

// baseCall runs f, turning a panic into an error string (a native that panics on hostile input is a divergence, not a crash).
func baseCall(f func()) (panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

// vecCorpusPath is testdata/<file>, or file itself when it is an absolute path (corpora CI generates outside the tree).
func vecCorpusPath(file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	return "testdata/" + file
}

// baseSeedBytes rewrites {"$bytes": {"$seed": label}} (a corpus value derived from a label, never raw key material) to the bytes
// the label stands for, on a copy; a native result never carries the placeholder, so only expected values change.
func baseSeedBytes(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if sm, ok := t["$bytes"].(map[string]any); ok && len(t) == 1 {
			if label, ok := sm["$seed"].(string); ok && len(sm) == 1 {
				d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
				return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(d[:])}
			}
		}
		if sv, ok := vecSeedValue(t); ok { // a lone {"$seed": label} value stands for the key string derived from the label
			return sv
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = baseSeedBytes(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = baseSeedBytes(x)
		}
		return a
	}
	return v
}

// baseUTF16 replaces, in place, every {"$utf16": [code units]} (a string holding a lone surrogate) by that string. Go strings are bytes,
// so a lone surrogate becomes its WTF-8 form, which is what the lane's lenient reader keeps for a "\ud800" escape.
func baseUTF16(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if u, ok := t["$utf16"].([]any); ok && len(t) == 1 {
			var b []byte
			num := func(x any) rune { n, _ := strconv.Atoi(fmt.Sprint(x)); return rune(n) }
			for i := 0; i < len(u); i++ {
				c := num(u[i])
				if c >= 0xD800 && c <= 0xDBFF && i+1 < len(u) {
					if lo := num(u[i+1]); lo >= 0xDC00 && lo <= 0xDFFF {
						c = 0x10000 + (c-0xD800)<<10 + (lo - 0xDC00)
						i++
					}
				}
				if c >= 0xD800 && c <= 0xDFFF {
					b = append(b, 0xE0|byte(c>>12), 0x80|byte((c>>6)&0x3F), 0x80|byte(c&0x3F))
				} else {
					b = unicodeutf8.AppendRune(b, c)
				}
			}
			return string(b)
		}
		for k, x := range t {
			t[k] = baseUTF16(x)
		}
	case []any:
		for i, x := range t {
			t[i] = baseUTF16(x)
		}
	}
	return v
}
