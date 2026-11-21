package pca

// Replays the SIEM reference corpus: the OCSF / CEF / ECS mappers, formatDecision, scrubError and the sink / export scenarios.
// Records are plain JSON objects. The comparison is over the Go values directly (not through encoding/json), so a lone surrogate in
// an output string survives the comparison.
//
// Skipped cases:
//   - a record whose reference form carries an `undefined` member (JSON has no undefined): the reference proof digest is
//     "(undigestible)" where the digest of the JSON form is real.

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func siemTestOpts(v any) SiemSerializeOptions {
	m, _ := v.(map[string]any)
	s, _ := m["signature"].(string)
	return SiemSerializeOptions{Signature: s}
}

func siemTestList(v any) []any {
	l, _ := v.([]any)
	return l
}

func siemTestOptStr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok {
		return &s
	}
	return nil
}

func siemTestResult(r SiemSinkResult) map[string]any {
	out := map[string]any{"ok": r.OK}
	if r.Error != nil {
		out["error"] = *r.Error
	}
	return out
}

func siemTestHTTP(spec any) (any, error) {
	m, _ := spec.(map[string]any)
	format := vecStr(m, "format")
	var events []SiemEvent
	for _, r := range siemTestList(m["events"]) {
		e, err := SiemFormatDecision(r, format, SiemSerializeOptions{})
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	mode := vecStr(m, "mode")
	var mu sync.Mutex
	var calls []SiemFetchInit
	var urls []string
	fetch := func(ctx context.Context, url string, in SiemFetchInit) (SiemFetchResponse, error) {
		mu.Lock()
		calls = append(calls, in)
		urls = append(urls, url)
		mu.Unlock()
		switch {
		case mode == "ok":
			return SiemFetchResponse{OK: true, Status: 200}, nil
		case strings.HasPrefix(mode, "st:"):
			parts := strings.SplitN(mode, ":", 3)
			code, _ := strconv.Atoi(parts[1])
			text := ""
			if len(parts) == 3 {
				text = parts[2]
			}
			return SiemFetchResponse{Status: code, StatusText: text}, nil
		case strings.HasPrefix(mode, "throws:"):
			return SiemFetchResponse{}, errors.New(mode[len("throws:"):])
		}
		<-ctx.Done() // hang until the sink gives up
		return SiemFetchResponse{}, ctx.Err()
	}
	opts := SiemHttpSinkOptions{Format: format, Fetch: fetch, ContentType: siemTestOptStr(m, "contentType"), Name: siemTestOptStr(m, "name")}
	if h, ok := m["headers"].(map[string]any); ok {
		opts.Headers = map[string]string{}
		for k, v := range h {
			opts.Headers[k], _ = v.(string)
		}
	}
	if f, ok := jsNum(m["timeoutMs"]); ok {
		opts.TimeoutMs = &f
	}
	sink := SiemHttpSink(vecStr(m, "url"), opts)
	res := sink.Deliver(events)
	out := map[string]any{"name": sink.Name(), "format": sink.Format(), "result": siemTestResult(res)}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) > 0 {
		hs := map[string]any{}
		for k, v := range calls[0].Headers {
			hs[k] = v
		}
		out["request"] = map[string]any{"url": urls[0], "method": calls[0].Method, "headers": hs, "body": calls[0].Body}
	}
	return out, nil
}

func siemTestConsole(spec any) (any, error) {
	m, _ := spec.(map[string]any)
	throws := vecStr(m, "throws")
	lines := []any{}
	opts := SiemConsoleSinkOptions{Format: vecStr(m, "format"), Name: siemTestOptStr(m, "name"), Logger: func(l string) {
		if throws != "" {
			panic(errors.New(throws))
		}
		lines = append(lines, l)
	}}
	sink := SiemConsoleSink(opts)
	var events []SiemEvent
	for _, r := range siemTestList(m["records"]) {
		e, err := SiemFormatDecision(r, sink.Format(), SiemSerializeOptions{})
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	res := sink.Deliver(events)
	return map[string]any{"name": sink.Name(), "format": sink.Format(), "result": siemTestResult(res), "lines": lines}, nil
}

type siemTestSink struct {
	format    string
	mode      string
	delivered *[]any
}

func (s *siemTestSink) Name() string   { return "s1" }
func (s *siemTestSink) Format() string { return s.format }
func (s *siemTestSink) Deliver(events []SiemEvent) SiemSinkResult {
	for _, e := range events {
		*s.delivered = append(*s.delivered, e.Line)
	}
	switch s.mode {
	case "ok":
		return SiemSinkResult{OK: true}
	case "fail":
		msg := "collector said no token=abcdef123"
		return SiemSinkResult{Error: &msg}
	case "failNoError":
		return SiemSinkResult{}
	}
	panic(errors.New("deliver exploded Bearer abcdefghij"))
}

func siemTestExport(spec any) (any, error) {
	m, _ := spec.(map[string]any)
	mode := vecStr(m, "sinkMode")
	onErrorThrows, _ := m["onErrorThrows"].(bool)
	delivered := []any{}
	errs := []any{}
	sink := &siemTestSink{format: vecStr(m, "format"), mode: mode, delivered: &delivered}
	opts := SiemExportOptions{
		Serialize: siemTestOpts(m["serialize"]),
		OnError: func(err error, s string, count int) {
			errs = append(errs, map[string]any{"message": err.Error(), "sink": s, "count": count})
			if mode == "throwsOnError" || onErrorThrows {
				panic(errors.New("cb"))
			}
		},
	}
	r := SiemExportBatch(siemTestList(m["records"]), sink, opts)
	res := map[string]any{"ok": r.OK, "delivered": r.Delivered, "format": r.Format}
	if !r.OK {
		res["error"] = r.Error
	}
	if r.Skipped > 0 {
		res["skipped"] = r.Skipped
	}
	return map[string]any{"result": res, "errors": errs, "delivered": delivered}, nil
}

// siemEach streams testdata/<file> case by case, but keeps the arguments as parsed (not rewritten): the parser records the text
// order of every object's members, which the CEF checks field and the JSON lines depend on, and a rewrite would lose it.
func siemEach(t *testing.T, file string, f func(c *baseCase)) {
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
		t.Fatal("not an object")
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
		tok() // [
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.Fatal(err)
			}
			v, err := ParseJSONLenient(raw)
			if err != nil {
				t.Fatalf("case %d: %v", n, err)
			}
			m := v.(map[string]any)
			args, _ := m["args"].([]any)
			f(&baseCase{Fn: m["fn"].(string), Name: m["name"].(string), Args: args, Out: normalizeJSON(m["out"]), C: m})
			n++
		}
		tok() // ]
	}
	if n == 0 {
		t.Fatalf("no cases in %s", file)
	}
}

func siemReplay(t *testing.T, file string, fns map[string]vecFn) { siemReplayWith(t, file, fns, false) }

// siemReplaySeeded resolves the corpus seed objects in args and in the expected output (derived keys appear in both).
func siemReplaySeeded(t *testing.T, file string, fns map[string]vecFn) {
	t.Helper()
	siemReplayWith(t, file, vecSeeded(fns), true)
}

func siemReplayWith(t *testing.T, file string, fns map[string]vecFn, seeded bool) {
	t.Helper()
	var k baseTally
	siemEach(t, file, func(c *baseCase) {
		if seeded {
			c.Out = vecResolveSeeds(c.Out)
		}
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
		if throws, _ := baseThrows(c.Out); throws {
			if err == nil && !(vecEngineCrash(c.Out) && vecRefusalValue(vecJSON(got))) {
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(normalizeJSON(got)))
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		// a non-finite number is the reference's {"$num"} marker; the Go records carry null there (what JSON.stringify makes of it)
		w, g := baseCanon(vecNumMarkersToNull(c.Out)), baseCanon(normalizeJSON(got))
		if w == g {
			return
		}
		if strings.Contains(w, "(undigestible)") && !strings.Contains(g, "(undigestible)") {
			k.skip(c.Fn, "the reference record carries an undefined member (JSON cannot): its digest is (undigestible)")
			return
		}
		k.fail(c, "%s", vecDiff(w, g))
	})
	k.finish(t)
}

func TestSiemVectors(t *testing.T) {
	arg := func(a []any, i int) any { return vecArg(a, i) }
	siemReplay(t, "ref-siem.json.gz", map[string]vecFn{
		"toOcsfEvent": func(a []any) (any, error) { return SiemToOcsfEvent(arg(a, 0), siemTestOpts(arg(a, 1))) },
		"toEcs":       func(a []any) (any, error) { return SiemToEcs(arg(a, 0), siemTestOpts(arg(a, 1))) },
		"toCef":       func(a []any) (any, error) { return SiemToCef(arg(a, 0), siemTestOpts(arg(a, 1))) },
		"formatDecision": func(a []any) (any, error) {
			format, _ := arg(a, 1).(string)
			e, err := SiemFormatDecision(arg(a, 0), format, siemTestOpts(arg(a, 2)))
			if err != nil {
				return nil, err
			}
			return e.Map(), nil
		},
		"scrubError": func(a []any) (any, error) {
			s, _ := arg(a, 0).(string)
			return SiemScrubError(s), nil
		},
		"httpSinkScenario":    func(a []any) (any, error) { return siemTestHTTP(arg(a, 0)) },
		"consoleSinkScenario": func(a []any) (any, error) { return siemTestConsole(arg(a, 0)) },
		"exportScenario":      func(a []any) (any, error) { return siemTestExport(arg(a, 0)) },
	})
}

// vecNumMarkersToNull replaces every {"$num": "NaN" | "Infinity" | "-Infinity"} of an expected value by null, on a copy.
func vecNumMarkersToNull(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["$num"].(string); ok && len(t) == 1 {
			return nil
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = vecNumMarkersToNull(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = vecNumMarkersToNull(x)
		}
		return a
	}
	return v
}
