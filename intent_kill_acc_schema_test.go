package pca

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Differential replays of two reference corpora, every case: the accumulator / monitor surface (testdata/killAcc.json.gz:
// declarations, selection, values, pre-states, receipts, sequencer key sets, a receipt against its holder) and the action schema
// surface (testdata/killG-schema.json.gz: shape, signature, digest, parameter values, conformance, the canonical projection). A
// refusal is compared by its exact reason text.

func killDoc(t *testing.T, file string) map[string]any {
	t.Helper()
	f, err := os.Open("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	return vecObj(v)
}

// killBad collects mismatches and reports the first of each section.
type killBad struct {
	n    int
	list []string
	per  map[string]int
}

func (b *killBad) add(section, name, format string, a ...any) {
	b.n++
	if b.per == nil {
		b.per = map[string]int{}
	}
	if b.per[section]++; b.per[section] <= 6 {
		b.list = append(b.list, "\n  "+name+": "+fmt.Sprintf(format, a...))
	}
}

func (b *killBad) finish(t *testing.T) {
	t.Helper()
	if b.n > 0 {
		t.Errorf("%d cases differ from the reference (per section: %v)%s", b.n, b.per, strings.Join(b.list, ""))
	}
}

// killReason is a refusal text as the corpora carry it: null when accepted.
func killReason(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestIntentAccKillCorpus(t *testing.T) {
	doc := killDoc(t, "killAcc.json.gz")
	optF := func(m map[string]any, k string) *float64 {
		if _, has := m[k]; !has {
			return nil
		}
		f := jsF(m[k])
		return &f
	}
	fns := map[string]func(in any) (any, error){
		"acc":     func(in any) (any, error) { return killReason(AccumulatorDeclError(in)), nil },
		"mon":     func(in any) (any, error) { return killReason(MonitorDeclError(in)), nil },
		"rshape":  func(in any) (any, error) { return killReason(AccReceiptShapeError(in)), nil },
		"ksshape": func(in any) (any, error) { return killReason(SequencerKeySetShapeError(in)), nil },
		"tracked": func(in any) (any, error) { return killReason(TrackedKeySetError(vecObj(in)["t"])), nil },
		"dkey": func(in any) (any, error) {
			if s, ok := DistinctKey(vecObj(in)["x"]); ok {
				return s, nil
			}
			return nil, nil
		},
		"states": func(in any) (any, error) { return append([]string{}, MonitorStates(vecObj(in))...), nil },
		"sel": func(in any) (any, error) {
			i := vecObj(in)
			schema, has := i["schema"]
			ok, throws := AccSelects(vecObj(i["a"]), vecStr(i, "verb"), schema, has)
			if throws {
				return nil, fmt.Errorf("the reference answers %v, this one refuses the schema", ok)
			}
			return ok, nil
		},
		"val": func(in any) (any, error) {
			i := vecObj(in)
			schema, has := i["schema"]
			v, err := AccValueOf(vecObj(i["a"]), vecStr(i, "verb"), vecObj(i["params"]), schema, has)
			if err != nil {
				return nil, err
			}
			if v["ok"] != true {
				return map[string]any{"reason": v["reason"], "value": 0, "key": nil}, nil
			}
			return map[string]any{"reason": nil, "value": v["val"], "key": v["key"]}, nil
		},
		"pre": func(in any) (any, error) {
			i := vecObj(in)
			return killReason(PreStateError(vecStr(i, "agg"), i["s"])), nil
		},
		"combine": func(in any) (any, error) {
			i := vecObj(in)
			if post, ok := CombineAcc(vecStr(i, "agg"), vecObj(i["pre"]), jsF(i["value"]), vecStr(i, "key")); ok {
				return jsNumber(post), nil
			}
			return nil, nil
		},
		"prev": func(in any) (any, error) {
			i := vecObj(in)
			return jsNumber(PreValue(vecStr(i, "agg"), vecObj(i["pre"]))), nil
		},
		"arith": func(in any) (any, error) {
			i := vecObj(in)
			return ReceiptArithmeticOk(vecStr(i, "agg"), vecObj(i["r"]), jsF(i["value"])), nil
		},
		"resdig": func(in any) (any, error) {
			d, ok := PcactnReservationDigest(vecObj(vecObj(in)["p"]))
			if !ok {
				return nil, fmt.Errorf("no digest")
			}
			return d, nil
		},
		"rdig": func(in any) (any, error) {
			d, ok := AccReceiptDigest(vecObj(in)["r"])
			if !ok {
				return nil, fmt.Errorf("no digest")
			}
			return d, nil
		},
		"ksdig": func(in any) (any, error) {
			d, ok := SequencerKeySetDigest(vecObj(in)["k"])
			if !ok {
				return nil, fmt.Errorf("no digest")
			}
			return d, nil
		},
		"rsig": func(in any) (any, error) {
			i := vecObj(in)
			return VerifyAccReceiptSignature(vecObj(i["r"]), vecStr(i, "signer"), rsStrMap(i["pin"])), nil
		},
		"ksverify": func(in any) (any, error) {
			i := vecObj(in)
			pq, has := i["rootPqPk"]
			return VerifySequencerKeySet(i["k"], i["root"], pq, has), nil
		},
		"holder": func(in any) (any, error) {
			i := vecObj(in)
			sets, _ := i["keySets"].([]any) // anything but a list holds no key set
			return VerifyReceiptAgainstHolder(vecObj(i["r"]), vecObj(i["holder"]), sets, jsF(i["now"]),
				ReceiptFreshness{MaxReceiptAgeMs: optF(i, "maxR"), MaxKeySetAgeMs: optF(i, "maxK"), Tracked: vecObj(i["tracked"])}), nil
		},
	}
	var bad killBad
	counts := map[string]int{}
	cases, _ := doc["cases"].([]any)
	for _, cv := range cases {
		c := vecObj(cv)
		fn, name := vecStr(c, "fn"), vecStr(c, "name")
		counts[fn]++
		f := fns[fn]
		if f == nil {
			bad.add(fn, name, "no Go entry point for %s", fn)
			continue
		}
		var got any
		var err error
		if p := baseCall(func() { got, err = f(normalizeJSONOrdered(c["in"])) }); p != "" {
			bad.add(fn, name, "panic: %s", p)
			continue
		}
		if err != nil {
			bad.add(fn, name, "%v (the reference: %s)", err, baseCanon(normalizeJSON(c["expect"])))
			continue
		}
		if w, g := baseCanon(normalizeJSON(c["expect"])), baseCanon(vecJSON(got)); w != g {
			bad.add(fn, name, "want %s got %s", w, g)
		}
	}
	bad.finish(t)
	want := map[string]int{"acc": 194, "pre": 104, "rshape": 103, "arith": 100, "ksshape": 94, "holder": 90, "mon": 85, "val": 43, "combine": 23, "prev": 23,
		"rsig": 22, "tracked": 21, "ksverify": 20, "states": 15, "sel": 15, "dkey": 15, "resdig": 5, "rdig": 4, "ksdig": 3}
	for fn, n := range want {
		if counts[fn] != n {
			t.Errorf("%s: %d cases, the corpus has %d", fn, counts[fn], n)
		}
	}
	if len(cases) != 979 || len(counts) != len(want) {
		t.Fatalf("replayed %d cases of %d functions, the corpus has 979 of %d", len(cases), len(counts), len(want))
	}
}

// The corpus records four families of parameter refusals of a conformance result without the bound the reference names in them.
var killBoundFamilies = []struct {
	re   *regexp.Regexp
	text string
}{
	{regexp.MustCompile(`^longer than \d+ UTF-8 bytes$`), "longer than the declared max_len"},
	{regexp.MustCompile(`^below min -?\d+$`), "below min"},
	{regexp.MustCompile(`^above max -?\d+$`), "above max"},
	{regexp.MustCompile(`^array items must be strings of at most \d+ UTF-8 bytes$`), "array items must be strings within max_len UTF-8 bytes"},
}

var killPathPrefix = regexp.MustCompile(`^('[^']*': )(.*)$`)

func killBoundless(reason string) string {
	prefix := ""
	if m := killPathPrefix.FindStringSubmatch(reason); m != nil {
		prefix, reason = m[1], m[2]
	}
	for _, f := range killBoundFamilies {
		if f.re.MatchString(reason) {
			return prefix + f.text
		}
	}
	return prefix + reason
}

func TestActionSchemaKillCorpus(t *testing.T) {
	doc := killDoc(t, "killG-schema.json.gz")
	var bad killBad
	total := 0
	parse := func(c map[string]any, k string) any {
		s, isText := c[k].(string)
		if !isText {
			t.Fatalf("%s: %s is not JSON text", vecStr(c, "name"), k)
		}
		v, err := ParseJSONLenient([]byte(s))
		if err != nil {
			t.Fatalf("%s: %s: %v", vecStr(c, "name"), k, err)
		}
		return normalizeJSONOrdered(v)
	}
	section := func(name string, n int, f func(c map[string]any) (want, got any)) {
		cases, _ := doc[name].([]any)
		if len(cases) != n {
			t.Errorf("%s: %d cases, the corpus has %d", name, len(cases), n)
		}
		for i, cv := range cases {
			c := vecObj(cv)
			total++
			id := vecStr(c, "name")
			if id == "" {
				id = fmt.Sprintf("%s/%d", name, i)
			}
			var want, got any
			if p := baseCall(func() { want, got = f(c) }); p != "" {
				bad.add(name, id, "panic: %s", p)
				continue
			}
			if w, g := baseCanon(normalizeJSON(want)), baseCanon(vecJSON(got)); w != g {
				bad.add(name, id, "want %s got %s", w, g)
			}
		}
	}
	// the canonicalizer words its own refusals (a shared primitive): for those the family is compared, as the corpus owner does
	const canonFamily = "malformed schema: canonicalize: "
	section("shape", 353, func(c map[string]any) (any, any) {
		want, got := c["want"], killReason(ActionSchemaShapeError(parse(c, "doc"), true))
		if w, _ := want.(string); strings.HasPrefix(w, canonFamily) {
			if g, _ := got.(string); strings.HasPrefix(g, canonFamily) {
				return true, true
			}
		}
		return want, got
	})
	section("verify", 39, func(c map[string]any) (any, any) {
		return c["want"], VerifyActionSchema(parse(c, "doc"), parse(c, "keys"))["reason"]
	})
	section("digest", 2, func(c map[string]any) (any, any) {
		d, _ := ActionSchemaDigest(parse(c, "doc"))
		return c["want"], d
	})
	section("value", 223, func(c map[string]any) (any, any) {
		decl, x := vecObj(parse(c, "decl")), parse(c, "x")
		code, reason := paramValueViolationReason(decl, x)
		if public := ParamValueViolation(decl, x); public != code {
			return "the public code " + code, public
		}
		w := vecObj(c["want"])
		if w == nil {
			return nil, killReason(code)
		}
		return map[string]any{"code": w["code"], "reason": w["ts_reason"]}, map[string]any{"code": code, "reason": reason}
	})
	section("conform", 30, func(c map[string]any) (any, any) {
		r, reason := conformActionReason(parse(c, "doc"), vecStr(c, "verb"), parse(c, "params"))
		if public := ConformAction(parse(c, "doc"), vecStr(c, "verb"), parse(c, "params")); public != r {
			return "the public result", fmt.Sprint(public)
		}
		w := vecObj(c["want"])
		if w["ok"] == true {
			return map[string]any{"ok": true}, map[string]any{"ok": r.OK}
		}
		return map[string]any{"ok": false, "code": w["code"], "path": w["path"], "reason": w["reason"]},
			map[string]any{"ok": r.OK, "code": r.Code, "path": killReason(r.Path), "reason": killBoundless(reason)}
	})
	section("verbOf", 7, func(c map[string]any) (any, any) {
		v, throws := SchemaVerb(parse(c, "doc"), vecStr(c, "verb"))
		if throws {
			return c["want"], "refused"
		}
		if c["want"] == nil {
			if v == nil {
				return nil, nil
			}
			return nil, v
		}
		return parse(c, "want"), v
	})
	section("canon", 9, func(c map[string]any) (any, any) {
		got, ok := CanonProjection(parse(c, "doc"), vecStr(c, "verb"), vecObj(parse(c, "params")))
		if !ok {
			return c["want"], "refused"
		}
		want := map[string]any{}
		pairs, _ := c["want"].([]any)
		for _, p := range pairs {
			kv, _ := p.([]any)
			k, _ := kv[0].(string)
			want[k] = kv[1]
		}
		return want, got
	})
	section("accum", 4, func(c map[string]any) (any, any) {
		got, throws := AccumulationParams(vecObj(parse(c, "verb")), vecStr(c, "unit"))
		if throws {
			return c["want"], "refused"
		}
		return c["want"], append([]string{}, got...)
	})
	bad.finish(t)
	if total != 667 {
		t.Fatalf("replayed %d cases, the corpus has 667", total)
	}
}
