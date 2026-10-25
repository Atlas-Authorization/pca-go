package pca

// Mutation kills for rule 19 (intent_map.go): every closed/typed shape check of the committed map at its exact boundary
// (packages/pca/src/intent-map-commit.ts is the oracle: dimError / mapHeaderError / mapCellError / mapMetricsError /
// mapLearnerError / entryShape / mapDisclosureError), the numeric cells, RFC 9162 path verification edges, the exact
// refusal reason of every decideMapDisclosure step (first failure wins), and the commit primitive's refusals.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func killEExpect(t *testing.T, name string, got, want bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", name, got, want)
	}
}

// killECopy deep-copies a JSON value (maps / slices) without normalising it.
func killECopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := make(map[string]any, len(x))
		for k, e := range x {
			o[k] = killECopy(e)
		}
		return o
	case []any:
		o := make([]any, len(x))
		for i, e := range x {
			o[i] = killECopy(e)
		}
		return o
	}
	return v
}

func killEStr(n int) string { return strings.Repeat("a", n) }

func killENumDim() map[string]any {
	return map[string]any{"kind": "num", "path": "action.params.x", "lo": jnum(0), "hi": jnum(10), "cuts": []any{jnum(5)}}
}

func killECatDim() map[string]any {
	return map[string]any{"kind": "cat", "path": "action.resource", "values": []any{
		map[string]any{"kind": "exact", "value": "a"}, map[string]any{"kind": "other", "value": mapOther}}}
}

// killECatN: a categorical dimension of exactly n values (n-1 exact + other) on path p.
func killECatN(p string, n int) map[string]any {
	vals := []any{}
	for i := 0; i < n-1; i++ {
		vals = append(vals, map[string]any{"kind": "exact", "value": fmt.Sprintf("v%d", i)})
	}
	vals = append(vals, map[string]any{"kind": "other", "value": mapOther})
	return map[string]any{"kind": "cat", "path": p, "values": vals}
}

func TestKillEMapStrAndDimPath(t *testing.T) {
	_, ok := mapStr(killEStr(256), maxMapStringBytes)
	killEExpect(t, "256 bytes", ok, true)
	_, ok = mapStr(killEStr(257), maxMapStringBytes)
	killEExpect(t, "257 bytes", ok, false)
	_, ok = mapStr("a\xed\xa0\x80", maxMapStringBytes)
	killEExpect(t, "lone surrogate", ok, false)
	_, ok = mapStr(jnum(1), maxMapStringBytes)
	killEExpect(t, "number", ok, false)
	killEExpect(t, "path resource", isDimPath("action.resource"), true)
	killEExpect(t, "path param", isDimPath("action.params.x_1"), true)
	killEExpect(t, "path other string", isDimPath("foo"), false)
	killEExpect(t, "path bad ident", isDimPath("action.params.a-b"), false)
	killEExpect(t, "path number", isDimPath(jnum(1)), false)
}

func TestKillEMapNumCells(t *testing.T) {
	for _, c := range []struct {
		lo, hi int64
		cuts   []int64
		want   string
	}{
		{0, 10, nil, "[[0 10]]"},
		{0, 10, []int64{0}, "[[0 0] [1 10]]"},
		{0, 10, []int64{1}, "[[0 0] [1 1] [2 10]]"},
		{0, 10, []int64{2}, "[[0 1] [2 2] [3 10]]"},
		{0, 10, []int64{9}, "[[0 8] [9 9] [10 10]]"},
		{0, 10, []int64{10}, "[[0 9] [10 10]]"},
		{0, 10, []int64{3, 4}, "[[0 2] [3 3] [4 4] [5 10]]"},
		{0, 10, []int64{3, 5}, "[[0 2] [3 3] [4 4] [5 5] [6 10]]"},
		{-10, -2, []int64{-5}, "[[-10 -6] [-5 -5] [-4 -2]]"},
		{7, 7, []int64{7}, "[[7 7]]"},
	} {
		cuts := []any{}
		for _, x := range c.cuts {
			cuts = append(cuts, jnum(x))
		}
		d := deep(t, map[string]any{"kind": "num", "path": "action.params.x", "lo": jnum(c.lo), "hi": jnum(c.hi), "cuts": cuts}).(map[string]any)
		if got := fmt.Sprint(mapNumCells(d)); got != c.want {
			t.Errorf("lo %d hi %d cuts %v: %s, want %s", c.lo, c.hi, c.cuts, got, c.want)
		}
		killEExpect(t, fmt.Sprint("dimOK ", c), mapDimOK(d), true)
	}
}

func TestKillEMapDimOK(t *testing.T) {
	type mut func(d map[string]any)
	num := map[string]mut{
		"base":               func(d map[string]any) {},
		"extra member":       func(d map[string]any) { d["x"] = jnum(1) },
		"missing cuts":       func(d map[string]any) { delete(d, "cuts") },
		"path resource":      func(d map[string]any) { d["path"] = "action.resource" },
		"path bad":           func(d map[string]any) { d["path"] = "foo" },
		"lo string":          func(d map[string]any) { d["lo"] = "0" },
		"hi string":          func(d map[string]any) { d["hi"] = "10" },
		"lo > hi":            func(d map[string]any) { d["lo"] = jnum(11); d["cuts"] = []any{} },
		"lo == hi":           func(d map[string]any) { d["lo"] = jnum(10); d["cuts"] = []any{} },
		"cuts not array":     func(d map[string]any) { d["cuts"] = jnum(5) },
		"cuts empty":         func(d map[string]any) { d["cuts"] = []any{} },
		"cut string":         func(d map[string]any) { d["cuts"] = []any{"5"} },
		"cut equal":          func(d map[string]any) { d["cuts"] = []any{jnum(5), jnum(5)} },
		"cut decreasing":     func(d map[string]any) { d["cuts"] = []any{jnum(5), jnum(4)} },
		"cut increasing":     func(d map[string]any) { d["cuts"] = []any{jnum(5), jnum(6)} },
		"cut zero first":     func(d map[string]any) { d["cuts"] = []any{jnum(0)} },
		"cut negative first": func(d map[string]any) { d["lo"] = jnum(-10); d["cuts"] = []any{jnum(-1)} },
		"cut below lo":       func(d map[string]any) { d["lo"] = jnum(1); d["cuts"] = []any{jnum(0)} },
		"cut at lo":          func(d map[string]any) { d["lo"] = jnum(1); d["cuts"] = []any{jnum(1)} },
		"cut above hi":       func(d map[string]any) { d["cuts"] = []any{jnum(11)} },
		"cut at hi":          func(d map[string]any) { d["cuts"] = []any{jnum(10)} },
		"256 cuts": func(d map[string]any) {
			c := []any{}
			for i := 0; i < 256; i++ {
				c = append(c, jnum(int64(i)))
			}
			d["hi"], d["cuts"] = jnum(1000), c
		},
		"257 cuts": func(d map[string]any) {
			c := []any{}
			for i := 0; i < 257; i++ {
				c = append(c, jnum(int64(i)))
			}
			d["hi"], d["cuts"] = jnum(1000), c
		},
	}
	numWant := map[string]bool{"base": true, "lo == hi": true, "cuts empty": true, "cut increasing": true, "cut zero first": true,
		"cut negative first": true, "cut at lo": true, "cut at hi": true, "256 cuts": true}
	for name, m := range num {
		d := killENumDim()
		m(d)
		killEExpect(t, "num "+name, mapDimOK(deep(t, d)), numWant[name])
	}
	vals := func(vs ...any) func(d map[string]any) { return func(d map[string]any) { d["values"] = vs } }
	ex := func(k, v string) map[string]any { return map[string]any{"kind": k, "value": v} }
	other := ex("other", mapOther)
	cat := map[string]mut{
		"base":                 func(d map[string]any) {},
		"extra member":         func(d map[string]any) { d["x"] = jnum(1) },
		"missing values":       func(d map[string]any) { delete(d, "values") },
		"path param":           func(d map[string]any) { d["path"] = "action.params.q" },
		"path bad":             func(d map[string]any) { d["path"] = "action.params.a-b" },
		"values not array":     func(d map[string]any) { d["values"] = other },
		"values empty":         func(d map[string]any) { d["values"] = []any{} },
		"only other":           vals(other),
		"value not object":     vals("a", other),
		"value extra member":   vals(map[string]any{"kind": "exact", "value": "a", "x": jnum(1)}, other),
		"value missing member": vals(map[string]any{"kind": "exact"}, other),
		"value kind regex":     vals(ex("regex", "a"), other),
		"value number":         vals(map[string]any{"kind": "exact", "value": jnum(1)}, other),
		"value 256 bytes":      vals(ex("exact", killEStr(256)), other),
		"value 257 bytes":      vals(ex("exact", killEStr(257)), other),
		"exact empty":          vals(ex("exact", ""), other),
		"prefix empty":         vals(ex("prefix", ""), other),
		"prefix":               vals(ex("prefix", "a"), other),
		"other wrong value":    vals(ex("exact", "a"), ex("other", "x")),
		"other first":          vals(other, ex("exact", "a"), other),
		"no other":             vals(ex("exact", "a")),
		"no other prefix last": vals(ex("exact", "a"), ex("prefix", "b")),
		"duplicate exact":      vals(ex("exact", "a"), ex("exact", "a"), other),
		"duplicate prefix":     vals(ex("prefix", "a"), ex("prefix", "a"), other),
		"exact and prefix":     vals(ex("exact", "a"), ex("prefix", "a"), other),
		"256 values":           func(d map[string]any) { d["values"] = killECatN("action.resource", 256)["values"] },
		"257 values":           func(d map[string]any) { d["values"] = killECatN("action.resource", 257)["values"] },
	}
	catWant := map[string]bool{"base": true, "path param": true, "only other": true, "value 256 bytes": true, "exact empty": true,
		"prefix": true, "exact and prefix": true, "256 values": true}
	for name, m := range cat {
		d := killECatDim()
		m(d)
		killEExpect(t, "cat "+name, mapDimOK(deep(t, d)), catWant[name])
	}
	killEExpect(t, "dim not object", mapDimOK(jnum(1)), false)
	killEExpect(t, "dim nil", mapDimOK(nil), false)
	killEExpect(t, "dim kind other", mapDimOK(deep(t, map[string]any{"kind": "set", "path": "action.resource", "values": []any{}})), false)
}

func killEHeader() map[string]any {
	return map[string]any{"verb": "v", "first": jnum(1), "cells": jnum(6), "dims": []any{killENumDim(), killECatDim()}}
}

func TestKillEMapHeaderOK(t *testing.T) {
	type mut func(h map[string]any)
	cases := map[string]mut{
		"base":            func(h map[string]any) {},
		"extra member":    func(h map[string]any) { h["x"] = jnum(1) },
		"missing dims":    func(h map[string]any) { delete(h, "dims") },
		"verb empty":      func(h map[string]any) { h["verb"] = "" },
		"verb number":     func(h map[string]any) { h["verb"] = jnum(1) },
		"verb 128":        func(h map[string]any) { h["verb"] = killEStr(128) },
		"verb 129":        func(h map[string]any) { h["verb"] = killEStr(129) },
		"first -1":        func(h map[string]any) { h["first"] = jnum(-1) },
		"first 0":         func(h map[string]any) { h["first"] = jnum(0) },
		"first string":    func(h map[string]any) { h["first"] = "1" },
		"first max-1":     func(h map[string]any) { h["first"] = jnum(1<<24 - 1) },
		"first max":       func(h map[string]any) { h["first"] = jnum(1 << 24) },
		"cells 0":         func(h map[string]any) { h["cells"] = jnum(0); h["dims"] = []any{} },
		"cells string":    func(h map[string]any) { h["cells"] = "4" },
		"cells mismatch":  func(h map[string]any) { h["cells"] = jnum(7) },
		"no dims cells 1": func(h map[string]any) { h["cells"] = jnum(1); h["dims"] = []any{} },
		"no dims cells 2": func(h map[string]any) { h["cells"] = jnum(2); h["dims"] = []any{} },
		"dims not array":  func(h map[string]any) { h["dims"] = killENumDim() },
		"bad dim": func(h map[string]any) {
			d := killECatN("action.params.q", 2)
			d["x"] = jnum(1)
			h["cells"], h["dims"] = jnum(2), []any{d}
		},
		"duplicate path": func(h map[string]any) {
			h["cells"], h["dims"] = jnum(4), []any{killECatN("action.params.q", 2), killECatN("action.params.q", 2)}
		},
		"16 dims": func(h map[string]any) {
			ds := []any{}
			for i := 0; i < 16; i++ {
				ds = append(ds, killECatN(fmt.Sprintf("action.params.p%d", i), 1))
			}
			h["cells"], h["dims"] = jnum(1), ds
		},
		"17 dims": func(h map[string]any) {
			ds := []any{}
			for i := 0; i < 17; i++ {
				ds = append(ds, killECatN(fmt.Sprintf("action.params.p%d", i), 1))
			}
			h["cells"], h["dims"] = jnum(1), ds
		},
		// 256 * 256 * 16 = 2^20 = maxVerbCells: accepted (cells and the running product at the bound)
		"cells 2^20": func(h map[string]any) {
			h["cells"], h["dims"] = jnum(1<<20), []any{killECatN("action.params.a", 256), killECatN("action.params.b", 256), killECatN("action.resource", 16)}
		},
		// 2^21 cells: over the bound
		"cells 2^21": func(h map[string]any) {
			h["cells"], h["dims"] = jnum(1<<21), []any{killECatN("action.params.a", 256), killECatN("action.params.b", 256), killECatN("action.resource", 16), killECatN("action.params.c", 2)}
		},
		// cells in range but the running product exceeds the bound
		"product 2^21 cells 2^20": func(h map[string]any) {
			h["cells"], h["dims"] = jnum(1<<20), []any{killECatN("action.params.a", 256), killECatN("action.params.b", 256), killECatN("action.resource", 16), killECatN("action.params.c", 2)}
		},
	}
	want := map[string]bool{"base": true, "verb 128": true, "first 0": true, "first max-1": true, "no dims cells 1": true, "16 dims": true, "cells 2^20": true}
	for name, m := range cases {
		h := killEHeader()
		m(h)
		killEExpect(t, "header "+name, mapHeaderOK(deep(t, h)), want[name])
	}
	killEExpect(t, "header not object", mapHeaderOK("x"), false)
}

func killECell() map[string]any {
	return map[string]any{"verb": "v", "cell": []any{jnum(0), jnum(1)}, "p_ppm": jnum(5), "in_grant": true}
}

func TestKillEMapCellMetricsLearnerOK(t *testing.T) {
	type mut func(c map[string]any)
	cells := map[string]mut{
		"base":          func(c map[string]any) {},
		"extra member":  func(c map[string]any) { c["x"] = jnum(1) },
		"missing grant": func(c map[string]any) { delete(c, "in_grant") },
		"verb empty":    func(c map[string]any) { c["verb"] = "" },
		"verb number":   func(c map[string]any) { c["verb"] = jnum(1) },
		"verb 128":      func(c map[string]any) { c["verb"] = killEStr(128) },
		"verb 129":      func(c map[string]any) { c["verb"] = killEStr(129) },
		"cell object":   func(c map[string]any) { c["cell"] = map[string]any{} },
		"cell empty":    func(c map[string]any) { c["cell"] = []any{} },
		"cell -1":       func(c map[string]any) { c["cell"] = []any{jnum(-1)} },
		"cell string":   func(c map[string]any) { c["cell"] = []any{"0"} },
		"cell 16": func(c map[string]any) {
			x := []any{}
			for i := 0; i < 16; i++ {
				x = append(x, jnum(0))
			}
			c["cell"] = x
		},
		"cell 17": func(c map[string]any) {
			x := []any{}
			for i := 0; i < 17; i++ {
				x = append(x, jnum(0))
			}
			c["cell"] = x
		},
		"p -1":         func(c map[string]any) { c["p_ppm"] = jnum(-1) },
		"p 0":          func(c map[string]any) { c["p_ppm"] = jnum(0) },
		"p one":        func(c map[string]any) { c["p_ppm"] = jnum(1_000_000) },
		"p one+1":      func(c map[string]any) { c["p_ppm"] = jnum(1_000_001) },
		"p string":     func(c map[string]any) { c["p_ppm"] = "5" },
		"grant number": func(c map[string]any) { c["in_grant"] = jnum(1) },
		"grant false":  func(c map[string]any) { c["in_grant"] = false },
	}
	cw := map[string]bool{"base": true, "verb 128": true, "cell empty": true, "cell 16": true, "p 0": true, "p one": true, "grant false": true}
	for name, m := range cells {
		c := killECell()
		m(c)
		killEExpect(t, "cell "+name, mapCellOK(deep(t, c)), cw[name])
	}
	killEExpect(t, "cell not object", mapCellOK(jnum(1)), false)

	metrics := func() map[string]any {
		m := map[string]any{"log2_vs_mbits": jnum(7)}
		for _, k := range mapMetricFields {
			m[k] = jnum(1)
		}
		return m
	}
	mm := map[string]mut{
		"base":          func(m map[string]any) {},
		"no log2":       func(m map[string]any) { delete(m, "log2_vs_mbits") },
		"missing risk":  func(m map[string]any) { delete(m, "residual_risk_ppm") },
		"extra member":  func(m map[string]any) { m["x"] = jnum(1) },
		"negative":      func(m map[string]any) { m["questions"] = jnum(-1) },
		"negative log2": func(m map[string]any) { m["log2_vs_mbits"] = jnum(-1) },
		"string":        func(m map[string]any) { m["conflicts"] = "1" },
		"zero everywhere": func(m map[string]any) {
			for k := range m {
				m[k] = jnum(0)
			}
		},
	}
	mw := map[string]bool{"base": true, "no log2": true, "zero everywhere": true}
	for name, mu := range mm {
		m := metrics()
		mu(m)
		killEExpect(t, "metrics "+name, mapMetricsOK(deep(t, m)), mw[name])
	}
	killEExpect(t, "metrics not object", mapMetricsOK(nil), false)

	killEExpect(t, "learner ok", mapLearnerOK(map[string]any{"learner_digest": dg("l")}), true)
	killEExpect(t, "learner bad digest", mapLearnerOK(map[string]any{"learner_digest": "abc"}), false)
	killEExpect(t, "learner extra", mapLearnerOK(map[string]any{"learner_digest": dg("l"), "x": jnum(1)}), false)
	killEExpect(t, "learner empty", mapLearnerOK(map[string]any{}), false)
	killEExpect(t, "learner not object", mapLearnerOK(dg("l")), false)
}

func TestKillEMapEntryAndDisclosureOK(t *testing.T) {
	m := buildMap(t, 500)
	entry := func() map[string]any { return killECopy(m.entry(1)).(map[string]any) }
	paths := func(n int) []any {
		p := []any{}
		for i := 0; i < n; i++ {
			p = append(p, dg(fmt.Sprint(i)))
		}
		return p
	}
	type mut func(e map[string]any)
	cases := map[string]mut{
		"base":         func(e map[string]any) {},
		"extra member": func(e map[string]any) { e["x"] = jnum(1) },
		"missing path": func(e map[string]any) { delete(e, "path") },
		"index -1":     func(e map[string]any) { e["index"] = jnum(-1) },
		"index string": func(e map[string]any) { e["index"] = "1" },
		"salt short":   func(e map[string]any) { e["salt"] = "abc" },
		"path object":  func(e map[string]any) { e["path"] = map[string]any{} },
		"path empty":   func(e map[string]any) { e["path"] = []any{} },
		"path 64":      func(e map[string]any) { e["path"] = paths(64) },
		"path 65":      func(e map[string]any) { e["path"] = paths(65) },
		"path bad":     func(e map[string]any) { e["path"] = []any{dg("a"), "abc"} },
	}
	want := map[string]bool{"base": true, "path empty": true, "path 64": true}
	for name, mu := range cases {
		e := entry()
		mu(e)
		killEExpect(t, "entry "+name, mapEntryOK(deep(t, e)), want[name])
	}
	killEExpect(t, "entry not object", mapEntryOK("x"), false)

	disc := func() map[string]any { return killECopy(m.disclose(0)).(map[string]any) }
	dcases := map[string]mut{
		"base":             func(d map[string]any) {},
		"extra member":     func(d map[string]any) { d["learner"] = m.entry(len(m.leaves) - 1) },
		"missing metrics":  func(d map[string]any) { delete(d, "metrics") },
		"size string":      func(d map[string]any) { d["size"] = "15" },
		"size 3":           func(d map[string]any) { d["size"] = jnum(3) },
		"size 4":           func(d map[string]any) { d["size"] = jnum(4) },
		"size 5":           func(d map[string]any) { d["size"] = jnum(5) },
		"size max":         func(d map[string]any) { d["size"] = jnum(1 << 24) },
		"size max+1":       func(d map[string]any) { d["size"] = jnum(1<<24 + 1) },
		"header entry bad": func(d map[string]any) { d["header"].(map[string]any)["index"] = jnum(-1) },
		"cell entry bad":   func(d map[string]any) { d["cell"].(map[string]any)["salt"] = "abc" },
		"metrics entry bad": func(d map[string]any) {
			d["metrics"].(map[string]any)["x"] = jnum(1)
		},
		"header leaf bad": func(d map[string]any) {
			d["header"].(map[string]any)["leaf"].(map[string]any)["cells"] = jnum(13)
		},
		"cell leaf bad": func(d map[string]any) {
			d["cell"].(map[string]any)["leaf"].(map[string]any)["p_ppm"] = jnum(-1)
		},
		"metrics leaf bad": func(d map[string]any) {
			d["metrics"].(map[string]any)["leaf"].(map[string]any)["questions"] = jnum(-1)
		},
	}
	dwant := map[string]bool{"base": true, "size 4": true, "size 5": true, "size max": true}
	for name, mu := range dcases {
		d := disc()
		mu(d)
		killEExpect(t, "disclosure "+name, mapDisclosureOK(deep(t, d)), dwant[name])
	}
	killEExpect(t, "disclosure not object", mapDisclosureOK(jnum(1)), false)
}

func TestKillEMapLeafHash(t *testing.T) {
	salt := make([]byte, 32)
	leaf := map[string]any{"learner_digest": dg("l")}
	h, ok := mapLeafHash("learner", salt, leaf)
	if !ok || len(h) != 32 {
		t.Fatal("learner leaf")
	}
	want := sha(append(append([]byte(mapTagLearner), salt...), []byte(`{"learner_digest":"`+dg("l")+`"}`)...))
	if string(h) != string(want) {
		t.Fatal("leaf hash is not SHA-256(tag || salt || canonical leaf)")
	}
	for name, c := range map[string]struct {
		kind string
		salt []byte
		leaf any
	}{
		"unknown kind":      {"node", salt, leaf},
		"salt 31":           {"learner", make([]byte, 31), leaf},
		"salt 33":           {"learner", make([]byte, 33), leaf},
		"bad kind and salt": {"node", make([]byte, 31), leaf},
		"no canonical form": {"learner", salt, map[string]any{"x": math.NaN()}},
		"func leaf":         {"learner", salt, func() {}},
	} {
		if h, ok := mapLeafHash(c.kind, c.salt, c.leaf); ok || h != nil {
			t.Errorf("%s: hashed", name)
		}
	}
	// node and commit hashes
	l, r := sha([]byte("l")), sha([]byte("r"))
	if string(mapNodeHash(l, r)) != string(sha(append(append([]byte(mapTagNode), l...), r...))) {
		t.Fatal("node hash")
	}
}

func TestKillEMapRootFromPath(t *testing.T) {
	for n := 1; n <= 17; n++ {
		hs := make([][]byte, n)
		for i := range hs {
			hs[i] = sha([]byte{byte(i), byte(n)})
		}
		root := mapTreeRoot(hs)
		for i := 0; i < n; i++ {
			p := mapAudit(hs, i)
			if got := mapRootFromPath(i, n, hs[i], p); string(got) != string(root) {
				t.Fatalf("size %d leaf %d does not open", n, i)
			}
			// one extra path element: the path is too long (nil, not a root)
			if got := mapRootFromPath(i, n, hs[i], append(append([][]byte{}, p...), hs[0])); got != nil {
				t.Errorf("size %d leaf %d: an over-long path is accepted", n, i)
			}
			if len(p) > 0 {
				if got := mapRootFromPath(i, n, hs[i], p[:len(p)-1]); got != nil {
					t.Errorf("size %d leaf %d: a short path is accepted", n, i)
				}
			}
		}
		// index outside [0, size)
		for _, idx := range []int{-1, n, n + 1} {
			for k := 0; k <= 6; k++ {
				p := make([][]byte, k)
				for j := range p {
					p[j] = hs[0]
				}
				if got := mapRootFromPath(idx, n, hs[0], p); got != nil {
					t.Errorf("size %d index %d path %d: not nil", n, idx, k)
				}
			}
		}
	}
	if mapRootFromPath(0, 0, sha(nil), nil) != nil {
		t.Error("empty tree")
	}
}

// killEBuild commits an arbitrary leaf list (fresh salts) as a builtMap.
func killEBuild(t *testing.T, leaves []mapLeaf) *builtMap {
	m := &builtMap{leaves: leaves}
	for i := range m.leaves {
		m.leaves[i].salt = make([]byte, 32)
		_, _ = rand.Read(m.leaves[i].salt)
		h, ok := mapLeafHash(m.leaves[i].kind, m.leaves[i].salt, deep(t, m.leaves[i].leaf))
		if !ok {
			t.Fatal("leaf hash")
		}
		m.hashes = append(m.hashes, h)
	}
	m.commit = mapCommitOf(len(m.hashes), mapTreeRoot(m.hashes))
	return m
}

func killEReason(t *testing.T, name string, in map[string]any, wantOK bool, reason string) {
	t.Helper()
	got, why := IntentMapPrimitive(deep(t, in))
	if got["ok"] != wantOK || why != reason {
		t.Errorf("%s: ok %v reason %q, want ok %v reason %q", name, got["ok"], why, wantOK, reason)
	}
}

func TestKillEMapDecisionReasons(t *testing.T) {
	m := buildMap(t, 500)
	base := func() map[string]any {
		return mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)
	}
	killEReason(t, "base", base(), true, "")
	disc := func(in map[string]any) map[string]any { return in["disclosure"].(map[string]any) }
	for name, c := range map[string]struct {
		mut    func(in map[string]any)
		reason string
	}{
		"disclosure null":      {func(in map[string]any) { in["disclosure"] = nil }, "map disclosure malformed: the disclosure must be exactly {size, header, cell, metrics}"},
		"commit malformed":     {func(in map[string]any) { in["map_commit"] = "abc" }, "the PCActn carries no map commitment"},
		"commit absent":        {func(in map[string]any) { delete(in, "map_commit") }, "the PCActn carries no map commitment"},
		"commit number":        {func(in map[string]any) { in["map_commit"] = jnum(1) }, "the PCActn carries no map commitment"},
		"params null":          {func(in map[string]any) { in["params"] = nil }, "params must be an object"},
		"params array":         {func(in map[string]any) { in["params"] = []any{} }, "params must be an object"},
		"params digest":        {func(in map[string]any) { in["params"] = map[string]any{"total": jnum(2)} }, "the params do not hash to action.params_digest"},
		"verb":                 {func(in map[string]any) { in["action"].(map[string]any)["verb"] = "air.cancel" }, "the disclosed header is not the action's verb"},
		"header index = first": {func(in map[string]any) { disc(in)["header"].(map[string]any)["index"] = jnum(1) }, "the disclosed header does not fit the committed layout"},
		"size one short":       {func(in map[string]any) { disc(in)["size"] = jnum(int64(len(m.leaves) - 1)) }, "the disclosed header does not fit the committed layout"},
		"size one more":        {func(in map[string]any) { disc(in)["size"] = jnum(int64(len(m.leaves) + 1)) }, "the header leaf does not open the map commitment"},
		"foreign commit":       {func(in map[string]any) { in["map_commit"] = buildMap(t, 500).commit }, "the header leaf does not open the map commitment"},
		"swapped cell":         {func(in map[string]any) { disc(in)["cell"] = m.entry(2) }, "the disclosed cell is not the action's cell"},
		"outside num":          {func(in map[string]any) {}, ""},
	} {
		in := base()
		c.mut(in)
		if name == "outside num" {
			continue
		}
		killEReason(t, name, in, false, c.reason)
	}
	// the action outside the dimension: the exact reason (not a cell mismatch)
	killEReason(t, "outside num", mapInput(t, m, map[string]any{"total": jnum(100_001)}, "skyair.example/bookings", 0), false, "the action's action.params.total lies outside the committed map's dimension")
	in := mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)
	in["action"].(map[string]any)["resource"] = jnum(5)
	killEReason(t, "resource number", in, false, "the action's action.resource lies outside the committed map's dimension")
	in = mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)
	delete(in["action"].(map[string]any), "resource")
	killEReason(t, "resource absent", in, false, "the action's action.resource lies outside the committed map's dimension")
	// params absent: hashed as {} (passes the digest), then total is absent -> outside
	in = mapInput(t, m, map[string]any{}, "skyair.example/bookings", 0)
	delete(in, "params")
	killEReason(t, "params absent", in, false, "the action's action.params.total lies outside the committed map's dimension")
	// params null with the digest of {}: still not an object
	in = mapInput(t, m, map[string]any{}, "skyair.example/bookings", 0)
	in["params"] = nil
	killEReason(t, "params null digest of {}", in, false, "params must be an object")
	// a cell outside the grant
	d := buildMap(t, 500, 0)
	killEReason(t, "outside grant", mapInput(t, d, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0), false, "the action's cell is outside the committed grant")
	// ε
	in = base()
	in["max_residual_risk_ppm"] = jnum(499)
	killEReason(t, "eps over", in, false, "the committed residual risk 500 ppm exceeds ε = 499")
	in["max_residual_risk_ppm"] = jnum(500)
	killEReason(t, "eps at", in, true, "")
	// other / prefix cells decide exactly
	killEReason(t, "other", mapInput(t, m, map[string]any{"total": jnum(1)}, "elsewhere", 3), true, "")
	killEReason(t, "other empty", mapInput(t, m, map[string]any{"total": jnum(1)}, "", 3), true, "")
	killEReason(t, "prefix", mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/x", 1), true, "")
	killEReason(t, "long prefix", mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bz", 2), true, "")
	killEReason(t, "exact over prefix", mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0), true, "")
}

// Custom maps: two identical cell leaves (index-only mismatch), a wrong-verb / short cell leaf at the right index, and a
// second metrics-shaped leaf at size-1.
func TestKillEMapDecisionCustomLeaves(t *testing.T) {
	dims := []any{map[string]any{"kind": "cat", "path": "action.resource", "values": []any{
		map[string]any{"kind": "exact", "value": "a"}, map[string]any{"kind": "other", "value": mapOther}}}}
	header := map[string]any{"verb": "v", "first": jnum(1), "cells": jnum(2), "dims": dims}
	cell := func(verb string, coords ...int64) map[string]any {
		c := []any{}
		for _, x := range coords {
			c = append(c, jnum(x))
		}
		return map[string]any{"verb": verb, "cell": c, "p_ppm": jnum(7), "in_grant": true}
	}
	metrics := map[string]any{}
	for _, k := range mapMetricFields {
		metrics[k] = jnum(1)
	}
	learner := map[string]any{"learner_digest": dg("l")}
	input := func(m *builtMap, cellIdx, metricsIdx int) map[string]any {
		pd, _ := ParamsDigest(map[string]any{})
		return map[string]any{"map_commit": m.commit, "action": map[string]any{"verb": "v", "resource": "a", "params_digest": pd},
			"params": map[string]any{}, "disclosure": map[string]any{"size": jnum(int64(len(m.leaves))), "header": m.entry(0),
				"cell": m.entry(cellIdx), "metrics": m.entry(metricsIdx)}}
	}
	ok := killEBuild(t, []mapLeaf{{kind: "header", leaf: header}, {kind: "cell", leaf: cell("v", 0)}, {kind: "cell", leaf: cell("v", 1)},
		{kind: "metrics", leaf: metrics}, {kind: "learner", leaf: learner}})
	killEReason(t, "custom base", input(ok, 1, 3), true, "")
	// cell 2 carries the coordinates of cell 1: only the index differs
	dup := killEBuild(t, []mapLeaf{{kind: "header", leaf: header}, {kind: "cell", leaf: cell("v", 0)}, {kind: "cell", leaf: cell("v", 0)},
		{kind: "metrics", leaf: metrics}, {kind: "learner", leaf: learner}})
	killEReason(t, "index only", input(dup, 2, 3), false, "the disclosed cell is not the action's cell")
	// right index and coordinates, other verb
	wv := killEBuild(t, []mapLeaf{{kind: "header", leaf: header}, {kind: "cell", leaf: cell("w", 0)}, {kind: "cell", leaf: cell("v", 1)},
		{kind: "metrics", leaf: metrics}, {kind: "learner", leaf: learner}})
	killEReason(t, "verb only", input(wv, 1, 3), false, "the disclosed cell is not the action's cell")
	// right index and verb, fewer coordinates / more coordinates
	short := killEBuild(t, []mapLeaf{{kind: "header", leaf: header}, {kind: "cell", leaf: cell("v")}, {kind: "cell", leaf: cell("v", 1)},
		{kind: "metrics", leaf: metrics}, {kind: "learner", leaf: learner}})
	killEReason(t, "length only (short)", input(short, 1, 3), false, "the disclosed cell is not the action's cell")
	long := killEBuild(t, []mapLeaf{{kind: "header", leaf: header}, {kind: "cell", leaf: cell("v", 0, 0)}, {kind: "cell", leaf: cell("v", 1)},
		{kind: "metrics", leaf: metrics}, {kind: "learner", leaf: learner}})
	killEReason(t, "length only (long)", input(long, 1, 3), false, "the disclosed cell is not the action's cell")
	// a metrics leaf that opens, but at size-1
	mm := killEBuild(t, []mapLeaf{{kind: "header", leaf: header}, {kind: "cell", leaf: cell("v", 0)}, {kind: "cell", leaf: cell("v", 1)},
		{kind: "metrics", leaf: metrics}, {kind: "metrics", leaf: metrics}})
	killEReason(t, "metrics at size-2", input(mm, 1, 3), true, "")
	killEReason(t, "metrics at size-1", input(mm, 1, 4), false, "the disclosed metrics leaf is not at its committed position")
	// header first + cells == size - 2 exactly fits; a header claiming one more cell does not
	big := killECopy(header).(map[string]any)
	big["first"] = jnum(2)
	bm := killEBuild(t, []mapLeaf{{kind: "header", leaf: big}, {kind: "cell", leaf: cell("v", 0)}, {kind: "cell", leaf: cell("v", 0)},
		{kind: "cell", leaf: cell("v", 1)}, {kind: "metrics", leaf: metrics}, {kind: "learner", leaf: learner}})
	killEReason(t, "first 2 fits", input(bm, 2, 4), true, "")
	killEReason(t, "first 2 short size", func() map[string]any {
		in := input(bm, 2, 4)
		in["disclosure"].(map[string]any)["size"] = jnum(5)
		return in
	}(), false, "the disclosed header does not fit the committed layout")
}

func TestKillEMapCommitPrimitive(t *testing.T) {
	salt := make([]byte, 32)
	salt[0] = 9
	leaf := map[string]any{"learner_digest": dg("l")}
	h, _ := mapLeafHash("learner", salt, leaf)
	one := map[string]any{"kind": "learner", "salt": b64.EncodeToString(salt), "leaf": leaf}
	if got := IntentMapCommitPrimitive(deep(t, map[string]any{"leaves": []any{one}})); got["map_commit"] != mapCommitOf(1, h) {
		t.Fatalf("one leaf: %v", got)
	}
	two := IntentMapCommitPrimitive(deep(t, map[string]any{"leaves": []any{one, one}}))
	if two["map_commit"] != mapCommitOf(2, mapNodeHash(h, h)) {
		t.Fatalf("two leaves: %v", two)
	}
	for name, in := range map[string]any{
		"empty leaves":  map[string]any{"leaves": []any{}},
		"leaves object": map[string]any{"leaves": map[string]any{}},
		"no leaves":     map[string]any{},
		"leaf string":   map[string]any{"leaves": []any{one, "x"}},
		"bad salt":      map[string]any{"leaves": []any{one, map[string]any{"kind": "learner", "salt": "abc", "leaf": leaf}}},
		"unknown kind":  map[string]any{"leaves": []any{one, map[string]any{"kind": "node", "salt": b64.EncodeToString(salt), "leaf": leaf}}},
		"no kind":       map[string]any{"leaves": []any{map[string]any{"salt": b64.EncodeToString(salt), "leaf": leaf}}},
	} {
		got := IntentMapCommitPrimitive(deep(t, in))
		if len(got) != 0 {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// A leaf with no strict canonical form (a non-canonical number lexeme reaching the internal decision un-normalised)
// does not open the commitment: the decision refuses (intent-map-commit.ts opens(): mapLeafHash throws -> false).
func TestKillEMapUnhashableLeafDoesNotOpen(t *testing.T) {
	m := buildMap(t, 500)
	in := mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)
	in = deep(t, in).(map[string]any)
	d := in["disclosure"].(map[string]any)
	d["metrics"].(map[string]any)["leaf"].(map[string]any)["questions"] = json.Number("1e0")
	if !mapDisclosureOK(d) {
		t.Fatal("shape: 1e0 is an integer")
	}
	if mapOpens("metrics", d["metrics"].(map[string]any), len(m.leaves), m.commit) {
		t.Fatal("an unhashable metrics leaf opens the commitment")
	}
	got := decideMapDisclosure(in["map_commit"], in["action"].(map[string]any), in["params"], true, d, -1, false)
	if got.ok || got.reason != "the metrics leaf does not open the map commitment" {
		t.Fatalf("decision: %+v", got)
	}
}
