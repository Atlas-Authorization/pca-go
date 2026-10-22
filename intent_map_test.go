package pca

// Kills for rule 19 (the committed map and Z0 disclosure, 16953c21): leaf hashing and the RFC 9162 openings, the exact
// cell of ω, every disclosure refusal, ε at and over the bound, and the `map` check in the pipeline (v2c goal, reported
// after accumulators, malformed context, policy.map typing).

import (
	"crypto/rand"
	"encoding/json"
	"testing"
)

type mapLeaf struct {
	kind string
	leaf map[string]any
	salt []byte
}

type builtMap struct {
	leaves []mapLeaf
	hashes [][]byte
	commit string
}

func mapAudit(hs [][]byte, idx int) [][]byte {
	if len(hs) == 1 {
		return nil
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	if idx < k {
		return append(mapAudit(hs[:k], idx), mapTreeRoot(hs[k:]))
	}
	return append(mapAudit(hs[k:], idx-k), mapTreeRoot(hs[:k]))
}

// buildMap: one verb air.book over total (num, cut 40000 in [0, 100000]) and resource (cat), all cells granted except
// those listed in denied (flat indices); metrics residual risk rr.
func buildMap(t *testing.T, rr int64, denied ...int) *builtMap {
	dims := []any{
		map[string]any{"kind": "num", "path": "action.params.total", "lo": jnum(0), "hi": jnum(100_000), "cuts": []any{jnum(40_000)}},
		map[string]any{"kind": "cat", "path": "action.resource", "values": []any{
			map[string]any{"kind": "exact", "value": "skyair.example/bookings"},
			map[string]any{"kind": "prefix", "value": "skyair.example/"},
			map[string]any{"kind": "prefix", "value": "skyair.example/b"},
			map[string]any{"kind": "other", "value": mapOther}}},
	}
	cells := 3 * 4
	m := &builtMap{}
	m.leaves = append(m.leaves, mapLeaf{kind: "header", leaf: map[string]any{"verb": "air.book", "first": jnum(1), "cells": jnum(int64(cells)), "dims": dims}})
	deny := map[int]bool{}
	for _, d := range denied {
		deny[d] = true
	}
	for i := 0; i < cells; i++ {
		m.leaves = append(m.leaves, mapLeaf{kind: "cell", leaf: map[string]any{"verb": "air.book", "cell": []any{jnum(int64(i / 4)), jnum(int64(i % 4))},
			"p_ppm": jnum(int64(990_000 - i)), "in_grant": !deny[i]}})
	}
	metrics := map[string]any{"log2_vs_mbits": jnum(7)}
	for _, k := range mapMetricFields {
		metrics[k] = jnum(1)
	}
	metrics["residual_risk_ppm"] = jnum(rr)
	m.leaves = append(m.leaves, mapLeaf{kind: "metrics", leaf: metrics}, mapLeaf{kind: "learner", leaf: map[string]any{"learner_digest": dg("learner")}})
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

func (m *builtMap) entry(i int) map[string]any {
	path := []any{}
	for _, h := range mapAudit(m.hashes, i) {
		path = append(path, b64.EncodeToString(h))
	}
	return map[string]any{"index": jnum(int64(i)), "salt": b64.EncodeToString(m.leaves[i].salt), "leaf": m.leaves[i].leaf, "path": path}
}

// disclose for the flat cell index `flat`.
func (m *builtMap) disclose(flat int) map[string]any {
	n := len(m.leaves)
	return map[string]any{"size": jnum(int64(n)), "header": m.entry(0), "cell": m.entry(1 + flat), "metrics": m.entry(n - 2)}
}

func mapInput(t *testing.T, m *builtMap, params map[string]any, resource string, flat int) map[string]any {
	pd, _ := ParamsDigest(params)
	return map[string]any{"map_commit": m.commit, "action": map[string]any{"verb": "air.book", "resource": resource, "params_digest": pd},
		"params": params, "disclosure": m.disclose(flat)}
}

func TestMutMapCommitAndCells(t *testing.T) {
	m := buildMap(t, 500)
	leaves := []any{}
	for _, l := range m.leaves {
		leaves = append(leaves, map[string]any{"kind": l.kind, "leaf": l.leaf, "salt": b64.EncodeToString(l.salt)})
	}
	if got := IntentMapCommitPrimitive(deep(t, map[string]any{"leaves": leaves})); got["map_commit"] != m.commit {
		t.Fatalf("commit primitive: %v want %s", got, m.commit)
	}
	run := func(in map[string]any) (map[string]any, string) { return IntentMapPrimitive(deep(t, in)) }
	type c struct {
		total    int64
		resource string
		flat     int
		cell     []int64
	}
	// numeric cells [0, 39999], {40000}, [40001, 100000]; cat: exact, longest prefix, other
	for name, x := range map[string]c{
		"0":           {0, "skyair.example/bookings", 0, []int64{0, 0}},
		"39999":       {39_999, "skyair.example/bookings", 0, []int64{0, 0}},
		"40000":       {40_000, "skyair.example/bookings", 4, []int64{1, 0}},
		"40001":       {40_001, "skyair.example/bookings", 8, []int64{2, 0}},
		"100000":      {100_000, "skyair.example/bookings", 8, []int64{2, 0}},
		"long-prefix": {1, "skyair.example/b2", 2, []int64{0, 2}},
		"prefix":      {1, "skyair.example/x", 1, []int64{0, 1}},
		"other":       {1, "elsewhere", 3, []int64{0, 3}},
	} {
		got, why := run(mapInput(t, m, map[string]any{"total": jnum(x.total)}, x.resource, x.flat))
		want := []any{}
		for _, v := range x.cell {
			want = append(want, jnum(v))
		}
		if got["ok"] != true || !sameJSON(got["cell"], want) {
			t.Fatalf("%s: %v %q", name, got, why)
		}
	}
	// outside the dimension
	for name, total := range map[string]any{"100001": jnum(100_001), "-1": jnum(-1), "string": "1", "fraction": json.Number("1.5"), "null": nil} {
		in := mapInput(t, m, map[string]any{"total": total}, "skyair.example/bookings", 0)
		if got, _ := run(in); got["ok"] != false {
			t.Fatalf("total %s: %v", name, got)
		}
	}
	in := mapInput(t, m, map[string]any{}, "skyair.example/bookings", 0)
	if got, _ := run(in); got["ok"] != false {
		t.Fatal("absent total")
	}
	base := func() map[string]any {
		return mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)
	}
	if got, why := run(base()); got["ok"] != true {
		t.Fatalf("base: %s", why)
	}
	// ε at and over the bound
	in = base()
	in["max_residual_risk_ppm"] = jnum(500)
	if got, _ := run(in); got["ok"] != true {
		t.Fatal("ε == residual risk")
	}
	in["max_residual_risk_ppm"] = jnum(499)
	if got, _ := run(in); got["ok"] != false {
		t.Fatal("ε < residual risk")
	}
	// every refusal
	for name, mut := range map[string]func(in map[string]any){
		"foreign-commit":   func(in map[string]any) { in["map_commit"] = buildMap(t, 500).commit },
		"commit-malformed": func(in map[string]any) { in["map_commit"] = "abc" },
		"params-digest":    func(in map[string]any) { in["params"] = map[string]any{"total": jnum(2)} },
		"params-null":      func(in map[string]any) { in["params"] = nil },
		"verb":             func(in map[string]any) { in["action"].(map[string]any)["verb"] = "air.cancel" },
		"salt":             func(in map[string]any) { in["disclosure"].(map[string]any)["cell"].(map[string]any)["salt"] = dg("x") },
		"path-short": func(in map[string]any) {
			e := in["disclosure"].(map[string]any)["cell"].(map[string]any)
			e["path"] = e["path"].([]any)[1:]
		},
		"size":            func(in map[string]any) { in["disclosure"].(map[string]any)["size"] = jnum(int64(len(m.leaves) + 1)) },
		"size-3":          func(in map[string]any) { in["disclosure"].(map[string]any)["size"] = jnum(3) },
		"swapped-cell":    func(in map[string]any) { in["disclosure"].(map[string]any)["cell"] = m.entry(2) },
		"metrics-as-cell": func(in map[string]any) { in["disclosure"].(map[string]any)["metrics"] = m.entry(len(m.leaves) - 1) },
		"header-index": func(in map[string]any) {
			in["disclosure"].(map[string]any)["header"].(map[string]any)["index"] = jnum(1)
		},
		"leaf-extra-member": func(in map[string]any) {
			in["disclosure"].(map[string]any)["cell"].(map[string]any)["leaf"].(map[string]any)["x"] = jnum(1)
		},
		"disclosure-null":  func(in map[string]any) { in["disclosure"] = nil },
		"disclosure-extra": func(in map[string]any) { in["disclosure"].(map[string]any)["learner"] = m.entry(len(m.leaves) - 1) },
	} {
		in := base()
		mut(in)
		if got, _ := run(in); got["ok"] != false {
			t.Fatalf("%s accepted", name)
		}
	}
	// a cell outside the grant
	d := buildMap(t, 500, 0)
	if got, _ := run(mapInput(t, d, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)); got["ok"] != false {
		t.Fatal("cell outside the grant")
	}
	// RFC 9162 path verification at small sizes: every leaf of trees of size 1..9 opens
	for n := 1; n <= 9; n++ {
		hs := make([][]byte, n)
		for i := range hs {
			hs[i] = sha([]byte{byte(i)})
		}
		root := mapTreeRoot(hs)
		for i := 0; i < n; i++ {
			got := mapRootFromPath(i, n, hs[i], mapAudit(hs, i))
			if got == nil || string(got) != string(root) {
				t.Fatalf("size %d leaf %d", n, i)
			}
			if i+1 < n && mapRootFromPath(i, n, hs[i], mapAudit(hs, i+1)) != nil && string(mapRootFromPath(i, n, hs[i], mapAudit(hs, i+1))) == string(root) {
				t.Fatalf("size %d leaf %d opens with another path", n, i)
			}
		}
	}
}

// useCommittedMap switches the fixture to a committed map: intent.map_digest = map_commit, the v2c goal, S's task map
// the commitment, map_form "commit" and the disclosure of the action's cell (total 38900 -> cell [0, 0]).
func (f *v2fx) useCommittedMap(rr int64) *builtMap {
	m := buildMap(f.t, rr)
	f.mapD, f.committed = m.commit, true
	f.S["layers"] = map[string]any{"task": map[string]any{"map_digest": f.mapD}}
	f.signRoot()
	f.is()["map_form"] = mapFormCommit
	f.rebind()
	f.ctx["map"] = map[string]any{"disclosure": m.disclose(0)}
	return m
}

func TestMutMapPipeline(t *testing.T) {
	withMap := append(append([]string{}, v2Base...), "map")
	f := newV2Fx(t)
	f.useCommittedMap(500)
	expectV2(t, "committed", f.verify(), withMap)
	// the v2 goal does not open a v2c grant: a map_form flip breaks the intent binding
	g := newV2Fx(t)
	g.useCommittedMap(500)
	delete(g.is(), "map_form")
	g.resign()
	if v := g.verify(); v.Checks["intent"] {
		t.Fatal("plain goal opened a v2c grant")
	}
	// map_form wire
	for _, bad := range []any{nil, "plain", jnum(1)} {
		h := newV2Fx(t)
		h.is()["map_form"] = bad
		h.resign()
		mustWire(t, "map_form", h.verify())
	}
	// the map check fails alone (after accumulators): no disclosure, ε over, a cell outside the grant
	for name, mut := range map[string]func(f *v2fx){
		"no-disclosure": func(f *v2fx) { delete(f.ctx, "map") },
		"eps-over": func(f *v2fx) {
			f.ctx["policy"] = map[string]any{"map": map[string]any{"max_residual_risk_ppm": jnum(499)}}
		},
		"wrong-cell": func(f *v2fx) { f.ctx["map"].(map[string]any)["disclosure"].(map[string]any)["cell"] = nil },
	} {
		h := newV2Fx(t)
		h.useCommittedMap(500)
		mut(h)
		expectV2(t, name, h.verify(), v2Base, "map")
	}
	h := newV2Fx(t)
	h.useCommittedMap(500)
	h.ctx["policy"] = map[string]any{"map": map[string]any{"max_residual_risk_ppm": jnum(500), "require": true}}
	expectV2(t, "eps-at", h.verify(), withMap)
	// policy.map.require without a committed map: map fails (also without intent_session)
	h = newV2Fx(t)
	h.ctx["policy"] = map[string]any{"map": map[string]any{"require": true}}
	expectV2(t, "require-plain", h.verify(), v2Base, "map")
	delete(h.p, "intent_session")
	h.resign()
	v := h.verify()
	if ok, has := v.Checks["map"]; !has || ok {
		t.Fatalf("require without intent_session: %v", v.Checks)
	}
	// a malformed context reports map too when the PCActn commits a map
	h = newV2Fx(t)
	h.useCommittedMap(500)
	h.ctx["params"] = nil
	expectV2(t, "ctx-malformed", h.verify(), nil, "schema", "intent_session", "accumulators", "map")
	// policy.map and context map are closed and typed
	for name, mut := range map[string]func(f *v2fx){
		"policy.map-null":     func(f *v2fx) { f.ctx["policy"] = map[string]any{"map": nil} },
		"policy.map-unknown":  func(f *v2fx) { f.ctx["policy"] = map[string]any{"map": map[string]any{"eps": jnum(1)}} },
		"policy.map-require1": func(f *v2fx) { f.ctx["policy"] = map[string]any{"map": map[string]any{"require": jnum(1)}} },
		"policy.map-eps-neg": func(f *v2fx) {
			f.ctx["policy"] = map[string]any{"map": map[string]any{"max_residual_risk_ppm": jnum(-1)}}
		},
		"map-null":    func(f *v2fx) { f.ctx["map"] = nil },
		"map-unknown": func(f *v2fx) { f.ctx["map"] = map[string]any{"disclosures": []any{}} },
	} {
		h := newV2Fx(t)
		mut(h)
		expectCtxFail(t, name, h.verify(), true)
	}
}
