package pca

// Outcome-space dimensions filled by the verifier: world facts (env.world.*), provenance (env.prov.*) and attested classifier
// labels (env.class.*). Every helper only adds a dimension, which refines the space.

import (
	"sort"
	"strconv"
	"strings"
)

const (
	ixWorldPrefix = "env.world."
	ixProvPrefix  = "env.prov."
	ixClassPrefix = "env.class."
)

// ixWorldDim is a numeric world dimension env.world.<name> with the given domain and cuts.
func ixWorldDim(name string, o map[string]any) map[string]any {
	lo, hi := ixF(o["lo"]), ixF(o["hi"])
	var cuts []float64
	for _, cv := range ixL(o["cuts"]) {
		c := ixF(cv)
		dup := false
		for _, x := range cuts {
			if x == c {
				dup = true
			}
		}
		if !dup && lo <= c && c <= hi {
			cuts = append(cuts, c)
		}
	}
	sort.Float64s(cuts)
	cs := make([]any, len(cuts))
	for i, c := range cuts {
		cs[i] = c
	}
	var dist any = "uniform"
	if o["dist"] != nil {
		dist = o["dist"]
	}
	return map[string]any{"kind": "num", "path": ixWorldPrefix + name, "lo": o["lo"], "hi": o["hi"], "cuts": cs, "dist": dist}
}

// ixExcessDim is the optimality dimension: excess >= 0, cuts at 0 and at every slack literal.
func ixExcessDim(name string, hi any, slacks []any) map[string]any {
	cuts := append([]any{0.0}, slacks...)
	return ixWorldDim(name, map[string]any{"lo": 0.0, "hi": hi, "cuts": cuts, "dist": "loguniform"})
}

// ixOptimalityCondition is the default slot compiler's optimality constraint: excess <= slack.
func ixOptimalityCondition(name string, slack any) map[string]any {
	return map[string]any{"field": ixWorldPrefix + name, "op": "lte", "value": slack}
}

// ixProvenanceDim is env.prov.<path> with the cells {first_party}, {trusted} and the OTHER cell = the tainted values.
func ixProvenanceDim(paramPath string) map[string]any {
	return map[string]any{"kind": "cat", "path": ixProvPrefix + paramPath, "values": []any{
		map[string]any{"kind": "exact", "value": "first_party"},
		map[string]any{"kind": "exact", "value": "trusted"},
		map[string]any{"kind": "other", "value": ixOther}}}
}

// ixClassifierDim is env.class.<id> over the classifier's closed label set (the OTHER cell is never output).
func ixClassifierDim(id string, labels []string) map[string]any {
	seen := map[string]bool{}
	var uniq []string
	for _, l := range labels {
		if !seen[l] {
			seen[l] = true
			uniq = append(uniq, l)
		}
	}
	sort.SliceStable(uniq, func(i, j int) bool { return compareUtf8(uniq[i], uniq[j]) < 0 })
	values := []any{}
	for _, v := range uniq {
		values = append(values, map[string]any{"kind": "exact", "value": v})
	}
	values = append(values, map[string]any{"kind": "other", "value": ixOther})
	return map[string]any{"kind": "cat", "path": ixClassPrefix + id, "values": values}
}

func ixCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ixWithDims is a copy of the space with dims added to verb (dimensions kept sorted by path).
func ixWithDims(omega map[string]any, verb string, dims []any) map[string]any {
	verbs := []any{}
	found := false
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		nv := ixCopyMap(vs)
		if ixS(vs["verb"]) != verb {
			nv["dims"] = append([]any{}, ixL(vs["dims"])...)
			verbs = append(verbs, nv)
			continue
		}
		found = true
		have := map[string]bool{}
		for _, d := range ixL(vs["dims"]) {
			have[ixS(ixM(d)["path"])] = true
		}
		for _, d := range dims {
			if have[ixS(ixM(d)["path"])] {
				ixFail("withDims: %s already has a dimension %s", verb, ixS(ixM(d)["path"]))
			}
		}
		all := append(append([]any{}, ixL(vs["dims"])...), dims...)
		sort.SliceStable(all, func(i, j int) bool {
			return compareUnits(utf16Units(ixS(ixM(all[i])["path"])), utf16Units(ixS(ixM(all[j])["path"]))) < 0
		})
		nv["dims"] = all
		verbs = append(verbs, nv)
	}
	if !found {
		ixFail("withDims: no verb %s in the space", verb)
	}
	out := ixCopyMap(omega)
	out["verbs"] = verbs
	return out
}

// ixGetPath reads a nested member; ok is false when any segment is missing.
func ixGetPath(root any, segs []string) (any, bool) {
	cur := root
	for _, s := range segs {
		switch t := cur.(type) {
		case map[string]any:
			v, ok := t[s]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			n, err := strconv.Atoi(s)
			if err != nil || strconv.Itoa(n) != s || n < 0 || n >= len(t) {
				return nil, false
			}
			cur = t[n]
		default:
			return nil, false
		}
	}
	return cur, true
}

// ixLiftOutcome lifts a concrete outcome with the verifier-computed env: it fills every world / prov / class dimension path.
// A provenance dimension with no computed label is `agent` (fail closed: the tainted cell).
func ixLiftOutcome(o, env map[string]any, dimPaths []any) map[string]any {
	values := ixCopyMap(ixM(o["values"]))
	world, prov, cls := env["world"], env["prov"], env["class"]
	for _, pv := range dimPaths {
		p := ixS(pv)
		switch {
		case strings.HasPrefix(p, ixWorldPrefix):
			v, _ := ixGetPath(world, []string{p[len(ixWorldPrefix):]})
			if ixIsNum(v) || ixIsStr(v) {
				values[p] = v
			}
		case strings.HasPrefix(p, ixProvPrefix):
			v, _ := ixGetPath(prov, strings.Split(p[len(ixProvPrefix):], "."))
			if s, ok := v.(string); ok {
				values[p] = s
			} else {
				values[p] = "agent"
			}
		case strings.HasPrefix(p, ixClassPrefix):
			v, _ := ixGetPath(cls, []string{p[len(ixClassPrefix):]})
			if ixIsStr(v) {
				values[p] = v
			}
		}
	}
	return map[string]any{"verb": o["verb"], "values": values}
}
