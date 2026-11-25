package pca

// Multi-principal intent: aggregation rules (unanimity, quorum, weighted, vetoers), the exact joint-acceptance DP and the
// common refinement of several outcome spaces.

import (
	"math"
	"sort"
)

const ixPPM = 1000000.0

func ixPpm(x float64) float64 { return math.Floor(float64(x*ixPPM) + 0.5) }

type ixUndefT struct{}

// ixUndef is an absent member (JavaScript undefined), kept apart from null only for the reference's error text.
var ixUndef = ixUndefT{}

// ixMember is o.k with the reference's TypeError on null / undefined.
func ixMember(o any, k string) any {
	if o == nil {
		ixFail("Cannot read properties of null (reading '%s')", k)
	}
	if _, u := o.(ixUndefT); u {
		ixFail("Cannot read properties of undefined (reading '%s')", k)
	}
	if m, ok := o.(map[string]any); ok {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return ixUndef
}

func ixIsInt(x any) bool {
	f, ok := x.(float64)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f)
}

// ixNormalizeRule is a rule in normal form {weights, threshold, veto}, with the reference's error messages.
func ixNormalizeRule(rule any, refs []string) map[string]any {
	vsv := ixMember(rule, "vetoers")
	var vetoers []any
	switch t := vsv.(type) {
	case nil, ixUndefT:
	case []any:
		vetoers = t
	case string:
		for _, r := range t {
			vetoers = append(vetoers, string(r))
		}
	default:
		ixFail("rule.vetoers is not iterable")
	}
	for _, v := range vetoers {
		s, ok := v.(string)
		found := false
		for _, r := range refs {
			if ok && r == s {
				found = true
			}
		}
		if !found {
			ixFail("aggregateIntentMaps: vetoer %s is not one of the maps", jsValueString(v))
		}
	}
	veto := make([]any, len(refs))
	for i, r := range refs {
		veto[i] = false
		for _, v := range vetoers {
			if s, ok := v.(string); ok && s == r {
				veto[i] = true
			}
		}
	}
	ones := func() []any {
		w := make([]any, len(refs))
		for i := range w {
			w[i] = 1.0
		}
		return w
	}
	switch ixMember(rule, "kind") {
	case "unanimity":
		return map[string]any{"weights": ones(), "threshold": float64(len(refs)), "veto": veto}
	case "quorum":
		k := ixMember(rule, "k")
		if !(ixIsInt(k) && k.(float64) >= 1 && k.(float64) <= float64(len(refs))) {
			ixFail("aggregateIntentMaps: quorum k must be an integer in [1, %d]", len(refs))
		}
		return map[string]any{"weights": ones(), "threshold": k, "veto": veto}
	}
	wmap := ixMember(rule, "weights")
	weights := make([]any, len(refs))
	for i, r := range refs {
		weights[i] = ixMember(wmap, r)
	}
	W := 0.0
	for _, w := range weights {
		if !(ixIsInt(w) && w.(float64) >= 0) {
			ixFail("aggregateIntentMaps: every principal needs a non-negative integer weight")
		}
		W += w.(float64)
	}
	th := ixMember(rule, "threshold")
	if !(ixIsInt(th) && th.(float64) >= 1 && th.(float64) <= W) {
		ixFail("aggregateIntentMaps: threshold must be an integer in [1, %s]", jsNumberString(W))
	}
	return map[string]any{"weights": weights, "threshold": th, "veto": veto}
}

func ixEffectiveVetoers(rule any, refs []string) []any {
	n := ixNormalizeRule(rule, refs)
	W := 0.0
	ws := n["weights"].([]any)
	for _, w := range ws {
		W += w.(float64)
	}
	out := []any{}
	for i, r := range refs {
		if n["veto"].([]any)[i].(bool) || n["threshold"].(float64) > W-ws[i].(float64) {
			out = append(out, r)
		}
	}
	return out
}

// ixRuleAdmits: vetoers must admit; the admitting weight must reach the threshold.
func ixRuleAdmits(n map[string]any, ins []any) bool {
	s := 0.0
	veto, ws := ixL(n["veto"]), ixL(n["weights"])
	for i := range ins {
		in, _ := ins[i].(bool)
		if i < len(veto) && veto[i] == true && !in {
			return false
		}
		if in {
			s += ixF(ws[i])
		}
	}
	return s >= ixF(n["threshold"])
}

// ixJointAcceptance is P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight.
func ixJointAcceptance(n map[string]any, ps []any) float64 {
	th := ixIdx(n["threshold"])
	if th < 0 || th > 1<<24 {
		ixFail("bad threshold")
	}
	dist := make([]float64, th+1)
	dist[0] = 1
	ws, veto := ixL(n["weights"]), ixL(n["veto"])
	for i, pv := range ps {
		p := ixF(pv)
		next := make([]float64, th+1)
		w := ixIdx(ws[i])
		for s := 0; s <= th; s++ {
			m := dist[s]
			if m == 0 {
				continue
			}
			t := s + w
			if t > th {
				t = th
			}
			next[t] = next[t] + float64(m*p)
			if veto[i] != true {
				next[s] = next[s] + float64(m*(1-p))
			}
		}
		dist = next
	}
	return dist[th]
}

// ---- cross-org: common refinement ----

func ixSev(r any) int {
	for i, s := range []string{"reversible", "rate_limited", "irreversible"} {
		if r == s {
			return i
		}
	}
	return -1
}

func ixReq(m map[string]any, k string) any {
	v, ok := m[k]
	if !ok {
		ixFail("missing member %s", k)
	}
	return v
}

func ixMergeDim(a, b map[string]any) map[string]any {
	if ixReq(a, "kind") != ixReq(b, "kind") {
		ixFail("commonRefinement: %s is numeric in one space and categorical in another", ixS(a["path"]))
	}
	if a["kind"] == "num" {
		if ixF(a["lo"]) != ixF(b["lo"]) || ixF(a["hi"]) != ixF(b["hi"]) {
			ixFail("commonRefinement: %s has different domains ([%s, %s] vs [%s, %s])", ixS(a["path"]),
				jsValueString(a["lo"]), jsValueString(a["hi"]), jsValueString(b["lo"]), jsValueString(b["hi"]))
		}
		var cuts []float64
		for _, l := range [][]any{ixL(a["cuts"]), ixL(b["cuts"])} {
			for _, cv := range l {
				c := ixF(cv)
				dup := false
				for _, x := range cuts {
					if x == c {
						dup = true
					}
				}
				if !dup {
					cuts = append(cuts, c)
				}
			}
		}
		sort.Float64s(cuts)
		cs := make([]any, len(cuts))
		for i, c := range cuts {
			cs[i] = c
		}
		return map[string]any{"kind": "num", "path": a["path"], "lo": a["lo"], "hi": a["hi"], "dist": a["dist"], "cuts": cs}
	}
	ex, pre := map[string]bool{}, map[string]bool{}
	for _, l := range [][]any{ixL(a["values"]), ixL(b["values"])} {
		for _, vv := range l {
			v := ixM(vv)
			switch v["kind"] {
			case "exact":
				ex[ixS(v["value"])] = true
			case "prefix":
				pre[ixS(v["value"])] = true
			}
		}
	}
	values := []any{}
	for _, v := range ixSortedKeys(ex) {
		values = append(values, map[string]any{"kind": "exact", "value": v})
	}
	for _, v := range ixSortedKeys(pre) {
		values = append(values, map[string]any{"kind": "prefix", "value": v})
	}
	values = append(values, map[string]any{"kind": "other", "value": ixOther})
	return map[string]any{"kind": "cat", "path": a["path"], "values": values}
}

// ixCommonRefinement is the union of the verbs; per verb the union of dimensions; per numeric dimension the union of cuts
// (domains must agree); per categorical dimension the union of the named values.
func ixCommonRefinement(omegas []any) map[string]any {
	byVerb := map[string]map[string]any{}
	approx := map[string]bool{}
	for _, ov := range omegas {
		o := ixM(ov)
		for _, x := range ixL(ixReq(o, "approximate")) {
			approx[ixS(x)] = true
		}
		for _, vv := range ixL(ixReq(o, "verbs")) {
			vs := ixM(vv)
			verb := ixS(vs["verb"])
			cur := byVerb[verb]
			if cur == nil {
				dims := []any{}
				for _, d := range ixL(vs["dims"]) {
					dims = append(dims, ixClone(d))
				}
				byVerb[verb] = map[string]any{"verb": vs["verb"], "reversibility": ixReq(vs, "reversibility"), "weight": 0.0, "dims": dims}
				continue
			}
			if ixSev(vs["reversibility"]) > ixSev(cur["reversibility"]) {
				cur["reversibility"] = vs["reversibility"]
			}
			cdims := cur["dims"].([]any)
			for _, dv := range ixL(vs["dims"]) {
				d := ixM(dv)
				i := -1
				for k, x := range cdims {
					if ixM(x)["path"] == d["path"] {
						i = k
						break
					}
				}
				if i < 0 {
					cdims = append(cdims, ixClone(d))
				} else {
					cdims[i] = ixMergeDim(ixM(cdims[i]), d)
				}
			}
			cur["dims"] = cdims
		}
	}
	keys := make([]string, 0, len(byVerb))
	for k := range byVerb {
		keys = append(keys, k)
	}
	ixSortU16(keys)
	verbs := make([]any, len(keys))
	for i, k := range keys {
		v := byVerb[k]
		dims := v["dims"].([]any)
		sort.SliceStable(dims, func(a, b int) bool {
			return compareUnits(utf16Units(ixS(ixM(dims[a])["path"])), utf16Units(ixS(ixM(dims[b])["path"]))) < 0
		})
		v["weight"] = 1 / float64(len(keys))
		verbs[i] = v
	}
	return map[string]any{"v": 1.0, "verbs": verbs, "approximate": ixToAny(ixSortedKeys(approx))}
}
