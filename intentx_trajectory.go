package pca

// Trajectory intent as ordinary intent: the augmented outcome space (one numeric dimension per accumulator, one categorical
// dimension per monitor), the verifier-computed lift of an action, the trajectory step rule and the wallet's default
// accumulators.

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	ixAccDimPrefix = "env.acc."
	ixMonDimPrefix = "env.mon."
)

func ixAccDimPath(id string) string { return ixAccDimPrefix + id + ".post" }
func ixMonDimPath(id string) string { return ixMonDimPrefix + id + ".state" }

// ixDimKindOf is the v2 dimension kind of a path (a naming convention over the v1 dimensions).
func ixDimKindOf(path string) string {
	for _, pk := range [][2]string{{"action.params.", "param"}, {ixAccDimPrefix, "acc"}, {ixMonDimPrefix, "mon"}, {"env.canon.", "canon"},
		{"env.world.", "world"}, {"env.rel.", "rel"}, {"env.prov.", "prov"}, {"env.class.", "class"}} {
		if strings.HasPrefix(path, pk[0]) {
			return pk[1]
		}
	}
	return "other"
}

func ixPredVerbs(p any) []any {
	v := ixReq(ixM(p), "verb")
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

func ixAugmentOmega(omega, psi, opts map[string]any) map[string]any {
	schema := ixM(opts["schema"])
	selects := func(a map[string]any, verb string) bool {
		sel := ixM(a["sel"])
		for _, v := range ixL(sel["verbs"]) {
			if v == verb {
				return true
			}
		}
		unit := sel["accumulates_into"]
		if unit != nil {
			var v map[string]any
			for _, x := range ixL(schema["verbs"]) {
				if ixS(ixM(x)["verb"]) == verb {
					v = ixM(x)
					break
				}
			}
			if v == nil {
				return false
			}
			ps, throws := accumulationParams(v, ixS(unit))
			if throws {
				ixFail("accumulationParams throws")
			}
			return len(ps) > 0
		}
		return false
	}
	verbs := []any{}
	for _, vv := range ixL(ixReq(omega, "verbs")) {
		vs := ixM(vv)
		verb := ixS(vs["verb"])
		extra := []any{}
		for _, av := range ixL(ixReq(psi, "accumulators")) {
			a := ixM(av)
			if ixM(ixReq(a, "holder"))["kind"] == "wallet" {
				continue
			}
			if opts["scope"] == "selected" && !selects(a, verb) {
				continue
			}
			if a["domain_max"] == nil {
				ixFail("augmentOmega: accumulator '%s' needs domain_max (A_psi) to be a dimension", ixS(a["id"]))
			}
			dm := ixF(a["domain_max"])
			var cuts []float64
			seen := map[float64]bool{}
			for _, c := range ixL(ixM(opts["cuts"])[ixS(a["id"])]) {
				f, ok := c.(float64)
				if ok && f == math.Trunc(f) && 0 <= f && f <= dm && math.Abs(f) <= 9007199254740991 && !seen[f] {
					seen[f] = true
					cuts = append(cuts, f)
				}
			}
			sort.Float64s(cuts)
			cs := make([]any, len(cuts))
			for i, c := range cuts {
				cs[i] = c
			}
			extra = append(extra, map[string]any{"kind": "num", "path": ixAccDimPath(ixS(a["id"])), "lo": 0.0, "hi": a["domain_max"], "cuts": cs, "dist": "loguniform"})
		}
		for _, mv := range ixL(ixReq(psi, "monitors")) {
			m := ixM(mv)
			if opts["scope"] == "selected" {
				if q := m["q"]; ixTruthy(q) {
					in := false
					for _, x := range ixPredVerbs(q) {
						if x == verb || x == "*" {
							in = true
						}
					}
					if !in {
						continue
					}
				}
			}
			vals := []any{}
			for _, s := range monitorStates(m) {
				vals = append(vals, map[string]any{"kind": "exact", "value": s})
			}
			extra = append(extra, map[string]any{"kind": "cat", "path": ixMonDimPath(ixS(m["id"])), "values": vals})
		}
		dims := []any{}
		for _, d := range ixL(vs["dims"]) {
			if k := ixDimKindOf(ixS(ixM(d)["path"])); k != "acc" && k != "mon" {
				dims = append(dims, d)
			}
		}
		dims = append(dims, extra...)
		sort.SliceStable(dims, func(i, j int) bool { return compareUtf8(ixS(ixM(dims[i])["path"]), ixS(ixM(dims[j])["path"])) < 0 })
		nv := ixCopyMap(vs)
		nv["dims"] = dims
		verbs = append(verbs, nv)
	}
	return map[string]any{"v": 1.0, "approximate": ixClone(ixReq(omega, "approximate")), "verbs": verbs}
}

func ixFindVerb(omega map[string]any, verb any) map[string]any {
	for _, v := range ixL(omega["verbs"]) {
		if ixM(v)["verb"] == verb {
			return ixM(v)
		}
	}
	return nil
}

// ixLiftAction is lift(history, action, t) as an outcome of the augmented space; nil when the verb is not in it.
func ixLiftAction(omegaTilde, psi map[string]any, history []any, cand map[string]any, schema map[string]any) map[string]any {
	vs := ixFindVerb(omegaTilde, ixReq(cand, "verb"))
	if vs == nil {
		return nil
	}
	var decl map[string]any
	if schema != nil {
		for _, v := range ixL(schema["verbs"]) {
			if ixM(v)["verb"] == cand["verb"] {
				decl = ixM(v)
				break
			}
		}
	}
	values := map[string]any{}
	params := ixReq(cand, "params")
	pm, _ := params.(map[string]any)
	for _, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		path := ixS(d["path"])
		switch ixDimKindOf(path) {
		case "param":
			x, ok := pm[strings.TrimPrefix(path, "action.params.")]
			if ok && (ixIsNum(x) || ixIsStr(x)) {
				values[path] = x
			}
		case "canon":
			name := strings.TrimPrefix(path, "env.canon.")
			pd := ixM(ixM(decl["params"])["action.params."+name])
			if len(pd) > 0 && pm != nil {
				if x, ok := pm[name]; ok {
					values[path] = ixCanonValue(pd, x)
				}
			}
		case "acc":
			id := strings.TrimSuffix(strings.TrimPrefix(path, ixAccDimPrefix), ".post")
			for _, av := range ixL(psi["accumulators"]) {
				if a := ixM(av); a["id"] == id {
					v, ok := accPost(a, history, ixS(cand["verb"]), pm, cand["t"], ixClone(schema), schema != nil)
					if !ok {
						ixFail("accPost throws")
					}
					values[path] = v
					break
				}
			}
		case "mon":
			id := strings.TrimSuffix(strings.TrimPrefix(path, ixMonDimPrefix), ".state")
			for _, mv := range ixL(psi["monitors"]) {
				if m := ixM(mv); m["id"] == id {
					values[path] = monitorState(m, history)
					break
				}
			}
		default:
			if path == "action.resource" {
				values[path] = ixReq(cand, "resource")
			}
		}
	}
	return map[string]any{"verb": cand["verb"], "values": values}
}

// ixStepTrajectory admits the action iff its lift lies in a cell the grant accepts; the history grows by a `reserved` event.
func ixStepTrajectory(omegaTilde, psi map[string]any, history []any, cand map[string]any, inGrant func(verb string, cell []any) bool, schema map[string]any) map[string]any {
	lifted := ixLiftAction(omegaTilde, psi, history, cand, schema)
	ok := false
	if lifted != nil {
		if vs := ixFindVerb(omegaTilde, lifted["verb"]); vs != nil {
			if cell := ixCellOf(vs, lifted); cell != nil {
				ok = inGrant(ixS(cand["verb"]), cell)
			}
		}
	}
	hist := append([]any{}, history...)
	if ok {
		hist = append(hist, map[string]any{"id": ixReq(cand, "id"), "verb": cand["verb"], "resource": ixReq(cand, "resource"), "params": cand["params"],
			"t": ixReq(cand, "t"), "status": "reserved"})
	}
	var l any
	if lifted != nil {
		l = lifted
	}
	return map[string]any{"admitted": ok, "history": hist, "lifted": l}
}

var ixSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9_]`)

func ixSanitize(u string) string {
	r := []rune(ixSanitizeRe.ReplaceAllString(u, "_"))
	if len(r) > 58 {
		r = r[:58]
	}
	return string(r)
}

// ixDefaultAccumulators are the accumulators the wallet always adds: a per-task spend sum per accumulation unit, a per-verb
// spend sum for every untagged money.amount parameter, and the wallet-held question counter.
func ixDefaultAccumulators(schema, o map[string]any) []any {
	holder := any(map[string]any{"kind": "site_local"})
	if ixTruthy(o["holder"]) {
		holder = o["holder"]
	}
	units := map[string]bool{}
	type unt struct{ verb, path string }
	var untagged []unt
	for _, vv := range ixL(ixReq(schema, "verbs")) {
		v := ixM(vv)
		params := ixM(ixReq(v, "params"))
		for _, path := range ixKeysSorted(params) {
			d := ixM(params[path])
			into := ixL(d["accumulates_into"])
			for _, u := range into {
				units[ixS(u)] = true
			}
			if d["type"] == "integer" && d["semantic"] == "money.amount" && len(into) == 0 {
				untagged = append(untagged, unt{ixS(v["verb"]), path})
			}
		}
	}
	out := []any{}
	for _, u := range ixSortUtf8(ixBoolKeys(units)) {
		out = append(out, map[string]any{"id": "spend_" + ixSanitize(u), "agg": "sum", "unit": u, "sel": map[string]any{"accumulates_into": u},
			"win": map[string]any{"kind": "task"}, "key": nil, "domain_max": ixReq(o, "spendDomainMax"), "holder": holder})
	}
	sort.SliceStable(untagged, func(i, j int) bool {
		return compareUtf8(untagged[i].verb+untagged[i].path, untagged[j].verb+untagged[j].path) < 0
	})
	for _, x := range untagged {
		id := []rune("spend_" + ixSanitize(x.verb) + "_" + ixSanitize(strings.TrimPrefix(x.path, "action.params.")))
		if len(id) > 64 {
			id = id[:64]
		}
		out = append(out, map[string]any{"id": string(id), "agg": "sum", "val": x.path, "sel": map[string]any{"verbs": []any{x.verb}},
			"win": map[string]any{"kind": "task"}, "key": nil, "domain_max": ixReq(o, "spendDomainMax"), "holder": holder})
	}
	var cap any = 6.0
	if o["questionCap"] != nil {
		cap = o["questionCap"]
	}
	out = append(out, map[string]any{"id": "questions", "agg": "count", "sel": map[string]any{"event": "intent_required"},
		"win": map[string]any{"kind": "task"}, "key": nil, "cap": cap, "holder": map[string]any{"kind": "wallet"}})
	return out
}

// ixDescribeAccCell is the fact line for an accumulator dimension of a cell.
func ixDescribeAccCell(d map[string]any, cellIndex int, label string, thisAction any) string {
	cells := ixNumCells(d)
	if cellIndex < 0 || cellIndex >= len(cells) {
		ixFail("describeAccCell: no such cell")
	}
	c := cells[cellIndex]
	f := func(x float64) string { return jsValueString(x) }
	var rng string
	if c.lo == c.hi {
		rng = "exactly " + f(c.lo)
	} else {
		rng = "between " + f(c.lo) + " and " + f(c.hi)
	}
	s := label + ": " + rng
	if thisAction != nil {
		s += " (this action: " + jsValueString(thisAction) + ")"
	}
	return s
}

// ixTrajectoryHarmRange is the per-session harm range of a trajectory Monte Carlo estimate, [0, L_max * H_max].
func ixTrajectoryHarmRange(maxSessionLength, harmMax any) float64 {
	l, ok1 := maxSessionLength.(float64)
	h, ok2 := harmMax.(float64)
	if !ok1 || !ok2 || l != math.Trunc(l) || l < 0 || l > 9007199254740991 || !(h >= 0) {
		ixFail("trajectoryHarmRange: bad arguments")
	}
	return l * h
}
