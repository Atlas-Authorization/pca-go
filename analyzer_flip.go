package pca

// The minimal-change counterfactual search on a deny or escalate: the smallest verified change that gets an action to the wanted
// decision, ordered by cost. Only a repair the real decision confirms is returned.

import (
	"math"
	"sort"
	"strings"
)

var anlRank = map[string]float64{"deny": 0, "escalate": 1, "allow": 2}

// anlCavCtx is the camelCase caveat context as the context map EvaluateCaveats reads.
func anlCavCtx(c any) map[string]any {
	m, ok := c.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	out := anlCopy(m)
	for _, p := range [][2]string{{"blastRadius", "blast_radius"}, {"reversibilityClass", "reversibility_class"}, {"delegationDepth", "delegation_depth"}, {"recentActionTimes", "recent_action_times"}} {
		if v, has := out[p[0]]; has {
			delete(out, p[0])
			out[p[1]] = v
		}
	}
	return out
}

func anlJSMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Max(a, b)
}

// anlWaitTime is the time at which a closed time or rate caveat opens (ok is false when no caveat names one).
func anlWaitTime(caveats []any, ctx any) (at float64, ok bool) {
	now := anlGet(ctx, "now")
	bump := func(v float64) {
		base := 0.0
		if ok {
			base = at
		}
		at, ok = anlJSMax(base, v), true
	}
	for _, c := range caveats {
		t, cat := anlGet(c, "type"), anlGet(c, "at")
		if t == "not_before" && anlIsNum(cat) && anlGt(cat, now) {
			bump(anlToNumber(cat))
		}
		mx, ps := anlGet(c, "max"), anlGet(c, "per_secs")
		if t == "rate" && anlIsNum(mx) && anlIsNum(ps) {
			span := anlToNumber(ps) * 1000
			var recent []float64
			for _, x := range anlReqList(anlNN(anlGet(ctx, "recentActionTimes"), []any{})) {
				if anlGt(x, anlToNumber(now)-span) {
					recent = append(recent, anlToNumber(x))
				}
			}
			sort.Float64s(recent)
			if float64(len(recent)) >= anlToNumber(mx) {
				i := float64(len(recent)) - anlToNumber(mx)
				v := math.NaN()
				if i == math.Trunc(i) && i >= 0 && i < float64(len(recent)) {
					v = recent[int(i)] + span
				}
				bump(v)
			}
		}
	}
	return at, ok
}

func anlMeters(m map[string]any) bool {
	cs := append([]any{}, m["caveats"].([]any)...)
	for _, x := range m["meets"].([]any) {
		cs = append(cs, x.(map[string]any)["caveats"].([]any)...)
	}
	for _, c := range cs {
		if t := anlGet(c, "type"); t == "rate" || t == "budget_alloc" || t == "max_blast_radius" {
			return true
		}
	}
	return false
}

func anlSetPath(o map[string]any, path []string, v any) map[string]any {
	if len(path) == 0 {
		return o
	}
	k, rest := path[0], path[1:]
	if len(rest) == 0 {
		o[k] = v
	} else {
		cur := anlNN(o[k], map[string]any{})
		o[k] = anlSetPath(anlSpread(cur), rest, v)
	}
	return o
}

func anlDecl(shape any, name string) any {
	if anlIsUndef(shape) {
		return anlUndef
	}
	return anlGet(anlGet(shape, "params"), name)
}

func anlWithParam(action any, params map[string]any, name string, v any) map[string]any {
	a := anlSpread(action)
	p := anlCopy(params)
	p[name] = v
	a["params"] = p
	return a
}

// anlUniq de-duplicates numbers by value, strings by value and other values by identity, keeping the first.
func anlUniq(xs []any) []any {
	seen := map[string]bool{}
	out := []any{}
	for i, x := range xs {
		var k string
		if f, ok := jsNum(x); ok {
			k = "n" + anlNumStr(f)
		} else if s, ok := x.(string); ok {
			k = "s" + s
		} else {
			k = "o" + anlNumStr(float64(i))
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}

func anlAnyList(v any) []any {
	l, ok := v.([]any)
	if !ok {
		anlFail("not iterable")
	}
	return append([]any{}, l...)
}

func anlFieldOf(pr *anlProbes, path string) *anlField {
	for i := range pr.fields {
		if pr.fields[i].path == path {
			return &pr.fields[i]
		}
	}
	return nil
}

func anlFreshStr(v any) bool {
	s, ok := v.(string)
	return ok && strings.HasPrefix(s, "\x00")
}

type anlDim struct {
	cost   float64
	make   func(a any, v any) map[string]any
	step   func(v any) map[string]any
	values []any
}

// anlMinimalFlip is the smallest verified change that gets `action` to the wanted decision (default allow), ordered by cost: wait,
// change one parameter, change two together, another resource, obtain a fact, split (opt-in), ask a human.
func anlMinimalFlip(policy, action, o any) map[string]any {
	model := anlToModel(policy)
	cctx := anlGet(o, "caveatContext")
	capsOK := anlIsUndef(cctx)
	if !capsOK {
		capsOK, _ = EvaluateCaveats(model["caveats"], anlCavCtx(cctx))
	}
	current := "deny"
	if capsOK {
		current = anlDecideAction(model, action)
	}
	want := anlNN(anlGet(o, "desired"), "allow")
	rankWant := math.NaN()
	if ws, ok := want.(string); ok {
		if r, has := anlRank[ws]; has {
			rankWant = r
		}
	}
	res := map[string]any{"current": current, "repairs": []any{}, "repairExists": false}
	if !anlTruthy(anlGet(o, "holderAuthenticated")) {
		res["refused"] = "counterfactuals are shown only to the authenticated holder"
		return res
	}
	if probe := anlGet(o, "probe"); anlTruthy(probe) {
		now := anlGet(probe, "now")
		history := anlReqList(anlGet(probe, "history"))
		anlFin := func(v any) bool { return anlIsNum(v) && finite(anlToNumber(v)) }
		// a clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (an infinite limit stays an unbounded cap)
		stamps := true
		for _, t := range history {
			stamps = stamps && anlFin(t)
		}
		if !anlFin(now) || !anlFin(anlGet(probe, "windowSecs")) || !stamps {
			res["refused"] = "probe budget exhausted"
			res["probe"] = map[string]any{"history": history}
			return res
		}
		recent := []any{}
		for _, t := range history {
			if anlGt(t, anlToNumber(now)-anlToNumber(anlGet(probe, "windowSecs"))*1000) {
				recent = append(recent, t)
			}
		}
		if !(float64(len(recent)) < anlToNumber(anlGet(probe, "limit"))) {
			res["refused"] = "probe budget exhausted"
			res["probe"] = map[string]any{"history": recent}
			return res
		}
		res["probe"] = map[string]any{"history": append(append([]any{}, recent...), now)}
	}
	digest := anlPolicyDigestOf(model)
	if anlRank[current] >= rankWant {
		return res
	}

	shape := anlUndef
	if schema := anlGet(o, "schema"); !anlIsUndef(schema) && schema != nil {
		for _, s := range anlReqList(schema) {
			if anlStrictEq(anlGet(s, "verb"), anlGet(action, "verb")) {
				shape = s
				break
			}
		}
	}
	reaches := func(a any) (string, bool) {
		d := anlDecideAction(model, a)
		if anlRank[d] >= rankWant {
			return d, true
		}
		return "", false
	}
	var cands []map[string]any
	push := func(repair map[string]any, cost float64, a any) {
		if d, ok := reaches(a); ok {
			cands = append(cands, map[string]any{"repair": repair, "cost": cost, "decision": d, "action": a})
		}
	}
	pr := anlProbesFor([]map[string]any{model}, nil)
	params := anlSpread(anlNN(anlGet(action, "params"), map[string]any{}))
	var names []string
	if ch := anlGet(o, "changeable"); !anlIsUndef(ch) && ch != nil {
		for _, n := range anlReqList(ch) {
			names = append(names, anlJS(n))
		}
	} else if !anlIsUndef(shape) {
		if pm, ok := anlGet(shape, "params").(map[string]any); ok {
			names = jsKeys(pm)
		}
	} else {
		names = jsKeys(params)
	}

	// 1. wait: a time caveat that is not open yet, or a rate window that will reset
	if !capsOK && anlTruthy(cctx) {
		at, has := anlWaitTime(model["caveats"].([]any), cctx)
		d := anlDecideAction(model, action)
		if has {
			later := anlSpread(cctx)
			later["now"] = at
			if ok, _ := EvaluateCaveats(model["caveats"], anlCavCtx(later)); ok && anlRank[d] >= rankWant {
				cands = append(cands, map[string]any{"repair": map[string]any{"kind": "wait_until", "at": at, "reason": "a time or rate caveat opens then"}, "cost": 1.0, "decision": d, "action": action})
			}
		}
	}
	finish := !capsOK // nothing else helps while a caveat is closed

	// 2. one parameter changed: the nearest verified value, per parameter
	if !finish {
		for _, name := range names {
			path := "action.params." + name
			decl := anlDecl(shape, name)
			cur := anlOwn(params, name)
			var pool []any
			if f := anlFieldOf(pr, path); f != nil {
				pool = append(pool, f.values...)
			}
			dvals := anlOget(decl, "values")
			if !anlIsUndef(dvals) {
				pool = append(pool, anlAnyList(dvals)...)
			}
			dmin, dmax := anlOget(decl, "min"), anlOget(decl, "max")
			if !anlIsUndef(dmin) {
				pool = append(pool, dmin)
			}
			if !anlIsUndef(dmax) {
				pool = append(pool, dmax)
			}
			var nums, strs []any
			for _, v := range pool {
				if anlIsAbsent(v) {
					continue
				}
				if anlIsFin(v) {
					nums = append(nums, v)
				}
				if s, ok := v.(string); ok && !strings.HasPrefix(s, "\x00") {
					strs = append(strs, v)
				}
			}
			T := anlThresholdsOf(model, path)
			integer := anlOget(decl, "type") == "integer" || (anlIsNum(cur) && anlToNumber(cur) == math.Trunc(anlToNumber(cur)))
			var ints []any
			if integer {
				for _, t := range T {
					ints = append(ints, anlToNumber(t)-1, anlToNumber(t)+1)
				}
			}
			curn := 0.0
			if anlIsNum(cur) {
				curn = anlToNumber(cur)
			}
			var numeric []any
			for _, v := range anlUniq(append(append([]any{}, nums...), ints...)) {
				vf := anlToNumber(v)
				if (anlIsUndef(dmin) || vf >= anlToNumber(dmin)) && (anlIsUndef(dmax) || vf <= anlToNumber(dmax)) {
					numeric = append(numeric, v)
				}
			}
			sort.SliceStable(numeric, func(i, j int) bool {
				a, b := anlToNumber(numeric[i]), anlToNumber(numeric[j])
				da, db := math.Abs(a-curn), math.Abs(b-curn)
				if da != db {
					return da < db
				}
				return a < b
			})
			ordered := append(append([]any{}, numeric...), anlUniq(strs)...)
			for _, v := range ordered {
				if anlStrictEq(v, cur) {
					continue
				}
				a := anlWithParam(action, params, name, v)
				if d, ok := reaches(a); ok {
					extra := 0.5
					if anlIsNum(v) && anlIsNum(cur) {
						extra = math.Min(1, math.Abs(anlToNumber(v)-anlToNumber(cur))/(math.Abs(anlToNumber(cur))+1))
					}
					cands = append(cands, map[string]any{"repair": anlU(map[string]any{"kind": "set_param", "param": name, "from": cur, "to": v}), "cost": 2 + extra, "decision": d, "action": a})
					break // the pool is ordered nearest first
				}
			}
		}
	}

	ares := anlGet(action, "resource")
	var otherRes []any
	for _, x := range pr.resources {
		if !anlFreshStr(x) && !anlStrictEq(x, ares) {
			otherRes = append(otherRes, x)
		}
	}

	// 2b. when no single edit works, the cheapest PAIR of edits
	if !finish && len(cands) == 0 {
		var dims []anlDim
		for _, name := range names {
			name := name
			var vals []any
			if f := anlFieldOf(pr, "action.params."+name); f != nil {
				vals = append(vals, f.values...)
			}
			if dv := anlOget(anlDecl(shape, name), "values"); !anlIsUndef(dv) {
				vals = append(vals, anlAnyList(dv)...)
			}
			var kept []any
			for _, v := range vals {
				_, isStr := v.(string)
				if (isStr && !anlFreshStr(v)) || anlIsNum(v) {
					if !anlStrictEq(v, anlOwn(params, name)) {
						kept = append(kept, v)
					}
				}
			}
			u := anlUniq(kept)
			if len(u) > 6 {
				u = u[:6]
			}
			dims = append(dims, anlDim{
				cost: 2,
				make: func(a any, v any) map[string]any {
					p := map[string]any{}
					if pm, ok := anlGet(a, "params").(map[string]any); ok {
						p = pm
					}
					return anlWithParam(a, p, name, v)
				},
				step: func(v any) map[string]any {
					return anlU(map[string]any{"kind": "set_param", "param": name, "from": anlOwn(params, name), "to": v})
				},
				values: u,
			})
		}
		rv := otherRes
		if len(rv) > 6 {
			rv = rv[:6]
		}
		dims = append(dims, anlDim{
			cost: 3,
			make: func(a any, v any) map[string]any {
				m := anlSpread(a)
				m["resource"] = v
				return m
			},
			step:   func(v any) map[string]any { return anlU(map[string]any{"kind": "set_resource", "from": ares, "to": v}) },
			values: rv,
		})
		for i := range dims {
			for j := i + 1; j < len(dims); j++ {
				for _, x := range dims[i].values {
					for _, y := range dims[j].values {
						a := dims[j].make(dims[i].make(action, x), y)
						if d, ok := reaches(a); ok {
							cands = append(cands, map[string]any{"repair": map[string]any{"kind": "combine", "steps": []any{dims[i].step(x), dims[j].step(y)}}, "cost": dims[i].cost + dims[j].cost, "decision": d, "action": a})
						}
					}
				}
			}
		}
	}

	if !finish {
		// 3. another allowed resource
		for _, r := range otherRes {
			a := anlSpread(action)
			a["resource"] = r
			push(anlU(map[string]any{"kind": "set_resource", "from": ares, "to": r}), 3, a)
		}
		// 4. a named fact that is missing: a subject or env field the policy reads
		for _, f := range pr.fields {
			if !strings.HasPrefix(f.path, "subject.") && !strings.HasPrefix(f.path, "env.") {
				continue
			}
			segs := strings.Split(f.path, ".")
			root, rest := segs[0], segs[1:]
			for _, v := range f.values {
				if anlIsAbsent(v) {
					continue
				}
				a := anlSpread(action)
				a[root] = anlSetPath(anlSpread(anlNN(anlGet(action, root), map[string]any{})), rest, v)
				_, before := reaches(action)
				if d, ok := reaches(a); ok && !before {
					cands = append(cands, map[string]any{"repair": map[string]any{"kind": "obtain_fact", "path": f.path, "value": v}, "cost": 4.0, "decision": d, "action": a})
					break
				}
			}
		}
	}

	// 5. split (opt-in, and only when nothing meters the total)
	if anlGet(o, "allowSplit") == true && !anlMeters(model) {
		for _, name := range names {
			cur := anlOwn(params, name)
			if !anlIsNum(cur) {
				continue
			}
			part := math.NaN()
			for _, c := range cands {
				r := c["repair"].(map[string]any)
				if r["kind"] == "set_param" && r["param"] == name && anlIsNum(anlOwn(r, "to")) {
					part = anlToNumber(r["to"])
					break
				}
			}
			cf := anlToNumber(cur)
			if math.IsNaN(part) || part <= 0 || part >= cf {
				continue
			}
			n := math.Ceil(cf / part)
			if n > 8 {
				continue
			}
			parts := []any{}
			ok := true
			for i := 0; i < int(n); i++ {
				v := part
				if i == int(n)-1 {
					v = cf - part*(n-1)
				}
				parts = append(parts, map[string]any{name: v})
				a := anlSpread(action)
				a["params"] = anlWithParam(map[string]any{}, params, name, v)["params"]
				if _, r := reaches(a); !r {
					ok = false
					break
				}
			}
			if ok {
				cands = append(cands, map[string]any{"repair": map[string]any{"kind": "split", "param": name, "parts": parts}, "cost": 3 + n, "decision": want, "action": action})
			}
		}
	}

	sort.SliceStable(cands, func(i, j int) bool { return anlToNumber(cands[i]["cost"]) < anlToNumber(cands[j]["cost"]) })
	mc := int(math.Max(0, math.Min(anlToNumber(anlNN(anlGet(o, "maxCandidates"), 8)), 1<<30)))
	top := cands
	if mc < len(top) {
		top = top[:mc]
	}
	res["repairExists"] = len(top) > 0
	redact := anlNN(anlGet(o, "redact"), "critical")
	hide := func(c map[string]any) map[string]any {
		r := c["repair"].(map[string]any)
		if redact == "none" || r["kind"] != "set_param" {
			return c
		}
		sens := anlOget(anlDecl(shape, r["param"].(string)), "sensitivity")
		if redact == "critical" && sens != "critical" {
			return c
		}
		res["redacted"] = true
		out := anlCopy(c)
		out["repair"] = map[string]any{"kind": "set_param", "param": r["param"], "redacted": true}
		out["action"] = anlSpread(action)
		return out
	}
	if redact == "all" {
		res["redacted"] = true
	} else {
		repairs := []any{}
		for _, c := range top {
			repairs = append(repairs, hide(c))
		}
		res["repairs"] = repairs
	}
	for _, c := range top {
		if c["decision"] == "allow" && c["repair"].(map[string]any)["kind"] != "split" {
			if current == "escalate" {
				res["humanFree"] = hide(c)
			}
			break
		}
	}
	if current == "escalate" || len(top) == 0 {
		kind := "access-request"
		if current == "escalate" {
			kind = "approval"
		}
		res["humanAsk"] = anlU(map[string]any{"verb": anlGet(action, "verb"), "resource": anlGet(action, "resource"), "params": anlCopy(params), "kind": kind, "policyDigest": digest})
	}
	return res
}
