package pca

// Static exposure of a workflow body (steps, dependency DAG, edges, budget). A body that is not a DAG is refused.

import (
	"math"
	"sort"
	"unicode/utf16"
)

const anlPathCap = 1000000.0

// anlDagID is a step id: ids are strings; anything else cannot name a step.
func anlDagID(v any) string {
	s, ok := v.(string)
	if !ok {
		anlFail("step id is not a string")
	}
	return s
}

func anlUnitLess(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func anlDagExposure(b any) map[string]any {
	steps := anlReqList(anlGet(b, "steps"))
	byID := map[string]any{}
	for _, s := range steps {
		byID[anlDagID(anlGet(s, "id"))] = s
	}
	if len(byID) != len(steps) {
		anlFail("dagExposure: duplicate step id")
	}
	level := map[string]int{}
	anc := map[string]map[string]bool{}
	visiting := map[string]bool{}
	var visit func(id string)
	visit = func(id string) {
		if _, done := level[id]; done {
			return
		}
		if visiting[id] {
			anlFail("dagExposure: cycle")
		}
		visiting[id] = true
		s, ok := byID[id]
		if !ok {
			anlFail("dagExposure: unknown step %s", id)
		}
		a := map[string]bool{}
		lv := 0
		for _, dv := range anlReqList(anlGet(s, "deps")) {
			d := anlDagID(dv)
			visit(d)
			a[d] = true
			for k := range anc[d] {
				a[k] = true
			}
			if level[d]+1 > lv {
				lv = level[d] + 1
			}
		}
		delete(visiting, id)
		anc[id] = a
		level[id] = lv
	}
	for _, s := range steps {
		visit(anlDagID(anlGet(s, "id")))
	}
	maxLevel := 0
	widths := map[int]int{}
	for _, lv := range level {
		if lv > maxLevel {
			maxLevel = lv
		}
		widths[lv]++
	}
	levelWidth := math.Inf(-1)
	for _, w := range widths {
		if float64(w) > levelWidth {
			levelWidth = float64(w)
		}
	}
	children := map[string][]string{}
	for _, s := range steps {
		children[anlDagID(anlGet(s, "id"))] = nil
	}
	for _, s := range steps {
		for _, d := range anlReqList(anlGet(s, "deps")) {
			children[anlDagID(d)] = append(children[anlDagID(d)], anlDagID(anlGet(s, "id")))
		}
	}
	memo := map[string]float64{}
	capped := false
	var toLeaves func(id string) float64
	toLeaves = func(id string) float64 {
		if n, ok := memo[id]; ok {
			return n
		}
		kids := children[id]
		n := 0.0
		if len(kids) == 0 {
			n = 1
		}
		for _, k := range kids {
			n += toLeaves(k)
		}
		if n > anlPathCap {
			n = anlPathCap
			capped = true
		}
		memo[id] = n
		return n
	}
	paths := 0.0
	for _, s := range steps {
		if anlLen(anlGet(s, "deps")) == 0 {
			paths = math.Min(anlPathCap, paths+toLeaves(anlDagID(anlGet(s, "id"))))
		}
	}

	budget := anlGet(b, "budget")
	caps, ok := anlGet(budget, "caps").(map[string]any)
	if !ok {
		anlFail("Object.entries requires an object")
	}
	cost := map[string]any{}
	for _, name := range jsKeys(caps) {
		capv := caps[name]
		total := 0.0
		for _, s := range steps {
			if sc, ok := anlGet(s, "cost").(map[string]any); ok && sc[name] != nil {
				if _, has := sc[name]; has {
					total += anlToNumber(sc[name])
				}
			}
		}
		cost[name] = map[string]any{"cap": capv, "total": total, "maxSpend": math.Min(anlToNumber(capv), total)}
	}
	maxSteps := anlGet(budget, "max_steps")
	never := []any{}
	for _, s := range steps {
		id := anlGet(s, "id")
		over := false
		if sc, ok := anlGet(s, "cost").(map[string]any); ok {
			for n, c := range sc {
				if anlToNumber(c) > anlToNumber(anlNN(caps[n], 0)) {
					over = true
				}
			}
		}
		if over {
			never = append(never, map[string]any{"step": id, "reason": "cost_over_cap"})
		} else if anlIsNum(maxSteps) && float64(len(anc[anlDagID(id)])+1) > anlToNumber(maxSteps) {
			never = append(never, map[string]any{"step": id, "reason": "needs_more_steps_than_budget"})
		}
	}

	edges := anlReqList(anlGet(b, "edges"))
	feeds := map[string]map[string]bool{}
	for _, s := range steps {
		feeds[anlDagID(anlGet(s, "id"))] = map[string]bool{}
	}
	edgeTo := func(e any) string { return anlDagID(anlGet(anlGet(e, "to"), "step")) }
	for _, e := range edges {
		f, ok := feeds[edgeTo(e)]
		if !ok {
			anlFail("cannot read properties of undefined (reading 'add')")
		}
		f[anlDagID(anlGet(anlGet(e, "from"), "step"))] = true
	}
	var lineageOf func(id string, seen map[string]bool)
	lineageOf = func(id string, seen map[string]bool) {
		f, ok := feeds[id]
		if !ok {
			anlFail("feeds.get is not a function or its return value is not iterable")
		}
		for k := range f {
			if !seen[k] {
				seen[k] = true
				lineageOf(k, seen)
			}
		}
	}
	sinks := []any{}
	unprotected := []any{}
	for _, s := range steps {
		sk := anlGet(s, "sink")
		if sk == nil {
			continue
		}
		sid := anlDagID(anlGet(s, "id"))
		seen := map[string]bool{}
		lineageOf(sid, seen)
		names := make([]string, 0, len(seen))
		for k := range seen {
			names = append(names, k)
		}
		sort.Slice(names, func(i, j int) bool { return anlUnitLess(names[i], names[j]) })
		lineage := make([]any, len(names))
		for i, n := range names {
			lineage[i] = n
		}
		protected := anlLen(anlGet(s, "deny_labels")) > 0 || anlLen(anlGet(s, "escalate_labels")) > 0
		for _, e := range edges {
			if edgeTo(e) == sid && anlLen(anlGet(e, "deny_labels")) > 0 {
				protected = true
			}
		}
		sinks = append(sinks, anlU(map[string]any{"step": sid, "sink": sk, "lineage": lineage, "protected": protected}))
		if !protected && len(lineage) > 0 {
			unprotected = append(unprotected, sid)
		}
	}
	orderingOnly := []any{}
	for _, s := range steps {
		if anlLen(anlGet(s, "deps")) == 0 {
			continue
		}
		fed := false
		for _, e := range edges {
			if edgeTo(e) == anlDagID(anlGet(s, "id")) {
				fed = true
			}
		}
		if !fed {
			orderingOnly = append(orderingOnly, anlGet(s, "id"))
		}
	}
	pipelinable := []any{}
	for i, e := range edges {
		if anlGet(e, "promise") != nil {
			pipelinable = append(pipelinable, i)
		}
	}
	var maxStepsOut any
	if anlIsNum(maxSteps) {
		maxStepsOut = math.Min(float64(len(steps)), anlToNumber(maxSteps))
	}
	return map[string]any{
		"steps": len(steps), "maxSteps": maxStepsOut, "depth": maxLevel + 1, "levelWidth": levelWidth,
		"paths": paths, "pathsCapped": capped, "cost": cost, "neverRunnable": never, "sinks": sinks, "unprotectedSinks": unprotected,
		"orderingOnly": orderingOnly, "pipelinable": pipelinable,
	}
}
