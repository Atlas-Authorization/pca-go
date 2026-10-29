package pca

// Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
// monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from the
// session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the
// store, its lock and the reservation are the host's.

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// isCountedStatus: a reserved or committed event counts toward a cap (a reservation counts as soon as it is made).
func isCountedStatus(s any) bool { return s == "reserved" || s == "committed" }

// inWindow: does the counted event stamped ti still count at t? task: always; sliding(ms): (t-ms, t]; period(ms, t0): the
// period containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
// window (fail closed: the caller treats the store as corrupt).
func inWindow(win map[string]any, ti, t any) bool {
	if !jsIsInt(ti) || !jsIsInt(t) {
		return false
	}
	fi, ft := jsF(ti), jsF(t)
	if fi > ft {
		return true
	}
	switch win["kind"] {
	case "task":
		return true
	case "sliding":
		return fi > ft-jsF(win["ms"])
	case "period":
		ms, t0 := jsF(win["ms"]), jsF(win["t0"])
		return math.Floor((fi-t0)/ms) == math.Floor((ft-t0)/ms)
	}
	return false
}

// accKeyOf: the canonical key of the grouping parameter, "•" when ungrouped, ok=false when the parameter is missing or not a
// string / safe integer.
func accKeyOf(a map[string]any, params map[string]any) (string, bool) {
	k, grouped := a["key"].(string)
	if !grouped {
		return "•", true
	}
	x, has := params[k[len("action.params."):]]
	if !has {
		return "", false
	}
	return distinctKey(x)
}

func emptyPre(agg string) map[string]any {
	switch agg {
	case "sum":
		return map[string]any{"sum": jsNumber(0)}
	case "count":
		return map[string]any{"count": jsNumber(0)}
	case "max":
		return map[string]any{"max": jsNumber(0)}
	}
	return map[string]any{"values": []any{}}
}

// accPreState is the pre-state of ψ for a candidate action. ok=false is the reference's throw: a past event's value or time is
// unreadable (store corruption), the candidate's key is missing, or a sum leaves the safe-integer range.
func accPreState(a map[string]any, history []any, candParams map[string]any, candT any, schema any, haveSchema bool) (map[string]any, bool) {
	key, ok := accKeyOf(a, candParams)
	if !ok {
		return nil, false
	}
	if !jsIsInt(candT) {
		return nil, false
	}
	win, _ := a["win"].(map[string]any)
	sum, count, mx := 0.0, 0.0, 0.0
	var vals []string
	for _, ev := range history {
		e, _ := ev.(map[string]any)
		counted := isCountedStatus(e["status"])
		if counted && !jsIsInt(e["t"]) {
			return nil, false
		}
		if !counted || !inWindow(win, e["t"], candT) {
			continue
		}
		verb, _ := e["verb"].(string)
		sel, throws := accSelects(a, verb, schema, haveSchema)
		if throws {
			return nil, false
		}
		params, _ := e["params"].(map[string]any)
		if !sel {
			continue
		}
		if ek, eok := accKeyOf(a, params); !eok || ek != key {
			continue
		}
		v, vok, vthrows := accValueOf(a, verb, params, schema, haveSchema)
		if vthrows || !vok {
			return nil, false
		}
		sum += v.val
		count++
		mx = math.Max(mx, v.val)
		if v.key != "" {
			vals = append(vals, v.key)
		}
	}
	switch a["agg"] {
	case "sum":
		if !jsIsSafeInteger(jsNumber(sum)) {
			return nil, false
		}
		return map[string]any{"sum": jsNumber(sum)}, true
	case "count":
		return map[string]any{"count": jsNumber(count)}, true
	case "max":
		return map[string]any{"max": jsNumber(mx)}, true
	}
	sort.Slice(vals, func(i, j int) bool { return compareUtf8(vals[i], vals[j]) < 0 })
	out := []any{}
	for i, v := range vals {
		if i == 0 || v != vals[i-1] {
			out = append(out, v)
		}
	}
	return map[string]any{"values": out}, true
}

// accPost is post_ψ(ξ, ω, t): the pre-state combined with ω when ω is selected, else the pre-state's value. ok=false: throws.
func accPost(a map[string]any, history []any, verb string, params map[string]any, t any, schema any, haveSchema bool) (float64, bool) {
	var pre map[string]any
	if _, grouped := a["key"].(string); grouped {
		if _, kok := accKeyOf(a, params); !kok {
			pre = emptyPre(a["agg"].(string))
		}
	}
	if pre == nil {
		p, ok := accPreState(a, history, params, t, schema, haveSchema)
		if !ok {
			return 0, false
		}
		pre = p
	}
	sel, throws := accSelects(a, verb, schema, haveSchema)
	if throws {
		return 0, false
	}
	if !sel {
		return preValue(a["agg"].(string), pre), true
	}
	v, ok, vthrows := accValueOf(a, verb, params, schema, haveSchema)
	if vthrows || !ok {
		return 0, false
	}
	return combineAcc(a["agg"].(string), pre, v)
}

// monitorInitialState is the start state of a monitor.
func monitorInitialState(m map[string]any) string {
	switch m["kind"] {
	case "requires_prior", "precedes":
		return "unmet"
	case "never":
		return "clean"
	case "always":
		return "ok"
	}
	return "idle"
}

// monitorStep is one monitor step on one event; statuses that do not count leave the state unchanged.
func monitorStep(m map[string]any, q string, e map[string]any) string {
	var counts bool
	if m["status"] == "committed" {
		counts = e["status"] == "committed"
	} else {
		counts = isCountedStatus(e["status"])
	}
	if !counts {
		return q
	}
	ctx := map[string]any{"action": map[string]any{"verb": e["verb"], "resource": e["resource"], "params": e["params"]}}
	match := func(p any) bool { return predicateMatches(p, ctx, &regexBudget{}) }
	switch m["kind"] {
	case "requires_prior", "precedes":
		if q == "met" || match(m["p"]) {
			return "met"
		}
		return "unmet"
	case "never":
		if q == "seen" || match(m["p"]) {
			return "seen"
		}
		return "clean"
	case "always":
		if q == "broken" || !match(m["p"]) {
			return "broken"
		}
		return "ok"
	case "responds_within":
		if q == "missed" {
			return "missed"
		}
		w := jsF(m["within"])
		pending, has := 0.0, false
		if strings.HasPrefix(q, "pending:") {
			pending, has = jsStringToNumber(q[len("pending:"):]), true
		}
		if has {
			if match(m["q"]) {
				has = false
			} else if pending-1 <= 0 {
				return "missed"
			} else {
				pending--
			}
		}
		if match(m["p"]) {
			if !has {
				pending, has = w, true
			} else {
				pending = math.Min(pending, w)
			}
		}
		if !has {
			return "idle"
		}
		return "pending:" + jsNumberString(pending)
	}
	return q
}

// jsStringToNumber is Number(s) for the decimal tails of a pending state (NaN otherwise).
func jsStringToNumber(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return f
}

// monitorState is q(ξ): the fold of the monitor over the history (admission order, current statuses).
func monitorState(m map[string]any, history []any) string {
	q := monitorInitialState(m)
	for _, ev := range history {
		e, _ := ev.(map[string]any)
		q = monitorStep(m, q, e)
	}
	return q
}
