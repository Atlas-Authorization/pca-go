package pca

import (
	"errors"
	"math"
	"slices"
	"sort"
	"strings"
)

// The principal's live agent console, data layer: projects a stream of activity events into a per-agent view with a threat read (see
// ImmuneAssess) and models the kill switch. Pure and offline: a projection over records you feed it. The "freeze" is a local
// kill-switch set a client or gateway consults before dispatching; authoritative revocation is the transparency ledger's revocation
// epoch.
//
// An event is {at, agent, verb, resource, outcome: auto|step_up|deny|executed, r?, taint?, digest?, goalCommit?}.

// EventFromPCActn is the activity event of a proof-carrying action and the verifier's outcome; at may be nil (then the action's iat).
func EventFromPCActn(p map[string]any, outcome string, at *float64) (map[string]any, error) {
	chain, ok := p["cap_chain"].([]any)
	if !ok {
		return nil, errors.New("eventFromPCActn: cap_chain must be a list")
	}
	var leaf map[string]any
	if len(chain) > 0 {
		leaf = rsMap(chain[len(chain)-1])
	}
	action := rsMap(p["action"])
	if action == nil {
		return nil, errors.New("eventFromPCActn: action must be an object")
	}
	e := map[string]any{}
	if at != nil {
		e["at"] = rsN(*at)
	} else if rsHas(p, "iat") {
		e["at"] = p["iat"]
	}
	e["agent"] = "unknown"
	if leaf != nil && leaf["holder"] != nil {
		e["agent"] = leaf["holder"]
	}
	if rsHas(action, "verb") {
		e["verb"] = action["verb"]
	}
	if rsHas(action, "resource") {
		e["resource"] = action["resource"]
	}
	e["outcome"] = outcome
	if rc := rsMap(p["risk_claim"]); rc != nil && rsHas(rc, "r") {
		e["r"] = rc["r"]
	}
	if pv := rsMap(p["provenance"]); pv != nil && rsHas(pv, "taint_level") {
		e["taint"] = pv["taint_level"]
	}
	d, err := HashCanonical(p)
	if err != nil {
		return nil, err
	}
	e["digest"] = d
	return e, nil
}

func consoleUsable(o any) bool {
	e := rsMap(o)
	if e == nil || !rsFinite(e["at"]) {
		return false
	}
	a, ok := e["agent"].(string)
	return ok && a != ""
}

func consoleTotals(actions, autos, stepUps, denies, executed float64) map[string]any {
	return map[string]any{"actions": rsN(actions), "autos": rsN(autos), "stepUps": rsN(stepUps), "denies": rsN(denies), "executed": rsN(executed)}
}

// BuildConsole projects events into the console view {agents, totals, window: {from, to}, dropped}, agents most threatened first (then
// most recently seen). An event with no finite time or no agent id cannot be placed in a timeline or attributed: it is counted in
// dropped, not guessed. A risk that is present but not a number is refused (an error) rather than summed as text.
func BuildConsole(all []any) (map[string]any, error) {
	var events []map[string]any
	for _, o := range all {
		if consoleUsable(o) {
			events = append(events, rsMap(o))
		}
	}
	dropped := len(all) - len(events)
	var order []string
	byAgent := map[string][]map[string]any{}
	for _, e := range events {
		a := e["agent"].(string)
		if _, seen := byAgent[a]; !seen {
			order = append(order, a)
		}
		byAgent[a] = append(byAgent[a], e)
	}
	agents := make([]map[string]any, 0, len(order))
	for _, name := range order {
		sorted := append([]map[string]any(nil), byAgent[name]...)
		sort.SliceStable(sorted, func(i, j int) bool { return rsCmp(jsF(sorted[i]["at"])-jsF(sorted[j]["at"])) < 0 })
		immune := InitialImmuneState()
		var autos, stepUps, denies, executed, totalRisk float64
		for _, e := range sorted {
			r := 0.0
			if ro := e["r"]; ro != nil {
				if !rsIsNum(ro) {
					return nil, errors.New("buildConsole: r must be a number")
				}
				r = jsF(ro)
			}
			totalRisk += r
			switch e["outcome"] {
			case "auto":
				autos++
			case "step_up":
				stepUps++
			case "deny":
				denies++
			case "executed":
				executed++
			}
			immune = ImmuneObserve(immune, map[string]any{"r": rsN(r), "at": e["at"], "stepUp": e["outcome"] == "step_up", "denied": e["outcome"] == "deny"})
		}
		agents = append(agents, map[string]any{"agent": name, "actions": rsN(float64(len(sorted))), "autos": rsN(autos), "stepUps": rsN(stepUps),
			"denies": rsN(denies), "executed": rsN(executed), "totalRisk": rsN(totalRisk), "firstSeen": sorted[0]["at"],
			"lastSeen": sorted[len(sorted)-1]["at"], "threat": ImmuneAssess(immune)})
	}
	sort.SliceStable(agents, func(i, j int) bool {
		x, y := agents[i], agents[j]
		if d := jsF(rsMap(y["threat"])["score"]) - jsF(rsMap(x["threat"])["score"]); d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		return rsCmp(jsF(y["lastSeen"])-jsF(x["lastSeen"])) < 0
	})
	var ta, tau, ts, td, te float64
	out := make([]any, len(agents))
	for i, a := range agents {
		ta += jsF(a["actions"])
		tau += jsF(a["autos"])
		ts += jsF(a["stepUps"])
		td += jsF(a["denies"])
		te += jsF(a["executed"])
		out[i] = a
	}
	from, to := 0.0, 0.0
	if len(events) > 0 {
		from, to = math.Inf(1), math.Inf(-1)
		for _, e := range events {
			from, to = math.Min(from, jsF(e["at"])), math.Max(to, jsF(e["at"]))
		}
	}
	return map[string]any{"agents": out, "totals": consoleTotals(ta, tau, ts, td, te), "window": map[string]any{"from": rsN(from), "to": rsN(to)},
		"dropped": rsN(float64(dropped))}, nil
}

// Anomalies are the agents whose current threat read is not calm (the console's "anomalies" panel).
func Anomalies(view map[string]any) []any {
	out := []any{}
	agents, _ := view["agents"].([]any)
	for _, a := range agents {
		if t := rsMap(rsMap(a)["threat"]); t["level"] != "calm" {
			out = append(out, a)
		}
	}
	return out
}

// ---- freeze (the kill switch) ---------------------------------------------------------------------------------

// EmptyFreeze is the empty freeze set {frozen: []}.
func EmptyFreeze() map[string]any { return map[string]any{"frozen": []any{}} }

func consoleFrozen(set map[string]any) ([]any, error) {
	l, ok := set["frozen"].([]any)
	if set == nil || !ok {
		return nil, errors.New("freeze set must be {frozen: [...]}")
	}
	return l, nil
}

// FreezeAgent freezes an agent: the set with the id added (sorted); the same set when it is already frozen.
func FreezeAgent(set map[string]any, agent any) (map[string]any, error) {
	a, ok := agent.(string)
	if !ok || a == "" {
		return nil, errors.New("freezeAgent: agent must be a non-empty string")
	}
	var cur []any
	if str, isStr := set["frozen"].(string); isStr && set != nil {
		// `set.frozen.includes(agent)` on a string is a substring test, and the spread reads its characters
		if strings.Contains(str, a) {
			return set, nil
		}
		for _, r := range str {
			cur = append(cur, string(r))
		}
	} else {
		var err error
		if cur, err = consoleFrozen(set); err != nil {
			return nil, err
		}
	}
	next := make([]any, 0, len(cur)+1)
	for _, o := range cur {
		if jsStrictEq(o, agent) {
			return set, nil
		}
		next = append(next, o) // the elements keep their own values (a number stays a number)
	}
	next = append(next, a)
	// Array.prototype.sort without a comparator orders by the elements' strings, in UTF-16 code-unit order
	sort.SliceStable(next, func(i, j int) bool {
		return slices.Compare(utf16Units(jsValueString(next[i])), utf16Units(jsValueString(next[j]))) < 0
	})
	return map[string]any{"frozen": next}, nil
}

// UnfreezeAgent is the set without the agent.
func UnfreezeAgent(set map[string]any, agent any) (map[string]any, error) {
	cur, err := consoleFrozen(set)
	if err != nil {
		return nil, err
	}
	next := []any{}
	for _, o := range cur {
		if !jsStrictEq(o, agent) {
			next = append(next, o)
		}
	}
	return map[string]any{"frozen": next}, nil
}

// IsFrozen is whether an agent is frozen. It fails closed: an agent with no usable id, or a malformed set, counts as frozen.
func IsFrozen(set any, agent any) bool {
	a, ok := agent.(string)
	m := rsMap(set)
	if !ok || a == "" || m == nil {
		return true
	}
	l, ok := m["frozen"].([]any)
	if !ok {
		return true
	}
	for _, o := range l {
		if jsStrictEq(o, agent) {
			return true
		}
	}
	return false
}

// sortUtf16 sorts strings by UTF-16 code units (String.prototype.sort / compareTo order).
func sortUtf16(xs []string) {
	sort.Slice(xs, func(i, j int) bool { return compareUnits(utf16Units(xs[i]), utf16Units(xs[j])) < 0 })
}
