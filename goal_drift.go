package pca

// Runtime drift monitoring, tighten-only (the TypeScript reference is @atlasauth/pca-goal `drift`). A monitor compares the action
// stream to the goal's expected profile (verbs, resources, magnitude, rate, novelty). Anomalies convert Allow to Escalate; the strike
// counter is a ratchet (never decreases); at `lockdown` strikes every Allow becomes Escalate. goalApplyDrift never relaxes a decision.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
)

// goalDefaultDrift is the default profile (a fresh map per call).
func goalDefaultDrift() map[string]any {
	return map[string]any{"windowMs": goalNum(60000), "maxPerWindow": goalNum(20), "maxNovel": goalNum(3), "magnitudeFactor": goalNum(3), "warmup": goalNum(5), "lockdown": goalNum(5)}
}

// goalDriftHas reports whether xs holds x (===).
func goalDriftHas(xs []any, x any) bool {
	for _, e := range xs {
		if anlStrictEq(e, x) {
			return true
		}
	}
	return false
}

func goalExpectedVerbs(g any) []any {
	out := []any{}
	for _, x := range anlReqList(anlGet(g, "grants")) {
		v := anlGet(x, "verb")
		if !goalDriftHas(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func goalDriftResIDs(s any) []any {
	switch anlGet(s, "k") {
	case "exact":
		return []any{anlGet(s, "id")}
	case "oneof":
		return append([]any{}, anlReqList(anlGet(s, "ids"))...)
	case "all_of":
		out := []any{}
		for _, p := range anlReqList(anlGet(s, "parts")) {
			out = append(out, goalDriftResIDs(p)...)
		}
		return out
	}
	return []any{}
}

func goalDriftKnownResources(g any) []any {
	out := []any{}
	for _, x := range anlReqList(anlGet(g, "grants")) {
		for _, y := range goalDriftResIDs(anlGet(x, "res")) {
			if !goalDriftHas(out, y) {
				out = append(out, y)
			}
		}
	}
	return out
}

// goalDriftNodeHex is Node's lenient Buffer.from(s, 'hex'): decoding stops at the first invalid pair.
func goalDriftNodeHex(v any) []byte {
	s, ok := v.(string)
	if !ok {
		anlFail("the first argument must be a string")
	}
	out := []byte{}
	for i := 0; i+1 < len(s); i += 2 {
		b, err := hex.DecodeString(s[i : i+2])
		if err != nil {
			break
		}
		out = append(out, b[0])
	}
	return out
}

// GoalDriftMonitor is the stateful monitor of one goal.
type GoalDriftMonitor struct {
	goal any
	o    map[string]any
	st   map[string]any
}

func goalDriftFreshState(strikes any) map[string]any {
	st := map[string]any{"strikes": strikes, "times": []any{}, "novel": []any{}, "seen": map[string]any{}}
	recordKeyOrder(st, []string{"strikes", "times", "novel", "seen"})
	return st
}

func goalNewDriftMonitor(goal any, opts any) *GoalDriftMonitor {
	o := goalDefaultDrift()
	for k, v := range anlSpread(opts) {
		o[k] = v
	}
	return &GoalDriftMonitor{goal: goal, o: o, st: goalDriftFreshState(goalNum(0))}
}

// goalDeepCopy is a deep copy of a JSON tree that keeps every object's member order.
func goalDeepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = goalDeepCopy(x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = goalDeepCopy(x)
		}
		return out
	}
	return v
}

func (m *GoalDriftMonitor) observe(a, t any) map[string]any {
	reasons := []any{}
	o := m.o
	verb := anlGet(a, "verb")
	if !goalDriftHas(goalExpectedVerbs(m.goal), verb) {
		reasons = append(reasons, "verb "+anlJS(verb)+" outside the goal profile")
	}
	known := goalDriftKnownResources(m.goal)
	res := anlGet(a, "res")
	novel, _ := m.st["novel"].([]any)
	if len(known) > 0 && !goalDriftHas(known, res) && !goalDriftHas(novel, res) {
		novel = append(novel, res)
		m.st["novel"] = novel
	}
	if float64(len(novel)) > goalExNum(o["maxNovel"]) {
		reasons = append(reasons, "novel resources beyond the allowance")
	}
	tn := goalExNum(t)
	times := []any{}
	old, _ := m.st["times"].([]any)
	for _, x := range old {
		if goalExNum(x) > tn-goalExNum(o["windowMs"]) {
			times = append(times, x)
		}
	}
	times = append(times, t)
	m.st["times"] = times
	if float64(len(times)) > goalExNum(o["maxPerWindow"]) {
		reasons = append(reasons, "rate above the profile")
	}
	params := anlGet(a, "params")
	pm, _ := params.(map[string]any)
	if pm == nil {
		anlFail("params.items is not a function")
	}
	seen, _ := m.st["seen"].(map[string]any)
	for _, p := range jsKeys(pm) {
		l := pm[p]
		if anlGet(l, "k") != "q" {
			continue
		}
		hist, _ := seen[p].([]any)
		v := anlGet(anlGet(l, "q"), "n")
		if float64(len(hist)) >= goalExNum(o["warmup"]) {
			mean := math.NaN() // warmup 0: 0 / 0 is NaN, never above
			if len(hist) > 0 {
				var sum float64
				for _, h := range hist {
					sum += goalExNum(h)
				}
				mean = sum / float64(len(hist))
			}
			if mean > 0 && goalExNum(v) > mean*goalExNum(o["magnitudeFactor"]) {
				reasons = append(reasons, p+" magnitude "+anlJS(o["magnitudeFactor"])+"x above the running mean")
			}
		}
		nh := append(append([]any{}, hist...), v)
		if len(nh) > 50 {
			nh = nh[len(nh)-50:]
		}
		if _, had := seen[p]; !had {
			ks := append(append([]string{}, jsKeys(seen)...), p)
			seen[p] = nh
			recordKeyOrder(seen, ks)
		} else {
			seen[p] = nh
		}
	}
	strikes := goalExNum(m.st["strikes"])
	if len(reasons) > 0 {
		strikes++ // ratchet: only ever increases
		m.st["strikes"] = jsNumber(strikes)
	}
	return map[string]any{"anomalous": len(reasons) > 0, "strikes": m.st["strikes"], "lockdown": strikes >= goalExNum(o["lockdown"]), "reasons": reasons}
}

func (m *GoalDriftMonitor) mac(state any, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(anlJSON(state)))
	return h.Sum(nil)
}

// seal is the sealed state: durable and not agent-writable (the monitor key is held outside the agent).
func (m *GoalDriftMonitor) seal(key []byte) map[string]any {
	return map[string]any{"state": m.st, "mac": hex.EncodeToString(m.mac(m.st, key))}
}

// goalRestoreDriftMonitor restores a monitor; a state that fails its MAC locks down (fail closed).
func goalRestoreDriftMonitor(goal any, sealed any, key []byte, opts any) *GoalDriftMonitor {
	m := goalNewDriftMonitor(goal, opts)
	state := anlGet(sealed, "state")
	want := m.mac(state, key)
	got := goalDriftNodeHex(anlGet(sealed, "mac"))
	if st, ok := state.(map[string]any); ok && len(got) == len(want) && hmac.Equal(got, want) {
		m.st = st
	} else {
		m.st = goalDriftFreshState(m.o["lockdown"])
	}
	return m
}

// goalApplyDrift is tighten-only: Allow becomes Escalate on an anomaly or lockdown; nothing else changes.
func goalApplyDrift(d string, s any) string {
	if d == "allow" && (anlTruthy(anlGet(s, "anomalous")) || anlTruthy(anlGet(s, "lockdown"))) {
		return "escalate"
	}
	return d
}

// goalGuardedDecide decides, observes, tightens.
func goalGuardedDecide(goal, ont any, mon *GoalDriftMonitor, c any, t any) map[string]any {
	base := goalDecideCase(goal, ont, c)["decision"].(string)
	signal := mon.observe(anlGet(c, "act"), t)
	return map[string]any{"decision": goalApplyDrift(base, signal), "signal": signal}
}

// Observe records one action at time t and returns the drift signal.
func (m *GoalDriftMonitor) Observe(a, t any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = m.observe(a, t); return nil })
	return
}

// State is the monitor's live state.
func (m *GoalDriftMonitor) State() map[string]any { return m.st }

// Seal is the MAC-sealed state under the monitor key.
func (m *GoalDriftMonitor) Seal(key []byte) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = m.seal(key); return nil })
	return
}

// GoalNewDriftMonitor is a monitor of a goal; opts override the default profile (windowMs, maxPerWindow, maxNovel, magnitudeFactor,
// warmup, lockdown).
func GoalNewDriftMonitor(goal any, opts map[string]any) (m *GoalDriftMonitor, err error) {
	_, err = anlTry(func() any { m = goalNewDriftMonitor(goal, opts); return nil })
	return
}

// GoalRestoreDriftMonitor restores a sealed monitor; a state that fails its MAC locks down.
func GoalRestoreDriftMonitor(goal, sealed any, key []byte, opts map[string]any) (m *GoalDriftMonitor, err error) {
	_, err = anlTry(func() any { m = goalRestoreDriftMonitor(goal, sealed, key, opts); return nil })
	return
}

// GoalApplyDrift is tighten-only: Allow becomes Escalate on an anomaly or lockdown.
func GoalApplyDrift(d string, s any) (r string, err error) {
	_, err = anlTry(func() any { r = goalApplyDrift(d, s); return nil })
	return
}

// GoalGuardedDecide decides, observes and tightens.
func GoalGuardedDecide(goal, ont any, mon *GoalDriftMonitor, c any, t any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalGuardedDecide(goal, ont, mon, c, t); return nil })
	return
}
