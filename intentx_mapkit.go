package pca

// The Intent Map: a content-addressed, replayable artifact holding the outcome space, the learner parameters, every answer, the
// learned cells, the conservative grant and the quantified fidelity (all probabilities and metrics are integer ppm so the digest is
// language-portable), and the wallet side of its committed (Merkle, per-leaf salted) form. Maps, omegas and learner options are
// plain JSON trees with the reference's field names. The committed-map verifier is intent_map.go.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

const (
	ixMkMapDomain = "atlas-pca/intent-map/v1"
	ixMkTagSalt   = "atlas-pca/intent-map/salt/v1\x00"
)

// ixMkRound is JS Math.round: the nearest integer, ties toward +infinity.
func ixMkRound(x float64) float64 {
	x = float64(x) // the argument is rounded before x-f reads it: no fused multiply-add when a product is passed in (arm64)
	f := math.Floor(x)
	if x-f >= 0.5 {
		return f + 1
	}
	return f
}

func ixMkPpm(x float64) float64 { return ixMkRound(x * ixPPM) }
func ixMkQz(x float64) float64  { return ixMkRound(x*ixPPM) / ixPPM }

func ixMkIsNum(x any) bool { _, ok := x.(float64); return ok }

func ixMkCopyList(v any) []any { return append([]any{}, ixL(v)...) }

// IntentOmegaToJSON is the integer-weight wire form of an outcome space.
func IntentOmegaToJSON(o map[string]any) (out map[string]any, err error) {
	r, err := ixTry(func() any { return ixMkOmegaToJSON(o) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMkOmegaToJSON(o map[string]any) map[string]any {
	verbs0 := ixL(o["verbs"])
	ws := make([]float64, len(verbs0))
	for i, v := range verbs0 {
		ws[i] = ixF(ixM(v)["weight"])
	}
	equal := true
	for _, w := range ws {
		if !(math.Abs(w-ws[0]) < 1e-15) {
			equal = false
		}
	}
	verbs := []any{}
	for _, vv := range verbs0 {
		v := ixM(vv)
		dims := []any{}
		for _, dv := range ixL(v["dims"]) {
			d := ixM(dv)
			if d["kind"] == "num" {
				nd := map[string]any{"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"], "cuts": ixMkCopyList(d["cuts"])}
				if x, ok := d["dist"]; ok {
					nd["dist"] = x
				}
				dims = append(dims, nd)
			} else {
				vals := []any{}
				for _, x := range ixL(d["values"]) {
					vals = append(vals, ixCopyMap(ixM(x)))
				}
				dims = append(dims, map[string]any{"kind": "cat", "path": d["path"], "values": vals})
			}
		}
		w := 1.0
		if !equal {
			w = math.Max(1, ixMkRound(ixF(v["weight"])*ixPPM))
		}
		verbs = append(verbs, map[string]any{"verb": v["verb"], "reversibility": v["reversibility"], "w": w, "dims": dims})
	}
	return map[string]any{"verbs": verbs, "approximate": ixMkCopyList(o["approximate"])}
}

// IntentOmegaFromJSON is the inverse of IntentOmegaToJSON.
func IntentOmegaFromJSON(j map[string]any) (out map[string]any, err error) {
	r, err := ixTry(func() any { return ixMkOmegaFromJSON(j) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMkOmegaFromJSON(j map[string]any) map[string]any {
	tot := 0.0
	for _, v := range ixL(j["verbs"]) {
		tot += ixF(ixM(v)["w"])
	}
	verbs := []any{}
	for _, vv := range ixL(j["verbs"]) {
		v := ixM(vv)
		dims := []any{}
		for _, dv := range ixL(v["dims"]) {
			d := ixM(dv)
			if d["kind"] == "num" {
				dims = append(dims, map[string]any{"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"],
					"cuts": ixMkCopyList(ixLrOpt(d, "cuts", []any{})), "dist": ixLrOpt(d, "dist", "uniform")})
			} else {
				// a categorical dimension holds one of its values: with none it can hold nothing, so it is refused
				src := ixL(d["values"])
				if len(src) == 0 {
					panic(fmt.Errorf("omegaFromJSON: categorical dimension '%s' has no values", ixS(d["path"])))
				}
				vals := []any{}
				for _, x := range src {
					vals = append(vals, ixCopyMap(ixM(x)))
				}
				dims = append(dims, map[string]any{"kind": "cat", "path": d["path"], "values": vals})
			}
		}
		verbs = append(verbs, map[string]any{"verb": v["verb"], "reversibility": v["reversibility"], "weight": ixF(v["w"]) / tot, "dims": dims})
	}
	return map[string]any{"v": 1.0, "approximate": ixMkCopyList(j["approximate"]), "verbs": verbs}
}

// IntentGrantDigest is the content address of a synthesized grant.
func IntentGrantDigest(g map[string]any) (string, error) {
	r, err := ixTry(func() any { return ixMkGrantDigest(g) })
	if err != nil {
		return "", err
	}
	return r.(string), nil
}

func ixMkGrantDigest(g map[string]any) string {
	inner := map[string]any{}
	if g["predicates"] != nil {
		inner["predicates"] = g["predicates"]
	}
	if c, ok := g["caveats"]; ok {
		inner["caveats"] = c
	} else {
		inner["caveats"] = []any{}
	}
	return ixHashCanon(map[string]any{"d": "atlas-pca/intent-grant/v1", "g": inner})
}

// IntentMapDigest is the content address of an Intent Map.
func IntentMapDigest(m any) (string, error) {
	r, err := ixTry(func() any { return ixHashCanon(map[string]any{"d": ixMkMapDomain, "m": m}) })
	if err != nil {
		return "", err
	}
	return r.(string), nil
}

func ixMkMetricsOf(l *IntentLearner) map[string]any {
	m := l.Metrics()
	rmax := 0.0
	for _, cv := range l.Cells() {
		c := ixM(cv)
		rmax += float64(ixF(c["mass"]) * (1 - ixF(c["p"])) * ixF(c["harm"]))
	}
	fid := 1.0
	if rmax > 0 {
		fid = 1 - ixF(m["residualRisk"])/rmax
	}
	var vsBits any
	if m["log2VersionSpace"] != nil {
		vsBits = ixMkRound(ixF(m["log2VersionSpace"]) * 1000)
	}
	return map[string]any{
		"residual_risk_ppm": ixMkPpm(ixF(m["residualRisk"])), "burden_ppm": ixMkPpm(ixF(m["burden"])),
		"uncertainty_ppm": ixMkPpm(ixF(m["uncertainty"])), "disagreement_ppm": ixMkPpm(ixF(m["disagreementMass"])),
		"mean_harm_ppm": ixMkPpm(ixF(m["meanHarm"])), "fidelity_est_ppm": ixMkPpm(fid),
		"entropy_mbits": ixMkRound(ixF(m["entropyBits"]) * 1000), "log2_vs_mbits": vsBits,
		"questions": m["questions"], "conflicts": m["conflicts"],
	}
}

// ixMkMetricKeys is the member order of the replayed metrics (the order the reference reports differences in).
var ixMkMetricKeys = []string{"residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm", "fidelity_est_ppm",
	"entropy_mbits", "log2_vs_mbits", "questions", "conflicts"}

func ixMkPriorMixOf(pm map[string]any) (beta float64, weight func(vs map[string]any, has func(int) bool) float64) {
	type term struct {
		cell    float64
		lq, lnq float64
	}
	byVerb := map[string][]term{}
	for _, cv := range ixL(pm["cells"]) {
		c := ixM(cv)
		q := ixMkQz(ixF(c["q"]))
		cell := c["cell"]
		if !(q >= 0 && q <= 1) || !jsIsSafeInteger(cell) || ixF(cell) < 0 {
			ixFail("pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0")
		}
		v := ixS(c["verb"])
		byVerb[v] = append(byVerb[v], term{ixF(cell), DetLn(q), DetLn(1 - q)})
	}
	return ixMkQz(ixF(pm["beta"])), func(vs map[string]any, has func(int) bool) float64 {
		lw := 0.0
		for _, t := range byVerb[ixS(vs["verb"])] {
			in := t.cell < float64(1<<31) && has(int(t.cell))
			if in {
				lw += t.lq
			} else {
				lw += t.lnq
			}
		}
		return DetExp(lw)
	}
}

func ixMkAnchorOpt(a map[string]any) map[string]any {
	p := ixM(a["policy"])
	return map[string]any{"policy": map[string]any{"predicates": p["predicates"], "caveats": ixLrOpt(p, "caveats", []any{})},
		"lambda": ixMkRound(ixF(a["lambda"])*1000) / 1000}
}

func ixMkAnchorJSON(a map[string]any) map[string]any {
	p := ixM(a["policy"])
	return map[string]any{"policy": map[string]any{"predicates": p["predicates"], "caveats": ixLrOpt(p, "caveats", []any{})},
		"lambda_milli": ixMkRound(ixF(a["lambda"]) * 1000)}
}

func ixMkQuantizeClass(h map[string]any) map[string]any {
	if len(h) == 0 || h["kind"] == "box" {
		return map[string]any{"kind": "box"}
	}
	decay := ixMkQz(ixLrOptF(h, "decay", 0.25))
	if h["kind"] == "union" {
		return map[string]any{"kind": "union", "k": h["k"], "decay": decay}
	}
	return map[string]any{"kind": "decision-list", "maxRules": h["maxRules"], "decay": decay, "conditions": ixLrOpt(h, "conditions", "box")}
}

func ixMkNullMassOf(o map[string]any, verb string) float64 {
	if f, ok := o["nullMass"].(float64); ok {
		return f
	}
	if nm, ok := o["nullMass"].(map[string]any); ok {
		if v, ok := nm[verb]; ok && v != nil {
			return ixF(v)
		}
	}
	return ixLrOptF(o, "defaultNullMass", 0.2)
}

// IntentCreateLearner builds a learner whose parameters are exactly representable in an Intent Map (ppm-quantised).
func IntentCreateLearner(omega, o map[string]any) (*IntentLearner, error) {
	r, err := ixTry(func() any { return ixMkCreateLearner(omega, o) })
	if err != nil {
		return nil, err
	}
	return r.(*IntentLearner), nil
}

func ixMkCreateLearner(omega, o map[string]any) *IntentLearner {
	if o == nil {
		o = map[string]any{}
	}
	eta0 := ixLrOptF(o, "eta", 0)
	defTau := 0.95
	if eta0 == 0 {
		defTau = 1
	}
	opts := map[string]any{
		"eta":             ixMkQz(eta0),
		"tau":             ixMkQz(ixLrOptF(o, "tau", defTau)),
		"strategy":        ixLrOpt(o, "strategy", "disagreement"),
		"hypothesisClass": ixMkQuantizeClass(ixM(o["hypothesisClass"])),
	}
	hooks := &IntentLearnerHooks{NullMass: func(vs map[string]any) float64 { return ixMkQz(ixMkNullMassOf(o, ixS(vs["verb"]))) }}
	if v, ok := o["agnosticSlack"]; ok {
		opts["agnosticSlack"] = v
	}
	if a := ixM(o["anchor"]); a != nil {
		opts["anchor"] = ixMkAnchorOpt(a)
	}
	if as := ixL(o["anchors"]); len(as) > 0 {
		list := []any{}
		for _, a := range as {
			list = append(list, ixMkAnchorOpt(ixM(a)))
		}
		opts["anchors"] = list
	}
	if mo := ixM(o["monotone"]); mo != nil {
		opts["monotone"] = map[string]any{"paths": ixMkCopyList(mo["paths"]), "offMass": ixMkQz(ixLrOptF(mo, "offMass", 0))}
	}
	if v, ok := o["etaPos"]; ok {
		opts["etaPos"] = ixMkQz(ixF(v))
	}
	if v, ok := o["etaNeg"]; ok {
		opts["etaNeg"] = ixMkQz(ixF(v))
	}
	if pm := ixM(o["priorMix"]); pm != nil {
		beta, w := ixMkPriorMixOf(pm)
		opts["priorMix"] = map[string]any{"beta": beta}
		hooks.PriorMixWeight = w
	}
	l := ixNewLearner(omega, opts, hooks)
	l.mapParams = o
	return l
}

func ixMkLearnerOptionsOf(l *IntentLearner) map[string]any {
	if l.mapParams == nil {
		ixFail("pca-intent: build the learner with createLearner() so its parameters are serialisable")
	}
	return l.mapParams
}

// IntentEmitMap is the Intent Map of a learner built with IntentCreateLearner; intentRef is a string or nil.
func IntentEmitMap(l *IntentLearner, intentRef any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixMkEmit(l, intentRef) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMkEmit(l *IntentLearner, intentRef any) map[string]any {
	o := ixMkLearnerOptionsOf(l)
	nullMassPpm := map[string]any{}
	for _, vv := range ixL(l.omega["verbs"]) {
		vs := ixM(vv)
		nullMassPpm[ixS(vs["verb"])] = ixMkPpm(ixMkNullMassOf(o, ixS(vs["verb"])))
	}
	grant := l.Synthesize()
	hc := l.hc
	learner := map[string]any{"hypothesis_class": IntentHypothesisClassName(hc)}
	if hc["kind"] == "union" {
		learner["class_params"] = map[string]any{"k": hc["k"], "decay_ppm": ixMkPpm(ixLrOptF(hc, "decay", 0.25))}
	}
	if hc["kind"] == "decision-list" {
		learner["class_params"] = map[string]any{"max_rules": hc["maxRules"], "decay_ppm": ixMkPpm(ixLrOptF(hc, "decay", 0.25))}
	}
	if l.hasAgnostic {
		learner["agnostic_slack"] = l.agnostic
	}
	learner["eta_ppm"] = ixMkPpm(l.eta)
	learner["tau_ppm"] = ixMkPpm(l.tau)
	learner["strategy"] = l.strategy
	learner["null_mass_ppm"] = nullMassPpm
	if a := ixM(o["anchor"]); a != nil {
		learner["anchor"] = ixMkAnchorJSON(a)
	}
	if as := ixL(o["anchors"]); len(as) > 0 {
		list := []any{}
		for _, a := range as {
			list = append(list, ixMkAnchorJSON(ixM(a)))
		}
		learner["anchors"] = list
	}
	if mo := ixM(o["monotone"]); mo != nil {
		learner["monotone"] = map[string]any{"paths": ixMkCopyList(mo["paths"]), "off_ppm": ixMkPpm(ixLrOptF(mo, "offMass", 0))}
	}
	if ixHas(o, "etaPos") || ixHas(o, "etaNeg") {
		learner["noise"] = map[string]any{"eta_pos_ppm": ixMkPpm(l.etaPos), "eta_neg_ppm": ixMkPpm(l.etaNeg)}
	}
	if pm := ixM(o["priorMix"]); pm != nil {
		cells := []any{}
		for _, cv := range ixL(pm["cells"]) {
			c := ixM(cv)
			cells = append(cells, map[string]any{"verb": c["verb"], "cell": c["cell"], "q_ppm": ixMkPpm(ixF(c["q"]))})
		}
		learner["prior_mix"] = map[string]any{"beta_ppm": ixMkPpm(ixF(pm["beta"])), "cells": cells}
	}
	observations := []any{}
	for _, x := range l.observations {
		ob := map[string]any{"verb": x["verb"], "values": ixCopyMap(ixM(x["values"])), "y": x["y"], "source": x["source"]}
		if x["region"] != nil {
			ob["region"] = x["region"]
		}
		observations = append(observations, ob)
	}
	cells := []any{}
	for _, cv := range l.Cells() {
		c := ixM(cv)
		cells = append(cells, map[string]any{"verb": c["verb"], "cell": c["cell"], "p_ppm": ixMkPpm(ixF(c["p"])), "in_grant": c["inGrant"]})
	}
	principals := []any{}
	if s, ok := intentRef.(string); ok && s != "" {
		principals = append(principals, s)
	}
	return map[string]any{"v": 1.0, "kind": "pca-intent-map", "intent_ref": intentRef, "principals": principals,
		"omega": ixMkOmegaToJSON(l.omega), "learner": learner, "observations": observations, "cells": cells, "grant": grant,
		"grant_digest": ixMkGrantDigest(grant), "metrics": ixMkMetricsOf(l)}
}

// IntentMapLearnerOptions are the learner parameters a map records (the inverse of what IntentEmitMap writes).
func IntentMapLearnerOptions(m map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixMkMapLearnerOptions(m) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMkReq(m map[string]any, k string) any {
	v, ok := m[k]
	if !ok {
		ixFail("KeyError: %s", k)
	}
	return v
}

func ixMkMapLearnerOptions(m map[string]any) map[string]any {
	lr := ixM(ixMkReq(m, "learner"))
	nullMass := map[string]any{}
	for k, v := range ixM(ixMkReq(lr, "null_mass_ppm")) {
		nullMass[k] = ixF(v) / ixPPM
	}
	cp := ixM(lr["class_params"])
	hcn := ixMkReq(lr, "hypothesis_class")
	var hc map[string]any
	switch hcn {
	case "per-verb-union/v1":
		hc = map[string]any{"kind": "union", "k": ixLrOpt(cp, "k", 2.0), "decay": ixLrOptF(cp, "decay_ppm", 250000) / ixPPM}
	case "per-verb-decision-list/v1", "per-verb-decision-list/v2":
		cond := "box"
		if hcn == "per-verb-decision-list/v1" {
			cond = "atomic"
		}
		hc = map[string]any{"kind": "decision-list", "maxRules": ixLrOpt(cp, "max_rules", 2.0), "decay": ixLrOptF(cp, "decay_ppm", 250000) / ixPPM, "conditions": cond}
	default:
		hc = map[string]any{"kind": "box"}
	}
	out := map[string]any{"eta": ixF(ixMkReq(lr, "eta_ppm")) / ixPPM, "tau": ixF(ixMkReq(lr, "tau_ppm")) / ixPPM,
		"strategy": ixMkReq(lr, "strategy"), "nullMass": nullMass, "hypothesisClass": hc}
	if lr["agnostic_slack"] != nil {
		out["agnosticSlack"] = lr["agnostic_slack"]
	}
	if a := ixM(lr["anchor"]); a != nil {
		out["anchor"] = map[string]any{"policy": a["policy"], "lambda": ixF(a["lambda_milli"]) / 1000}
	}
	if as := ixL(lr["anchors"]); len(as) > 0 {
		list := []any{}
		for _, av := range as {
			a := ixM(av)
			list = append(list, map[string]any{"policy": a["policy"], "lambda": ixF(a["lambda_milli"]) / 1000})
		}
		out["anchors"] = list
	}
	if mo := ixM(lr["monotone"]); mo != nil {
		out["monotone"] = map[string]any{"paths": ixMkCopyList(mo["paths"]), "offMass": ixF(mo["off_ppm"]) / ixPPM}
	}
	if no := ixM(lr["noise"]); no != nil {
		out["etaPos"] = ixF(no["eta_pos_ppm"]) / ixPPM
		out["etaNeg"] = ixF(no["eta_neg_ppm"]) / ixPPM
	}
	if pm := ixM(lr["prior_mix"]); pm != nil {
		cells := []any{}
		for _, cv := range ixL(pm["cells"]) {
			c := ixM(cv)
			cells = append(cells, map[string]any{"verb": c["verb"], "cell": c["cell"], "q": ixF(c["q_ppm"]) / ixPPM})
		}
		out["priorMix"] = map[string]any{"beta": ixF(pm["beta_ppm"]) / ixPPM, "cells": cells}
	}
	return out
}

func ixMkLearnerFromMap(m map[string]any) *IntentLearner {
	l := ixMkCreateLearner(ixMkOmegaFromJSON(ixM(ixMkReq(m, "omega"))), ixMkMapLearnerOptions(m))
	for _, ov := range ixL(ixMkReq(m, "observations")) {
		o := ixM(ov)
		l.observe(map[string]any{"verb": o["verb"], "values": o["values"]}, ixF(o["y"]), ixS(o["source"]), ixM(o["region"]))
	}
	return l
}

// IntentLearnerFromMap rebuilds the learner a map describes (omega + prior + observations).
func IntentLearnerFromMap(m map[string]any) (*IntentLearner, error) {
	r, err := ixTry(func() any { return ixMkLearnerFromMap(m) })
	if err != nil {
		return nil, err
	}
	return r.(*IntentLearner), nil
}

// ixMkDiffers2 is the mismatch of a replayed number and a claimed one, written as the negation of the positive condition: a claim
// that is missing, not a number or NaN is a mismatch (the comparison `|a-b| > 2` is false for NaN and let such a map verify).
func ixMkDiffers2(a, b any) bool {
	x, ok1 := a.(float64)
	y, ok2 := b.(float64)
	return !(ok1 && ok2 && math.Abs(x-y) <= 2)
}

// IntentVerifyMap replays a single-principal map and checks every number, every cell and the grant: {ok, problems}.
func IntentVerifyMap(mv any) map[string]any {
	problems := []any{}
	done := func() map[string]any { return map[string]any{"ok": len(problems) == 0, "problems": problems} }
	m, isMap := mv.(map[string]any)
	if !isMap || m["v"] != 1.0 || m["kind"] != "pca-intent-map" {
		return map[string]any{"ok": false, "problems": []any{"not an intent map v1"}}
	}
	_, err := ixTry(func() any {
		if len(ixL(ixMkReq(m, "principals"))) > 1 || m["aggregation"] != nil {
			problems = []any{"combined map: verify each principal map and recombine with verifyAggregate"}
			return nil
		}
		r := ixMkEmit(ixMkLearnerFromMap(m), ixMkReq(m, "intent_ref"))
		if r["grant_digest"] != ixMkReq(m, "grant_digest") || ixMkGrantDigest(ixM(ixMkReq(m, "grant"))) != ixMkReq(m, "grant_digest") {
			problems = append(problems, "grant does not match the replayed posterior")
		}
		rc, mc := ixL(r["cells"]), ixL(ixMkReq(m, "cells"))
		if len(rc) != len(mc) {
			problems = append(problems, "cell count differs")
		} else {
			for i, cv := range rc {
				c := ixM(cv)
				xm, ok := mc[i].(map[string]any)
				if !ok {
					ixFail("cell %d is not an object", i)
				}
				if c["verb"] != xm["verb"] || c["in_grant"] != xm["in_grant"] || ixMkDiffers2(c["p_ppm"], xm["p_ppm"]) {
					problems = append(problems, "cell "+jsNumberString(float64(i))+" differs")
				}
			}
		}
		rm := ixM(r["metrics"])
		mm, mmOK := ixMkReq(m, "metrics").(map[string]any)
		for _, k := range ixMkMetricKeys {
			a := rm[k]
			b, present := mm[k]
			if !mmOK {
				present = false
			}
			var bad bool
			if a == nil || (present && b == nil) {
				bad = !(a == nil && present && b == nil)
			} else {
				bad = ixMkDiffers2(a, b)
			}
			if bad {
				claimed := "undefined"
				if present {
					claimed = jsValueString(b)
				}
				problems = append(problems, "metric "+k+" differs ("+claimed+" claimed, "+jsValueString(a)+" replayed)")
			}
		}
		return nil
	})
	if err != nil {
		problems = append(problems, "replay failed: "+err.Error())
	}
	return done()
}

// IntentApplyDivergence is one more labelled observation; a NEGATIVE one also vetoes the outcome's cell for good.
func IntentApplyDivergence(l *IntentLearner, outcome map[string]any, y float64) (map[string]any, error) {
	r, err := ixTry(func() any {
		count := func() float64 {
			n := 0.0
			for _, cv := range l.Cells() {
				if ixM(cv)["inGrant"] == true {
					n++
				}
			}
			return n
		}
		before := count()
		l.observe(outcome, y, "runtime", nil)
		return map[string]any{"before": before, "after": count(), "grant": l.Synthesize()}
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// ---- committed form (wallet side) ----

// IntentMapCommit is a committed Intent Map: the commitment, the leaves with their salts and the disclosure builder.
type IntentMapCommit struct {
	MapCommit string
	Size      int
	Leaves    []any
	disclose  func(verb string, resource any, params map[string]any) map[string]any
}

// Disclose opens the verb header, the action's cell and the metrics leaf against the commitment.
func (c *IntentMapCommit) Disclose(verb string, resource any, params map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any { return c.disclose(verb, resource, params) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixMkSplit(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func ixMkAuditPath(hs [][]byte, idx int, out *[][]byte) {
	if len(hs) == 1 {
		return
	}
	k := ixMkSplit(len(hs))
	if idx < k {
		ixMkAuditPath(hs[:k], idx, out)
		*out = append(*out, mapTreeRoot(hs[k:]))
	} else {
		ixMkAuditPath(hs[k:], idx-k, out)
		*out = append(*out, mapTreeRoot(hs[:k]))
	}
}

func ixMkLeafSalt(secret []byte, i int) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(i))
	h := sha256.Sum256(append(append([]byte(ixMkTagSalt), secret...), n[:]...))
	return h[:]
}

// IntentCommitMap builds the committed form (rule 19 leaf order) with per-leaf salts from a 32-byte secret.
func IntentCommitMap(headers []any, cells map[string][]any, metrics map[string]any, learnerDigest string, secret []byte) (*IntentMapCommit, error) {
	r, err := ixTry(func() any { return ixMkCommitMap(headers, cells, metrics, learnerDigest, secret) })
	if err != nil {
		return nil, err
	}
	return r.(*IntentMapCommit), nil
}

func ixMkCommitMap(headers []any, cells map[string][]any, metrics map[string]any, learnerDigest string, secret []byte) *IntentMapCommit {
	if len(secret) != 32 {
		ixFail("commit_map: the secret is 32 bytes")
	}
	heads := append([]any{}, headers...)
	sort.SliceStable(heads, func(i, j int) bool { return ixS(ixM(heads[i])["verb"]) < ixS(ixM(heads[j])["verb"]) })
	for i := 1; i < len(heads); i++ {
		if ixM(heads[i])["verb"] == ixM(heads[i-1])["verb"] {
			ixFail("commit_map: duplicate verb")
		}
	}
	nxt := len(heads)
	type full struct {
		verb  string
		first int
		n     int
		hdr   map[string]any
	}
	var fulls []full
	for _, hv := range heads {
		h := ixM(hv)
		n := 1
		for _, d := range ixL(h["dims"]) {
			n *= mapDimCells(ixM(d))
		}
		hdr := map[string]any{"verb": h["verb"], "first": float64(nxt), "cells": float64(n), "dims": h["dims"]}
		fulls = append(fulls, full{ixS(h["verb"]), nxt, n, hdr})
		nxt += n
	}
	type leafT struct {
		kind string
		leaf any
	}
	var leaves []leafT
	for _, f := range fulls {
		leaves = append(leaves, leafT{"header", f.hdr})
	}
	for _, f := range fulls {
		cs := cells[f.verb]
		if cs == nil || len(cs) != f.n {
			ixFail("commit_map: verb %s needs %d cell leaves", f.verb, f.n)
		}
		for _, cv := range cs {
			c := ixM(cv)
			leaves = append(leaves, leafT{"cell", map[string]any{"verb": f.verb, "cell": c["cell"], "p_ppm": c["p_ppm"], "in_grant": c["in_grant"]}})
		}
	}
	leaves = append(leaves, leafT{"metrics", metrics}, leafT{"learner", map[string]any{"learner_digest": learnerDigest}})
	for _, lf := range leaves {
		var e string
		switch lf.kind {
		case "header":
			e = mapHeaderError(lf.leaf)
		case "cell":
			e = mapCellError(lf.leaf)
		case "metrics":
			e = mapMetricsError(lf.leaf)
		default:
			e = mapLearnerError(lf.leaf)
		}
		if e != "" {
			ixFail("commit_map: %s", e)
		}
	}
	size := len(leaves)
	if size < 4 || size > maxMapLeaves {
		ixFail("commit_map: the map has too few or too many leaves")
	}
	salts := make([][]byte, size)
	hashes := make([][]byte, size)
	for i, lf := range leaves {
		salts[i] = ixMkLeafSalt(secret, i)
		h, ok := mapLeafHash(lf.kind, salts[i], ixNums(lf.leaf))
		if !ok {
			ixFail("map_leaf_hash: the leaf has no strict canonical form")
		}
		hashes[i] = h
	}
	root := mapTreeRoot(hashes)
	entry := func(i int) map[string]any {
		var path [][]byte
		ixMkAuditPath(hashes, i, &path)
		ps := make([]any, len(path))
		for k, p := range path {
			ps[k] = b64.EncodeToString(p)
		}
		return map[string]any{"index": float64(i), "salt": b64.EncodeToString(salts[i]), "leaf": leaves[i].leaf, "path": ps}
	}
	out := &IntentMapCommit{MapCommit: mapCommitOf(size, root), Size: size}
	for i, lf := range leaves {
		out.Leaves = append(out.Leaves, map[string]any{"kind": lf.kind, "leaf": lf.leaf, "salt": b64.EncodeToString(salts[i])})
	}
	out.disclose = func(verb string, resource any, params map[string]any) map[string]any {
		hi := -1
		for i, f := range fulls {
			if f.verb == verb {
				hi = i
				break
			}
		}
		if hi < 0 {
			ixFail("commit_map.disclose: verb %s is not in the map", verb)
		}
		_, flat, why := mapCellOf(fulls[hi].hdr, resource, params)
		if why != "" {
			ixFail("commit_map.disclose: %s", why)
		}
		return map[string]any{"size": float64(size), "header": entry(hi), "cell": entry(fulls[hi].first + flat), "metrics": entry(size - 2)}
	}
	return out
}

func ixMkNumCellCount(lo, hi float64, cuts []any) int {
	n := 0
	cur := lo
	for _, cv := range cuts {
		c := ixF(cv)
		if c < lo || c > hi {
			continue
		}
		if cur <= c-1 {
			n++
		}
		n++
		cur = c + 1
	}
	if cur <= hi {
		return n + 1
	}
	return n
}

// IntentCommitIntentMap commits an Intent Map; secret (32 random bytes kept per session) derives every leaf salt.
func IntentCommitIntentMap(m map[string]any, secret []byte) (*IntentMapCommit, error) {
	r, err := ixTry(func() any { return ixMkCommitIntentMap(m, secret) })
	if err != nil {
		return nil, err
	}
	return r.(*IntentMapCommit), nil
}

func ixMkCommitIntentMap(m map[string]any, secret []byte) *IntentMapCommit {
	omega := ixM(ixMkReq(m, "omega"))
	verbs := ixL(ixMkReq(omega, "verbs"))
	headers := []any{}
	for _, vv := range verbs {
		v := ixM(vv)
		dims := []any{}
		for _, dv := range ixL(v["dims"]) {
			d := ixM(dv)
			if d["kind"] == "num" {
				cuts := []any{}
				for _, c := range ixL(d["cuts"]) {
					if ixF(d["lo"]) <= ixF(c) && ixF(c) <= ixF(d["hi"]) {
						cuts = append(cuts, c)
					}
				}
				dims = append(dims, map[string]any{"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"], "cuts": cuts})
			} else {
				vals := []any{}
				for _, x := range ixL(d["values"]) {
					xm := ixM(x)
					vals = append(vals, map[string]any{"kind": xm["kind"], "value": xm["value"]})
				}
				dims = append(dims, map[string]any{"kind": "cat", "path": d["path"], "values": vals})
			}
		}
		headers = append(headers, map[string]any{"verb": v["verb"], "dims": dims})
	}
	cells := map[string][]any{}
	allCells := ixL(ixMkReq(m, "cells"))
	for _, vv := range verbs {
		v := ixM(vv)
		var counts []int
		total := 1
		for _, dv := range ixL(v["dims"]) {
			d := ixM(dv)
			var n int
			if d["kind"] == "num" {
				n = ixMkNumCellCount(ixF(d["lo"]), ixF(d["hi"]), ixL(d["cuts"]))
			} else {
				n = len(ixL(d["values"]))
			}
			counts = append(counts, n)
			total *= n
		}
		slots := make([]any, total)
		for _, cv := range allCells {
			c := ixM(cv)
			if c["verb"] != v["verb"] {
				continue
			}
			cell := ixL(c["cell"])
			if len(cell) != len(counts) {
				ixFail("commitIntentMap: cell of %s has the wrong arity", ixS(v["verb"]))
			}
			flat := 0
			for j, iv := range cell {
				if !(jsIsInt(iv) && ixF(iv) >= 0 && ixF(iv) < float64(counts[j])) {
					ixFail("commitIntentMap: cell index out of range for %s", ixS(v["verb"]))
				}
				flat = flat*counts[j] + int(ixF(iv))
			}
			slots[flat] = map[string]any{"cell": ixMkCopyList(c["cell"]), "p_ppm": c["p_ppm"], "in_grant": c["in_grant"]}
		}
		for _, s := range slots {
			if s == nil {
				ixFail("commitIntentMap: the map does not list every cell of %s", ixS(v["verb"]))
			}
		}
		cells[ixS(v["verb"])] = slots
	}
	metrics := map[string]any{}
	mm := ixM(ixMkReq(m, "metrics"))
	for k, x := range mm {
		if k != "log2_vs_mbits" {
			metrics[k] = x
		}
	}
	if mm["log2_vs_mbits"] != nil {
		metrics["log2_vs_mbits"] = mm["log2_vs_mbits"]
	}
	return ixMkCommitMap(headers, cells, metrics, ixHashCanon(ixMkReq(m, "learner")), secret)
}
