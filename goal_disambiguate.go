package pca

// Questions over the symmetric difference of competing readings and active disambiguation by version-space halving (the
// TypeScript reference is @atlasauth/pca-goal `disambiguate`). A reading is {id, family, deterministic, goal, notes}; the question
// options are GoalDisambOpts. The reference's asynchronous `ask` is a plain function returning "allow" or "deny".

import (
	"sort"
)

// GoalDisambOpts are the question options: the ontology, optional risk and mass weights per action, the question budget (nil =
// the number of readings) and, for N-version interpretation, the disagreement-mass threshold (nil = 0).
type GoalDisambOpts struct {
	Ont           any
	RiskOf        func(act any) float64
	MassOf        func(act any) float64
	Budget        any
	MassThreshold any
}

var goalDefaultRisk = map[string]float64{"read": 1, "reversible": 2, "external_send": 8, "irreversible": 10}

func goalDisambH2(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	// Math.log2 is the fdlibm log2 (ixLog2); the explicit conversions stop a fused multiply-add
	return -(float64(p*ixLog2(p)) + float64((1-p)*ixLog2(1-p)))
}

func goalAllowsWitness(g, ont, w any) bool {
	hist := goalReplay(g, ont, anlGet(w, "prior"), anlGet(w, "rels"))
	return goalDecideCase(g, ont, map[string]any{"act": anlGet(w, "act"), "hist": hist, "rels": anlGet(w, "rels")})["decision"] == "allow"
}

func goalDisambAllowSet(r, w, ont any) bool { return goalAllowsWitness(anlGet(r, "goal"), ont, w) }

// goalDisambWitnesses are the candidate witness actions: decision-cell representatives of the joint space plus every reading's cap
// sequences.
func goalDisambWitnesses(readings []any, ont any) []map[string]any {
	goals := make([]any, len(readings))
	for i, r := range readings {
		goals[i] = anlGet(r, "goal")
	}
	out := []map[string]any{}
	for _, c := range goalCells(goalBuildSpace(goals, nil), nil)["cases"].([]any) {
		out = append(out, map[string]any{"act": anlGet(c, "act"), "prior": []any{}, "rels": anlGet(c, "rels")})
	}
	for _, r := range readings {
		ex := goalBoundaryExamples(anlGet(r, "goal"), GoalExampleOpts{Ont: ont, Extra: goals})["examples"].([]any)
		for _, e := range ex {
			if anlGet(e, "kind") == "cap_sequence" {
				prior := []any{}
				for _, a := range anlReqList(anlGet(anlGet(e, "hist"), "adms")) {
					prior = append(prior, anlGet(a, "act"))
				}
				out = append(out, map[string]any{"act": anlGet(e, "act"), "prior": prior, "rels": anlGet(e, "rels")})
			}
		}
	}
	return out
}

// goalQuestions are the questions ranked by H2(vote) x risk x mass (best first).
func goalQuestions(readingsIn any, opts GoalDisambOpts) []any {
	readings := anlReqList(readingsIn)
	ont := opts.Ont
	k := len(readings)
	cls := map[string]any{}
	for _, v := range anlReqList(anlGet(ont, "verbs")) {
		cls[anlJS(anlGet(v, "verb"))] = anlGet(v, "cls")
	}
	riskOf := opts.RiskOf
	if riskOf == nil {
		riskOf = func(a any) float64 {
			c, ok := cls[anlJS(anlGet(a, "verb"))]
			if !ok {
				c = ""
			}
			if s, isStr := c.(string); isStr {
				if r, ok := goalDefaultRisk[s]; ok {
					return r
				}
			}
			return 10
		}
	}
	type scored struct {
		q     map[string]any
		score float64
		id    string
	}
	out := []scored{}
	seen := map[string]bool{}
	for _, w := range goalDisambWitnesses(readings, ont) {
		yes := []any{}
		for _, r := range readings {
			if goalDisambAllowSet(r, w, ont) {
				yes = append(yes, anlGet(r, "id"))
			}
		}
		if len(yes) == 0 || len(yes) == k {
			continue
		}
		prior := w["prior"].([]any)
		qid := anlJSON([]any{w["act"], goalNum(int64(len(prior)))})
		if seen[qid] {
			continue
		}
		seen[qid] = true
		notAllow := []any{}
		for _, r := range readings {
			if !goalDriftHas(yes, anlGet(r, "id")) {
				notAllow = append(notAllow, anlGet(r, "id"))
			}
		}
		text := "Should this be allowed: " + goalFmtAct(w["act"])
		if len(prior) > 0 {
			text += " (after " + itoa(len(prior)) + " earlier identical action(s))"
		}
		text += "?"
		mass := 1.0
		if opts.MassOf != nil {
			mass = opts.MassOf(w["act"])
		}
		score := goalDisambH2(float64(len(yes))/float64(k)) * riskOf(w["act"]) * mass
		out = append(out, scored{map[string]any{"id": qid, "act": w["act"], "prior": prior, "rels": w["rels"], "allow": yes, "notAllow": notAllow, "text": text, "score": score}, score, qid})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if d := out[j].score - out[i].score; d != 0 {
			return d < 0
		}
		return utf16Less(out[i].id, out[j].id)
	})
	res := make([]any, len(out))
	for i, s := range out {
		res[i] = s.q
	}
	return res
}

// goalDisagreementMass is the fraction of witness cells on which the readings do not all agree on Allow.
func goalDisagreementMass(readingsIn any, ont any) float64 {
	readings := anlReqList(readingsIn)
	w := goalDisambWitnesses(readings, ont)
	if len(w) == 0 {
		return 0
	}
	split := 0
	for _, x := range w {
		n := 0
		for _, r := range readings {
			if goalDisambAllowSet(r, x, ont) {
				n++
			}
		}
		if n > 0 && n < len(readings) {
			split++
		}
	}
	return float64(split) / float64(len(w))
}

// goalDisambiguate is active disambiguation by version-space halving over the finite class of readings: every question strictly
// shrinks the class, so at most k-1 questions. Realizability (assumption): the principal's intent is one of the readings.
func goalDisambiguate(readingsIn any, ask func(q any) string, opts GoalDisambOpts) map[string]any {
	readings := anlReqList(readingsIn)
	ont := opts.Ont
	budget := float64(len(readings))
	if opts.Budget != nil {
		budget = goalExNum(opts.Budget)
	}
	active := append([]any{}, readings...)
	asked := []any{}
	for len(active) > 1 && float64(len(asked)) < budget {
		qs := goalQuestions(active, opts)
		if len(qs) == 0 {
			break // the survivors agree on every witness cell
		}
		q := qs[0]
		asked = append(asked, q)
		ans := ask(q)
		next := []any{}
		for _, r := range active {
			if goalDisambAllowSet(r, q, ont) == (ans == "allow") {
				next = append(next, r)
			}
		}
		active = next
	}
	mass := goalDisagreementMass(active, ont)
	goals := make([]any, len(active))
	remaining := make([]any, len(active))
	for i, r := range active {
		goals[i] = anlGet(r, "goal")
		remaining[i] = anlGet(r, "id")
	}
	g := goalMeet(goals)
	if mass > 0 {
		hole := map[string]any{"hid": "budget", "q": "Question budget exhausted with disagreement left.", "domain": []any{}, "affects": []any{}, "global": true}
		holes := append(append([]any{}, anlReqList(anlGet(g, "holes"))...), hole)
		sort.SliceStable(holes, func(i, j int) bool {
			return utf16Less(anlStr(anlGet(holes[i], "hid"), "hid"), anlStr(anlGet(holes[j], "hid"), "hid"))
		})
		g2 := anlSpread(g)
		g2["holes"] = holes
		return map[string]any{"status": "budget_exhausted", "goal": g2, "asked": asked, "residualMass": mass, "remaining": remaining}
	}
	return map[string]any{"status": "resolved", "goal": g, "asked": asked, "residualMass": goalNum(0), "remaining": remaining}
}

// GoalQuestions are the witness questions that split the readings, ranked best first.
func GoalQuestions(readings any, opts GoalDisambOpts) (r []any, err error) {
	_, err = anlTry(func() any { r = goalQuestions(readings, opts); return nil })
	return
}

// GoalDisagreementMass is the fraction of witness cells on which the readings do not all agree on Allow.
func GoalDisagreementMass(readings, ont any) (r float64, err error) {
	_, err = anlTry(func() any { r = goalDisagreementMass(readings, ont); return nil })
	return
}

// GoalAllowsWitness reports whether the goal allows the witness action after its prior actions.
func GoalAllowsWitness(g, ont, w any) (r bool, err error) {
	_, err = anlTry(func() any { r = goalAllowsWitness(g, ont, w); return nil })
	return
}

// GoalDisambiguate asks the principal (ask answers "allow" or "deny") until the readings are resolved or the budget is spent.
func GoalDisambiguate(readings any, ask func(q any) string, opts GoalDisambOpts) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalDisambiguate(readings, ask, opts); return nil })
	return
}
