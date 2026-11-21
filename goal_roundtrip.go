package pca

// Round-trip checks (the TypeScript reference is @atlasauth/pca-goal `roundtrip`): the lossless card tape, semantic widening
// mutations and the explainer + comparator detector, measured by mutation and tighten-only (it can only escalate). An explainer
// turns the card lines into prose; a comparator judges whether that prose is equivalent to the principal's text.

import (
	"regexp"
	"strconv"
	"strings"
)

// GoalExplainer is the explainer: it sees ONLY the compiled card lines, never the goal text or the model's reasoning.
type GoalExplainer interface {
	Explain(lines []string) (string, error)
}

// GoalComparator judges whether an explanation is equivalent to the principal's text: {equivalent: bool, reason?: string}.
type GoalComparator interface {
	Equivalent(goalText, explanation string) (map[string]any, error)
}

var goalMutationKinds = []string{"widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant"}

// goalCardRoundTrips: decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape.
func goalCardRoundTrips(g any) bool {
	return goalStable(goalDecodeGoal(goalEncodeGoal(g))) == goalStable(g)
}

// goalRoundTrip is "ok" or "escalate"; any failure of the explainer or the comparator escalates.
func goalRoundTrip(goal any, goalText string, ex GoalExplainer, cm GoalComparator) string {
	r, err := anlTry(func() any {
		lines := []string{}
		for _, l := range anlReqList(goalRenderCard(goal)["lines"]) {
			lines = append(lines, anlStr(l, "line"))
		}
		e, err := ex.Explain(lines)
		if err != nil {
			return "escalate"
		}
		v, err := cm.Equivalent(goalText, e)
		if err != nil {
			return "escalate"
		}
		if anlTruthy(anlGet(v, "equivalent")) {
			return "ok"
		}
		return "escalate"
	})
	if err != nil {
		return "escalate"
	}
	return r.(string)
}

type goalDetExplainer struct{}

func (goalDetExplainer) Explain(p []string) (string, error) { return strings.Join(p, "\n"), nil }

// GoalDeterministicExplainer is the explainer that returns the card lines unchanged.
var GoalDeterministicExplainer GoalExplainer = goalDetExplainer{}

var goalMinorRe = regexp.MustCompile(`(\d+) ([A-Z]{3}) minor units`)

type goalLexical struct{ o any }

func goalRtIDs(x any) string {
	seen := []any{}
	for _, i := range anlReqList(x) {
		if !goalDriftHas(seen, i) {
			seen = append(seen, i)
		}
	}
	strs := make([]string, len(seen))
	for i, s := range seen {
		strs[i] = anlStr(s, "id")
	}
	return strings.Join(goalSortU16(strs), ",")
}

func (l goalLexical) Equivalent(text, explanation string) (res map[string]any, err error) {
	_, err = anlTry(func() any {
		a, b := goalExtractCandidates(text, l.o, nil), goalExtractCandidates(explanation, l.o, nil)
		type amt struct{ ccy, minor string }
		bAmounts := []amt{}
		for _, m := range goalMinorRe.FindAllStringSubmatch(explanation, -1) {
			f, _ := strconv.ParseFloat(m[1], 64) // Number(): huge values are doubles
			bAmounts = append(bAmounts, amt{m[2], anlJS(f)})
		}
		if goalRtIDs(anlGet(a, "ids")) != goalRtIDs(anlGet(b, "ids")) {
			res = map[string]any{"equivalent": false, "reason": "ids differ"}
			return nil
		}
		// every amount stated in the policy must be one the principal wrote (the principal may write extras only as decoys)
		wrote := map[string]bool{}
		aAmounts := anlReqList(anlGet(a, "amounts"))
		for _, m := range aAmounts {
			wrote[anlJS(anlGet(m, "ccy"))+anlJS(anlGet(m, "minor"))] = true
		}
		for _, m := range bAmounts {
			if !wrote[m.ccy+m.minor] {
				res = map[string]any{"equivalent": false, "reason": "amount " + m.ccy + " " + m.minor + " not stated by the principal"}
				return nil
			}
		}
		if len(aAmounts) > 0 && len(bAmounts) == 0 {
			res = map[string]any{"equivalent": false, "reason": "no amount in the policy"}
			return nil
		}
		res = map[string]any{"equivalent": true}
		return nil
	})
	return
}

// GoalLexicalComparator is the offline reference comparator: the card lines judged lexically (ids, amounts) against an ontology.
func GoalLexicalComparator(o any) GoalComparator { return goalLexical{o} }

func goalRtScale(x any, f float64) any {
	k := anlGet(anlGet(x, "u"), "k")
	if k == "money" || k == "count" {
		return anlSet2(x, "n", jsNumber(goalExNum(anlGet(x, "n"))*f))
	}
	return x
}

func goalRtMapLits(c any, f func(any) any) any {
	switch anlGet(c, "k") {
	case "cmp":
		r := anlGet(c, "r")
		op := anlGet(c, "op")
		if anlGet(r, "k") == "lit" && anlGet(anlGet(r, "v"), "k") == "q" && (op == "lte" || op == "lt") {
			r = map[string]any{"k": "lit", "v": map[string]any{"k": "q", "q": f(anlGet(anlGet(r, "v"), "q"))}}
		}
		return anlSet2(c, "r", r)
	case "and", "or":
		a, b := goalRtMapLits(anlGet(c, "a"), f), goalRtMapLits(anlGet(c, "b"), f)
		return anlSet2(anlSet2(c, "a", a), "b", b)
	}
	return c
}

// goalMutateGoal applies a semantic mutation that WIDENS the policy (or leaves it equal); nil when the goal has nothing to mutate.
func goalMutateGoal(g any, kind string, ontology any) map[string]any {
	x, ok := goalDeepCopy(g).(map[string]any)
	if !ok {
		anlFail("goal is not an object")
	}
	scale10 := func(z any) any { return goalRtScale(z, 10) }
	switch kind {
	case "widen_cap":
		bounds := anlReqList(anlGet(x, "bounds"))
		if len(bounds) == 0 {
			return nil
		}
		b0 := bounds[0].(map[string]any)
		b0["cap"] = goalRtScale(anlGet(b0, "cap"), 10)
		return x
	case "widen_where":
		for _, y := range anlReqList(anlGet(x, "grants")) {
			if anlJSON(goalRtMapLits(anlGet(y, "cond"), scale10)) != anlJSON(anlGet(y, "cond")) {
				y.(map[string]any)["cond"] = goalRtMapLits(anlGet(y, "cond"), scale10)
				return x
			}
		}
		return nil
	case "drop_prohibit", "drop_bound":
		field := "prohibits"
		if kind == "drop_bound" {
			field = "bounds"
		}
		l := anlReqList(anlGet(x, field))
		if len(l) == 0 {
			return nil
		}
		x[field] = l[:len(l)-1]
		return x
	case "swap_resource":
		for _, y := range anlReqList(anlGet(x, "grants")) {
			if anlGet(anlGet(y, "res"), "k") == "exact" {
				y.(map[string]any)["res"] = map[string]any{"k": "exact", "id": anlStr(anlGet(anlGet(y, "res"), "id"), "id") + "9"}
				return x
			}
		}
		return nil
	case "add_grant":
		have := []any{}
		for _, y := range anlReqList(anlGet(x, "grants")) {
			have = append(have, anlGet(y, "verb"))
		}
		for _, v := range anlReqList(anlGet(ontology, "verbs")) {
			if anlGet(v, "effect") == "read" || goalDriftHas(have, anlGet(v, "id")) {
				continue
			}
			prohibited := false
			for _, p := range anlReqList(anlGet(x, "prohibits")) {
				if anlGet(anlGet(p, "target"), "k") == "verb" && anlStrictEq(anlGet(anlGet(p, "target"), "verb"), anlGet(v, "id")) {
					prohibited = true
					break
				}
			}
			if prohibited {
				continue
			}
			x["grants"] = append(append([]any{}, anlReqList(anlGet(x, "grants"))...),
				map[string]any{"gid": "injected", "verb": anlGet(v, "id"), "res": map[string]any{"k": "any", "reason": "injected"}, "cond": map[string]any{"k": "true"}})
			x["wildcardAck"] = append(append([]any{}, anlReqList(anlGet(x, "wildcardAck"))...), "injected")
			return goalCanonicalizeGoal(x)
		}
		return nil
	}
	return nil
}

// goalMeasureDetection is the fraction of semantic widenings the explainer + comparator pair flags (they can only escalate; this is a
// measured detector). Each case is {goal, text}.
func goalMeasureDetection(cases any, ontology any, ex GoalExplainer, cm GoalComparator) []any {
	out := []any{}
	cs := anlReqList(cases)
	for _, kind := range goalMutationKinds {
		applied, detected := 0, 0
		for _, c := range cs {
			m := goalMutateGoal(anlGet(c, "goal"), kind, ontology)
			if m == nil {
				continue
			}
			applied++
			if goalRoundTrip(m, anlStr(anlGet(c, "text"), "text"), ex, cm) == "escalate" {
				detected++
			}
		}
		rate := 0.0
		if applied > 0 {
			rate = float64(detected) / float64(applied)
		}
		out = append(out, map[string]any{"kind": kind, "applied": goalNum(int64(applied)), "detected": goalNum(int64(detected)), "rate": rate})
	}
	return out
}

// GoalCardRoundTrips reports whether the goal survives the card tape unchanged.
func GoalCardRoundTrips(g any) (r bool, err error) {
	_, err = anlTry(func() any { r = goalCardRoundTrips(g); return nil })
	return
}

// GoalRoundTrip is "ok" or "escalate": the explainer sees only the card lines, the comparator judges them against the text.
func GoalRoundTrip(goal any, goalText string, ex GoalExplainer, cm GoalComparator) string {
	return goalRoundTrip(goal, goalText, ex, cm)
}

// GoalMutateGoal applies a widening mutation (one of widen_cap, widen_where, drop_prohibit, drop_bound, swap_resource, add_grant).
func GoalMutateGoal(g any, kind string, ontology any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalMutateGoal(g, kind, ontology); return nil })
	return
}

// GoalMeasureDetection measures, per mutation kind, how many widenings the explainer + comparator pair flags.
func GoalMeasureDetection(cases, ontology any, ex GoalExplainer, cm GoalComparator) (r []any, err error) {
	_, err = anlTry(func() any { r = goalMeasureDetection(cases, ontology, ex, cm); return nil })
	return
}
