package pca

// The semantic judge panel and the intent-conformance attestation (IC-Att): signed judge verdicts, split-conformal calibration, the
// k-of-n threshold over trusted judges, and the attestation a relying party re-verifies from the verdicts it names.

import (
	"math"
	"sort"
)

const ixSemanticJudgeDomain = "atlas-pca/semantic-judge/v1\x00"

const ixScoreScale = 1000000.0

// IntentQuantizeScore is a judge score on the integer ppm grid (a non-finite score is 0).
func IntentQuantizeScore(score float64) float64 {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0
	}
	q := ixMkRound(score*ixScoreScale) + 0
	if q < 0 {
		return 0
	}
	if q > ixScoreScale {
		return ixScoreScale
	}
	return q
}

func ixAtJudgeMessage(v map[string]any) ([]byte, bool) {
	base := map[string]any{"v": 1.0, "actionDigest": v["actionDigest"], "goalCommitment": v["goalCommitment"], "faithful": v["faithful"] == true,
		"score_ppm": IntentQuantizeScore(ixF(v["score"])), "judgeMeasurement": jsValueString(ixLrOpt(v, "judgeMeasurement", ""))}
	alg, algP := v["alg"]
	pqPk, pqP := v["pq_pk"]
	st, ok := bindSuiteFields(base, alg, algP, pqPk, pqP)
	if !ok {
		return nil, false
	}
	b, ok := ixStrictCanon(st)
	if !ok {
		return nil, false
	}
	return append([]byte(ixSemanticJudgeDomain), b...), true
}

// IntentVerifyJudgeVerdict verifies one signed verdict against the action and goal it must be bound to; a PQ-suite verdict needs its key
// pinned (pins: {pqPins}).
func IntentVerifyJudgeVerdict(vv any, expected, pins map[string]any) bool {
	v, ok := vv.(map[string]any)
	if !ok {
		return false
	}
	if !ixIsB32(v["judge"]) {
		return false
	}
	ad, ok1 := v["actionDigest"].(string)
	gc, ok2 := v["goalCommitment"].(string)
	if !ok1 || !ok2 || ad != expected["actionDigest"] || gc != expected["goalCommitment"] {
		return false
	}
	if _, ok := v["faithful"].(bool); !ok {
		return false
	}
	if sc, ok := v["score"].(float64); !ok || math.IsNaN(sc) || math.IsInf(sc, 0) || sc < 0 || sc > 1 {
		return false
	}
	if _, ok := v["judgeMeasurement"].(string); !ok {
		return false
	}
	if _, ok := v["sig"].(string); !ok {
		return false
	}
	alg, algP := v["alg"]
	if !suiteSupported(alg, algP) {
		return false
	}
	msg, ok := ixAtJudgeMessage(v)
	if !ok {
		return false
	}
	return verifyPinnedSuite(alg, algP, ixS(v["judge"]), v["pq_pk"], msg, v["sig"], v["pq_sig"], ixPqPins(pins))
}

func ixAtScores(samples any) []float64 {
	var out []float64
	for _, sv := range ixL(samples) {
		s := ixM(sv)
		if f, ok := s["score"].(float64); s != nil && s["faithful"] == false && ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
			out = append(out, f)
		}
	}
	return out
}

// IntentConformalThreshold is the split-conformal cutoff over the unfaithful calibration scores (+Inf: not enough negatives).
func IntentConformalThreshold(calibration any) float64 {
	cal := ixM(calibration)
	alpha := 1.0
	if a, ok := cal["alpha"].(float64); ok && !math.IsNaN(a) && !math.IsInf(a, 0) {
		switch {
		case a <= 0:
			alpha = math.SmallestNonzeroFloat64
		case a > 1:
			alpha = 1
		default:
			alpha = a
		}
	}
	unf := ixAtScores(cal["samples"])
	m := len(unf)
	if m == 0 {
		return math.Inf(1)
	}
	rank := math.Ceil(float64(m+1) * (1 - alpha))
	if rank > float64(m) {
		return math.Inf(1)
	}
	sort.Float64s(unf)
	return unf[int(math.Max(rank, 1))-1]
}

// IntentEmpiricalFalseAllowRate is the share of unfaithful calibration scores above the cutoff.
func IntentEmpiricalFalseAllowRate(samples any, cutoff float64) float64 {
	unf := ixAtScores(samples)
	if len(unf) == 0 {
		return 0
	}
	allowed := 0
	for _, s := range unf {
		if s > cutoff {
			allowed++
		}
	}
	return float64(allowed) / float64(len(unf))
}

// IntentVerifySemanticThreshold is the k-of-n check over trusted judges. opts: judgeKeys, k, goalCommitment, actionDigest,
// calibration?, pqPins?. The attested-judge gate is not part of this port.
func IntentVerifySemanticThreshold(verdicts any, opts map[string]any) map[string]any {
	fail := func(reason string, agree int) map[string]any {
		return map[string]any{"ok": false, "agreeCount": float64(agree), "aggregateScore": 0.0, "reason": reason}
	}
	allow := map[string]bool{}
	for _, k := range ixL(opts["judgeKeys"]) {
		if ixIsB32(k) {
			allow[ixS(k)] = true
		}
	}
	ad, ok1 := opts["actionDigest"].(string)
	gc, ok2 := opts["goalCommitment"].(string)
	if !ok1 || !ok2 {
		return fail("missing action/goal binding", 0)
	}
	kv, hasK := opts["k"]
	k, isNum := kv.(float64)
	if !isNum || k != math.Trunc(k) || math.IsInf(k, 0) || k < 1 {
		ks := "undefined"
		if hasK {
			ks = jsValueString(kv)
		}
		return fail("invalid quorum k="+ks, 0)
	}
	type group struct {
		faithful map[bool]bool
		scoreQ   []float64
	}
	byJudge := map[string]*group{}
	var judges []string
	exp := map[string]any{"actionDigest": ad, "goalCommitment": gc}
	for _, vv := range ixL(verdicts) {
		v := ixM(vv)
		judge, ok := v["judge"].(string)
		if !ok || !allow[judge] || !IntentVerifyJudgeVerdict(v, exp, opts) {
			continue
		}
		g := byJudge[judge]
		if g == nil {
			g = &group{faithful: map[bool]bool{}}
			byJudge[judge] = g
			judges = append(judges, judge)
		}
		g.faithful[v["faithful"] == true] = true
		q := IntentQuantizeScore(ixF(v["score"]))
		seen := false
		for _, x := range g.scoreQ {
			if x == q {
				seen = true
			}
		}
		if !seen {
			g.scoreQ = append(g.scoreQ, q)
		}
	}
	type agree struct {
		judge  string
		scoreQ float64
	}
	var agreeing []agree
	for _, j := range judges {
		g := byJudge[j]
		if len(g.faithful) == 1 && g.faithful[true] && len(g.scoreQ) == 1 {
			agreeing = append(agreeing, agree{j, g.scoreQ[0]})
		}
	}
	sort.SliceStable(agreeing, func(i, j int) bool { return compareUtf8(agreeing[i].judge, agreeing[j].judge) < 0 })
	n := len(agreeing)
	score := 0.0
	if n > 0 {
		sum := 0.0
		for _, a := range agreeing {
			sum += a.scoreQ / ixScoreScale
		}
		score = sum / float64(n)
	}
	if float64(n) < k {
		return map[string]any{"ok": false, "agreeCount": float64(n), "aggregateScore": score,
			"reason": "only " + jsNumberString(float64(n)) + " distinct trusted judge(s) agree, need " + jsNumberString(k)}
	}
	if ixTruthy(opts["calibration"]) {
		cutoff := IntentConformalThreshold(opts["calibration"])
		if !(score > cutoff) {
			return map[string]any{"ok": false, "agreeCount": float64(n), "aggregateScore": score, "cutoff": cutoff,
				"reason": "aggregateScore " + jsNumberString(score) + " does not exceed calibrated cutoff " + jsNumberString(cutoff)}
		}
		return map[string]any{"ok": true, "agreeCount": float64(n), "aggregateScore": score, "cutoff": cutoff}
	}
	return map[string]any{"ok": true, "agreeCount": float64(n), "aggregateScore": score}
}

func ixAtToPpm(x float64) any {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return nil
	}
	return math.Floor(float64(x*1000000) + 0.5)
}

// IntentConformanceAttestation verifies a panel's verdicts for one action and produces the IC-Att. input is the judge input
// (intentRef, mapDigest, actionDigest, goalCommitment); opts: judgeKeys, k, calibration?.
func IntentConformanceAttestation(input map[string]any, verdicts []any, opts map[string]any) (att map[string]any, err error) {
	r, err := ixTry(func() any { return ixAtAttest(input, verdicts, opts) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixAtAttest(input map[string]any, verdicts []any, opts map[string]any) map[string]any {
	vo := map[string]any{"judgeKeys": opts["judgeKeys"], "k": opts["k"], "goalCommitment": input["goalCommitment"], "actionDigest": input["actionDigest"]}
	if ixTruthy(opts["calibration"]) {
		vo["calibration"] = opts["calibration"]
	}
	if pins := opts["pqPins"]; pins != nil {
		vo["pqPins"] = pins
	}
	r := IntentVerifySemanticThreshold(verdicts, vo)
	digests := make([]string, len(verdicts))
	for i, v := range verdicts {
		digests[i] = ixHashCanon(v)
	}
	ixSortU16(digests)
	var calDigest any
	if ixTruthy(opts["calibration"]) {
		calDigest = ixCalibrationDigest(ixM(opts["calibration"]))
	}
	score := ixAtToPpm(ixF(r["aggregateScore"]))
	if score == nil {
		score = 0.0
	}
	var cutoff any
	if c, has := r["cutoff"]; has {
		cutoff = ixAtToPpm(ixF(c))
	}
	att := map[string]any{"v": 1.0, "kind": "pca-ic-att", "intent_ref": input["intentRef"], "map_digest": input["mapDigest"],
		"action_digest": input["actionDigest"], "goal_commitment": input["goalCommitment"], "verdict_digests": ixToAny(digests),
		"calibration_digest": calDigest, "k": opts["k"], "ok": r["ok"], "agree_count": r["agreeCount"], "aggregate_score_ppm": score,
		"cutoff_ppm": cutoff}
	if reason := ixS(r["reason"]); reason != "" {
		att["reason"] = reason
	}
	return att
}

// IntentVerifyICAtt re-verifies an IC-Att from the verdicts it names (a relying party never trusts the ok bit).
func IntentVerifyICAtt(att, input map[string]any, verdicts []any, opts map[string]any) map[string]any {
	problems := []any{}
	r, err := ixTry(func() any {
		again := ixAtAttest(input, verdicts, opts)
		if ixICAttDigest(again) != ixICAttDigest(att) {
			problems = append(problems, "IC-Att does not match the recomputation from its verdicts")
		}
		if again["ok"] != true {
			why := "unknown"
			if s := ixS(again["reason"]); s != "" {
				why = s
			}
			problems = append(problems, "panel does not pass: "+why)
		}
		return nil
	})
	_ = r
	if err != nil {
		panic(err)
	}
	return map[string]any{"ok": len(problems) == 0, "problems": problems}
}

// IntentCheckConformance asks the panel for its verdicts and attests: {att, verdicts}.
func IntentCheckConformance(panel func(input map[string]any) []any, input, opts map[string]any) (map[string]any, error) {
	r, err := ixTry(func() any {
		verdicts := panel(input)
		return map[string]any{"att": ixAtAttest(input, verdicts, opts), "verdicts": verdicts}
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}
