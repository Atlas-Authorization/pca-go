package pca

// Conformal risk control for the intent-fidelity program (the TypeScript reference is @atlasauth/pca-goal `crc`): the choice rule
// uses the integer arithmetic of the mechanised statement ((sum of losses + 1) * b <= a * (n + 1), alpha = a / b, B = 1).
// Alphas and calibrations are JSON trees ({a, b} / {level, n, feasible, correctedRisk, minN}); like the reference these are
// panic-style, with error-returning Goal* wrappers.

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// goalCrcNum is a JSON number for a float; Infinity (a minN with alpha 0) is the {"$num": "Infinity"} marker, as the numerics
// corpus writes it.
func goalCrcNum(f float64) any {
	if math.IsInf(f, 1) {
		return map[string]any{"$num": "Infinity"}
	}
	return jsNumber(f)
}

// goalAlphaOf is alpha = a / b with b = 100000 (a = Math.round(x * b)).
func goalAlphaOf(x float64) map[string]any {
	const b = 100000
	v := float64(x * b)
	r := math.Floor(v)
	if v-r >= 0.5 {
		r++
	}
	return map[string]any{"a": jsNumber(r), "b": goalNum(b)}
}

// goalAssertMonotone: `losses[i][l]` in {0,1}, nonincreasing in l (larger l = more conservative); panics when violated.
func goalAssertMonotone(losses any) {
	for i, r := range anlReqList(losses) {
		row := anlReqList(r)
		for _, v := range row {
			if f, ok := jsNum(v); !ok || (f != 0 && f != 1) {
				anlFail("loss must be 0 or 1 (case %d)", i)
			}
		}
		for l := 1; l < len(row); l++ {
			if goalCrcLoss(row[l]) > goalCrcLoss(row[l-1]) {
				anlFail("loss is not nonincreasing in the threshold (case %d, level %d)", i, l)
			}
		}
	}
}

func goalCrcLoss(v any) float64 { f, _ := jsNum(v); return f }

// goalCalibrate is the smallest threshold whose corrected empirical risk is <= alpha; with none feasible the top (loss-0,
// escalate-all) level. `gate` (nil = none) only makes the choice MORE conservative, which keeps the guarantee.
func goalCalibrate(losses any, alpha any, gate func(k, n int64) bool) map[string]any {
	goalAssertMonotone(losses)
	rows := anlReqList(losses)
	n := len(rows)
	K := 0
	if n > 0 {
		K = len(anlReqList(rows[0]))
	}
	if K == 0 {
		anlFail("calibrate: no levels")
	}
	a, aok := jsNum(anlGet(alpha, "a"))
	b, bok := jsNum(anlGet(alpha, "b"))
	if !aok || !bok {
		anlFail("alpha must be {a, b} numbers")
	}
	minN := math.Inf(1)
	if a != 0 {
		minN = math.Ceil(b/a) - 1
	}
	for l := 0; l < K; l++ {
		k := int64(0)
		for _, r := range rows {
			k += int64(goalCrcLoss(anlReqList(r)[l]))
		}
		if (float64(k)+1)*b <= a*float64(n+1) && (gate == nil || gate(k, int64(n))) {
			return map[string]any{"level": l, "n": n, "feasible": true, "correctedRisk": goalCrcNum(float64(k+1) / float64(n+1)), "minN": goalCrcNum(minN)}
		}
	}
	return map[string]any{"level": K - 1, "n": n, "feasible": false, "correctedRisk": goalCrcNum(1 / float64(n+1)), "minN": goalCrcNum(minN)}
}

var goalAssumptions = []string{
	"Exchangeability: calibration and deployment goals are exchangeable within the domain. Distribution shift, a new ontology version, a new model or a new prompt breaks it: recalibrate and re-run the gate.",
	"Label quality: probe labels are the intended policy of the benchmark author; inter-annotator agreement is reported where human labels exist and is not claimed for synthetic goals.",
	"Probe coverage: the guarantee is about the published probe set (boundary examples of the intended policy, extreme amounts, other resources, other verbs), not about every possible action.",
	"Non-adaptive deployment: an adaptive attacker is handled by the hostile corpus and its widening-rate gate, not by this bound.",
	"Independence is not assumed for safety (the meet is within every reading); it affects only how often disagreement is detected.",
	"Recorded outputs: offline runs replay recorded model outputs. Rates measured on fixture recordings describe the pipeline, not any live model; live rates come from the scheduled evaluation.",
}

// goalCrcFixed is `x.toFixed(d)`: a non-number throws as the reference's property read would.
func goalCrcFixed(x any, d int) string {
	f, ok := jsNum(x)
	if !ok {
		anlFail("toFixed of a non-number")
	}
	return anlToFixed(f, d)
}

// goalRenderReportMarkdown renders the fidelity report; rs is an array of DomainReport trees and meta {source, modelSet}.
func goalRenderReportMarkdown(rs any, meta any) string {
	s := anlJS
	g := anlGet
	reports := anlReqList(rs)
	var L []string
	src := "recorded fixtures"
	if g(meta, "source") == "live" {
		src = "live models"
	}
	L = append(L, "# Intent fidelity report ("+src+")", "", "Model set: "+s(g(meta, "modelSet")), "",
		"| Domain | alpha | n (test) | widening k | rate | 95% upper (Clopper-Pearson) | escalation | false restriction | mean questions | gate |",
		"|---|---|---|---|---|---|---|---|---|---|")
	for _, r := range reports {
		t := g(r, "test")
		w := g(t, "widening")
		gate := "FAIL"
		if anlTruthy(g(r, "gatePassed")) {
			gate = "pass"
		}
		L = append(L, fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |",
			s(g(r, "domain")), s(g(r, "alpha")), s(g(t, "n")), s(g(w, "k")), goalCrcFixed(g(w, "rate"), 4), goalCrcFixed(g(w, "cpUpper95"), 4),
			goalCrcFixed(g(t, "escalationRate"), 3), goalCrcFixed(g(t, "falseRestrictionRate"), 3), goalCrcFixed(g(t, "meanQuestions"), 2), gate))
	}
	L = append(L, "", "## Calibrated threshold per domain", "")
	for _, r := range reports {
		c := g(r, "calibration")
		L = append(L, fmt.Sprintf("- %s: level \"%s\" (feasible: %s; calibration n = %s; corrected risk %s; minimum n for alpha: %s)",
			s(g(r, "domain")), s(g(c, "levelName")), s(g(c, "feasible")), s(g(c, "n")), goalCrcFixed(g(c, "correctedRisk"), 4), s(g(c, "minN"))))
	}
	L = append(L, "", "## Per level (all cases)", "")
	for _, r := range reports {
		L = append(L, "### "+s(g(r, "domain")), "", "| Level | widening k/n | 95% upper | escalation rate |", "|---|---|---|---|")
		for _, p := range anlReqList(g(r, "perLevel")) {
			w := g(p, "widening")
			L = append(L, fmt.Sprintf("| %s | %s/%s | %s | %s |", s(g(p, "level")), s(g(w, "k")), s(g(w, "n")),
				goalCrcFixed(g(w, "cpUpper95"), 4), goalCrcFixed(g(p, "escalationRate"), 3)))
		}
		L = append(L, "")
	}
	L = append(L, "## Compile-widening (IR to policy)", "", "Must be exactly zero; any nonzero value blocks the release.", "")
	for _, r := range reports {
		cw := g(r, "compileWidening")
		L = append(L, fmt.Sprintf("- %s: %s of %s", s(g(r, "domain")), s(g(cw, "k")), s(g(cw, "n"))))
	}
	L = append(L, "", "## Guarantee and assumptions", "",
		"Under the assumptions below, E[loss] <= alpha (finite-sample corrected, proved in Crc.lean), where loss = 1 when the auto-accepted policy permits a probe the principal rejects.", "")
	for _, a := range goalAssumptions {
		L = append(L, "- "+a)
	}
	return strings.Join(L, "\n") + "\n"
}

// goalCpUpper95 is the 95% Clopper-Pearson upper bound after k widenings in n (1 when n = 0).
func goalCpUpper95(k, n float64) float64 {
	if n == 0 {
		return 1
	}
	u, err := ClopperPearsonUpper(k, n, 0.05)
	if err != nil {
		panic(err)
	}
	return u
}

// GoalAlphaOf is alpha = a / b for a rate x.
func GoalAlphaOf(x float64) map[string]any { return goalAlphaOf(x) }

// GoalAssertMonotone refuses losses that are not 0/1 or not nonincreasing in the level.
func GoalAssertMonotone(losses any) error {
	_, err := anlTry(func() any { goalAssertMonotone(losses); return nil })
	return err
}

// GoalCalibrate picks the calibrated level (gate nil = no extra gate).
func GoalCalibrate(losses any, alpha any, gate func(k, n int64) bool) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalCalibrate(losses, alpha, gate); return nil })
	return
}

// GoalAssumptions are the stated assumptions of the guarantee.
func GoalAssumptions() []string { return append([]string(nil), goalAssumptions...) }

// GoalRenderReportMarkdown renders the fidelity report.
func GoalRenderReportMarkdown(rs any, meta any) (string, error) {
	return goalStrWrap(func() string { return goalRenderReportMarkdown(rs, meta) })
}

// GoalCpUpper95 is the 95% Clopper-Pearson upper bound.
func GoalCpUpper95(k, n int64) (float64, error) {
	if k < 0 || n < 0 || k > n {
		return 0, errors.New("cpUpper95: need integers 0 <= k <= n")
	}
	var u float64
	_, err := anlTry(func() any { u = goalCpUpper95(float64(k), float64(n)); return nil })
	return u, err
}
