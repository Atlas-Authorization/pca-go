package pca

// Replay of the reference corpus for goal drift and conformal risk control: the tighten-only drift monitor (driven through a step
// script, as the monitor is stateful), calibration numerics and the fidelity report.

import (
	"strconv"
	"testing"
)

func goalVxFlow(a []any) any {
	goal := vecArg(a, 0)
	opts := vecArg(a, 1)
	mon := goalNewDriftMonitor(goal, opts)
	var last any
	out := []any{}
	for _, sv := range anlReqList(vecArg(a, 2)) {
		s := sv.(map[string]any)
		switch s["op"] {
		case "observe":
			out = append(out, mon.observe(s["act"], s["t"]))
		case "state":
			out = append(out, goalDeepCopy(mon.st))
		case "seal":
			last = goalDeepCopy(mon.seal(goalVxB64(s["key"])))
			out = append(out, last)
		case "restoreLast":
			sealed := goalDeepCopy(last).(map[string]any)
			switch s["mode"] {
			case "state":
				sealed["state"].(map[string]any)["strikes"] = goalNum(0)
			case "mac":
				m := sealed["mac"].(string)
				flip := "0"
				if m[0] == '0' {
					flip = "1"
				}
				sealed["mac"] = flip + m[1:]
			case "badmac":
				sealed["mac"] = "zz"
			}
			mon = goalRestoreDriftMonitor(goal, sealed, goalVxB64(s["key"]), opts)
			out = append(out, goalDeepCopy(mon.st))
		case "guarded":
			r := goalGuardedDecide(goal, s["ont"], mon, s["case"], s["t"])
			out = append(out, map[string]any{"decision": r["decision"], "signal": r["signal"]})
		}
	}
	return out
}

func TestGoalDriftVectors(t *testing.T) {
	replayVectors(t, "ref-goal-drift.json.gz", map[string]vecFn{
		"flow": func(a []any) (any, error) { return goalVecTry(func() any { return goalVxFlow(a) }) },
		"applyDrift": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalApplyDrift(goalVecStr(vecArg(a, 0)), vecArg(a, 1)) })
		},
		"alphaOf": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalAlphaOf(goalExNum(vecArg(a, 0))) })
		},
		"calibrate": func(a []any) (any, error) {
			return goalVecTry(func() any {
				var gate func(k, n int64) bool
				if g := vecArg(a, 2); g != "none" {
					f, err := strconv.ParseFloat(goalVecStr(g)[2:], 64)
					if err != nil {
						anlFail("bad gate")
					}
					gate = func(k, n int64) bool { return goalCpUpper95(float64(k), float64(n)) <= f/1e5 }
				}
				return goalCalibrate(vecArg(a, 0), vecArg(a, 1), gate)
			})
		},
		"assertMonotone": func(a []any) (any, error) {
			return goalVecTry(func() any { goalAssertMonotone(vecArg(a, 0)); return nil })
		},
		"cpUpper95": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalCpUpper95(goalExNum(vecArg(a, 0)), goalExNum(vecArg(a, 1))) })
		},
		"renderReportMarkdown": func(a []any) (any, error) {
			return goalVecTry(func() any { return goalRenderReportMarkdown(vecArg(a, 0), vecArg(a, 1)) })
		},
	})
}
