package pca

// The console-activity framework report: a compliance evidence report (EU AI Act, SOC 2, GDPR) over the activity stream.

import (
	"fmt"
	"math"
	"strings"
)

func cmpSafetyBound(p any) float64 {
	kappa, bMax := cmpProp(p, "kappa"), cmpProp(p, "bMax")
	if !xpGt(kappa, 0) {
		return 0
	}
	b := xpToNum(bMax)
	if !math.IsNaN(b) {
		b = math.Max(0, b)
	}
	return b / xpToNum(kappa)
}

type cmpFwSummary struct {
	totalActions, humanOverseen, denied, attributableAgents int
	autonomous                                              int
	autonomousBound, maxTaint                               float64
}

func cmpBaseSummary(inp any) cmpFwSummary {
	events, ok := cmpProp(inp, "events").([]any)
	if !ok {
		xpPanic("e.filter is not a function")
	}
	p := cmpProp(cmpProp(inp, "policy"), "riskPolicy")
	decisions := cmpQ(inp, "decisions")
	dlen := 0
	if !cmpNullish(decisions) {
		if l := cmpLength(decisions); !xpIsUndef(l) {
			dlen = cmpLenInt(l)
		}
	}
	taint := 0.0
	for _, x := range events {
		t := cmpProp(x, "taint")
		v := 0.0
		if !xpIsUndef(t) {
			if xpIsFin(t) {
				v, _ = jsNum(t)
			} else {
				v = math.Inf(1)
			}
		}
		taint = math.Max(taint, v)
	}
	var agents cmpSet
	s := cmpFwSummary{totalActions: len(events), maxTaint: taint}
	for _, x := range events {
		agents.add(cmpProp(x, "agent"))
	}
	for _, x := range events {
		switch cmpProp(x, "outcome") {
		case "auto", "executed":
			s.autonomous++
		}
	}
	for _, x := range events {
		switch cmpProp(x, "outcome") {
		case "step_up":
			s.humanOverseen++
		case "deny":
			s.denied++
		}
	}
	s.humanOverseen += dlen
	s.attributableAgents = len(agents.keys)
	s.autonomousBound = cmpSafetyBound(p) * xpToNum(cmpProp(p, "kappa"))
	return s
}

func cmpFwPeriod(events []any) map[string]any {
	var from, to any = xpInt(0), xpInt(0)
	first := true
	for _, e := range events {
		if a := cmpProp(e, "at"); xpIsFin(a) {
			if first {
				from, to, first = a, a, false
			}
			if xpLt(a, from) {
				from = a
			}
			if xpGt(a, to) {
				to = a
			}
		}
	}
	return map[string]any{"from": from, "to": to}
}

func cmpCtl(id, name, status, evidence string) any {
	return map[string]any{"id": id, "name": name, "status": status, "evidence": evidence}
}

func cmpPW(ok bool) string {
	if ok {
		return "pass"
	}
	return "warn"
}

func cmpFwControls(framework string, inp any, s cmpFwSummary) []any {
	bound := s.autonomousBound
	switch framework {
	case "eu-ai-act":
		logged := s.totalActions > 0
		oversight := s.humanOverseen > 0 || !(math.IsNaN(bound) || math.IsInf(bound, 0))
		goal := xpTruthy(cmpOwn(inp, "hasGoalCommitment"))
		fin := !(math.IsNaN(bound) || math.IsInf(bound, 0))
		bs := xpNumStr(bound)
		art15 := "fail"
		if fin {
			art15 = "pass"
		}
		tr := "no goal commitment supplied"
		if goal {
			tr = "every action binds to a signed goal commitment (lineage)"
		}
		return []any{
			cmpCtl("art12-record-keeping", "Automatic logging of events", cmpPW(logged), fmt.Sprintf("%d attributable actions recorded", s.totalActions)),
			cmpCtl("art14-human-oversight", "Human oversight", cmpPW(oversight), fmt.Sprintf("%d human-reviewed actions; autonomous bound %s", s.humanOverseen, bs)),
			cmpCtl("art15-robustness", "Bounded autonomy (accuracy/robustness)", art15, fmt.Sprintf("machine-checked safety bound = %s between human co-signs", bs)),
			cmpCtl("art13-transparency", "Transparency / traceability", cmpPW(goal), tr),
		}
	case "soc2":
		preds, _ := cmpQ(cmpOwn(inp, "policy"), "predicates").([]any)
		constrained := len(preds) > 0
		c1, c8 := "the supplied policy lists no predicates", "the supplied policy lists no predicates"
		if constrained {
			c1, c8 = "actions constrained by signed predicates + capability attenuation (deny by default)", "policy is signed into the grant; tampering breaks verification"
		}
		return []any{
			cmpCtl("cc6.1-access", "Logical access — least privilege", cmpPW(constrained), c1),
			cmpCtl("cc7.2-monitoring", "Monitoring of anomalies", cmpPW(s.totalActions > 0), fmt.Sprintf("%d denied + %d escalated actions captured", s.denied, s.humanOverseen)),
			cmpCtl("cc7.3-audit-trail", "Audit trail", cmpPW(s.totalActions > 0), fmt.Sprintf("%d content-addressed actions across %d agents", s.totalActions, s.attributableAgents)),
			cmpCtl("cc8.1-change", "Change management (policy integrity)", cmpPW(constrained), c8),
		}
	}
	goal := xpTruthy(cmpOwn(inp, "hasGoalCommitment"))
	erasure := xpTruthy(cmpOwn(inp, "erasureSupported"))
	pu, er := "no goal commitment supplied", "erasure path not asserted"
	if goal {
		pu = "actions bound to a committed goal/purpose"
	}
	if erasure {
		er = "erasure path wired"
	}
	return []any{
		cmpCtl("art5-purpose", "Purpose limitation", cmpPW(goal), pu),
		cmpCtl("art5-minimization", "Data minimisation", cmpPW(s.totalActions > 0), "taint-gated data flows; max taint observed = "+xpNumStr(s.maxTaint)),
		cmpCtl("art5-accountability", "Accountability", cmpPW(s.attributableAgents > 0), fmt.Sprintf("%d attributable agent identities", s.attributableAgents)),
		cmpCtl("art17-erasure", "Right to erasure", cmpPW(erasure), er),
	}
}

// ComplianceFrameworkReport is a compliance evidence report for a framework from the console activity stream: inp is
// {policy, events, decisions?, hasGoalCommitment?, erasureSupported?}. now (epoch ms) defaults to the clock when it is not given.
func ComplianceFrameworkReport(framework, inp, now any, nowGiven bool) (map[string]any, error) {
	var out map[string]any
	err := xpTry(func() {
		s := cmpBaseSummary(inp)
		fw, ok := framework.(string)
		valid := false
		for _, f := range cmpFrameworkIDs {
			valid = valid || (ok && f == fw)
		}
		if !valid {
			xpPanic(fmt.Sprintf("frameworkReport: unknown framework '%s' (have: %s)", xpStr(framework), strings.Join(cmpFrameworkIDs, ", ")))
		}
		controls := cmpFwControls(fw, inp, s)
		pass := true
		for _, c := range controls {
			if c.(map[string]any)["status"] == "fail" {
				pass = false
			}
		}
		if !nowGiven {
			now = cmpNowMs()
		}
		events, _ := cmpProp(inp, "events").([]any)
		out = map[string]any{"framework": fw, "generatedAt": now, "period": cmpFwPeriod(events),
			"summary": map[string]any{"totalActions": xpInt(s.totalActions), "autonomous": xpInt(s.autonomous), "humanOverseen": xpInt(s.humanOverseen),
				"denied": xpInt(s.denied), "attributableAgents": xpInt(s.attributableAgents), "autonomousBound": cmpNumOut(s.autonomousBound),
				"maxTaintObserved": cmpNumOut(s.maxTaint)},
			"controls": controls, "pass": pass}
	})
	return out, err
}

// ComplianceFrameworkReportToMarkdown is a short Markdown block of a framework report, for an audit package.
func ComplianceFrameworkReportToMarkdown(r any) (string, error) {
	var out string
	err := xpTry(func() {
		summary := cmpProp(r, "summary")
		controls, ok := cmpProp(r, "controls").([]any)
		if !ok {
			xpPanic("r.controls.map is not a function")
		}
		gen := cmpProp(r, "generatedAt")
		var date any = gen
		switch t := gen.(type) {
		case nil:
			date = 0
		case bool:
			date = 0
			if t {
				date = 1
			}
		}
		pass := "FAIL"
		if xpTruthy(cmpProp(r, "pass")) {
			pass = "PASS"
		}
		lines := []string{"# PCA compliance evidence — " + xpStr(cmpProp(r, "framework")), "",
			fmt.Sprintf("Generated %s · %s actions · %s agents · overall: %s", cmpIsoString(date), xpStr(cmpProp(summary, "totalActions")),
				xpStr(cmpProp(summary, "attributableAgents")), pass), "", "| Control | Status | Evidence |", "| --- | --- | --- |"}
		for _, c := range controls {
			lines = append(lines, fmt.Sprintf("| %s (%s) | %s | %s |", xpStr(cmpProp(c, "name")), xpStr(cmpProp(c, "id")), cmpUpper(cmpProp(c, "status")), xpStr(cmpProp(c, "evidence"))))
		}
		lines = append(lines, "", "_Evidence mapping, not a legal certification._")
		out = strings.Join(lines, "\n")
	})
	return out, err
}
