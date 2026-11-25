package pca

// Outcome verification (postconditions on observed effects, evaluated by the one predicate evaluator), the runtime intent
// digests (judge input, conformance attestation digest, just-in-time consent) and the question cards of human studies.

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

func ixEff(field string) string { return "env.effect." + field }

func ixPC(id, verb, desc string, where ...any) map[string]any {
	return map[string]any{"id": id, "verb": verb, "description": desc, "where": where}
}

func ixAmtConds() []any {
	return []any{map[string]any{"field": ixEff("amount"), "op": "lte", "ref": "action.params.amount"},
		map[string]any{"field": ixEff("amount"), "op": "gte", "value": 0.0}}
}

func ixEqRef(field, ref string) map[string]any {
	return map[string]any{"field": ixEff(field), "op": "eq", "ref": ref}
}

// ixDefaultPostconditions are the built-in postconditions of the common verbs.
func ixDefaultPostconditions() []any {
	return []any{
		ixPC("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", ixAmtConds()...),
		ixPC("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", ixEqRef("recipient", "action.params.recipient")),
		ixPC("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", ixAmtConds()...),
		ixPC("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", ixAmtConds()...),
		ixPC("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", ixEqRef("recipient", "action.params.recipient")),
		ixPC("gmail.send.to", "gmail.send", "the mail went only to the requested address", ixEqRef("to", "action.params.to")),
		ixPC("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", ixEqRef("channel", "action.params.channel")),
		ixPC("files.write.path", "files.write", "the written path is the requested resource", ixEqRef("path", "action.resource")),
		ixPC("files.delete.path", "files.delete", "the deleted path is the requested resource", ixEqRef("path", "action.resource")),
		ixPC("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", ixEqRef("repo", "action.resource")),
		ixPC("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", ixEqRef("hour", "env.hour")),
	}
}

type ixLeaf struct{ field, ref string }

func ixLeaves(cv any, out *[]ixLeaf) {
	c, ok := cv.(map[string]any)
	if !ok {
		return
	}
	if ixIsGroupCond(c) {
		if l, ok := c["all_of"].([]any); ok {
			for _, x := range l {
				ixLeaves(x, out)
			}
		} else if l, ok := c["any_of"].([]any); ok {
			for _, x := range l {
				ixLeaves(x, out)
			}
		} else if ixHas(c, "not") {
			ixLeaves(c["not"], out)
		}
		return
	}
	if f, ok := c["field"].(string); ok {
		l := ixLeaf{field: f}
		if r, ok := c["ref"].(string); ok {
			l.ref = r
		}
		*out = append(*out, l)
	}
}

// ixEffectContext is the evaluator's context for an action plus its observed effect.
func ixEffectContext(vs, o map[string]any, effect any) map[string]any {
	a := ixOutcomeToAction(vs, o)
	ctx := map[string]any{"action": map[string]any{"verb": a["verb"], "resource": a["resource"], "params": a["params"], "reversibility_class": vs["reversibility"]}}
	if s, ok := a["subject"]; ok {
		ctx["subject"] = s
	}
	env := map[string]any{}
	if e, ok := a["env"].(map[string]any); ok {
		for k, v := range e {
			env[k] = v
		}
	}
	env["effect"] = effect
	ctx["env"] = env
	return ctx
}

func ixCheckPostconditions(vs, o map[string]any, effect any, pcs []any) map[string]any {
	if pcs == nil {
		pcs = ixDefaultPostconditions()
	}
	ctx := ixEffectContext(vs, o, effect)
	var violated, missing, checked, notApplicable []string
	for _, pv := range pcs {
		pc := ixM(pv)
		if ixReq(pc, "verb") != o["verb"] {
			continue
		}
		var ls []ixLeaf
		for _, c := range ixL(ixReq(pc, "where")) {
			ixLeaves(c, &ls)
		}
		na := false
		for _, l := range ls {
			if l.ref != "" {
				if !strings.HasPrefix(l.ref, "env.effect.") {
					if _, ok := ixGetDotted(ctx, l.ref); !ok {
						na = true
					}
				}
			}
		}
		if na {
			notApplicable = append(notApplicable, ixS(pc["id"]))
			continue
		}
		var need []string
		seen := map[string]bool{}
		for _, l := range ls {
			fs := []string{l.field}
			if l.ref != "" {
				fs = append(fs, l.ref)
			}
			for _, f := range fs {
				if strings.HasPrefix(f, "env.effect.") && !seen[f] {
					seen[f] = true
					need = append(need, f)
				}
			}
		}
		var lacking []string
		for _, f := range need {
			if _, ok := ixGetDotted(ctx, f); !ok {
				lacking = append(lacking, f)
			}
		}
		if len(lacking) > 0 {
			missing = append(missing, lacking...)
			continue
		}
		checked = append(checked, ixS(pc["id"]))
		if !evaluatePredicates([]any{map[string]any{"verb": o["verb"], "resource": "*", "where": pc["where"]}}, ctx) {
			violated = append(violated, ixS(pc["id"]))
		}
	}
	uniq := map[string]bool{}
	var ms []string
	for _, m := range missing {
		if !uniq[m] {
			uniq[m] = true
			ms = append(ms, m)
		}
	}
	ixSortU16(ms)
	status := "ok"
	if len(violated) > 0 {
		status = "violated"
	} else if len(ms) > 0 {
		status = "pending"
	}
	l := func(x []string) []any { return ixToAny(x) }
	return map[string]any{"status": status, "violated": l(violated), "missing": l(ms), "checked": l(checked), "notApplicable": l(notApplicable)}
}

// ---- runtime digests ----

const ixICAttDomain = "atlas-pca/intent-ic-att/v1"

func ixPcactnActionOf(vs, o map[string]any) map[string]any {
	a := ixOutcomeToAction(vs, o)
	pd, err := ParamsDigest(ixNums(a["params"]))
	if err != nil {
		ixFail("%v", err)
	}
	return map[string]any{"verb": a["verb"], "resource": a["resource"], "params_digest": pd, "reversibility_class": vs["reversibility"]}
}

func ixJudgeInputOf(omega, o map[string]any, p float64, ctx map[string]any, catalog any) map[string]any {
	vs := ixFindVerb(omega, ixReq(o, "verb"))
	if vs == nil {
		ixFail("judgeInputOf: no verb %s in the space", ixS(o["verb"]))
	}
	out := ixCopyMap(ctx)
	out["renderedAction"] = ixRenderAction(vs, ixM(ixReq(o, "values")), catalog)
	out["p"] = p
	out["reversibility"] = vs["reversibility"]
	out["actionDigest"] = ixHashCanon(ixPcactnActionOf(vs, o))
	return out
}

func ixCalibrationDigest(c map[string]any) string {
	var samples []any
	for _, sv := range ixL(ixReq(c, "samples")) {
		s := ixM(sv)
		samples = append(samples, map[string]any{"score": ixReq(s, "score"), "faithful": ixReq(s, "faithful")})
	}
	if samples == nil {
		samples = []any{}
	}
	return ixHashCanon(map[string]any{"d": "atlas-pca/intent-calibration/v1", "alpha": ixReq(c, "alpha"), "samples": samples})
}

func ixICAttDigest(a map[string]any) string {
	return ixHashCanon(map[string]any{"d": ixICAttDomain, "a": a})
}

func ixSemanticRiskContribution(score float64) float64 {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 1
	}
	r := 1 - score
	if r < 0 {
		return 0
	}
	if r > 1 {
		return 1
	}
	return r
}

// ixFoldSemanticRisk is the monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r.
func ixFoldSemanticRisk(r float64, att map[string]any) float64 {
	score := math.NaN()
	if ppm, ok := att["aggregate_score_ppm"].(float64); ok {
		score = ppm / 1000000
	}
	return math.Max(r, ixSemanticRiskContribution(score))
}

func ixJitConsentRequest(omega, o map[string]any, p float64, ctx map[string]any, catalog any) map[string]any {
	vs := ixFindVerb(omega, ixReq(o, "verb"))
	if vs == nil {
		ixFail("jitConsentRequest: no verb %s in the space", ixS(o["verb"]))
	}
	values := ixM(ixReq(o, "values"))
	return map[string]any{"v": 1.0, "kind": "pca-intent-jit", "intent_ref": ixReq(ctx, "intentRef"), "map_digest": ixReq(ctx, "mapDigest"),
		"verb": o["verb"], "values": ixCopyMap(values), "reversibility": vs["reversibility"], "p_ppm": math.Floor(float64(p*1000000) + 0.5),
		"text": ixRenderAction(vs, values, catalog) + " This cannot be undone. Approve?"}
}

func ixJitConsentDigest(r map[string]any) string {
	return ixHashCanon(map[string]any{"d": "atlas-pca/intent-jit/v1", "r": r})
}

// ---- question cards ----

var ixFieldRe = regexp.MustCompile(`^(action\.params\.[a-z_][a-z0-9_]*|action\.resource)$`)

func ixFactOf(d map[string]any, i int) map[string]any {
	label := ixLabelOf(ixS(d["path"]))
	var text string
	if d["kind"] == "num" {
		c := ixCellAt(ixNumCells(d), i)
		if c.lo == c.hi {
			text = "exactly " + jsValueString(c.lo)
		} else {
			text = "any value from " + jsValueString(c.lo) + " to " + jsValueString(c.hi) + " (for example " + jsValueString(ixRepValue(d, i)) + ")"
		}
	} else {
		vals := ixL(d["values"])
		if i < 0 || i >= len(vals) {
			ixFail("cell index out of range")
		}
		v := ixM(vals[i])
		switch v["kind"] {
		case "exact":
			text = `"` + ixS(v["value"]) + `"`
		case "prefix":
			text = `anything under "` + ixS(v["value"]) + `" not named elsewhere`
		default:
			text = "any value not named anywhere in the grant or your request"
		}
	}
	return map[string]any{"path": d["path"], "label": label, "text": text}
}

func ixQuestionCard(omega, q map[string]any, catalog any) map[string]any {
	vs := ixFindVerb(omega, ixReq(q, "verb"))
	if vs == nil {
		ixFail("questionCard: no verb %s", ixS(q["verb"]))
	}
	cell := ixL(ixReq(q, "cell"))
	facts, partial := []any{}, []any{}
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		if k >= len(cell) {
			ixFail("cell index missing")
		}
		facts = append(facts, ixFactOf(d, ixIdx(cell[k])))
	}
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		if d["kind"] == "num" {
			c := ixCellAt(ixNumCells(d), ixIdx(cell[k]))
			partial = append(partial, map[string]any{"path": d["path"], "kind": "num", "lo": c.lo, "hi": c.hi})
		} else {
			opts := []any{}
			for _, v := range ixL(d["values"]) {
				if ixM(v)["kind"] == "exact" {
					opts = append(opts, ixM(v)["value"])
				}
			}
			partial = append(partial, map[string]any{"path": d["path"], "kind": "cat", "options": opts})
		}
	}
	body := map[string]any{"v": 1.0, "verb": q["verb"], "cell": ixClone(cell), "sentence": ixRenderQuestion(vs, cell, catalog), "facts": facts,
		"reversibility": vs["reversibility"], "answers": []any{"yes", "no", "partly"}, "partial": partial}
	out := ixCopyMap(body)
	out["digest"] = ixHashCanon(map[string]any{"d": "atlas-pca/intent-card/v1", "c": body})
	return out
}

// ixStrings is [...new Set(x.filter(nonempty string))]: x must be an array.
func ixStrings(x any) []any {
	l, ok := x.([]any)
	if !ok {
		ixFail("input.notFor.filter is not a function")
	}
	out := []any{}
	for _, v := range l {
		if s, ok := v.(string); ok && s != "" {
			dup := false
			for _, o := range out {
				if o == s {
					dup = true
				}
			}
			if !dup {
				out = append(out, s)
			}
		}
	}
	return out
}

func ixIsIntNotNeg0(x any) bool {
	f, ok := x.(float64)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f) && !(f == 0 && math.Signbit(f))
}

func ixSetOf(x any) []any {
	var l []any
	switch t := x.(type) {
	case nil:
		return []any{}
	case string:
		for _, r := range t {
			l = append(l, string(r))
		}
	case []any:
		l = t
	default:
		ixFail("object is not iterable")
	}
	out := []any{}
	for _, v := range l {
		dup := false
		for _, o := range out {
			if o == v {
				dup = true
			}
		}
		if !dup {
			out = append(out, v)
		}
	}
	return out
}

func ixCardErr(msg string) map[string]any { return map[string]any{"ok": false, "error": msg} }

func ixJsStrOf(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok {
		return "undefined"
	}
	return jsValueString(v)
}

func ixParseCardAnswer(card, inp map[string]any) map[string]any {
	if inp["answer"] != "partly" {
		if inp["answer"] == "yes" {
			return map[string]any{"ok": true, "answer": 1.0}
		}
		return map[string]any{"ok": true, "answer": 0.0}
	}
	partial := ixL(ixReq(card, "partial"))
	if nf, has := inp["newField"]; has {
		s, ok := nf.(string)
		if !ok || !ixFieldRe.MatchString(s) {
			return ixCardErr("unknown field " + jsValueString(nf))
		}
		for _, sv := range partial {
			if ixM(sv)["path"] == s {
				return ixCardErr(s + " is already on the card; answer partly for it directly")
			}
		}
		vals := ixStrings(inp["notFor"])
		if len(vals) == 0 {
			return ixCardErr("name at least one value")
		}
		values := []any{}
		for _, v := range vals {
			values = append(values, map[string]any{"kind": "exact", "value": v})
		}
		values = append(values, map[string]any{"kind": "other", "value": ixOther})
		return map[string]any{"ok": true, "answer": map[string]any{"kind": "partial", "path": s,
			"newDim": map[string]any{"kind": "cat", "path": s, "values": values},
			"parts":  []any{map[string]any{"values": vals, "y": 0.0}, map[string]any{"other": true, "y": 1.0}}}}
	}
	path := inp["path"]
	var slot map[string]any
	for _, sv := range partial {
		if s := ixM(sv); s["path"] == path {
			slot = s
			break
		}
	}
	if slot == nil {
		return ixCardErr("the card has no field " + ixJsStrOf(inp, "path"))
	}
	if slot["kind"] == "num" {
		lo, hi := ixF(slot["lo"]), ixF(slot["hi"])
		inRange := func(x any) bool { return ixIsIntNotNeg0(x) && x.(float64) >= lo && x.(float64) <= hi }
		rng := func(a, b float64) string { return "[" + jsValueString(a) + ", " + jsValueString(b) + "]" }
		if x, has := inp["upTo"]; has {
			if !inRange(x) || x.(float64) == hi {
				return ixCardErr("upTo must be an integer in " + rng(lo, hi-1))
			}
			xf := x.(float64)
			return map[string]any{"ok": true, "answer": map[string]any{"kind": "partial", "path": slot["path"], "cuts": []any{x},
				"parts": []any{map[string]any{"lo": lo, "hi": xf, "y": 1.0}, map[string]any{"lo": xf + 1, "hi": hi, "y": 0.0}}}}
		}
		if x, has := inp["from"]; has {
			if !inRange(x) || x.(float64) == lo {
				return ixCardErr("from must be an integer in " + rng(lo+1, hi))
			}
			xf := x.(float64)
			return map[string]any{"ok": true, "answer": map[string]any{"kind": "partial", "path": slot["path"], "cuts": []any{x},
				"parts": []any{map[string]any{"lo": lo, "hi": xf - 1, "y": 0.0}, map[string]any{"lo": xf, "hi": hi, "y": 1.0}}}}
		}
		if exv, has := inp["except"]; has {
			ex := ixSetOf(exv)
			allInt := true
			for _, v := range ex {
				if !ixIsIntNotNeg0(v) {
					allInt = false
				}
			}
			if allInt {
				sort.SliceStable(ex, func(i, j int) bool { return ex[i].(float64) < ex[j].(float64) })
			}
			good := len(ex) > 0
			for _, v := range ex {
				if !inRange(v) {
					good = false
				}
			}
			if !good {
				return ixCardErr("except values must be integers in " + rng(lo, hi))
			}
			parts := []any{}
			for _, v := range ex {
				parts = append(parts, map[string]any{"lo": v, "hi": v, "y": 0.0})
			}
			parts = append(parts, map[string]any{"lo": lo, "hi": hi, "y": 1.0})
			return map[string]any{"ok": true, "answer": map[string]any{"kind": "partial", "path": slot["path"], "cuts": ex, "parts": parts}}
		}
		return ixCardErr("a numeric partly answer needs upTo, from or except")
	}
	nfv, has := inp["notFor"]
	if !has {
		return ixCardErr("a categorical partly answer needs notFor")
	}
	vals := ixStrings(nfv)
	if len(vals) == 0 {
		return ixCardErr("name at least one value")
	}
	return map[string]any{"ok": true, "answer": map[string]any{"kind": "partial", "path": slot["path"], "values": vals,
		"parts": []any{map[string]any{"values": vals, "y": 0.0}, map[string]any{"other": true, "y": 1.0}}}}
}
