package pca

// The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers (the TypeScript
// reference is @atlasauth/pca-goal `card`). Two different goals never print the same card.

import (
	"fmt"
	"strings"
)

var goalOpWords = map[string]string{"eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "in": "is one of", "nin": "is none of"}

func goalQ(x any) string {
	if anlIsUndef(x) {
		return "undefined"
	}
	return goalJq(x)
}

// goalQs renders each member of an array with goalQ, joined by ", ".
func goalQs(xs any) string {
	l := anlReqList(xs)
	parts := make([]string, len(l))
	for i, x := range l {
		parts[i] = goalQ(x)
	}
	return strings.Join(parts, ", ")
}

func goalUnit(u any) string {
	if anlGet(u, "k") == "money" {
		return anlJS(anlGet(u, "ccy")) + " minor units"
	}
	return anlJS(anlGet(u, "k"))
}

func goalQuantity(x any) string {
	return anlJS(anlGet(x, "n")) + " " + goalUnit(anlGet(x, "u"))
}

func goalValue(v any) string {
	switch anlGet(v, "k") {
	case "q":
		return goalQuantity(anlGet(v, "q"))
	case "s":
		return goalQ(anlGet(v, "s"))
	}
	items := anlReqList(anlGet(v, "items"))
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = goalValue(it)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func goalTerm(t any) string {
	switch anlGet(t, "k") {
	case "param":
		ty := anlGet(t, "ty")
		what := "text"
		if anlGet(ty, "k") == "q" {
			what = goalUnit(anlGet(ty, "u"))
		}
		return fmt.Sprintf("param %s (%s)", goalQ(anlGet(t, "path")), what)
	case "lit":
		return goalValue(anlGet(t, "v"))
	}
	return fmt.Sprintf("running total of bound %s (%s)", goalQ(anlGet(t, "bid")), goalUnit(anlGet(t, "u")))
}

func goalCond(c any) string {
	switch anlGet(c, "k") {
	case "true":
		return "always"
	case "cmp":
		w := "undefined"
		if op, ok := anlGet(c, "op").(string); ok {
			if x, ok := goalOpWords[op]; ok {
				w = x
			}
		}
		return fmt.Sprintf("%s %s %s", goalTerm(anlGet(c, "l")), w, goalTerm(anlGet(c, "r")))
	case "and":
		return fmt.Sprintf("(%s) AND (%s)", goalCond(anlGet(c, "a")), goalCond(anlGet(c, "b")))
	case "or":
		return fmt.Sprintf("(%s) OR (%s)", goalCond(anlGet(c, "a")), goalCond(anlGet(c, "b")))
	case "not":
		return fmt.Sprintf("NOT (%s)", goalCond(anlGet(c, "c")))
	}
	return "undefined" // the reference switch has no default
}

func goalRes(s any) string {
	switch anlGet(s, "k") {
	case "exact":
		return "exactly " + goalQ(anlGet(s, "id"))
	case "oneof":
		return "one of [" + goalQs(anlGet(s, "ids")) + "]"
	case "related":
		return fmt.Sprintf("%s of %s", anlJS(anlGet(s, "rel")), goalQ(anlGet(s, "anchor")))
	case "all_of":
		ps := anlReqList(anlGet(s, "parts"))
		parts := make([]string, len(ps))
		for i, p := range ps {
			parts[i] = goalRes(p)
		}
		return "ALL OF (" + strings.Join(parts, " AND ") + ")"
	}
	return "ANY RESOURCE (reason: " + goalQ(anlGet(s, "reason")) + ")"
}

func goalWin(w any) string {
	switch anlGet(w, "k") {
	case "task":
		return "per task"
	case "lifetime":
		return "over the lifetime"
	case "sliding":
		return fmt.Sprintf("in any %s ms window", anlJS(anlGet(w, "ms")))
	}
	return fmt.Sprintf("per %s ms period starting at %s", anlJS(anlGet(w, "ms")), anlJS(anlGet(w, "t0")))
}

func goalScope(s any) string {
	if anlGet(s, "k") == "fleet" {
		return "fleet [" + goalQs(anlGet(s, "agents")) + "]"
	}
	return anlJS(anlGet(s, "k"))
}

func goalGrantLine(x any) string {
	return fmt.Sprintf("ALLOW %s: verb %s on %s when %s", goalQ(anlGet(x, "gid")), goalQ(anlGet(x, "verb")), goalRes(anlGet(x, "res")), goalCond(anlGet(x, "cond")))
}

func goalProhibitLine(x any) string {
	t := anlGet(x, "target")
	var tgt string
	if anlGet(t, "k") == "verb" {
		tgt = "verb " + goalQ(anlGet(t, "verb"))
	} else {
		tgt = "every verb of effect class " + goalQ(anlGet(t, "cls"))
	}
	return fmt.Sprintf("NEVER %s: %s on %s when %s", goalQ(anlGet(x, "pid")), tgt, goalRes(anlGet(x, "res")), goalCond(anlGet(x, "cond")))
}

func goalBoundLine(b any) string {
	sel := anlGet(b, "sel")
	var over string
	if anlGet(sel, "k") == "gids" {
		over = "grants [" + goalQs(anlGet(sel, "gids")) + "]"
	} else {
		over = "effect class " + goalQ(anlGet(sel, "cls"))
	}
	agg := anlGet(b, "agg")
	mid := ""
	switch agg {
	case "count":
	case "distinct":
		mid = " of " + goalQ(anlGet(b, "key"))
	default:
		mid = " of " + goalTerm(anlGet(b, "value"))
	}
	exc := "ask the principal"
	if anlGet(b, "onExceed") == "deny" {
		exc = "deny"
	}
	return fmt.Sprintf("LIMIT %s: %s%s over %s, %s, scope %s, at most %s; beyond that: %s",
		goalQ(anlGet(b, "bid")), anlJS(agg), mid, over, goalWin(anlGet(b, "window")), goalScope(anlGet(b, "scope")), goalQuantity(anlGet(b, "cap")), exc)
}

func goalValidityLine(v any) string {
	mi := anlGet(v, "maxIdle")
	idle := "none"
	if anlGt(mi, 0) {
		idle = anlJS(mi) + " ms"
	}
	return fmt.Sprintf("VALID from %s to %s; idle limit %s", anlJS(anlGet(v, "notBefore")), anlJS(anlGet(v, "notAfter")), idle)
}

func goalDelegationLine(d any) string {
	return fmt.Sprintf("DELEGATION depth at most %s, narrow only %s, delegates may use grants [%s]",
		anlJS(anlGet(d, "maxDepth")), anlJS(anlGet(d, "narrowOnly")), goalQs(anlGet(d, "mayTouch")))
}

func goalEscalateLine(c any) string { return "ASK THE PRINCIPAL when " + goalCond(c) }

func goalHoleLine(h any) string {
	aff := "everything"
	if !anlTruthy(anlGet(h, "global")) {
		aff = "[" + goalQs(anlGet(h, "affects")) + "]"
	}
	return fmt.Sprintf("UNRESOLVED %s: %s options [%s] affects %s", goalQ(anlGet(h, "hid")), goalQ(anlGet(h, "q")), goalQs(anlGet(h, "domain")), aff)
}

// goalRenderCard is one line per clause, in the goal's canonical order; `warnings` lists what the principal must look at twice.
func goalRenderCard(g any) map[string]any {
	lines := []any{fmt.Sprintf("Goal v%s for principal %s; ontology %s; request text digest %s",
		anlJS(anlGet(g, "v")), goalQ(anlGet(g, "principal")), goalQ(anlGet(g, "ontDigest")), goalQ(anlGet(g, "nlDigest")))}
	warnings := []any{}
	for _, s := range anlReqList(anlGet(g, "sources")) {
		lines = append(lines, "Source "+goalQ(s))
	}
	for _, x := range anlReqList(anlGet(g, "grants")) {
		lines = append(lines, goalGrantLine(x))
		if anlGet(anlGet(x, "res"), "k") == "any" {
			ack := " (NOT acknowledged)"
			if anlIncludes(anlGet(g, "wildcardAck"), anlGet(x, "gid")) {
				ack = " (acknowledged)"
			}
			warnings = append(warnings, "grant "+goalQ(anlGet(x, "gid"))+" applies to every resource"+ack)
		}
	}
	for _, x := range anlReqList(anlGet(g, "prohibits")) {
		lines = append(lines, goalProhibitLine(x))
	}
	for _, b := range anlReqList(anlGet(g, "bounds")) {
		lines = append(lines, goalBoundLine(b))
	}
	lines = append(lines, goalValidityLine(anlGet(g, "validity")))
	lines = append(lines, goalDelegationLine(anlGet(g, "deleg")))
	for _, c := range anlReqList(anlGet(g, "escalateOn")) {
		lines = append(lines, goalEscalateLine(c))
	}
	for _, a := range anlReqList(anlGet(g, "wildcardAck")) {
		lines = append(lines, "Wildcard acknowledged for "+goalQ(a))
	}
	holes := anlReqList(anlGet(g, "holes"))
	for _, h := range holes {
		lines = append(lines, goalHoleLine(h))
	}
	if len(holes) > 0 {
		warnings = append(warnings, "this goal has unresolved questions and cannot be signed")
	}
	return map[string]any{"lines": lines, "warnings": warnings}
}

// GoalRenderCard is the policy card of a goal.
func GoalRenderCard(g any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalRenderCard(g); return nil })
	return
}

// GoalRenderCond is the text of one condition.
func GoalRenderCond(c any) (string, error) { return goalStrWrap(func() string { return goalCond(c) }) }

// GoalRenderQuantity is the text of one quantity.
func GoalRenderQuantity(q any) (string, error) {
	return goalStrWrap(func() string { return goalQuantity(q) })
}
