package pca

import (
	"errors"
	"math"
	"sort"
	"strings"
)

// Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them
// autonomously) and evaluate an action's provenance against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels
// something upstream attached; this checks them against ceilings and never tracks data through a program.
//
// A policy is {classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}], defaultMaxTaintForAuto?}; a context is
// {verb, resource, taint, trustedRefs?}; a result is {outcome: allow|step_up|deny, class?, reason?}.

func dlpMatches(pattern, resource any) (bool, error) {
	if s, ok := pattern.(string); ok && s == "*" {
		return true, nil
	}
	p, ok := pattern.(string)
	if !ok {
		return false, errors.New("DLP: a class resource must be a string")
	}
	if strings.HasSuffix(p, "*") {
		r, ok := resource.(string)
		if !ok {
			return false, errors.New("DLP: the resource must be a string")
		}
		return strings.HasPrefix(r, p[:len(p)-1]), nil
	}
	r, ok := resource.(string)
	return ok && p == r, nil
}

func dlpSpecificity(pattern string) float64 {
	switch {
	case pattern == "*":
		return 0
	case strings.HasSuffix(pattern, "*"):
		return float64(jsLen(pattern) - 1)
	}
	return float64(jsLen(pattern)) + 1000 // exact beats any prefix
}

// dlpStrictness: a malformed ceiling sorts first (so the policy denies instead of picking a lenient sibling); an absent ceiling sorts last.
func dlpStrictness(c map[string]any) float64 {
	m, present := c["maxTaintForAuto"]
	if !present {
		return math.Inf(1)
	}
	if rsIsNum(m) {
		return jsF(m)
	}
	return math.Inf(-1)
}

func dlpVerbMatches(c map[string]any, verb any) (bool, error) {
	vs := c["verbs"]
	if !rsTruthy(vs) {
		return true, nil
	}
	switch t := vs.(type) {
	case []any:
		for _, x := range t {
			if jsStrictEq(x, verb) {
				return true, nil
			}
		}
		return false, nil
	case string:
		return strings.Contains(t, jsValueString(verb)), nil
	}
	return false, errors.New("DLP: verbs must be a list")
}

func dlpClassFor(classes []any, ctx map[string]any) (map[string]any, error) {
	var applicable []map[string]any
	for _, o := range classes {
		c := rsMap(o)
		if c == nil {
			return nil, errors.New("DLP: a class must be an object")
		}
		m, err := dlpMatches(c["resource"], ctx["resource"])
		if err != nil {
			return nil, err
		}
		if !m {
			continue
		}
		v, err := dlpVerbMatches(c, ctx["verb"])
		if err != nil {
			return nil, err
		}
		if v {
			applicable = append(applicable, c)
		}
	}
	if len(applicable) == 0 {
		return nil, nil
	}
	res := func(c map[string]any) string { s, _ := c["resource"].(string); return s }
	sort.SliceStable(applicable, func(i, j int) bool {
		a, b := applicable[i], applicable[j]
		if s := rsCmp(dlpSpecificity(res(b)) - dlpSpecificity(res(a))); s != 0 {
			return s < 0
		}
		return rsCmp(dlpStrictness(a)-dlpStrictness(b)) < 0
	})
	return applicable[0], nil
}

func dlpMalformed(policy, cls map[string]any) bool {
	if cls != nil {
		return (rsHas(cls, "maxTaintForAuto") && !rsIsNum(cls["maxTaintForAuto"])) || (rsHas(cls, "hardDenyAbove") && !rsIsNum(cls["hardDenyAbove"]))
	}
	return rsHas(policy, "defaultMaxTaintForAuto") && !rsIsNum(policy["defaultMaxTaintForAuto"])
}

func dlpResult(outcome string, cls map[string]any, reason string) map[string]any {
	r := map[string]any{"outcome": outcome}
	if cls != nil && rsHas(cls, "name") {
		r["class"] = cls["name"]
	}
	if reason != "" {
		r["reason"] = reason
	}
	return r
}

// EvaluateDlp evaluates an action's data flow against the DLP policy. It fails CLOSED: a malformed policy or ceiling is a deny, and a
// taint that is not a finite number is treated as maximally tainted so it can never beat a ceiling. An error is returned only for a
// malformed class or context the reference refuses by throwing.
func EvaluateDlp(policy, ctx map[string]any) (map[string]any, error) {
	classes, ok := any(nil), false
	if policy != nil {
		classes, ok = policy["classes"]
	}
	list, isList := classes.([]any)
	if !ok || !isList {
		return dlpResult("deny", nil, "malformed DLP policy"), nil
	}
	cls, err := dlpClassFor(list, ctx)
	if err != nil {
		return nil, err
	}
	if dlpMalformed(policy, cls) {
		return dlpResult("deny", cls, "malformed DLP policy: ceilings must be numbers"), nil
	}
	var max any
	var hasMax bool
	if cls != nil {
		max, hasMax = cls["maxTaintForAuto"], rsHas(cls, "maxTaintForAuto")
	} else {
		max, hasMax = policy["defaultMaxTaintForAuto"], rsHas(policy, "defaultMaxTaintForAuto")
	}
	taint, bad := math.Inf(1), !rsFinite(ctx["taint"]) // a non-finite taint is maximally tainted even under an unbounded ceiling
	if rsFinite(ctx["taint"]) {
		taint = jsF(ctx["taint"])
	}
	if !hasMax {
		return dlpResult("allow", cls, ""), nil // no ceiling at all: nothing to compare against
	}
	m := jsF(max)
	label := "<default>"
	if cls != nil && cls["name"] != nil {
		label = jsValueString(cls["name"])
	}
	if cls != nil && rsHas(cls, "hardDenyAbove") && (bad || taint > jsF(cls["hardDenyAbove"])) {
		return dlpResult("deny", cls, "taint "+rsNumStr(taint)+" exceeds hard ceiling "+rsNumStr(jsF(cls["hardDenyAbove"]))+" for '"+label+"'"), nil
	}
	if bad || taint > m {
		return dlpResult("step_up", cls, "taint "+rsNumStr(taint)+" > "+rsNumStr(m)+" for '"+label+"' — needs human review"), nil
	}
	return dlpResult("allow", cls, ""), nil
}

func dlpClass(name string, resource any, max, hard float64) map[string]any {
	return map[string]any{"name": name, "resource": resource, "maxTaintForAuto": jsNumber(max), "hardDenyAbove": jsNumber(hard)}
}

// DefaultDlpPolicy is the preset: PII resources accept only clean (taint 0) autonomously and secrets hard-deny any taint. opts is
// {piiResource?, secretsResource?} and must not be nil.
func DefaultDlpPolicy(opts map[string]any) (map[string]any, error) {
	if opts == nil {
		return nil, errors.New("defaultDlpPolicy: opts must not be null")
	}
	classes := []any{}
	if rsTruthy(opts["piiResource"]) {
		classes = append(classes, dlpClass("pii", opts["piiResource"], 0, 2))
	}
	if rsTruthy(opts["secretsResource"]) {
		classes = append(classes, dlpClass("secrets", opts["secretsResource"], 0, 0))
	}
	return map[string]any{"classes": classes}, nil
}
