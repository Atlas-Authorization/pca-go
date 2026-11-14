package pca

import (
	"fmt"
	"sort"
)

// Policy classes (NIST NGAC idea): a decision is the meet of the answers of every class consulted, and the record names who said
// no. Fail-strict: no class is a deny, a malformed list, a duplicate or an unknown class is a deny. Total: nothing here panics.
// Port of packages/pca/src/policy-classes.ts; replays policy-classes-vectors.json.

var PolicyClasses = []string{"constitution", "regulatory", "org", "blueprint", "user"}

func policyClassIndex(c string) int {
	for i, x := range PolicyClasses {
		if x == c {
			return i
		}
	}
	return -1
}

// ClassVerdict is one class's answer: the revision and digest of its policy and its decision.
type ClassVerdict struct {
	Class    string
	Revision int64
	Digest   string
	Decision string
}

// ClassDecision is the combined record. Reason is "" when not set.
type ClassDecision struct {
	Decision    string
	Classes     []ClassVerdict
	DeniedBy    []string
	EscalatedBy []string
	Reason      string
}

// ClassVerdictsError: "" = a well-formed list (closed members, known classes, each at most once).
func ClassVerdictsError(list any) string {
	arr, ok := list.([]any)
	if !ok {
		return "policy classes must be an array"
	}
	if len(arr) > len(PolicyClasses) {
		return fmt.Sprintf("more than %d policy classes", len(PolicyClasses))
	}
	seen := map[string]bool{}
	for i, x := range arr {
		m, ok := x.(map[string]any)
		if !ok {
			return fmt.Sprintf("policy_classes[%d] must be an object", i)
		}
		for _, k := range jsKeys(m) {
			if k != "class" && k != "revision" && k != "digest" && k != "decision" {
				return fmt.Sprintf("policy_classes[%d] has unknown member '%s'", i, k)
			}
		}
		c, isStr := m["class"].(string)
		if !isStr || policyClassIndex(c) < 0 {
			return fmt.Sprintf("policy_classes[%d].class is not a known class", i)
		}
		if seen[c] {
			return fmt.Sprintf("policy class '%s' appears twice", c)
		}
		seen[c] = true
		if !k3Int(m["revision"]) {
			return fmt.Sprintf("policy_classes[%d].revision must be a non-negative safe integer", i)
		}
		if !k3Str(m["digest"], 128) {
			return fmt.Sprintf("policy_classes[%d].digest invalid", i)
		}
		if d, _ := m["decision"].(string); d != "allow" && d != "escalate" && d != "deny" {
			return fmt.Sprintf("policy_classes[%d].decision must be allow, escalate or deny", i)
		}
	}
	return ""
}

func classDeny(reason string) ClassDecision {
	return ClassDecision{Decision: "deny", Classes: []ClassVerdict{}, DeniedBy: []string{}, EscalatedBy: []string{}, Reason: reason}
}

// DecideClasses: the meet of the class decisions, classes in the fixed order of PolicyClasses.
func DecideClasses(list any) ClassDecision {
	arr, isArr := list.([]any)
	if isArr && len(arr) == 0 {
		return classDeny("no_policy_class")
	}
	if e := ClassVerdictsError(list); e != "" {
		return classDeny("malformed policy classes: " + e)
	}
	classes := make([]ClassVerdict, 0, len(arr))
	for _, x := range arr {
		m := x.(map[string]any)
		classes = append(classes, ClassVerdict{m["class"].(string), leaseInt(m["revision"]), m["digest"].(string), m["decision"].(string)})
	}
	sort.SliceStable(classes, func(a, b int) bool { return policyClassIndex(classes[a].Class) < policyClassIndex(classes[b].Class) })
	out := ClassDecision{Classes: classes, DeniedBy: []string{}, EscalatedBy: []string{}}
	ds := make([]string, len(classes))
	for i, c := range classes {
		ds[i] = c.Decision
		switch c.Decision {
		case "deny":
			out.DeniedBy = append(out.DeniedBy, c.Class)
		case "escalate":
			out.EscalatedBy = append(out.EscalatedBy, c.Class)
		}
	}
	out.Decision = MeetAll(ds...)
	return out
}
