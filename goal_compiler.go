package pca

// Policy canonical bytes and digest, and the typed front door of the proved goal compiler (the TypeScript reference is
// @atlasauth/pca-goal `compiler`). The kernel itself (typecheck / compile / decide / render) is the Dafny-generated code behind the
// goalkernel package: it is wired in goal_compiler_kernel.go (build tag pcagoalkernel); without the tag goal_compiler_stub.go
// makes every kernel call fail with an explicit "goal kernel not built" error, so nothing ever decides without the proved code.

import (
	"crypto/sha256"
	"sort"
	"strings"
)

// goalCanonicalPolicy is the canonical text of a policy (sorted-key JSON, no floats), the input of the policy digest.
func goalCanonicalPolicy(p any) string {
	switch t := p.(type) {
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = goalCanonicalPolicy(x)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = anlQuote(k) + ":" + goalCanonicalPolicy(t[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return anlJSON(p)
}

func goalPolicyDigest(p any) string {
	h := sha256.Sum256([]byte(goalCanonicalPolicy(p)))
	return b64.EncodeToString(h[:])
}

// GoalCanonicalPolicy is the canonical text of a policy.
func GoalCanonicalPolicy(p any) string { return goalCanonicalPolicy(p) }

// GoalPolicyDigest is the policy digest (G-T5).
func GoalPolicyDigest(p any) string { return goalPolicyDigest(p) }

// GoalTypecheck returns the type reasons of a goal against an ontology; empty = well typed. ErrGoalKernelNotBuilt without the tag.
func GoalTypecheck(goal, ont any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalTypecheck(goal, ont); return nil })
	return
}

// GoalCompileGoal is C: Goal -> Policy | Escalate(reasons): {ok:true, policy} or {ok:false, reasons}.
func GoalCompileGoal(goal, ont any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalCompileGoal(goal, ont); return nil })
	return
}

// GoalDecideGoal is the reference semantics D_G(a, H): "allow", "escalate" or "deny".
func GoalDecideGoal(goal, ont, act, hist any) (d string, err error) {
	_, err = anlTry(func() any { d = goalDecideGoal(goal, ont, act, hist); return nil })
	return
}

// GoalDecidePolicy is the compiled policy's decision with the witness of an Allow and the checker's verdict on it.
func GoalDecidePolicy(goal, ont, act, hist any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalDecidePolicy(goal, ont, act, hist); return nil })
	return
}

// GoalRenderTape is the card as a token tape: decodeGoal(renderTape(g)) equals g.
func GoalRenderTape(goal any) (t GoalTape, err error) {
	_, err = anlTry(func() any { t = goalRenderTape(goal); return nil })
	return
}
