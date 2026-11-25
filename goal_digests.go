package pca

// Content digests of the goal-to-decision flow (the TypeScript reference is @atlasauth/pca-goal `digests`): strict canonical
// JSON, safe integers only. A float, a cycle or a lone surrogate panics (the Goal* wrappers return the error).

import "sort"

func goalDigestOf(v any) string {
	h, err := HashCanonical(v)
	if err != nil {
		panic(err)
	}
	return h
}

// goalGoalDigest is the digest of the whole signed Goal.
func goalGoalDigest(goal any) string {
	return goalDigestOf(map[string]any{"d": "atlas-pca/goal-ir/v1", "goal": goal})
}

// goalNlDigest is the digest of the instruction text a goal was interpreted from (what `Goal.nlDigest` must equal).
func goalNlDigest(instruction any) string {
	return goalDigestOf(map[string]any{"d": "atlas-pca/goal-nl/v1", "text": instruction})
}

// goalModelSetDigest is the digest of the model set that produced a goal: sorted (UTF-16 order), de-duplicated ids.
func goalModelSetDigest(models any) string {
	seen := map[string]bool{}
	ids := []string{}
	for _, m := range anlReqList(models) {
		s, ok := m.(string)
		if !ok {
			anlFail("model id is not a string")
		}
		if !seen[s] {
			seen[s] = true
			ids = append(ids, s)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return goalNormalizeU16Cmp(ids[i], ids[j]) < 0 })
	out := make([]any, len(ids))
	for i, s := range ids {
		out[i] = s
	}
	return goalDigestOf(map[string]any{"d": "atlas-pca/goal-model-set/v1", "models": out})
}

// goalApprovalDigest is the digest of an approval's covered fields: any changed member changes it.
func goalApprovalDigest(body any) string {
	return goalDigestOf(map[string]any{"d": "atlas-pca/goal-approval-body/v1", "body": body})
}

func goalStrWrap(f func() string) (s string, err error) {
	_, err = anlTry(func() any { s = f(); return nil })
	return
}

// GoalDigest, GoalNlDigest, GoalModelSetDigest and GoalApprovalDigest are the error-returning public forms.
func GoalDigest(goal any) (string, error) {
	return goalStrWrap(func() string { return goalGoalDigest(goal) })
}
func GoalNlDigest(instruction string) (string, error) {
	return goalStrWrap(func() string { return goalNlDigest(instruction) })
}
func GoalModelSetDigest(models []string) (string, error) {
	l := make([]any, len(models))
	for i, m := range models {
		l[i] = m
	}
	return goalStrWrap(func() string { return goalModelSetDigest(l) })
}
func GoalApprovalDigest(body any) (string, error) {
	return goalStrWrap(func() string { return goalApprovalDigest(body) })
}
