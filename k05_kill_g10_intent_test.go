package pca

import "testing"

func TestG10DecideIntentApprovedGoalMisconfigured(t *testing.T) {
	const want = "intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)"
	for name, p := range map[string]*IntentPolicy{
		"approved_goal not a closed object": {approvedGoalBad: true},
		"approved_goal digest malformed":    {ApprovedGoal: &ApprovedGoalRef{GoalDigest: "x", PolicyDigest: "y"}},
	} {
		if ev, why := decideIntent(map[string]any{}, map[string]any{}, p); !ev || why != want {
			t.Errorf("%s: %v %q", name, ev, why)
		}
	}
}
