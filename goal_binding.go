package pca

// Decision-to-effect binding and the claimed-fidelity gate (the TypeScript reference is @atlasauth/pca-goal `binding`).

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// goalActionDigest is the digest of exactly the action that was decided: verb, resource and every parameter.
func goalActionDigest(a any) string {
	return goalDigestOf(map[string]any{"d": "atlas-pca/goal-action/v1", "act": a})
}

func goalBindDecision(a any, decision string) map[string]any {
	return map[string]any{"decision": decision, "action_digest": goalActionDigest(a)}
}

// goalGuardExecute is true only for an `allow` bound to exactly this action (swapped params or verb, escalate, deny all refuse). Total.
func goalGuardExecute(b any, executed any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	m, isMap := b.(map[string]any)
	if !isMap || m["decision"] != "allow" {
		return false
	}
	x, isStr := m["action_digest"].(string)
	if !isStr {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(x), []byte(goalActionDigest(executed))) == 1
}

// goalClaimGate: an agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, only downward
// (escalate); a NaN or non-numeric replay is unconfirmed and tightens. A nil replay is the reference's undefined.
func goalClaimGate(base string, minPpm any, replayed any) string {
	if replayed == nil {
		return base
	}
	r, rOK := jsNum(replayed)
	m, mOK := jsNum(minPpm)
	if rOK && mOK && r >= m {
		return base
	}
	return TightenDecision(base, "escalate")
}

// goalGoalCommit is the hiding goal commitment (goal binding v3): sha256("pca-goal:v3:commit:<goal>:<policy>:<salt>"), base64url.
func goalGoalCommit(goalDigest, policyDigest, salt any) string {
	h := sha256.Sum256([]byte(wellFormedUTF8(fmt.Sprintf("pca-goal:v3:commit:%s:%s:%s", anlJS(goalDigest), anlJS(policyDigest), anlJS(salt)))))
	return b64.EncodeToString(h[:])
}

// goalOpenCommit is the constant-time check that `commit` opens to (goal, policy, salt); a non-string commit panics.
func goalOpenCommit(commit, goalDigest, policyDigest, salt any) bool {
	c, ok := commit.(string)
	if !ok {
		anlFail("commit must be a string")
	}
	return subtle.ConstantTimeCompare([]byte(c), []byte(goalGoalCommit(goalDigest, policyDigest, salt))) == 1
}

// GoalActionDigest is the digest of an action.
func GoalActionDigest(a any) (string, error) {
	return goalStrWrap(func() string { return goalActionDigest(a) })
}

// GoalBindDecision binds a decision to its action's digest.
func GoalBindDecision(a any, decision string) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalBindDecision(a, decision); return nil })
	return
}

// GoalGuardExecute is true only for an allow bound to exactly this action. Total.
func GoalGuardExecute(b any, executed any) bool { return goalGuardExecute(b, executed) }

// GoalClaimGate applies the claimed-fidelity gate; replayed nil = not replayed.
func GoalClaimGate(base string, minPpm any, replayed any) string {
	return goalClaimGate(base, minPpm, replayed)
}

// GoalGoalCommit is the hiding goal commitment of goal binding v3.
func GoalGoalCommit(goalDigest, policyDigest, salt string) string {
	return goalGoalCommit(goalDigest, policyDigest, salt)
}

// GoalOpenCommit reports whether commit opens to (goal, policy, salt), in constant time.
func GoalOpenCommit(commit, goalDigest, policyDigest, salt string) bool {
	return goalOpenCommit(commit, goalDigest, policyDigest, salt)
}
