package pca

import "strings"

// IntentGoal is the goal string that binds a grant to an intent statement (and optionally an Intent Map).
func IntentGoal(ref, mapDigest string) string {
	if mapDigest != "" {
		return intentGoalPrefix + ref + ":" + mapDigest
	}
	return intentGoalPrefix + ref
}

// ParseIntentGoal splits an intent goal string; ok is false when it is not one.
func ParseIntentGoal(goal string) (ref, mapDigest string, ok bool) {
	if !strings.HasPrefix(goal, intentGoalPrefix) {
		return "", "", false
	}
	parts := strings.Split(goal[len(intentGoalPrefix):], ":")
	if parts[0] == "" || len(parts) > 2 {
		return "", "", false
	}
	if len(parts) == 2 {
		return parts[0], parts[1], true
	}
	return parts[0], "", true
}
