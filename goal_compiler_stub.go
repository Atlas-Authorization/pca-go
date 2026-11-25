//go:build !pcagoalkernel

package pca

import "errors"

// ErrGoalKernelNotBuilt is returned by every kernel-backed goal call when the package is built without the pcagoalkernel tag.
var ErrGoalKernelNotBuilt = errors.New("pca-goal: goal kernel not built (build with -tags pcagoalkernel after the proved kernel is extracted)")

func goalKernelUnavailable() { panic(ErrGoalKernelNotBuilt) }

func goalTypecheck(goal, ont any) []any {
	goalKernelUnavailable()
	return nil
}

func goalCompileGoal(goal, ont any) map[string]any {
	goalKernelUnavailable()
	return nil
}

func goalDecideGoal(goal, ont, act, hist any) string {
	goalKernelUnavailable()
	return ""
}

func goalDecidePolicy(goal, ont, act, hist any) map[string]any {
	goalKernelUnavailable()
	return nil
}

func goalRenderTape(goal any) GoalTape {
	goalKernelUnavailable()
	return nil
}
