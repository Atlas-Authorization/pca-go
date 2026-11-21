//go:build pcagoalkernel

package pca

// GoalCompileSelGoalProved is the typed front door of the proved compiler for selector goals: selector reasons, expansion, then the
// proved core compiler.
func GoalCompileSelGoalProved(sg, ont, cat any) (r map[string]any, err error) {
	return GoalCompileSelGoal(sg, ont, cat, goalCompileGoal)
}
