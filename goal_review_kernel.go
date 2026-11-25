//go:build pcagoalkernel

package pca

// goalProvedKernel is the review kernel of the reference (`provedKernel`): compile, policy digest and the reference decision, backed
// by the proved goal kernel.
func goalProvedKernel() *GoalReviewKernel {
	return &GoalReviewKernel{Compile: goalCompileGoal, PolicyDigest: goalPolicyDigest, Decide: goalDecideGoal}
}

// GoalProvedKernel is goalProvedKernel.
func GoalProvedKernel() *GoalReviewKernel { return goalProvedKernel() }
