package pca

// GoalDefaultRisk is the public form of the pca-goal export DEFAULT_RISK.
var GoalDefaultRisk = goalDefaultRisk

// GoalExpectedVerbs is the public form of the pca-goal export expectedVerbs.
func GoalExpectedVerbs(g any) []any {
	return goalExpectedVerbs(g)
}

// GoalDefaultDrift is the public form of the pca-goal export DEFAULT_DRIFT.
func GoalDefaultDrift() map[string]any {
	return goalDefaultDrift()
}

// GoalMkAct is the public form of the pca-goal export mkAct.
func GoalMkAct(verb string, res string, params map[string]any, over map[string]any) map[string]any {
	return goalMkAct(verb, res, params, over)
}

// GoalBuildSpace is the public form of the pca-goal export buildSpace.
func GoalBuildSpace(goals any, extraVerbs []string) *GoalSpace {
	return goalBuildSpace(goals, extraVerbs)
}

// GoalCheckGoalTests is the public form of the pca-goal export checkGoalTests.
func GoalCheckGoalTests(s any, pins any, decide func(t any) string) map[string]any {
	return goalCheckGoalTests(s, pins, decide)
}

// GoalExpectedDecision is the public form of the pca-goal export expectedDecision.
func GoalExpectedDecision(a any) string {
	return goalExpectedDecision(a)
}

// GoalMakeGoalTests is the public form of the pca-goal export makeGoalTests.
func GoalMakeGoalTests(g any, confirmed any) map[string]any {
	return goalMakeGoalTests(g, confirmed)
}

// GoalSignGoalTests is the public form of the pca-goal export signGoalTests.
func GoalSignGoalTests(s any, secret any, rest ...any) map[string]any {
	return goalSignGoalTests(s, secret, rest...)
}

// GoalSignPin is the public form of the pca-goal export signPin.
func GoalSignPin(p any, secret any, rest ...any) map[string]any {
	return goalSignPin(p, secret, rest...)
}

// GoalMaxCells is the public form of the pca-goal export MAX_CELLS.
const GoalMaxCells = goalMaxCells

// GoalCellKey is the public form of the pca-goal export cellKey.
func GoalCellKey(sp *GoalSpace, c any) string {
	return goalCellKey(sp, c)
}

// GoalAllowWitness is the public form of the pca-goal export allowWitness.
func GoalAllowWitness(g any, gr any, ont any) map[string]any {
	return goalAllowWitness(g, gr, ont)
}

// GoalReviewSet is the public form of the pca-goal export reviewSet.
func GoalReviewSet(examples any, cap int) []any {
	return goalReviewSet(examples, cap)
}

// GoalCcyExponent is the public form of the pca-goal export CCY_EXPONENT.
var GoalCcyExponent = goalCcyExponent

// GoalFmtAct is the public form of the pca-goal export fmtAct.
func GoalFmtAct(a any) string {
	return goalFmtAct(a)
}

// GoalFmtMoney is the public form of the pca-goal export fmtMoney.
func GoalFmtMoney(ccy any, minor any) string {
	return goalFmtMoney(ccy, minor)
}

// GoalFmtQuantity is the public form of the pca-goal export fmtQuantity.
func GoalFmtQuantity(q any) any {
	return goalFmtQuantity(q)
}

// GoalFmtValue is the public form of the pca-goal export fmtValue.
func GoalFmtValue(v any) any {
	return goalFmtValue(v)
}

// GoalReviewLimits is the public form of the pca-goal export REVIEW_LIMITS.
func GoalReviewLimits(o any) map[string]int64 {
	return goalReviewLimits(o)
}

// GoalMutationKinds is the public form of the pca-goal export MUTATION_KINDS.
var GoalMutationKinds = goalMutationKinds

// GoalAllowClassVerbs is the public form of the pca-goal export allowClassVerbs.
func GoalAllowClassVerbs(cat any, allOf any, noneOf any) []any {
	return goalAllowClassVerbs(cat, allOf, noneOf)
}

// GoalClassVerbs is the public form of the pca-goal export classVerbs.
func GoalClassVerbs(cat any, allOf any, noneOf any) []any {
	return goalClassVerbs(cat, allOf, noneOf)
}

// GoalFloatClassVerbs is the public form of the pca-goal export floatClassVerbs.
func GoalFloatClassVerbs(cat any, allOf any, noneOf any) []any {
	return goalFloatClassVerbs(cat, allOf, noneOf)
}

// GoalSelCatalogOfDefs is the public form of the pca-goal export selCatalogOfDefs.
func GoalSelCatalogOfDefs(defs any, reg Registry, review any) map[string]any {
	return goalSelCatalogOfDefs(defs, reg, review)
}

// GoalSelCatalogOfDomain is the public form of the pca-goal export selCatalogOfDomain.
func GoalSelCatalogOfDomain(domain any) any {
	return goalSelCatalogOfDomain(domain)
}

// GoalUnreviewed is the public form of the pca-goal export UNREVIEWED.
const GoalUnreviewed = goalUnreviewed

// GoalSelIdRe is the public form of the pca-goal export SEL_ID_RE.
var GoalSelIdRe = goalSelIDRE
