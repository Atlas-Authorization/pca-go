package pca

// AnalyzerAnalyzeCaveats is the public form of the pca-analyzer export analyzeCaveats.
func AnalyzerAnalyzeCaveats(caveats any) map[string]any {
	return anlAnalyzeCaveats(caveats)
}

// AnalyzerVetoesFromConstitution is the public form of the pca-analyzer export vetoesFromConstitution.
func AnalyzerVetoesFromConstitution(c any) map[string]any {
	return anlVetoesFromConstitution(c)
}

// AnalyzerCoverageGate is the public form of the pca-analyzer export coverageGate.
func AnalyzerCoverageGate(r any, minimum any) map[string]any {
	return anlCoverageGate(r, minimum)
}

// AnalyzerPermitId is the public form of the pca-analyzer export permitId.
func AnalyzerPermitId(i int) string {
	return anlPermitID(i)
}

// AnalyzerWitnessOf is the public form of the pca-analyzer export witnessOf.
func AnalyzerWitnessOf(model map[string]any, action any) map[string]any {
	return anlWitnessOf(model, action)
}

// AnalyzerDagExposure is the public form of the pca-analyzer export dagExposure.
func AnalyzerDagExposure(b any) map[string]any {
	return anlDagExposure(b)
}

// AnalyzerDefaultMaxCombinations is the public form of the pca-analyzer export DEFAULT_MAX_COMBINATIONS.
const AnalyzerDefaultMaxCombinations = anlDefaultMaxCombinations

// AnalyzerAdmitsAction is the public form of the pca-analyzer export admitsAction.
func AnalyzerAdmitsAction(model map[string]any, action any) bool {
	return anlAdmitsAction(model, action)
}

// AnlProbes is the public name of anlProbes.
type AnlProbes = anlProbes

// AnalyzerCollectProbes is the public form of the pca-analyzer export collectProbes.
func AnalyzerCollectProbes(inputs map[string]any) *AnlProbes {
	return anlCollectProbes(inputs)
}

// AnalyzerDecideAction is the public form of the pca-analyzer export decideAction.
func AnalyzerDecideAction(model map[string]any, action any) string {
	return anlDecideAction(model, action)
}

// AnalyzerProbeSet is the public form of the pca-analyzer export probeSet.
func AnalyzerProbeSet(m map[string]any) []any {
	return anlProbeSet(m)
}

// AnlRep is the public name of anlRep.
type AnlRep = anlRep

// AnalyzerRepToAction is the public form of the pca-analyzer export repToAction.
func AnalyzerRepToAction(rep *AnlRep) map[string]any {
	return anlRepToAction(rep)
}

// AnalyzerToModel is the public form of the pca-analyzer export toModel.
func AnalyzerToModel(p any) map[string]any {
	return anlToModel(p)
}

// AnalyzerVetoApplies is the public form of the pca-analyzer export vetoApplies.
func AnalyzerVetoApplies(v any, ctx map[string]any) bool {
	return anlVetoApplies(v, ctx)
}

// AnalyzerDelegationEnvelope is the public form of the pca-analyzer export delegationEnvelope.
func AnalyzerDelegationEnvelope(chainIn any, opts any) map[string]any {
	return anlDelegationEnvelope(chainIn, opts)
}

// AnalyzerDiffGate is the public form of the pca-analyzer export diffGate.
func AnalyzerDiffGate(d any, allowIn any) map[string]any {
	return anlDiffGate(d, allowIn)
}

// AnalyzerDiffPolicies is the public form of the pca-analyzer export diffPolicies.
func AnalyzerDiffPolicies(a any, b any, optsIn any) map[string]any {
	return anlDiffPolicies(a, b, optsIn)
}

// AnalyzerEscalationSurface is the public form of the pca-analyzer export escalationSurface.
func AnalyzerEscalationSurface(policy any, opts any) map[string]any {
	return anlEscalationSurface(policy, opts)
}

// AnalyzerFindWithBackend is the public form of the pca-analyzer export findWithBackend.
func AnalyzerFindWithBackend(q any, name any, result any) map[string]any {
	return anlFindWithBackend(q, name, result)
}

// AnalyzerMaxExposure is the public form of the pca-analyzer export maxExposure.
func AnalyzerMaxExposure(policy any, given any) map[string]any {
	return anlMaxExposure(policy, given)
}

// AnalyzerThresholdsOf is the public form of the pca-analyzer export thresholdsOf.
func AnalyzerThresholdsOf(model map[string]any, path string) []any {
	return anlThresholdsOf(model, path)
}

// AnalyzerFullInterval is the public form of the pca-analyzer export FULL_INTERVAL.
var AnalyzerFullInterval = anlFullInterval

// AnlIv is the public name of anlIv.
type AnlIv = anlIv

// AnalyzerIntervalEmpty is the public form of the pca-analyzer export intervalEmpty.
func AnalyzerIntervalEmpty(iv AnlIv) bool {
	return anlIntervalEmpty(iv)
}

// AnalyzerNumericConjunctionSatisfiable is the public form of the pca-analyzer export numericConjunctionSatisfiable.
func AnalyzerNumericConjunctionSatisfiable(conditions any) bool {
	return anlNumericConjunctionSatisfiable(conditions)
}

// AnalyzerEvalFilter is the public form of the pca-analyzer export evalFilter.
func AnalyzerEvalFilter(e any, row any) any {
	return anlEvalFilter(e, row)
}

// AnalyzerEvalUcast is the public form of the pca-analyzer export evalUcast.
func AnalyzerEvalUcast(uv any, row any) bool {
	return anlEvalUcast(uv, row)
}

// AnalyzerToFilter is the public form of the pca-analyzer export toFilter.
func AnalyzerToFilter(res any, o any) (out map[string]any) {
	return anlToFilter(res, o)
}

// AnalyzerToUcast is the public form of the pca-analyzer export toUcast.
func AnalyzerToUcast(e any) map[string]any {
	return anlToUcast(e)
}

// AnalyzerMinimalFlip is the public form of the pca-analyzer export minimalFlip.
func AnalyzerMinimalFlip(policy any, action any, o any) map[string]any {
	return anlMinimalFlip(policy, action, o)
}

// AnalyzerAlwaysAllows is the public form of the pca-analyzer export alwaysAllows.
func AnalyzerAlwaysAllows(policy any, verb any, opts any) map[string]any {
	return anlAlwaysAllows(policy, verb, opts)
}

// AnalyzerAlwaysDenies is the public form of the pca-analyzer export alwaysDenies.
func AnalyzerAlwaysDenies(policy any, verb any, opts any) map[string]any {
	return anlAlwaysDenies(policy, verb, opts)
}

// AnalyzerDisjoint is the public form of the pca-analyzer export disjoint.
func AnalyzerDisjoint(a any, b any, opts any) map[string]any {
	return anlDisjoint(a, b, opts)
}

// AnalyzerIntentConformance is the public form of the pca-analyzer export intentConformance.
func AnalyzerIntentConformance(policy any, intent any, opts any) map[string]any {
	return anlIntentConformance(policy, intent, opts)
}

// AnalyzerPredicateNumericSatisfiable is the public form of the pca-analyzer export predicateNumericSatisfiable.
func AnalyzerPredicateNumericSatisfiable(where any) bool {
	return anlPredicateNumericSatisfiable(where)
}

// AnalyzerSubsumes is the public form of the pca-analyzer export subsumes.
func AnalyzerSubsumes(a any, b any, opts any) map[string]any {
	return anlSubsumes(a, b, opts)
}

// AnalyzerAccessRequestSigDomain is the public form of the pca-analyzer export ACCESS_REQUEST_SIG_DOMAIN.
const AnalyzerAccessRequestSigDomain = anlAccessRequestSigDomain

// AnalyzerSignAccessRequest is the public form of the pca-analyzer export signAccessRequest.
func AnalyzerSignAccessRequest(r any, kp *KeyPair) map[string]any {
	return anlSignAccessRequest(r, kp)
}

// AnalyzerSuggestNarrowing is the public form of the pca-analyzer export suggestNarrowing.
func AnalyzerSuggestNarrowing(policy any, observedIn any, optsIn any) map[string]any {
	return anlSuggestNarrowing(policy, observedIn, optsIn)
}

// AnalyzerVerifyAccessRequest is the public form of the pca-analyzer export verifyAccessRequest.
func AnalyzerVerifyAccessRequest(sv any, expected any) (ok bool) {
	return anlVerifyAccessRequest(sv, expected)
}

// AnalyzerEvaluateResidual is the public form of the pca-analyzer export evaluateResidual.
func AnalyzerEvaluateResidual(r any, ctx any) string {
	return anlEvaluateResidual(r, ctx)
}

// AnalyzerPolicyDigestOf is the public form of the pca-analyzer export policyDigestOf.
func AnalyzerPolicyDigestOf(model map[string]any) string {
	return anlPolicyDigestOf(model)
}

// AnalyzerResidualPolicy is the public form of the pca-analyzer export residualPolicy.
func AnalyzerResidualPolicy(r any) map[string]any {
	return anlResidualPolicy(r)
}

// AnalyzerWhatMayIDo is the public form of the pca-analyzer export whatMayIDo.
func AnalyzerWhatMayIDo(policy any, verbs any, knownIn any, oIn any) []any {
	return anlWhatMayIDo(policy, verbs, knownIn, oIn)
}

// AnalyzerPolicyTestsKind is the public form of the pca-analyzer export POLICY_TESTS_KIND.
const AnalyzerPolicyTestsKind = anlPolicyTestsKind

// AnalyzerPolicyTestsSigDomain is the public form of the pca-analyzer export POLICY_TESTS_SIG_DOMAIN.
const AnalyzerPolicyTestsSigDomain = anlPolicyTestsSigDomain

// AnalyzerDecideAll is the public form of the pca-analyzer export decideAll.
func AnalyzerDecideAll(policy any, doc any) []any {
	return anlDecideAll(policy, doc)
}

// AnalyzerGenerateBoundaryTests is the public form of the pca-analyzer export generateBoundaryTests.
func AnalyzerGenerateBoundaryTests(policy any, optsIn any) map[string]any {
	return anlGenerateBoundaryTests(policy, optsIn)
}

// AnalyzerPolicyTestsDoc is the public form of the pca-analyzer export policyTestsDoc.
func AnalyzerPolicyTestsDoc(policy any, cases any) map[string]any {
	return anlPolicyTestsDoc(policy, cases)
}

// AnalyzerRunPolicyTests is the public form of the pca-analyzer export runPolicyTests.
func AnalyzerRunPolicyTests(policy any, doc any, optsIn any) map[string]any {
	return anlRunPolicyTests(policy, doc, optsIn)
}

// AnalyzerSignPolicyTests is the public form of the pca-analyzer export signPolicyTests.
func AnalyzerSignPolicyTests(doc any, kp *KeyPair) map[string]any {
	return anlSignPolicyTests(doc, kp)
}

// AnalyzerVerifyPolicyTests is the public form of the pca-analyzer export verifyPolicyTests.
func AnalyzerVerifyPolicyTests(s any, expected any) (ok bool) {
	return anlVerifyPolicyTests(s, expected)
}

// AnalyzerReversibilityOrder is the public form of the pca-analyzer export REVERSIBILITY_ORDER.
var AnalyzerReversibilityOrder = reversibilityOrder

// AnalyzerValidatePolicyAgainstSchema is the public form of the pca-analyzer export validatePolicyAgainstSchema.
func AnalyzerValidatePolicyAgainstSchema(policy any, src any, optsIn any) map[string]any {
	return anlValidatePolicyAgainstSchema(policy, src, optsIn)
}

// AnalyzerVerbShapes is the public form of the pca-analyzer export verbShapes.
func AnalyzerVerbShapes(src any) []any {
	return anlVerbShapes(src)
}

// AnalyzerVerbShapesFromActionDefs is the public form of the pca-analyzer export verbShapesFromActionDefs.
func AnalyzerVerbShapesFromActionDefs(defs any) []any {
	return anlVerbShapesFromActionDefs(defs)
}
