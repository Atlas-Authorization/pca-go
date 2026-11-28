package pca

// IntentRef is the public form of the pca-intent export intentRef.
func IntentRef(s map[string]any) string {
	return ixIntentRef(s)
}

// IntentGoalPrefix is the public form of the pca-intent export INTENT_GOAL_PREFIX.
const IntentGoalPrefix = intentGoalPrefix

// IntentLayerCeilings is the public form of the pca-intent export LAYER_CEILINGS.
var IntentLayerCeilings = ixLayerCeilings

// IntentRefDomain is the public form of the pca-intent export INTENT_REF_DOMAIN.
const IntentRefDomain = ixIntentRefDomain

// IntentSigDomain is the public form of the pca-intent export INTENT_SIG_DOMAIN.
const IntentSigDomain = ixIntentSigDomain

// IntentDecideLayerCeilings is the public form of the pca-intent export decideLayerCeilings.
func IntentDecideLayerCeilings(layers any, actx map[string]any) string {
	return decideLayerCeilings(layers, actx)
}

// IntentCalibrateConfusion is the public form of the pca-intent export calibrateConfusion.
func IntentCalibrateConfusion(samples []any, labels []any, deltaGamma float64) map[string]any {
	return ixCalibrateConfusion(samples, labels, deltaGamma)
}

// IntentClassifierCardNote is the public form of the pca-intent export classifierCardNote.
func IntentClassifierCardNote(id string, c map[string]any) string {
	return ixClassifierCardNote(id, c)
}

// IntentClassifierRisk is the public form of the pca-intent export classifierRisk.
func IntentClassifierRisk(m map[string]any) float64 {
	return ixClassifierRisk(m)
}

// IntentConfusionDigest is the public form of the pca-intent export confusionDigest.
func IntentConfusionDigest(c map[string]any) string {
	return ixConfusionDigest(c)
}

// IntentLabelSound is the public form of the pca-intent export labelSound.
func IntentLabelSound(m map[string]any) bool {
	return ixLabelSound(m)
}

// IntentLabelSoundBound is the public form of the pca-intent export labelSoundBound.
func IntentLabelSoundBound(m map[string]any, hMax float64) float64 {
	return ixLabelSoundBound(m, hMax)
}

// IntentPublishedErrorRate is the public form of the pca-intent export publishedErrorRate.
func IntentPublishedErrorRate(c map[string]any) float64 {
	return ixPublishedErrorRate(c)
}

// IntentCpGridBits is the public form of the pca-intent export CP_GRID_BITS.
const IntentCpGridBits = cpGridBits

// IntentAnalyzeDisagreement is the public form of the pca-intent export analyzeDisagreement.
func IntentAnalyzeDisagreement(outputs []any, opts map[string]any) map[string]any {
	return ixAnalyzeDisagreement(outputs, opts)
}

// IntentCommitteeAnchors is the public form of the pca-intent export committeeAnchors.
func IntentCommitteeAnchors(outputs []any, lam any) []any {
	return ixCommitteeAnchors(outputs, lam)
}

// IntentPanelFlags is the public form of the pca-intent export panelFlags.
func IntentPanelFlags(r map[string]any) bool {
	return ixPanelFlags(r)
}

// IntentParseSlotsJSON is the public form of the pca-intent export parseSlotsJSON.
func IntentParseSlotsJSON(raw string, catalog any) map[string]any {
	return ixParseSlotsJSON(raw, catalog)
}

// IntentSlotsPrompt is the public form of the pca-intent export slotsPrompt.
func IntentSlotsPrompt(text string, catalog any) string {
	return ixSlotsPrompt(text, catalog)
}

// IntentDefaultPostconditions is the public form of the pca-intent export DEFAULT_POSTCONDITIONS.
func IntentDefaultPostconditions() []any {
	return ixDefaultPostconditions()
}

// IntentCheckPostconditions is the public form of the pca-intent export checkPostconditions.
func IntentCheckPostconditions(vs map[string]any, o map[string]any, effect any, pcs []any) map[string]any {
	return ixCheckPostconditions(vs, o, effect, pcs)
}

// IntentEffectContext is the public form of the pca-intent export effectContext.
func IntentEffectContext(vs map[string]any, o map[string]any, effect any) map[string]any {
	return ixEffectContext(vs, o, effect)
}

// IntentFrameStateDomain is the public form of the pca-intent export FRAME_STATE_DOMAIN.
const IntentFrameStateDomain = ixFrameStateDomain

// IntentCheckFrame is the public form of the pca-intent export checkFrame.
func IntentCheckFrame(spec any, action any, pre any, post any, opts map[string]any) map[string]any {
	return ixCheckFrame(spec, action, pre, post, opts)
}

// IntentSnapshotState is the public form of the pca-intent export snapshotState.
func IntentSnapshotState(values map[string]any, keepValues bool) map[string]any {
	return ixSnapshotState(values, keepValues)
}

// IntentWriteSetOf is the public form of the pca-intent export writeSetOf.
func IntentWriteSetOf(spec map[string]any, action map[string]any) []string {
	return ixWriteSetOf(spec, action)
}

// IntentCellFromCoords is the public form of the pca-intent export cellFromCoords.
func IntentCellFromCoords(vs map[string]any, coordsV any) any {
	return ixCellFromCoords(vs, coordsV)
}

// IntentRequiredBody is the public form of the pca-intent export intentRequiredBody.
func IntentRequiredBody(i map[string]any) map[string]any {
	return ixIntentRequiredBody(i)
}

// IntentCellCoords is the public form of the pca-intent export cellCoords.
func IntentCellCoords(vs map[string]any, cell []any) map[string]any {
	return ixCellCoords(vs, cell)
}

// IntentLayerApprovalDomain is the public form of the pca-intent export LAYER_APPROVAL_DOMAIN.
const IntentLayerApprovalDomain = ixLayerApprovalDomain

// IntentAssertAskable is the public form of the pca-intent export assertAskable.
func IntentAssertAskable(view map[string]any, c map[string]any) {
	ixAssertAskable(view, c)
}

// IntentCeilingOf is the public form of the pca-intent export ceilingOf.
func IntentCeilingOf(c map[string]*IntentAdmitter, vs map[string]any, o map[string]any) any {
	return ixCeilingOf(c, vs, o)
}

// IntentCellKeyOf is the public form of the pca-intent export cellKeyOf.
func IntentCellKeyOf(omega map[string]any, c map[string]any) string {
	return ixCellKeyOf(omega, c)
}

// IntentLayerCells is the public form of the pca-intent export layerCells.
func IntentLayerCells(omega map[string]any, a *IntentAdmitter) []any {
	return ixLayerCells(omega, a)
}

// IntentOwnerRisk is the public form of the pca-intent export ownerRisk.
func IntentOwnerRisk(omega map[string]any, cells []any, acceptability func(vs, o map[string]any) float64) float64 {
	return ixOwnerRisk(omega, cells, acceptability)
}

// IntentSignLayerApproval is the public form of the pca-intent export signLayerApproval.
func IntentSignLayerApproval(s map[string]any, seedB64 string) map[string]any {
	return ixSignLayerApproval(s, seedB64)
}

// IntentLearnerOptionsOf is the public form of the pca-intent export learnerOptionsOf.
func IntentLearnerOptionsOf(l *IntentLearner) map[string]any {
	return ixMkLearnerOptionsOf(l)
}

// IntentAcceptabilityOf is the public form of the pca-intent export acceptabilityOf.
func IntentAcceptabilityOf(policy any) func(vs, o map[string]any) float64 {
	return ixAcceptabilityOf(policy)
}

// IntentMeasureGrant is the public form of the pca-intent export measureGrant.
func IntentMeasureGrant(omega map[string]any, grant any, acceptability func(vs, o map[string]any) float64, opts map[string]any) map[string]any {
	return ixMeasureGrant(omega, grant, acceptability, opts)
}

// IntentMeasureGrantExact is the public form of the pca-intent export measureGrantExact.
func IntentMeasureGrantExact(omega map[string]any, grant any, acceptability func(vs, o map[string]any) float64) map[string]any {
	return ixMeasureGrantExact(omega, grant, acceptability)
}

// IntentEffectiveVetoers is the public form of the pca-intent export effectiveVetoers.
func IntentEffectiveVetoers(rule any, refs []string) []any {
	return ixEffectiveVetoers(rule, refs)
}

// IntentJointAcceptance is the public form of the pca-intent export jointAcceptance.
func IntentJointAcceptance(n map[string]any, ps []any) float64 {
	return ixJointAcceptance(n, ps)
}

// IntentNormalizeRule is the public form of the pca-intent export normalizeRule.
func IntentNormalizeRule(rule any, refs []string) map[string]any {
	return ixNormalizeRule(rule, refs)
}

// IntentRuleAdmits is the public form of the pca-intent export ruleAdmits.
func IntentRuleAdmits(n map[string]any, ins []any) bool {
	return ixRuleAdmits(n, ins)
}

// IntentDefaultHarm is the public form of the pca-intent export DEFAULT_HARM.
var IntentDefaultHarm = ixDefaultHarm

// IntentExactSpan is the public form of the pca-intent export EXACT_SPAN.
const IntentExactSpan = ixExactSpan

// IntentCatCellOf is the public form of the pca-intent export catCellOf.
func IntentCatCellOf(d map[string]any, s string) int {
	return ixCatCellOf(d, s)
}

// IntentCatRep is the public form of the pca-intent export catRep.
func IntentCatRep(d map[string]any, i int) string {
	return ixCatRep(d, i)
}

// IntentCellCount is the public form of the pca-intent export cellCount.
func IntentCellCount(d map[string]any) int {
	return ixCellCount(d)
}

// IntentCellOf is the public form of the pca-intent export cellOf.
func IntentCellOf(vs map[string]any, o map[string]any) []any {
	return ixCellOf(vs, o)
}

// IntentCellOfValue is the public form of the pca-intent export cellOfValue.
func IntentCellOfValue(d map[string]any, x any) int {
	return ixCellOfValue(d, x)
}

// IntentCellRep is the public form of the pca-intent export cellRep.
func IntentCellRep(vs map[string]any, idx []any) map[string]any {
	return ixCellRep(vs, idx)
}

// IxHarm is the public name of ixHarm.
type IxHarm = ixHarm

// IntentCellStats is the public form of the pca-intent export cellStats.
func IntentCellStats(vs map[string]any, idx []any, h *IxHarm) (mass float64, harm float64) {
	return ixCellStats(vs, idx, h)
}

// IntentDecodeCell is the public form of the pca-intent export decodeCell.
func IntentDecodeCell(vs map[string]any, flat float64) []any {
	return ixDecodeCell(vs, flat)
}

// IntentDimCellStats is the public form of the pca-intent export dimCellStats.
func IntentDimCellStats(d map[string]any, i int, h *IxHarm) (mass float64, harm float64) {
	return ixDimCellStats(d, i, h)
}

// IntentIntervalWeight is the public form of the pca-intent export intervalWeight.
func IntentIntervalWeight(d map[string]any, a float64, b float64) float64 {
	return ixIntervalWeight(d, a, b)
}

// IxCell is the public name of ixCell.
type IxCell = ixCell

// IntentNumCells is the public form of the pca-intent export numCells.
func IntentNumCells(d map[string]any) []IxCell {
	return ixNumCells(d)
}

// IntentNumRep is the public form of the pca-intent export numRep.
func IntentNumRep(d map[string]any, i int) float64 {
	return ixNumRep(d, i)
}

// IntentRepValue is the public form of the pca-intent export repValue.
func IntentRepValue(d map[string]any, i int) any {
	return ixRepValue(d, i)
}

// IntentVerbCellCount is the public form of the pca-intent export verbCellCount.
func IntentVerbCellCount(vs map[string]any) float64 {
	return ixVerbCellCount(vs)
}

// IntentVerbSpace is the public form of the pca-intent export verbSpace.
func IntentVerbSpace(omega map[string]any, verb string) any {
	return ixVerbSpace(omega, verb)
}

// IntentEncodeCell is the public form of the pca-intent export encodeCell.
func IntentEncodeCell(vs map[string]any, idx []any) float64 {
	return ixEncodeCell(vs, idx)
}

// IntentHarmMax is the public form of the pca-intent export harmMax.
func IntentHarmMax(omega map[string]any, h *IxHarm) float64 {
	return ixHarmMax(omega, h)
}

// IntentHarmOf is the public form of the pca-intent export harmOf.
func IntentHarmOf(vs map[string]any, o map[string]any, h *IxHarm) float64 {
	return ixHarmOf(vs, o, h)
}

// IntentSampleOutcome is the public form of the pca-intent export sampleOutcome.
func IntentSampleOutcome(omega map[string]any, rand func() float64) (map[string]any, map[string]any) {
	return ixSampleOutcome(omega, rand)
}

// IntentDefaultDomains is the public form of the pca-intent export DEFAULT_DOMAINS.
var IntentDefaultDomains = ixDefaultDomains

// IntentAnyResource is the public form of the pca-intent export ANY_RESOURCE.
const IntentAnyResource = ixAnyResource

// IntentNormalizePolicy is the public form of the pca-intent export normalizePolicy.
func IntentNormalizePolicy(p any) map[string]any {
	return ixNormalizePolicy(p)
}

// IntentOutcomeToAction is the public form of the pca-intent export outcomeToAction.
func IntentOutcomeToAction(vs map[string]any, o map[string]any) map[string]any {
	return ixOutcomeToAction(vs, o)
}

// IntentProfileDigest is the public form of the pca-intent export intentProfileDigest.
func IntentProfileDigest(p map[string]any) string {
	return ixIntentProfileDigest(p)
}

// IntentProfileApplies is the public form of the pca-intent export profileApplies.
func IntentProfileApplies(p map[string]any, u map[string]any) bool {
	return ixProfileApplies(p, u)
}

// IntentProfileCeiling is the public form of the pca-intent export profileCeiling.
func IntentProfileCeiling(p map[string]any, u map[string]any, vs map[string]any, o map[string]any) bool {
	return ixProfileCeiling(p, u, vs, o)
}

// IntentProfileVetoCells is the public form of the pca-intent export profileVetoCells.
func IntentProfileVetoCells(p map[string]any, omega map[string]any) []any {
	return ixProfileVetoCells(p, omega)
}

// IntentSignIntentProfile is the public form of the pca-intent export signIntentProfile.
func IntentSignIntentProfile(body map[string]any, seedB64 string) map[string]any {
	return ixSignIntentProfile(body, seedB64)
}

// IntentStandingAdmits is the public form of the pca-intent export standingAdmits.
func IntentStandingAdmits(p map[string]any, u map[string]any, action any) bool {
	return ixStandingAdmits(p, u, action)
}

// IntentStandingPermits is the public form of the pca-intent export standingPermits.
func IntentStandingPermits(p map[string]any, u map[string]any, action any) bool {
	return ixStandingPermits(p, u, action)
}

// IntentVerifyIntentProfile is the public form of the pca-intent export verifyIntentProfile.
func IntentVerifyIntentProfile(pv any, pin any) map[string]any {
	return ixVerifyIntentProfile(pv, pin)
}

// IntentVerifyProfileSuccession is the public form of the pca-intent export verifyProfileSuccession.
func IntentVerifyProfileSuccession(prev map[string]any, next map[string]any) map[string]any {
	return ixVerifyProfileSuccession(prev, next)
}

// IntentMaxProfileRules is the public form of the pca-intent export MAX_PROFILE_RULES.
const IntentMaxProfileRules = ixMaxProfileRules

// IntentIsTainted is the public form of the pca-intent export isTainted.
func IntentIsTainted(level any) bool {
	return ixIsTainted(level)
}

// IntentProvenanceBanner is the public form of the pca-intent export provenanceBanner.
func IntentProvenanceBanner(level any, what string) any {
	return ixProvenanceBanner(level, what)
}

// IntentProvenanceFriction is the public form of the pca-intent export provenanceFriction.
func IntentProvenanceFriction(base any, sensitivity any, level any) any {
	return ixProvenanceFriction(base, sensitivity, level)
}

// IntentWithinGrantRegret is the public form of the pca-intent export withinGrantRegret.
func IntentWithinGrantRegret(c IntentRegretCase) (regret float64, admitted bool) {
	return ixWithinGrantRegret(c)
}

// IntentNarrowStart is the public form of the pca-intent export narrowStart.
func IntentNarrowStart(omega map[string]any, slots map[string]any, opts map[string]any) map[string]any {
	return ixNarrowStart(omega, slots, opts)
}

// IntentRegionCells is the public form of the pca-intent export regionCells.
func IntentRegionCells(vs map[string]any, r map[string]any, mode string) []int {
	return ixRegionCells(vs, r, mode)
}

// IntentRegionOfCell is the public form of the pca-intent export regionOfCell.
func IntentRegionOfCell(vs map[string]any, idx []any) map[string]any {
	return ixRegionOfCell(vs, idx)
}

// IntentRestrictRegion is the public form of the pca-intent export restrictRegion.
func IntentRestrictRegion(r map[string]any, d map[string]any, part map[string]any) map[string]any {
	return ixRestrictRegion(r, d, part)
}

// IntentValueInRegionDim is the public form of the pca-intent export valueInRegionDim.
func IntentValueInRegionDim(path string, rd map[string]any, x any) bool {
	return ixValueInRegionDim(path, rd, x)
}

// IntentDimCellsIn is the public form of the pca-intent export dimCellsIn.
func IntentDimCellsIn(d map[string]any, rd map[string]any, mode string) []int {
	return ixDimCellsIn(d, rd, mode)
}

// IntentClaimsOf is the public form of the pca-intent export claimsOf.
func IntentClaimsOf(policy any, omega map[string]any) []any {
	return ixClaimsOf(policy, omega)
}

// IntentRenderQuestion is the public form of the pca-intent export renderQuestion.
func IntentRenderQuestion(vs map[string]any, cell []any, catalog any) string {
	return ixRenderQuestion(vs, cell, catalog)
}

// IntentBackTranslationDiff is the public form of the pca-intent export backTranslationDiff.
func IntentBackTranslationDiff(grant any, slots map[string]any, omega map[string]any) []any {
	return ixBackTranslationDiff(grant, slots, omega)
}

// IntentClaimDiff is the public form of the pca-intent export claimDiff.
func IntentClaimDiff(a any, b any, omega map[string]any, n0 string, n1 string) []any {
	return ixClaimDiff(a, b, omega, n0, n1)
}

// IntentRenderAction is the public form of the pca-intent export renderAction.
func IntentRenderAction(vs map[string]any, values map[string]any, catalog any) string {
	return ixRenderAction(vs, values, catalog)
}

// IntentRenderCaveat is the public form of the pca-intent export renderCaveat.
func IntentRenderCaveat(cv any) string {
	return ixRenderCaveat(cv)
}

// IntentRenderCondition is the public form of the pca-intent export renderCondition.
func IntentRenderCondition(cv any) string {
	return ixRenderCondition(cv)
}

// IntentRenderGrant is the public form of the pca-intent export renderGrant.
func IntentRenderGrant(policy any, catalog any) string {
	return ixRenderGrant(policy, catalog)
}

// IntentIcAttDomain is the public form of the pca-intent export IC_ATT_DOMAIN.
const IntentIcAttDomain = ixICAttDomain

// IntentCalibrationDigest is the public form of the pca-intent export calibrationDigest.
func IntentCalibrationDigest(c map[string]any) string {
	return ixCalibrationDigest(c)
}

// IntentFoldSemanticRisk is the public form of the pca-intent export foldSemanticRisk.
func IntentFoldSemanticRisk(r float64, att map[string]any) float64 {
	return ixFoldSemanticRisk(r, att)
}

// IntentIcAttDigest is the public form of the pca-intent export icAttDigest.
func IntentIcAttDigest(a map[string]any) string {
	return ixICAttDigest(a)
}

// IntentJitConsentDigest is the public form of the pca-intent export jitConsentDigest.
func IntentJitConsentDigest(r map[string]any) string {
	return ixJitConsentDigest(r)
}

// IntentJitConsentRequest is the public form of the pca-intent export jitConsentRequest.
func IntentJitConsentRequest(omega map[string]any, o map[string]any, p float64, ctx map[string]any, catalog any) map[string]any {
	return ixJitConsentRequest(omega, o, p, ctx, catalog)
}

// IntentJudgeInputOf is the public form of the pca-intent export judgeInputOf.
func IntentJudgeInputOf(omega map[string]any, o map[string]any, p float64, ctx map[string]any, catalog any) map[string]any {
	return ixJudgeInputOf(omega, o, p, ctx, catalog)
}

// IntentPcactnActionOf is the public form of the pca-intent export pcactnActionOf.
func IntentPcactnActionOf(vs map[string]any, o map[string]any) map[string]any {
	return ixPcactnActionOf(vs, o)
}

// IntentCanonValue is the public form of the pca-intent export canonValue.
func IntentCanonValue(d map[string]any, x any) string {
	return ixCanonValue(d, x)
}

// IntentDeriveOmegaFromSchema is the public form of the pca-intent export deriveOmegaFromSchema.
func IntentDeriveOmegaFromSchema(o map[string]any) map[string]any {
	return ixDeriveOmegaFromSchema(o)
}

// IntentSignIntent is the public form of the pca-intent export signIntent.
func IntentSignIntent(s map[string]any, seedB64 string) map[string]any {
	return ixSignIntent(s, seedB64)
}

// IntentVerifyIntent is the public form of the pca-intent export verifyIntent.
func IntentVerifyIntent(sv any, opts map[string]any) map[string]any {
	return ixVerifyIntent(sv, opts)
}

// IntentAccDimPrefix is the public form of the pca-intent export ACC_DIM_PREFIX.
const IntentAccDimPrefix = ixAccDimPrefix

// IntentMonDimPrefix is the public form of the pca-intent export MON_DIM_PREFIX.
const IntentMonDimPrefix = ixMonDimPrefix

// IntentAccDimPath is the public form of the pca-intent export accDimPath.
func IntentAccDimPath(id string) string {
	return ixAccDimPath(id)
}

// IntentAugmentOmega is the public form of the pca-intent export augmentOmega.
func IntentAugmentOmega(omega map[string]any, psi map[string]any, opts map[string]any) map[string]any {
	return ixAugmentOmega(omega, psi, opts)
}

// IntentDefaultAccumulators is the public form of the pca-intent export defaultAccumulators.
func IntentDefaultAccumulators(schema map[string]any, o map[string]any) []any {
	return ixDefaultAccumulators(schema, o)
}

// IntentDescribeAccCell is the public form of the pca-intent export describeAccCell.
func IntentDescribeAccCell(d map[string]any, cellIndex int, label string, thisAction any) string {
	return ixDescribeAccCell(d, cellIndex, label, thisAction)
}

// IntentDimKindOf is the public form of the pca-intent export dimKindOf.
func IntentDimKindOf(path string) string {
	return ixDimKindOf(path)
}

// IntentMonDimPath is the public form of the pca-intent export monDimPath.
func IntentMonDimPath(id string) string {
	return ixMonDimPath(id)
}

// IntentStepTrajectory is the public form of the pca-intent export stepTrajectory.
func IntentStepTrajectory(omegaTilde map[string]any, psi map[string]any, history []any, cand map[string]any, inGrant func(verb string, cell []any) bool, schema map[string]any) map[string]any {
	return ixStepTrajectory(omegaTilde, psi, history, cand, inGrant, schema)
}

// IntentTrajectoryHarmRange is the public form of the pca-intent export trajectoryHarmRange.
func IntentTrajectoryHarmRange(maxSessionLength any, harmMax any) float64 {
	return ixTrajectoryHarmRange(maxSessionLength, harmMax)
}

// IntentLiftAction is the public form of the pca-intent export liftAction.
func IntentLiftAction(omegaTilde map[string]any, psi map[string]any, history []any, cand map[string]any, schema map[string]any) map[string]any {
	return ixLiftAction(omegaTilde, psi, history, cand, schema)
}

// IntentQuestionCard is the public form of the pca-intent export questionCard.
func IntentQuestionCard(omega map[string]any, q map[string]any, catalog any) map[string]any {
	return ixQuestionCard(omega, q, catalog)
}

// IntentParseCardAnswer is the public form of the pca-intent export parseCardAnswer.
func IntentParseCardAnswer(card map[string]any, inp map[string]any) map[string]any {
	return ixParseCardAnswer(card, inp)
}

// IntentBoundaryWitnesses is the public form of the pca-intent export boundaryWitnesses.
func IntentBoundaryWitnesses(grant any, omega map[string]any, catalog any) []any {
	return ixBoundaryWitnesses(grant, omega, catalog)
}

// IntentCheckWitnesses is the public form of the pca-intent export checkWitnesses.
func IntentCheckWitnesses(ws []any, oracle func(w map[string]any) bool) map[string]any {
	return ixCheckWitnesses(ws, oracle)
}

// IntentClassPrefix is the public form of the pca-intent export CLASS_PREFIX.
const IntentClassPrefix = ixClassPrefix

// IntentProvPrefix is the public form of the pca-intent export PROV_PREFIX.
const IntentProvPrefix = ixProvPrefix

// IntentWorldPrefix is the public form of the pca-intent export WORLD_PREFIX.
const IntentWorldPrefix = ixWorldPrefix

// IntentClassifierDim is the public form of the pca-intent export classifierDim.
func IntentClassifierDim(id string, labels []string) map[string]any {
	return ixClassifierDim(id, labels)
}

// IntentExcessDim is the public form of the pca-intent export excessDim.
func IntentExcessDim(name string, hi any, slacks []any) map[string]any {
	return ixExcessDim(name, hi, slacks)
}

// IntentLiftOutcome is the public form of the pca-intent export liftOutcome.
func IntentLiftOutcome(o map[string]any, env map[string]any, dimPaths []any) map[string]any {
	return ixLiftOutcome(o, env, dimPaths)
}

// IntentOptimalityCondition is the public form of the pca-intent export optimalityCondition.
func IntentOptimalityCondition(name string, slack any) map[string]any {
	return ixOptimalityCondition(name, slack)
}

// IntentProvenanceDim is the public form of the pca-intent export provenanceDim.
func IntentProvenanceDim(paramPath string) map[string]any {
	return ixProvenanceDim(paramPath)
}

// IntentWithDims is the public form of the pca-intent export withDims.
func IntentWithDims(omega map[string]any, verb string, dims []any) map[string]any {
	return ixWithDims(omega, verb, dims)
}

// IntentWorldDim is the public form of the pca-intent export worldDim.
func IntentWorldDim(name string, o map[string]any) map[string]any {
	return ixWorldDim(name, o)
}
