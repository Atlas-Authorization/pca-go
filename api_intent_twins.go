package pca

import "regexp"

// Exported, documented forms of flagship exports whose only Go definition was an unexported twin.

// ActionSchemaDomain is the public form of the flagship export ACTION_SCHEMA_DOMAIN.
const ActionSchemaDomain = actionSchemaDomain

// ActionSchemaKind is the public form of the flagship export ACTION_SCHEMA_KIND.
const ActionSchemaKind = actionSchemaKind

// ActionSchemaRefDomain is the public form of the flagship export ACTION_SCHEMA_REF_DOMAIN.
const ActionSchemaRefDomain = actionSchemaRefDomain

// DefaultMaxItems is the public form of the flagship export DEFAULT_MAX_ITEMS.
const DefaultMaxItems = defaultMaxItems

// DefaultMaxLen is the public form of the flagship export DEFAULT_MAX_LEN.
const DefaultMaxLen = defaultMaxLen

// MaxSchemaParams is the public form of the flagship export MAX_SCHEMA_PARAMS.
const MaxSchemaParams = maxSchemaParams

// MaxSchemaValues is the public form of the flagship export MAX_SCHEMA_VALUES.
const MaxSchemaValues = maxSchemaValues

// MaxSchemaVerbs is the public form of the flagship export MAX_SCHEMA_VERBS.
const MaxSchemaVerbs = maxSchemaVerbs

// ParamPathRe is the public form of the flagship export PARAM_PATH_RE.
var ParamPathRe = regexp.MustCompile(`^action\.params\.[A-Za-z0-9_]{1,64}$`)

// ParamTypes is the public form of the flagship export PARAM_TYPES.
var ParamTypes = paramTypes

// ParamTypesV2 is the public form of the flagship export PARAM_TYPES_V2.
var ParamTypesV2 = paramTypesV2

// SchemaV2Effects is the public form of the flagship export SCHEMA_V2_EFFECTS.
var SchemaV2Effects = schemaV2Effects

// Sensitivities is the public form of the flagship export SENSITIVITIES.
var Sensitivities = sensitivities

// AccumulationParams is the public form of the flagship export accumulationParams.
func AccumulationParams(v map[string]any, unit string) (out []string, throws bool) {
	return accumulationParams(v, unit)
}

// ActionSchemaDigest is the public form of the flagship export actionSchemaDigest.
func ActionSchemaDigest(doc any) (string, bool) {
	return actionSchemaDigest(doc)
}

// ActionSchemaShapeError is the public form of the flagship export actionSchemaShapeError.
func ActionSchemaShapeError(dv any, signed bool) string {
	return actionSchemaShapeError(dv, signed)
}

// ConfirmationShapeError is the public form of the flagship export confirmationShapeError.
func ConfirmationShapeError(cv any) string {
	return confirmationShapeError(cv)
}

// ConformAction is the public form of the flagship export conformAction.
func ConformAction(doc any, verb string, paramsV any) SchemaConform {
	return conformAction(doc, verb, paramsV)
}

// FormatCheck is the public form of the flagship export formatCheck.
func FormatCheck(f string) func(string) bool {
	return formatCheck(f)
}

// ParamValueViolation is the public form of the flagship export paramValueViolation.
func ParamValueViolation(d map[string]any, x any) string {
	return paramValueViolation(d, x)
}

// SchemaFloorsError is the public form of the flagship export schemaFloorsError.
func SchemaFloorsError(f any) string {
	return schemaFloorsError(f)
}

// VerifyActionSchema verifies a site-signed schema against the site's discovery keys: {ok: true} or {ok: false, reason}.
func VerifyActionSchema(dv any, keysV any) map[string]any {
	if r := verifyActionSchemaReason(dv, keysV); r != "" {
		return map[string]any{"ok": false, "reason": r}
	}
	return map[string]any{"ok": true}
}

// AccAggs is the public form of the flagship export ACC_AGGS.
var AccAggs = accAggs

// AccReceiptDomain is the public form of the flagship export ACC_RECEIPT_DOMAIN.
const AccReceiptDomain = accReceiptDomain

// AccReceiptRefDomain is the public form of the flagship export ACC_RECEIPT_REF_DOMAIN.
const AccReceiptRefDomain = accReceiptRefDomain

// AccReserveDomain is the public form of the flagship export ACC_RESERVE_DOMAIN.
const AccReserveDomain = accReserveDomain

// DefaultMaxKeysetAgeMs is the public form of the flagship export DEFAULT_MAX_KEYSET_AGE_MS.
const DefaultMaxKeysetAgeMs = defaultMaxKeySetAgeMs

// DefaultMaxReceiptAgeMs is the public form of the flagship export DEFAULT_MAX_RECEIPT_AGE_MS.
const DefaultMaxReceiptAgeMs = defaultMaxReceiptAgeMs

// MaxMonitorWithin is the public form of the flagship export MAX_MONITOR_WITHIN.
const MaxMonitorWithin = maxMonitorWithin

// MaxReceiptLifetimeMs is the public form of the flagship export MAX_RECEIPT_LIFETIME_MS.
const MaxReceiptLifetimeMs = maxReceiptLifetimeMs

// MaxSessionAccumulators is the public form of the flagship export MAX_SESSION_ACCUMULATORS.
const MaxSessionAccumulators = maxSessionAccumulators

// MaxSessionMonitors is the public form of the flagship export MAX_SESSION_MONITORS.
const MaxSessionMonitors = maxSessionMonitors

// MonitorKinds is the public form of the flagship export MONITOR_KINDS.
var MonitorKinds = monitorKinds

// ReceiptSkewMs is the public form of the flagship export RECEIPT_SKEW_MS.
const ReceiptSkewMs = receiptSkewMs

// SequencerKeysDomain is the public form of the flagship export SEQUENCER_KEYS_DOMAIN.
const SequencerKeysDomain = sequencerKeysDomain

// SequencerKeysRefDomain is the public form of the flagship export SEQUENCER_KEYS_REF_DOMAIN.
const SequencerKeysRefDomain = sequencerKeysRefDomain

// AccReceiptDigest is the public form of the flagship export accReceiptDigest.
func AccReceiptDigest(r any) (string, bool) {
	return accReceiptDigest(r)
}

// AccSelects is the public form of the flagship export accSelects.
func AccSelects(a map[string]any, verb string, schema any, haveSchema bool) (bool, bool) {
	return accSelects(a, verb, schema, haveSchema)
}

// AccumulatorDeclError is the public form of the flagship export accumulatorDeclError.
func AccumulatorDeclError(av any) string {
	return accumulatorDeclError(av)
}

// DistinctKey is the public form of the flagship export distinctKey.
func DistinctKey(x any) (string, bool) {
	return distinctKey(x)
}

// MonitorDeclError is the public form of the flagship export monitorDeclError.
func MonitorDeclError(mv any) string {
	return monitorDeclError(mv)
}

// MonitorInitialState is the public form of the flagship export monitorInitialState.
func MonitorInitialState(m map[string]any) string {
	return monitorInitialState(m)
}

// MonitorStates is the public form of the flagship export monitorStates.
func MonitorStates(m map[string]any) []string {
	return monitorStates(m)
}

// PcactnReservationDigest is the public form of the flagship export pcactnReservationDigest.
func PcactnReservationDigest(p map[string]any) (string, bool) {
	return pcactnReservationDigest(p)
}

// PreStateError is the public form of the flagship export preStateError.
func PreStateError(agg string, s any) string {
	return preStateError(agg, s)
}

// PreValue is the public form of the flagship export preValue.
func PreValue(agg string, pre map[string]any) float64 {
	return preValue(agg, pre)
}

// ReceiptArithmeticOk is the public form of the flagship export receiptArithmeticOk.
func ReceiptArithmeticOk(agg string, r map[string]any, val float64) bool {
	return receiptArithmeticOk(agg, r, val)
}

// SequencerKeySetDigest is the public form of the flagship export sequencerKeySetDigest.
func SequencerKeySetDigest(ks any) (string, bool) {
	return sequencerKeySetDigest(ks)
}

// TrackedKeySetError is the public form of the flagship export trackedKeySetError.
func TrackedKeySetError(t any) string {
	return trackedKeySetError(t)
}

// VerifyAccReceiptSignature is the public form of the flagship export verifyAccReceiptSignature.
func VerifyAccReceiptSignature(r map[string]any, expectedSigner string, pins map[string]string) bool {
	return verifyAccReceiptSignature(r, expectedSigner, pins)
}

// VerifySequencerKeySet is the public form of the flagship export verifySequencerKeySet.
func VerifySequencerKeySet(kv any, root any, rootPq any, rootPqPresent bool) bool {
	return verifySequencerKeySet(kv, root, rootPq, rootPqPresent)
}

// SuiteMembers is the public form of the flagship export SUITE_MEMBERS.
var SuiteMembers = suiteMembers

// ArtifactRef is the public form of the flagship export artifactRef.
func ArtifactRef(refDomain, slot string, artifact any) (string, bool) {
	return artifactRef(refDomain, slot, artifact)
}

// ArtifactSuiteError is the public form of the flagship export artifactSuiteError.
func ArtifactSuiteError(a map[string]any) string {
	return artifactSuiteError(a)
}

// IsParamPath is the public form of the flagship export isParamPath.
func IsParamPath(path any) bool {
	return isParamPath(path)
}

// IsPathSegment is the public form of the flagship export isPathSegment.
func IsPathSegment(s string) bool {
	return isPathSegment(s)
}

// PinPqOk is the public form of the flagship export pinPqOk.
func PinPqOk(pin map[string]any) bool {
	return pinPqOK(pin)
}

// ResolveParamPath is the public form of the flagship export resolveParamPath.
func ResolveParamPath(params any, path any) (any, bool) {
	return resolveParamPath(params, path)
}

// SetNested is the public form of the flagship export setNested.
func SetNested(root map[string]any, path string, value any) bool {
	return setNested(root, path, value)
}

// Utf8Len is the public form of the flagship export utf8Len.
func Utf8Len(s string) int {
	return utf8Len(s)
}

// VerifyArtifactSig is the public form of the flagship export verifyArtifactSig.
func VerifyArtifactSig(domain string, artifact map[string]any, pk any, pinPq any) bool {
	return verifyArtifactSig(domain, artifact, pk, pinPq)
}

// EnvelopeIntentFields is the public form of the flagship export ENVELOPE_INTENT_FIELDS.
var EnvelopeIntentFields = envelopeIntentFields

// IntentGoalCommitDomain is the public form of the flagship export INTENT_GOAL_COMMIT_DOMAIN.
const IntentGoalCommitDomain = intentGoalCommitDomain

// IntentGoalV2cPrefix is the public form of the flagship export INTENT_GOAL_V2C_PREFIX.
const IntentGoalV2cPrefix = intentGoalV2cPrefix

// IntentGoalV2Prefix is the public form of the flagship export INTENT_GOAL_V2_PREFIX.
const IntentGoalV2Prefix = intentGoalV2Prefix

// IntentGoalV3Prefix is the public form of the flagship export INTENT_GOAL_V3_PREFIX.
const IntentGoalV3Prefix = intentGoalV3Prefix

// PpmOne is the public form of the flagship export PPM_ONE.
const PpmOne = ppmOne

// RootGoalCommit is the public form of the flagship export rootGoalCommit.
func RootGoalCommit(grant map[string]any) (string, bool) {
	return rootGoalCommit(grant)
}

// ValidateIntentWire is the public form of the flagship export validateIntentWire.
func ValidateIntentWire(v any) string {
	return validateIntentWire(v)
}

// MaxClassifierLabels is the public form of the flagship export MAX_CLASSIFIER_LABELS.
const MaxClassifierLabels = maxClassifierLabels

// MaxCommittedClasses is the public form of the flagship export MAX_COMMITTED_CLASSES.
const MaxCommittedClasses = maxCommittedClasses

// ClassifierCheckActive is the public form of the flagship export classifierCheckActive.
func ClassifierCheckActive(committed, classifiers any) bool {
	return classifierCheckActive(committed, classifiers)
}

// ValidateClassifierPolicy returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateClassifierPolicy(pv any) string {
	return validateClassifierPolicyError(pv)
}

// ValidateClassifierVerdictWire returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateClassifierVerdictWire(vv any) string {
	return classifierVerdictWireReason(vv)
}

// IntentProvenanceActive is the public form of the flagship export intentProvenanceActive.
func IntentProvenanceActive(provPresent bool, labels, policy any) bool {
	return intentProvenanceActive(provPresent, labels, policy)
}

// IntentWBContextError is the public form of the flagship export intentWBContextError.
func IntentWBContextError(is map[string]any, artifacts any, policy any) string {
	return intentWBContextError(is, artifacts, policy)
}

// AccKeyOf is the public form of the flagship export accKeyOf.
func AccKeyOf(a map[string]any, params map[string]any) (string, bool) {
	return accKeyOf(a, params)
}

// AccPost is the public form of the flagship export accPost.
func AccPost(a map[string]any, history []any, verb string, params map[string]any, t any, schema any, haveSchema bool) (float64, bool) {
	return accPost(a, history, verb, params, t, schema, haveSchema)
}

// AccPreState is the public form of the flagship export accPreState.
func AccPreState(a map[string]any, history []any, candParams map[string]any, candT any, schema any, haveSchema bool) (map[string]any, bool) {
	return accPreState(a, history, candParams, candT, schema, haveSchema)
}

// InWindow is the public form of the flagship export inWindow.
func InWindow(win map[string]any, ti, t any) bool {
	return inWindow(win, ti, t)
}

// MonitorStep is the public form of the flagship export monitorStep: one monitor step on one event. "" is no state (a nil event,
// or a counted event under an unknown monitor kind).
func MonitorStep(m map[string]any, q string, e map[string]any) string {
	return monitorStep(m, q, e)
}

// MonitorState is the public form of the flagship export monitorState: the fold of a monitor over a session history, in admission
// order. "" is no state (a null history entry, or an unknown monitor kind once an event counts).
func MonitorState(m map[string]any, history []any) string {
	return monitorState(m, history)
}

// MapFormCommit is the public form of the flagship export MAP_FORM_COMMIT.
const MapFormCommit = mapFormCommit

// MapMetricFields is the public form of the flagship export MAP_METRIC_FIELDS.
var MapMetricFields = mapMetricFields

// MapOther is the public form of the flagship export MAP_OTHER.
const MapOther = mapOther

// MapTagCell is the public form of the flagship export MAP_TAG_CELL.
const MapTagCell = mapTagCell

// MapTagCommit is the public form of the flagship export MAP_TAG_COMMIT.
const MapTagCommit = mapTagCommit

// MapTagHeader is the public form of the flagship export MAP_TAG_HEADER.
const MapTagHeader = mapTagHeader

// MapTagLearner is the public form of the flagship export MAP_TAG_LEARNER.
const MapTagLearner = mapTagLearner

// MapTagMetrics is the public form of the flagship export MAP_TAG_METRICS.
const MapTagMetrics = mapTagMetrics

// MapTagNode is the public form of the flagship export MAP_TAG_NODE.
const MapTagNode = mapTagNode

// MaxMapCuts is the public form of the flagship export MAX_MAP_CUTS.
const MaxMapCuts = maxMapCuts

// MaxMapDims is the public form of the flagship export MAX_MAP_DIMS.
const MaxMapDims = maxMapDims

// MaxMapLeaves is the public form of the flagship export MAX_MAP_LEAVES.
const MaxMapLeaves = maxMapLeaves

// MaxMapStringBytes is the public form of the flagship export MAX_MAP_STRING_BYTES.
const MaxMapStringBytes = maxMapStringBytes

// MaxMapValues is the public form of the flagship export MAX_MAP_VALUES.
const MaxMapValues = maxMapValues

// MaxVerbCells is the public form of the flagship export MAX_VERB_CELLS.
const MaxVerbCells = maxVerbCells

// MapCellError is the public form of the flagship export mapCellError.
func MapCellError(cv any) string {
	return mapCellError(cv)
}

// MapCellOf is the public form of the flagship export mapCellOf.
func MapCellOf(h map[string]any, resource any, params any) ([]int, int, string) {
	return mapCellOf(h, resource, params)
}

// MapCommitOf is the public form of the flagship export mapCommitOf.
func MapCommitOf(size int, root []byte) string {
	return mapCommitOf(size, root)
}

// MapDisclosureError is the public form of the flagship export mapDisclosureError.
func MapDisclosureError(dv any) string {
	return mapDisclosureError(dv)
}

// MapHeaderError is the public form of the flagship export mapHeaderError.
func MapHeaderError(hv any) string {
	return mapHeaderError(hv)
}

// MapLeafHash is the public form of the flagship export mapLeafHash.
func MapLeafHash(kind string, salt []byte, leaf any) ([]byte, bool) {
	return mapLeafHash(kind, salt, leaf)
}

// MapLearnerError is the public form of the flagship export mapLearnerError.
func MapLearnerError(lv any) string {
	return mapLearnerError(lv)
}

// MapMetricsError is the public form of the flagship export mapMetricsError.
func MapMetricsError(mv any) string {
	return mapMetricsError(mv)
}

// MapNodeHash is the public form of the flagship export mapNodeHash.
func MapNodeHash(l, r []byte) []byte {
	return mapNodeHash(l, r)
}

// MapNumCells is the public form of the flagship export mapNumCells.
func MapNumCells(d map[string]any) [][2]float64 {
	return mapNumCells(d)
}

// MapRootFromPath is the public form of the flagship export mapRootFromPath.
func MapRootFromPath(index, size int, leaf []byte, path [][]byte) []byte {
	return mapRootFromPath(index, size, leaf, path)
}

// IntentRequiredDomain is the public form of the flagship export INTENT_REQUIRED_DOMAIN.
const IntentRequiredDomain = intentRequiredDomain

// CellCoordsError is the public form of the flagship export cellCoordsError.
func CellCoordsError(c any) string {
	return cellCoordsError(c)
}

// CheckSessionRevocation is the public form of the flagship export checkSessionRevocation: {ok: true} or {ok: false, reason}.
func CheckSessionRevocation(ev any, session any, authority any, ids any, now any, maxAgeMs any, last any, lastP bool, pins map[string]string) map[string]any {
	if r := checkSessionRevocation(ev, session, authority, ids, now, maxAgeMs, last, lastP, pins); r != "" {
		return map[string]any{"ok": false, "reason": r}
	}
	return map[string]any{"ok": true}
}

// DeltaRevocationId is the public form of the flagship export deltaRevocationId.
func DeltaRevocationId(grantID string) string {
	return deltaRevocationID(grantID)
}

// MapRevocationId is the public form of the flagship export mapRevocationId.
func MapRevocationId(mapDigest string) string {
	return mapRevocationID(mapDigest)
}

// ProfileRevocationId is the public form of the flagship export profileRevocationId.
func ProfileRevocationId(p string, version float64) string {
	return profileRevocationID(p, version)
}

// SessionRevocationId is the public form of the flagship export sessionRevocationId.
func SessionRevocationId(session string) string {
	return sessionRevocationID(session)
}

// SessionRevocationScope is the public form of the flagship export sessionRevocationScope.
func SessionRevocationScope(session string) string {
	return sessionRevocationScope(session)
}

// IntentSessionCaveat is the public form of the flagship export INTENT_SESSION_CAVEAT.
const IntentSessionCaveat = intentSessionCaveat

// MaxSessionSeq is the public form of the flagship export MAX_SESSION_SEQ.
const MaxSessionSeq = maxSessionSeq

// IntentSessionCaveatError is the public form of the flagship export intentSessionCaveatError.
func IntentSessionCaveatError(cv any) string {
	return intentSessionCaveatError(cv)
}

// IntentSessionFields is the public form of the flagship export INTENT_SESSION_FIELDS.
var IntentSessionFields = intentSessionFields

// IntentSessionKind is the public form of the flagship export INTENT_SESSION_KIND.
const IntentSessionKind = intentSessionKind

// IntentSessionRefDomain is the public form of the flagship export INTENT_SESSION_REF_DOMAIN.
const IntentSessionRefDomain = intentSessionRefDomain

// IntentSessionSigDomain is the public form of the flagship export INTENT_SESSION_SIG_DOMAIN.
const IntentSessionSigDomain = intentSessionSigDomain

// MaxIsAcc is the public form of the flagship export MAX_IS_ACC.
const MaxIsAcc = maxISAcc

// MaxIsClasses is the public form of the flagship export MAX_IS_CLASSES.
const MaxIsClasses = maxISClasses

// MaxIsFacts is the public form of the flagship export MAX_IS_FACTS.
const MaxIsFacts = maxISFacts

// MaxIsLabels is the public form of the flagship export MAX_IS_LABELS.
const MaxIsLabels = maxISLabels

// MaxIsProvPaths is the public form of the flagship export MAX_IS_PROV_PATHS.
const MaxIsProvPaths = maxISProvPaths

// MaxIsProvRefs is the public form of the flagship export MAX_IS_PROV_REFS.
const MaxIsProvRefs = maxISProvRefs

// MaxIsStringBytes is the public form of the flagship export MAX_IS_STRING_BYTES.
const MaxIsStringBytes = maxISStringBytes

// MaxSessionPrincipals is the public form of the flagship export MAX_SESSION_PRINCIPALS.
const MaxSessionPrincipals = maxSessionPrincipals

// GrantSessionCaveat is the public form of the flagship export grantSessionCaveat.
func GrantSessionCaveat(grant any) (map[string]any, bool) {
	return grantSessionCaveat(grant)
}

// SessionRootDigest is the public form of the flagship export sessionRootDigest.
func SessionRootDigest(s any) (string, bool) {
	return sessionRootDigest(s)
}

// ValidateIntentSessionWire is the public form of the flagship export validateIntentSessionWire.
func ValidateIntentSessionWire(v any) string {
	return validateIntentSessionWire(v)
}

// VerifySessionRoot is the public form of the flagship export verifySessionRoot: {ok: true} or {ok: false, reason}.
func VerifySessionRoot(sv any, pins any) map[string]any {
	if r := verifySessionRoot(sv, pins); r != "" {
		return map[string]any{"ok": false, "reason": r}
	}
	return map[string]any{"ok": true}
}

// CanonProjection is the public form of the flagship export canonProjection.
func CanonProjection(doc any, verb string, params map[string]any) (map[string]any, bool) {
	return canonProjection(doc, verb, params)
}

// IntentV2ContextError is the public form of the flagship export intentV2ContextError.
func IntentV2ContextError(c *IntentV2Context) string {
	return intentV2ContextError(c)
}

// LabelsDomain is the public form of the flagship export LABELS_DOMAIN.
const LabelsDomain = labelsDomain

// LabelsRefDomain is the public form of the flagship export LABELS_REF_DOMAIN.
const LabelsRefDomain = labelsRefDomain

// MaxLabelFields is the public form of the flagship export MAX_LABEL_FIELDS.
const MaxLabelFields = maxLabelFields

// FlowAllowed is the public form of the flagship export flowAllowed.
func FlowAllowed(rules map[string]any, cls, origin string, aud any) bool {
	return flowAllowed(rules, cls, origin, aud)
}

// FlowRuleFor is the public form of the flagship export flowRuleFor.
func FlowRuleFor(rules map[string]any, cls string) (string, bool) {
	return flowRuleFor(rules, cls)
}

// ValidateFlowRules returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateFlowRules(rv any) string {
	return validateFlowRulesError(rv)
}

// ValidateLabelsWire returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateLabelsWire(lv any) string {
	return labelsWireReason(lv)
}

// MaxOffers is the public form of the flagship export MAX_OFFERS.
const MaxOffers = maxOffers

// MaxOfferAttrs is the public form of the flagship export MAX_OFFER_ATTRS.
const MaxOfferAttrs = maxOfferAttrs

// MaxQueryKeys is the public form of the flagship export MAX_QUERY_KEYS.
const MaxQueryKeys = maxQueryKeys

// OfferSetDomain is the public form of the flagship export OFFER_SET_DOMAIN.
const OfferSetDomain = offerSetDomain

// OfferSetRefDomain is the public form of the flagship export OFFER_SET_REF_DOMAIN.
const OfferSetRefDomain = offerSetRefDomain

// DecideOfferSet is the public form of the flagship export decideOfferSet.
func DecideOfferSet(policy map[string]any, committed any, committedP bool, ov any, oP bool, params any, aud, session any, clock bool, now, skew float64) (float64, string) {
	return decideOfferSet(policy, committed, committedP, ov, oP, params, aud, session, clock, now, skew)
}

// OfferMatches is the public form of the flagship export offerMatches.
func OfferMatches(offer map[string]any, f map[string]any) bool {
	return offerMatches(offer, f)
}

// ValidateOfferPolicy returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateOfferPolicy(pv any) string {
	return validateOfferPolicyError(pv)
}

// ValidateOfferSetWire returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateOfferSetWire(ov any) string {
	return validateOfferSetWireError(ov)
}

// DefaultWorldSkewMs is the public form of the flagship export DEFAULT_WORLD_SKEW_MS.
const DefaultWorldSkewMs = defaultWorldSkewMs

// FactDomain is the public form of the flagship export FACT_DOMAIN.
const FactDomain = factDomain

// FactRefDomain is the public form of the flagship export FACT_REF_DOMAIN.
const FactRefDomain = factRefDomain

// MaxCommittedFacts is the public form of the flagship export MAX_COMMITTED_FACTS.
const MaxCommittedFacts = maxCommittedFacts

// MaxRelational is the public form of the flagship export MAX_RELATIONAL.
const MaxRelational = maxRelational

// MaxWorlds is the public form of the flagship export MAX_WORLDS.
const MaxWorlds = maxWorlds

// IntentWorldActive is the public form of the flagship export intentWorldActive.
func IntentWorldActive(cf, co, policy any) bool {
	return intentWorldActive(cf, co, policy)
}

// RatioPpm is the public form of the flagship export ratioPpm.
func RatioPpm(a, b float64) (float64, bool) {
	return ratioPpm(a, b)
}

// ValidateFactWire returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateFactWire(fv any) string {
	return factWireReason(fv)
}

// ValidateWorldPolicy returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateWorldPolicy(pv any) string {
	return validateWorldPolicyError(pv)
}

// LabelRefPrefix is the public form of the flagship export LABEL_REF_PREFIX.
const LabelRefPrefix = labelRefPrefix

// MaxCommittedLabels is the public form of the flagship export MAX_COMMITTED_LABELS.
const MaxCommittedLabels = maxCommittedLabels

// MaxProvPaths is the public form of the flagship export MAX_PROV_PATHS.
const MaxProvPaths = maxProvPaths

// MaxProvRefs is the public form of the flagship export MAX_PROV_REFS.
const MaxProvRefs = maxProvRefs

// ValidateProvWire returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateProvWire(pv any) string {
	return validateProvWireError(pv)
}

// ValidateProvenancePolicy returns "" when the value is well-formed and otherwise the first problem (the flagship returns null for a well-formed value).
func ValidateProvenancePolicy(pv any) string {
	return validateProvenancePolicyError(pv)
}

// IntentActionDomain is the public form of the flagship export INTENT_ACTION_DOMAIN.
const IntentActionDomain = ixIntentActionDomain

// ParamPathReV2 is the public form of the flagship export PARAM_PATH_RE_V2.
var ParamPathReV2 = reParamPathV2

// ScoreScale is the public form of the flagship export SCORE_SCALE.
const ScoreScale = ixScoreScale

// SemanticJudgeDomain is the public form of the flagship export SEMANTIC_JUDGE_DOMAIN.
const SemanticJudgeDomain = ixSemanticJudgeDomain

// WalletFloorExact is the public form of the flagship export WALLET_FLOOR_EXACT.
var WalletFloorExact = ixWalletFloorExact

// WalletFloorPrefixes is the public form of the flagship export WALLET_FLOOR_PREFIXES.
var WalletFloorPrefixes = ixWalletFloorPrefixes

// EffectiveSensitivity is the public form of the flagship export effectiveSensitivity.
func EffectiveSensitivity(d, floor map[string]any) any {
	return ixEffectiveSensitivity(d, floor)
}

// FloorApplies is the public form of the flagship export floorApplies.
func FloorApplies(semantic string, floor map[string]any) bool {
	return ixFloorApplies(semantic, floor)
}

// IsCounted is the public form of the flagship export isCounted.
func IsCounted(s any) bool {
	return isCountedStatus(s)
}

// SemanticRiskContribution is the public form of the flagship export semanticRiskContribution.
func SemanticRiskContribution(score float64) float64 {
	return ixSemanticRiskContribution(score)
}

// VerbReversibility is the public form of the flagship export verbReversibility.
func VerbReversibility(v map[string]any) string {
	return ixVerbReversibility(v)
}
