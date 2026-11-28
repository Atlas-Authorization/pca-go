package pca

// MaxRenderFields is the public form of the pca export MAX_RENDER_FIELDS.
const MaxRenderFields = maxRenderFields

// ProvOrigins is the public form of the pca export PROV_ORIGINS.
var ProvOrigins = provOrigins

// IsProvMediatorPin is the public form of the pca export isProvMediatorPin.
func IsProvMediatorPin(k any) bool {
	return isProvMediatorPin(k)
}

// IsAwaitingAuditScheme is the public form of the pca export isAwaitingAuditScheme.
func IsAwaitingAuditScheme(s string) bool {
	return isAwaitingAuditScheme(s)
}

// AllocationsMonotone is the public form of the pca export allocationsMonotone.
func AllocationsMonotone(cavv any) (string, bool) {
	return allocationsMonotone(cavv)
}

// IsModelDerivedPath is the public form of the pca export isModelDerivedPath.
func IsModelDerivedPath(path string, single []string) bool {
	return isModelDerivedPath(path, single)
}

// EscalateReasonPrefixes is the public form of the pca export ESCALATE_REASON_PREFIXES.
var EscalateReasonPrefixes = escalateReasonPrefixes

// TightenListError is the public form of the pca export tightenListError.
func TightenListError(t any, present bool) string {
	return tightenListError(t, present)
}

// UnitTagsError is the public form of the pca export unitTagsError.
func UnitTagsError(u any) string {
	return unitTagsError(u)
}

// EnvelopeCaveat is the public form of the pca export ENVELOPE_CAVEAT.
const EnvelopeCaveat = envelopeCaveat

// FreshAtRefDomain is the public form of the pca export FRESH_AT_REF_DOMAIN.
const FreshAtRefDomain = freshAtRefDomain

// ValidateFreshAtWire is the public form of the pca export validateFreshAtWire.
func ValidateFreshAtWire(v any) string {
	return validateFreshAtWire(v)
}

// FreshAtCheck is the public name of freshAtCheck.
type FreshAtCheck = freshAtCheck

// DecideFreshAt is the public form of the pca export decideFreshAt.
func DecideFreshAt(pcactn map[string]any, policy *FreshAtPolicy, now int64) FreshAtCheck {
	return decideFreshAt(pcactn, policy, now)
}

// FreshAtDomain is the public form of the pca export FRESH_AT_DOMAIN.
const FreshAtDomain = freshAtDomain

// CompareUtf8 is the public form of the pca export compareUtf8.
func CompareUtf8(a string, b string) int {
	return compareUtf8(a, b)
}

// HasLoneSurrogate is the public form of the pca export hasLoneSurrogate.
func HasLoneSurrogate(s string) bool {
	return hasLoneSurrogate(s)
}

// VerifyB64u is the public form of the pca export verifyB64u.
func VerifyB64u(pub string, msg []byte, sig string) bool {
	return verifyB64u(pub, msg, sig)
}

// ConditionsDigest is the public form of the pca export conditionsDigest.
func ConditionsDigest(pre any, post any) (string, error) {
	return conditionsDigest(pre, post)
}

// PlanLeaf is the public form of the pca export planLeaf.
func PlanLeaf(nodeID any, action map[string]any, cond string) (map[string]any, error) {
	return planLeaf(nodeID, action, cond)
}

// MaxObligations is the public form of the pca export MAX_OBLIGATIONS.
const MaxObligations = maxObligations

// PcaGrantType is the public form of the pca export PCA_GRANT_TYPE.
const PcaGrantType = pcaGrantType

// PcaGrantDomain is the public form of the pca export PCA_GRANT_DOMAIN.
const PcaGrantDomain = pcaGrantDomain

// TemplateSigDomain is the public form of the pca export TEMPLATE_SIG_DOMAIN.
const TemplateSigDomain = templateSigDomain

// TightenSigDomain is the public form of the pca export TIGHTEN_SIG_DOMAIN.
const TightenSigDomain = tightenSigDomain

// MaxSlotSet is the public form of the pca export MAX_SLOT_SET.
const MaxSlotSet = maxSlotSet

// MaxSlotString is the public form of the pca export MAX_SLOT_STRING.
const MaxSlotString = maxSlotString

// SigSuite is the public name of sigSuite.
type SigSuite = sigSuite

// ResolveSigAlg is the public form of the pca export resolveSigAlg.
func ResolveSigAlg(alg any, present bool) (SigSuite, bool) {
	return resolveSigAlg(alg, present)
}

// PqVerifyKey is the public name of pqVerifyKey.
type PqVerifyKey = pqVerifyKey

// MlDsa65VerifyB64u is the public form of the pca export mlDsa65VerifyB64u.
func MlDsa65VerifyB64u(key PqVerifyKey, msg []byte, sigB64u any) bool {
	return mlDsa65VerifyB64u(key, msg, sigB64u)
}

// VerifyLeafSuite is the public form of the pca export verifyLeafSuite.
func VerifyLeafSuite(alg any, algPresent bool, holder string, key PqVerifyKey, msg []byte, sig any, pqSig any) bool {
	return verifyLeafSuite(alg, algPresent, holder, key, msg, sig, pqSig)
}

// BindSuiteFields is the public form of the pca export bindSuiteFields.
func BindSuiteFields(base map[string]any, alg any, algPresent bool, pqPk any, pqPresent bool) (map[string]any, bool) {
	return bindSuiteFields(base, alg, algPresent, pqPk, pqPresent)
}

// HolderPqCommitment is the public form of the pca export holderPqCommitment.
func HolderPqCommitment(pqPk string) string {
	return holderPqCommitment(pqPk)
}

// LessCat1Verify is the public form of the pca export lessCat1Verify. It reports false when this build carries no LESS
// backend (the backend registers itself at init, so a package-level alias would capture nil).
func LessCat1Verify(pk, msg, sig []byte) bool {
	if lessCat1Verify == nil {
		return false
	}
	return lessCat1Verify(pk, msg, sig)
}

// PqAuthority is the public name of pqAuthority.
type PqAuthority = pqAuthority

// ResolvePqVerifyKey is the public form of the pca export resolvePqVerifyKey.
func ResolvePqVerifyKey(alg any, present bool, artifactPk any, auth PqAuthority) (PqVerifyKey, bool) {
	return resolvePqVerifyKey(alg, present, artifactPk, auth)
}

// ValidateShareSignatureWire is the public form of the pca export validateShareSignatureWire.
func ValidateShareSignatureWire(s map[string]any) string {
	return validateShareSignatureWire(s)
}

// ValidateSignatureWire is the public form of the pca export validateSignatureWire.
func ValidateSignatureWire(p map[string]any) string {
	return validateSignatureWire(p)
}

// VerifyPinnedSuite is the public form of the pca export verifyPinnedSuite.
func VerifyPinnedSuite(alg any, algPresent bool, identity string, artifactPqPk any, msg []byte, sig any, pqSig any, pins map[string]string) bool {
	return verifyPinnedSuite(alg, algPresent, identity, artifactPqPk, msg, sig, pqSig, pins)
}

// MlDsa87PublicKeyBytes is the public form of the pca export ML_DSA_87_PUBLIC_KEY_BYTES.
const MlDsa87PublicKeyBytes = mlDsa87PublicKeyBytes

// MlDsa87SignatureBytes is the public form of the pca export ML_DSA_87_SIGNATURE_BYTES.
const MlDsa87SignatureBytes = mlDsa87SignatureBytes

// MaxLikePatternLen is the public form of the pca export MAX_LIKE_PATTERN_LEN.
const MaxLikePatternLen = maxLikePatternLen

// MaxMatchesPatternLen is the public form of the pca export MAX_MATCHES_PATTERN_LEN.
const MaxMatchesPatternLen = maxMatchesPatternLen

// MaxMemberClosureNodes is the public form of the pca export MAX_MEMBER_CLOSURE_NODES.
const MaxMemberClosureNodes = maxMemberClosureNodes

// MaxPatternSubjectLen is the public form of the pca export MAX_PATTERN_SUBJECT_LEN.
const MaxPatternSubjectLen = maxPatternSubjectLen

// MaxReResourceLen is the public form of the pca export MAX_RE_RESOURCE_LEN.
const MaxReResourceLen = maxREResourceLen

// ReversibilityOrder is the public form of the pca export REVERSIBILITY_ORDER.
var ReversibilityOrder = reversibilityOrder

// EvaluatePredicates is the public form of the pca export evaluatePredicates.
func EvaluatePredicates(predicates any, ctx map[string]any) bool {
	return evaluatePredicates(predicates, ctx)
}

// IsSafeRegexSource is the public form of the pca export isSafeRegexSource.
func IsSafeRegexSource(src []uint16) bool {
	return isSafeRegexSource(src)
}

// RegexBudget is the public name of regexBudget.
type RegexBudget = regexBudget

// PredicateMatches is the public form of the pca export predicateMatches.
func PredicateMatches(pv any, ctx map[string]any, b *RegexBudget) (ok bool) {
	return predicateMatches(pv, ctx, b)
}

// ResolvePath is the public form of the pca export resolvePath.
func ResolvePath(ctx map[string]any, path any) (any, bool) {
	return resolvePath(ctx, path)
}

// EvaluateConditionTri is the public form of the pca export evaluateConditionTri.
func EvaluateConditionTri(cv any, ctx map[string]any, b *RegexBudget) int {
	return evaluateConditionTri(cv, ctx, b)
}

// RevepochDomain is the public form of the pca export REVEPOCH_DOMAIN.
const RevepochDomain = revEpochDomain

// ReInst is the public name of reInst.
type ReInst = reInst

// CompileSafeRegex is the public form of the pca export compileSafeRegex.
func CompileSafeRegex(src []uint16) (prog []ReInst) {
	return compileSafeRegex(src)
}

// RunSafeRegex is the public form of the pca export runSafeRegex.
func RunSafeRegex(prog []ReInst, subject []uint16) (matched bool, ok bool) {
	return runSafeRegex(prog, subject)
}

// MaxMatchSteps is the public form of the pca export MAX_MATCH_STEPS.
const MaxMatchSteps = maxMatchSteps

// MaxNfaInstructions is the public form of the pca export MAX_NFA_INSTRUCTIONS.
const MaxNfaInstructions = maxNFAInstructions

// SafeRegexFullMatch is the public form of the pca export safeRegexFullMatch.
func SafeRegexFullMatch(src []uint16, subject []uint16) (bool, bool) {
	return safeRegexFullMatch(src, subject)
}

// DecodeCanonicalBase64url is the public form of the pca export decodeCanonicalBase64url.
func DecodeCanonicalBase64url(seg string) ([]byte, error) {
	return decodeCanonicalBase64url(seg)
}

// UndoEvents is the public form of the pca export UNDO_EVENTS.
var UndoEvents = undoEvents

// UndoStates is the public form of the pca export UNDO_STATES.
var UndoStates = undoStates

// VetoVias is the public form of the pca export VETO_VIAS.
var VetoVias = vetoVias

// ClipUnits is the public form of the pca export clipUnits.
func ClipUnits(s string, n int) string {
	return clipUnits(s, n)
}

// MaxAudLen is the public form of the pca export MAX_AUD_LEN.
const MaxAudLen = maxAudLen

// MaxNonceLen is the public form of the pca export MAX_NONCE_LEN.
const MaxNonceLen = maxNonceLen

// WorkflowDomain is the public form of the pca export WORKFLOW_DOMAIN.
const WorkflowDomain = workflowDomain

// WfReceiptDomain is the public form of the pca export WF_RECEIPT_DOMAIN.
const WfReceiptDomain = wfReceiptDomain
