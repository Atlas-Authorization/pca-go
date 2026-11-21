package pca

import "crypto/ecdsa"

// ActionBlankReason is the public form of the flagship export blankReason.
func ActionBlankReason(s string) bool {
	return blankReason(s)
}

// ActionRevRank is the public form of the flagship export REV_RANK.
var ActionRevRank = revRank

// ActionDefDigest is the public form of the flagship export defDigest.
func ActionDefDigest(d map[string]any) (string, error) {
	return defDigest(d)
}

// ActionFloorDecision is the public form of the flagship export floorDecision.
func ActionFloorDecision(g GrantFacts, callContext []string, rho Profile) string {
	return floorDecision(g, callContext, rho)
}

// EvolutionClasses is the public form of the flagship export EVOLUTION_CLASSES.
var EvolutionClasses = evolutionClasses

// EvolutionDiffDomain is the public form of the flagship export EVOLUTION_DIFF_DOMAIN.
const EvolutionDiffDomain = evolutionDiffDomain

// EvolutionDomain is the public form of the flagship export EVOLUTION_DOMAIN.
const EvolutionDomain = evolutionDomain

// EvolutionRecordKind is the public form of the flagship export EVOLUTION_RECORD_KIND.
const EvolutionRecordKind = evolutionRecordKind

// MaxEscTier is the public form of the flagship export MAX_ESC_TIER.
const MaxEscTier = maxEscTier

// MaxEvolutionSteps is the public form of the flagship export MAX_EVOLUTION_STEPS.
const MaxEvolutionSteps = maxEvolutionSteps

// ReapprovalDomain is the public form of the flagship export REAPPROVAL_DOMAIN.
const ReapprovalDomain = reapprovalDomain

// ReapprovalKind is the public form of the flagship export REAPPROVAL_KIND.
const ReapprovalKind = reapprovalKind

// ActionPinError is the public form of the flagship export actionPinError.
func ActionPinError(xv any) string {
	return actionPinError(xv)
}

// DecidePin is the public form of the flagship export decidePin.
func DecidePin(in map[string]any) (res map[string]any) {
	return decidePin(in)
}

// EvolutionDiffDigest is the public form of the flagship export evolutionDiffDigest.
func EvolutionDiffDigest(r map[string]any) (string, bool) {
	return evolutionDiffDigest(r)
}

// EvolutionRecordError is the public form of the flagship export evolutionRecordError.
func EvolutionRecordError(xv any, signed bool) string {
	return evolutionRecordError(xv, signed)
}

// ReapprovalValid is the public form of the flagship export reapprovalValid.
func ReapprovalValid(rv any, grantID, issuer, verb, diff any) (res bool) {
	return reapprovalValid(rv, grantID, issuer, verb, diff)
}

// VerifyEvolutionRecord is the public form of the flagship export verifyEvolutionRecord: {ok: true} or {ok: false, reason}.
func VerifyEvolutionRecord(rec any, keys any) map[string]any {
	if r := verifyEvolutionRecord(rec, keys); r != "" {
		return map[string]any{"ok": false, "reason": r}
	}
	return map[string]any{"ok": true}
}

// VerifyRegistrySig is the public form of the flagship export verifyRegistrySig: {ok: true} or {ok: false, reason}.
func VerifyRegistrySig(domain string, body any, sig map[string]any, keysV any) map[string]any {
	if r := verifyRegistrySig(domain, body, sig, keysV); r != "" {
		return map[string]any{"ok": false, "reason": r}
	}
	return map[string]any{"ok": true}
}

// AnchorEntryOf is the public form of the flagship export anchorEntryOf: the anchor entry of a verified manifest (an OK
// AllowlistResult, or its decoded JSON form), or of a bare {issuer, version, digest} entry; false when it is not well formed.
func AnchorEntryOf(v any) (AnchorEntry, bool) {
	return anchorEntryOfWhat(v)
}

// AmdArkSpkiSha384 is the public form of the flagship export AMD_ARK_SPKI_SHA384.
var AmdArkSpkiSha384 = amdARKSpkiSHA384

// DefaultAcceptedStatuses is the public form of the flagship export DEFAULT_ACCEPTED_STATUSES.
var DefaultAcceptedStatuses = defaultAcceptedStatuses

// IntelSgxRootCaSpkiSha256 is the public form of the flagship export INTEL_SGX_ROOT_CA_SPKI_SHA256.
const IntelSgxRootCaSpkiSha256 = intelSGXRootCASpkiSHA256

// FormatVbiosVersion is the public form of the flagship export formatVbiosVersion.
func FormatVbiosVersion(raw []byte) string {
	return formatVbiosVersion(raw)
}

// AttestBindDomain is the public form of the flagship export ATTEST_BIND_DOMAIN.
const AttestBindDomain = attestBindDomain

// RequiresAttestation is the public form of the flagship export requiresAttestation.
func RequiresAttestation(binding any) bool {
	return requiresAttestation(binding)
}

// EmbeddedConstitution is the public form of the flagship export embeddedConstitution.
func EmbeddedConstitution(c map[string]any) map[string]any {
	return embeddedConstitution(c)
}

// MaxTightenRules is the public form of the flagship export MAX_TIGHTEN_RULES.
const MaxTightenRules = maxTightenRules

// VerifyAmdCertChain is the public form of the flagship export verifyAmdCertChain.
func VerifyAmdCertChain(vcekDer []byte, askArkPem string, pin string, nowMs int64, clockSkew any) (string, *ecdsa.PublicKey, []byte) {
	return verifyAmdCertChain(vcekDer, askArkPem, pin, nowMs, clockSkew)
}

// SthDomain is the public form of the flagship export STH_DOMAIN.
const SthDomain = sthDomain

// SthWitnessDomain is the public form of the flagship export STH_WITNESS_DOMAIN.
const SthWitnessDomain = sthWitnessDomain

// PassportSigDomain is the public form of the flagship export PASSPORT_SIG_DOMAIN.
const PassportSigDomain = passportSigDomain

// SigSuites is the public form of the flagship export SIG_SUITES.
var SigSuites = sigSuites

// StateChainDomain is the public form of the flagship export STATE_CHAIN_DOMAIN.
const StateChainDomain = stateChainDomain

// StateDigestDomain is the public form of the flagship export STATE_DIGEST_DOMAIN.
const StateDigestDomain = stateDigestDomain

// CanonicalState is the public form of the flagship export canonicalState.
func CanonicalState(state any) (map[string]any, bool) {
	return canonicalState(state)
}

// ClassRank is the public form of the flagship export CLASS_RANK.
var ClassRank = classRank

// ChainCriticalOk is the public form of the flagship export CHAIN_CRITICAL_OK.
var ChainCriticalOk = chainCriticalOK

// RecognisedCriticalExtensions is the public form of the flagship export RECOGNISED_CRITICAL_EXTENSIONS.
var RecognisedCriticalExtensions = recognisedCriticalExtensions

// CheckChainRoles is the public form of the flagship export checkChainRoles.
func CheckChainRoles(ordered [][]byte) string {
	return checkChainRoles(ordered)
}

// TbsOfCertificate is the public form of the flagship export tbsOfCertificate.
func TbsOfCertificate(cert []byte) ([]byte, error) {
	return tbsOfCertificate(cert)
}

// UnrecognisedCriticalExtension is the public form of the flagship export unrecognisedCriticalExtension.
func UnrecognisedCriticalExtension(cert []byte, recognised map[string]bool) (string, bool, error) {
	return unrecognisedCriticalExtension(cert, recognised)
}

// GoalEffectClasses is the public form of the flagship export EFFECT_CLASSES.
var GoalEffectClasses = goalEffectClasses

// SevSnpPolicyDebugBit is the public form of the flagship export SEV_SNP_POLICY_DEBUG_BIT.
const SevSnpPolicyDebugBit = snpPolicyDebugBit

// GoalBenchApplyHostile is the public form of the flagship export applyHostile.
func GoalBenchApplyHostile(c map[string]any, kind string, o, t any, r func() float64) map[string]any {
	return goalBenchApplyHostile(c, kind, o, t, r)
}

// GoalBenchBuildText is the public form of the flagship export buildText.
func GoalBenchBuildText(o, t any, slots map[string]any, r func() float64) (string, bool) {
	return goalBenchBuildText(o, t, slots, r)
}

// GoalBenchCompletionsFrom is the public form of the flagship export completionsFrom.
func GoalBenchCompletionsFrom(rec map[string]any) map[string]GoalComplete {
	return goalBenchCompletionsFrom(rec)
}

// IntentActionDigest is the public form of the flagship export intentActionDigest.
func IntentActionDigest(action map[string]any) string {
	return ixIntentActionDigest(action)
}

// IntentProfileShapeError is the public form of the flagship export intentProfileShapeError.
func IntentProfileShapeError(pv any, signed bool) (msg string) {
	return ixProfileShapeError(pv, signed)
}

// GoalBenchRequestOf is the public form of the flagship export requestOf.
func GoalBenchRequestOf(c any) map[string]any {
	return goalBenchRequestOf(c)
}

// LeaseShardOf is the public form of the flagship export shardOf.
func LeaseShardOf(id string, shards int) int {
	return leaseShardOf(id, shards)
}

// GoalBenchSimulateOutput is the public form of the flagship export simulateOutput.
func GoalBenchSimulateOutput(c any, spec GoalSimSpec) string {
	return goalBenchSimulateOutput(c, spec)
}

// GoalBenchTruthOnt is the public form of the flagship export truthOnt.
func GoalBenchTruthOnt(c any, g any) map[string]any {
	return goalBenchTruthOnt(c, g)
}

// WalletFloorOverrides is the public form of the flagship export walletFloorOverrides.
func WalletFloorOverrides(verbs []any, floor map[string]any) []any {
	return ixWalletFloorOverrides(verbs, floor)
}
