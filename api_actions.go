package pca

// ActionVerifyPack is the public form of the pca-actions export verifyPack.
func ActionVerifyPack(packV any, keys any, shards map[string]any) (digest string, defCount int, reason string) {
	return verifyPack(packV, keys, shards)
}

// ActionRatePeriods is the public form of the pca-actions export RATE_PERIODS.
var ActionRatePeriods = rbRatePeriods

// ActionMaxRevOf is the public form of the pca-actions export maxRevOf.
func ActionMaxRevOf(xs []string) string {
	return maxRevOf(xs)
}

// ActionVerbConfirmationError is the public form of the pca-actions export verbConfirmationError.
func ActionVerbConfirmationError(v map[string]any, reg Registry, pins any) string {
	return verbConfirmationError(v, reg, pins)
}

// ActionKeyRoles is the public form of the pca-actions export KEY_ROLES.
var ActionKeyRoles = keyRoles

// ActionVerbFactsDomain is the public form of the pca-actions export VERB_FACTS_DOMAIN.
const ActionVerbFactsDomain = verbFactsDomain

// ActionFactsDigest is the public form of the pca-actions export factsDigest.
func ActionFactsDigest(v map[string]any) (string, error) {
	return factsDigest(v)
}

// ActionReviewerPinsError is the public form of the pca-actions export reviewerPinsError.
func ActionReviewerPinsError(pv any) string {
	return reviewerPinsError(pv)
}

// ActionCoreRegistry is the public form of the pca-actions export CORE_REGISTRY.
var ActionCoreRegistry = coreRegistry

// ActionEffectTraits is the public form of the pca-actions export EFFECT_TRAITS.
var ActionEffectTraits = effectTraits

// ActionRoleTraits is the public form of the pca-actions export ROLE_TRAITS.
var ActionRoleTraits = roleTraits

// ActionTagTraits is the public form of the pca-actions export TAG_TRAITS.
var ActionTagTraits = tagTraits

// ActionRoleSensitivityFloor is the public form of the pca-actions export ROLE_SENSITIVITY_FLOOR.
var ActionRoleSensitivityFloor = roleSensitivityFloor

// ActionTagSensitivityFloor is the public form of the pca-actions export TAG_SENSITIVITY_FLOOR.
var ActionTagSensitivityFloor = tagSensitivityFloor

// ActionDefKind is the public form of the pca-actions export ACTION_DEF_KIND.
const ActionDefKind = actionDefKind

// ActionPpmMax is the public form of the pca-actions export PPM_MAX.
const ActionPpmMax = ppmMax

// ActionProvenanceLevels is the public form of the pca-actions export PROVENANCE_LEVELS.
var ActionProvenanceLevels = provenanceLevels

// ActionPackKind is the public form of the pca-actions export ACTION_PACK_KIND.
const ActionPackKind = actionPackKind

// ActionMaxDefAliases is the public form of the pca-actions export MAX_DEF_ALIASES.
const ActionMaxDefAliases = maxDefAliases

// ActionMaxDefContext is the public form of the pca-actions export MAX_DEF_CONTEXT.
const ActionMaxDefContext = maxDefContext

// ActionMaxDefParams is the public form of the pca-actions export MAX_DEF_PARAMS.
const ActionMaxDefParams = maxDefParams

// ActionMaxDefSideEffects is the public form of the pca-actions export MAX_DEF_SIDE_EFFECTS.
const ActionMaxDefSideEffects = maxDefSideEffects

// ActionMaxDefTraits is the public form of the pca-actions export MAX_DEF_TRAITS.
const ActionMaxDefTraits = maxDefTraits

// ActionMaxParamPathDepth is the public form of the pca-actions export MAX_PARAM_PATH_DEPTH.
const ActionMaxParamPathDepth = maxParamPathDepth

// ActionMaxRegistryTraits is the public form of the pca-actions export MAX_REGISTRY_TRAITS.
const ActionMaxRegistryTraits = maxRegistryTraits

// ActionMaxTraitImpliesDepth is the public form of the pca-actions export MAX_TRAIT_IMPLIES_DEPTH.
const ActionMaxTraitImpliesDepth = maxTraitImpliesDepth

// ActionBindingKinds is the public form of the pca-actions export BINDING_KINDS.
var ActionBindingKinds = bindingKinds

// ActionBlastPpm is the public form of the pca-actions export BLAST_PPM.
var ActionBlastPpm = blastPPM

// ActionBlastRadii is the public form of the pca-actions export BLAST_RADII.
var ActionBlastRadii = defBlastRadii

// ActionCaveatKinds is the public form of the pca-actions export CAVEAT_KINDS.
var ActionCaveatKinds = caveatKinds

// ActionContextKeys is the public form of the pca-actions export CONTEXT_KEYS.
var ActionContextKeys = contextKeys

// ActionCoreRoles is the public form of the pca-actions export CORE_ROLES.
var ActionCoreRoles = coreRoles

// ActionIdempotencyModes is the public form of the pca-actions export IDEMPOTENCY_MODES.
var ActionIdempotencyModes = idempotencyModes

// ActionIdClasses is the public form of the pca-actions export ID_CLASSES.
var ActionIdClasses = idClasses

// ActionParamFormats is the public form of the pca-actions export PARAM_FORMATS.
var ActionParamFormats = paramFormats

// ActionParamRuleIds is the public form of the pca-actions export PARAM_RULE_IDS.
var ActionParamRuleIds = paramRuleIDs

// ActionParamTags is the public form of the pca-actions export PARAM_TAGS.
var ActionParamTags = paramTags

// ActionReviewStates is the public form of the pca-actions export REVIEW_STATES.
var ActionReviewStates = reviewStates

// ActionScopeBlast is the public form of the pca-actions export SCOPE_BLAST.
var ActionScopeBlast = scopeBlast

// ActionUnitKinds is the public form of the pca-actions export UNIT_KINDS.
var ActionUnitKinds = unitKinds

// ActionSensitivityRank is the public form of the pca-actions export SENSITIVITY_RANK.
var ActionSensitivityRank = sensitivityRank

// ActionRegistryOfSchema is the public form of the pca-actions export registryOfSchema.
func ActionRegistryOfSchema(doc map[string]any) (Registry, error) {
	return registryOfSchema(doc)
}

// ActionSchemaFloorError is the public form of the pca-actions export schemaFloorError.
func ActionSchemaFloorError(doc map[string]any, pins any) (res string) {
	return schemaFloorError(doc, pins)
}

// ActionSchemaVerbFloorError is the public form of the pca-actions export schemaVerbFloorError.
func ActionSchemaVerbFloorError(v map[string]any, reg Registry, pins any) (res string) {
	return schemaVerbFloorError(v, reg, pins)
}

// ActionDefDigestDomain is the public form of the pca-actions export DEF_DIGEST_DOMAIN.
const ActionDefDigestDomain = defDigestDomain

// ActionPackDigestDomain is the public form of the pca-actions export PACK_DIGEST_DOMAIN.
const ActionPackDigestDomain = packDigestDomain

// ActionRolesDigestDomain is the public form of the pca-actions export ROLES_DIGEST_DOMAIN.
const ActionRolesDigestDomain = rolesDigestDomain

// ActionTraitsDigestDomain is the public form of the pca-actions export TRAITS_DIGEST_DOMAIN.
const ActionTraitsDigestDomain = traitsDigestDomain

// ActionPackProof is the public form of the pca-actions export packProof.
func ActionPackProof(digests []string, digest string) (map[string]any, error) {
	return packProof(digests, digest)
}

// ActionPackRoot is the public form of the pca-actions export packRoot.
func ActionPackRoot(digests []string) (string, error) {
	return packRoot(digests)
}

// ActionTablesDigest is the public form of the pca-actions export tablesDigest.
func ActionTablesDigest() (string, error) {
	return tablesDigest()
}

// ActionTraitsDigest is the public form of the pca-actions export traitsDigest.
func ActionTraitsDigest(reg Registry) (string, error) {
	return traitsDigest(reg)
}

// ActionVerifyPackProof is the public form of the pca-actions export verifyPackProof.
func ActionVerifyPackProof(root string, proof map[string]any, digest string) bool {
	return verifyPackProof(root, proof, digest)
}

// ActionDeclProfile is the public form of the pca-actions export declProfile.
func ActionDeclProfile(d map[string]any) Profile {
	return declProfile(d)
}

// ActionHintTraits is the public form of the pca-actions export hintTraits.
func ActionHintTraits(d map[string]any) []string {
	return hintTraits(d)
}

// ActionImpliedFromFacts is the public form of the pca-actions export impliedFromFacts.
func ActionImpliedFromFacts(effects []string, params []map[string]any, scope string, worstRev string) ([]string, error) {
	return impliedFromFacts(effects, params, scope, worstRev)
}

// ActionIdPatternError is the public form of the pca-actions export idPatternError.
func ActionIdPatternError(p any) string {
	return idPatternError(p)
}

// ActionIdClassChars is the public form of the pca-actions export ID_CLASS_CHARS.
var ActionIdClassChars = idClassChars

// ActionNsRe is the public form of the pca-actions export NS_RE.
var ActionNsRe = actionNsRe

// ActionDefaultExtensions is the public form of the pca-actions export DEFAULT_EXTENSIONS.
var ActionDefaultExtensions = aimDefaultExtensions

// ActionTokensOf is the public form of the pca-actions export tokensOf.
func ActionTokensOf(name any) []string {
	return aimTokensOf(name)
}

// ActionAliasOf is the public form of the pca-actions export aliasOf.
func ActionAliasOf(raw any, verb string) (string, bool) {
	return aimAliasOf(raw, verb)
}

// ActionClip is the public form of the pca-actions export clip.
func ActionClip(v any, maxBytes int) string {
	return aimClip(v, maxBytes)
}

// AimGqlSchema is the public name of aimGqlSchema.
type AimGqlSchema = aimGqlSchema

// ActionFromIntrospection is the public form of the pca-actions export fromIntrospection.
func ActionFromIntrospection(doc any) *AimGqlSchema {
	return aimGqlFromIntrospection(doc)
}

// AimProtoModel is the public name of aimProtoModel.
type AimProtoModel = aimProtoModel

// ActionParseDescriptorSet is the public form of the pca-actions export parseDescriptorSet.
func ActionParseDescriptorSet(bytes []byte) *AimProtoModel {
	return aimParseDescriptorSet(bytes)
}

// ActionParseProto is the public form of the pca-actions export parseProto.
func ActionParseProto(src string, maxTokens int) *AimProtoModel {
	return aimParseProto(src, maxTokens)
}

// ActionImportLimits is the public name of actionImportLimits.
type ActionImportLimits = actionImportLimits

// ActionResolveLimits is the public form of the pca-actions export resolveLimits.
func ActionResolveLimits(over any) ActionImportLimits {
	return aimResolveLimits(over)
}

// ActionCheckParsed is the public form of the pca-actions export checkParsed.
func ActionCheckParsed(root any, lim ActionImportLimits) int64 {
	return aimCheckParsed(root, lim)
}

// ActionTextSizeCheck is the public form of the pca-actions export textSizeCheck.
func ActionTextSizeCheck(text any, lim ActionImportLimits) {
	aimTextSizeCheck(text, lim)
}

// ActionModelPromptVersion is the public form of the pca-actions export MODEL_PROMPT_VERSION.
const ActionModelPromptVersion = aimModelPromptVersion

// ActionSuggestRulesDomain is the public form of the pca-actions export SUGGEST_RULES_DOMAIN.
const ActionSuggestRulesDomain = actionSuggestRulesDomain

// AisFacts is the public name of aisFacts.
type AisFacts = aisFacts

// ActionFactsOf is the public form of the pca-actions export factsOf.
func ActionFactsOf(d map[string]any) AisFacts {
	return aisFactsOf(d)
}

// ActionEffectiveParamSensitivity is the public form of the pca-actions export effectiveParamSensitivity.
func ActionEffectiveParamSensitivity(p map[string]any) string {
	return effectiveParamSensitivity(p)
}

// ActionDeclaredReversibility is the public form of the pca-actions export declaredReversibility.
func ActionDeclaredReversibility(d map[string]any) any {
	return declaredReversibility(d)
}

// ActionSortUniq is the public form of the pca-actions export sortUniq.
func ActionSortUniq(xs []string) []string {
	return aisSortUniq(xs)
}

// ActionWorstReversibility is the public form of the pca-actions export worstReversibility.
func ActionWorstReversibility(r any, params map[string]any) string {
	return worstReversibility(r, params)
}

// ActionPackRefDomain is the public form of the pca-actions export PACK_REF_DOMAIN.
const ActionPackRefDomain = packRefDomain

// ActionPackShardDomain is the public form of the pca-actions export PACK_SHARD_DOMAIN.
const ActionPackShardDomain = packShardDomain

// ActionPackSigDomain is the public form of the pca-actions export PACK_SIG_DOMAIN.
const ActionPackSigDomain = packSigDomain

// ActionRulesDigestDomain is the public form of the pca-actions export RULES_DIGEST_DOMAIN.
const ActionRulesDigestDomain = rulesDigestDomain

// ActionCompareVersions is the public form of the pca-actions export compareVersions.
func ActionCompareVersions(a string, b string) (int, error) {
	return compareVersions(a, b)
}

// ActionPackDefs is the public form of the pca-actions export packDefs.
func ActionPackDefs(pack map[string]any, shards map[string]any) ([]any, error) {
	return packDefs(pack, shards)
}

// ActionPackDigest is the public form of the pca-actions export packDigest.
func ActionPackDigest(p map[string]any) (string, error) {
	return packDigest(p)
}

// ActionPackShapeError is the public form of the pca-actions export packShapeError.
func ActionPackShapeError(xv any, signed bool) (res string) {
	return packShapeError(xv, signed)
}

// ActionShardDigest is the public form of the pca-actions export shardDigest.
func ActionShardDigest(s any) (string, error) {
	return shardDigest(s)
}

// ActionPackShardKind is the public form of the pca-actions export PACK_SHARD_KIND.
const ActionPackShardKind = packShardKind

// ActionStabilities is the public form of the pca-actions export STABILITIES.
var ActionStabilities = stabilities

// ActionDefaultShardDefs is the public form of the pca-actions export DEFAULT_SHARD_DEFS.
const ActionDefaultShardDefs = defaultShardDefs

// ActionMaxEvolutionRecords is the public form of the pca-actions export MAX_EVOLUTION_RECORDS.
const ActionMaxEvolutionRecords = maxEvolutionRecords

// ActionLeq is the public form of the pca-actions export leq.
const ActionLeq = relEq

// ActionExtendRegistry is the public form of the pca-actions export extendRegistry.
func ActionExtendRegistry(base Registry, custom []any) (Registry, error) {
	return extendRegistry(base, custom)
}

// ActionProfileError is the public form of the pca-actions export profileError.
func ActionProfileError(v any, depth int) string {
	return defJSONProfileError(v, depth)
}

// ActionTopTraits is the public form of the pca-actions export topTraits.
func ActionTopTraits(reg Registry) []string {
	return topTraits(reg)
}

// ActionEscTiers is the public form of the pca-actions export ESC_TIERS.
var ActionEscTiers = actionEscTiers

// ActionRiskNames is the public form of the pca-actions export RISK_NAMES.
var ActionRiskNames = actionRiskNames

// ActionIsContextKey is the public form of the pca-actions export isContextKey.
func ActionIsContextKey(k string) bool {
	return isContextKey(k)
}

// ActionDecisionRank is the public form of the pca-actions export DECISION_RANK.
var ActionDecisionRank = decisionRank

// ActionJsonProfileError is the public form of the pca-actions export jsonProfileError.
func ActionJsonProfileError(v any, depth int) string {
	return defJSONProfileError(v, depth)
}

// ActionParamNameError is the public form of the pca-actions export paramNameError.
func ActionParamNameError(name string) string {
	return paramNameError(name)
}

// ActionValidateDef is the public form of the pca-actions export validateDef.
func ActionValidateDef(x any) (reason string) {
	return validateDef(x)
}

// ActionIsFormat is the public form of the pca-actions export isFormat.
func ActionIsFormat(v any) bool {
	return isFormat(v)
}

// ActionIsRole is the public form of the pca-actions export isRole.
func ActionIsRole(v any) bool {
	return isRole(v)
}
