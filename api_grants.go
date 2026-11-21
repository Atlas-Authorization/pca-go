package pca

// GrantsFreshAtDomain is the public form of the pca-grants export FRESH_AT_DOMAIN.
const GrantsFreshAtDomain = freshAtDomain

// GrantsFreshAtCheck is the public form of the pca-grants export FreshAtCheck.
type GrantsFreshAtCheck = freshAtCheck

// GrantsFreshAtRefDomain is the public form of the pca-grants export FRESH_AT_REF_DOMAIN.
const GrantsFreshAtRefDomain = freshAtRefDomain

// GrantsValidateFreshAtWire is the public form of the pca-grants export validateFreshAtWire.
func GrantsValidateFreshAtWire(v any) string {
	return validateFreshAtWire(v)
}

// GrantsDecideFreshAt is the public form of the pca-grants export decideFreshAt.
func GrantsDecideFreshAt(pcactn map[string]any, policy *FreshAtPolicy, now int64) FreshAtCheck {
	return decideFreshAt(pcactn, policy, now)
}

// GrantsAgentBlueprintDomain is the public form of the pca-grants export AGENT_BLUEPRINT_DOMAIN.
const GrantsAgentBlueprintDomain = agentBlueprintDomain

// GrantsBreakGlassDomain is the public form of the pca-grants export BREAK_GLASS_DOMAIN.
const GrantsBreakGlassDomain = breakGlassDomain

// GrantsBreakGlassReviewDomain is the public form of the pca-grants export BREAK_GLASS_REVIEW_DOMAIN.
const GrantsBreakGlassReviewDomain = breakGlassReviewDomain

// GrantsMaxBreakGlassUses is the public form of the pca-grants export MAX_BREAK_GLASS_USES.
const GrantsMaxBreakGlassUses = maxBreakGlassUses

// GrantsMaxBreakGlassWindowMs is the public form of the pca-grants export MAX_BREAK_GLASS_WINDOW_MS.
const GrantsMaxBreakGlassWindowMs = maxBreakGlassWindowMs

// GrantsMaxReviewWithinMs is the public form of the pca-grants export MAX_REVIEW_WITHIN_MS.
const GrantsMaxReviewWithinMs = maxReviewWithinMs

// GrantsBundleDomain is the public form of the pca-grants export BUNDLE_DOMAIN.
const GrantsBundleDomain = bundleDomain

// GrantsBundleRefDomain is the public form of the pca-grants export BUNDLE_REF_DOMAIN.
const GrantsBundleRefDomain = bundleRefDomain

// GrantsLogHeadDomain is the public form of the pca-grants export LOG_HEAD_DOMAIN.
const GrantsLogHeadDomain = logHeadDomain

// GrantsRecordDomain is the public form of the pca-grants export RECORD_DOMAIN.
const GrantsRecordDomain = recordDomain

// GrantsCompareVersion is the public form of the pca-grants export compareVersion.
func GrantsCompareVersion(a string, b string) int {
	return compareVersion(a, b)
}

// GrantsGrantAmendDomain is the public form of the pca-grants export GRANT_AMEND_DOMAIN.
const GrantsGrantAmendDomain = grantAmendDomain

// GrantsGrantRevokeDomain is the public form of the pca-grants export GRANT_REVOKE_DOMAIN.
const GrantsGrantRevokeDomain = grantRevokeDomain

// GrantsNeedApproveDomain is the public form of the pca-grants export NEED_APPROVE_DOMAIN.
const GrantsNeedApproveDomain = needApproveDomain

// GrantsLeaseDomain is the public form of the pca-grants export LEASE_DOMAIN.
const GrantsLeaseDomain = leaseDomain

// GrantsLeaseRevokeDomain is the public form of the pca-grants export LEASE_REVOKE_DOMAIN.
const GrantsLeaseRevokeDomain = leaseRevokeDomain

// GrantsLeaseCap is the public form of the pca-grants export leaseCap.
func GrantsLeaseCap(l map[string]any) int64 {
	return leaseCap(l)
}

// GrantsListCursorDomain is the public form of the pca-grants export LIST_CURSOR_DOMAIN.
const GrantsListCursorDomain = listCursorDomain

// GrantsListReceiptDomain is the public form of the pca-grants export LIST_RECEIPT_DOMAIN.
const GrantsListReceiptDomain = listReceiptDomain

// GrantsShadowDiffDomain is the public form of the pca-grants export SHADOW_DIFF_DOMAIN.
const GrantsShadowDiffDomain = shadowDiffDomain

// GrantsPromotionApprovalDomain is the public form of the pca-grants export PROMOTION_APPROVAL_DOMAIN.
const GrantsPromotionApprovalDomain = promotionApprovalDomain

// GrantsWideningExplanationDomain is the public form of the pca-grants export WIDENING_EXPLANATION_DOMAIN.
const GrantsWideningExplanationDomain = wideningExplanationDomain
