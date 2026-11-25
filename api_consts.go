package pca

import "regexp"

// Public constants of the sibling packages: domains, header names, limits and shape patterns. Each value is the one the
// corresponding verifier enforces.

// Agent cards and A2A.
const (
	// AgentcardDefaultAlg is the default signature algorithm of an agent card.
	AgentcardDefaultAlg = "EdDSA"
	// AgentcardPcaAttestorID is the attestor id of PCA-issued agent facts.
	AgentcardPcaAttestorID = "did:atlas:pca-attestor"
	// AgentcardWellKnownAgentCardPath is the well-known path of an agent card.
	AgentcardWellKnownAgentCardPath = "/.well-known/agent-card.json"
	// AgentcardWellKnownAgentFactsPath is the well-known path of agent facts.
	AgentcardWellKnownAgentFactsPath = "/.well-known/agent-facts.json"
	// AcpX402V2PaymentRequiredHeader is the x402 v2 payment-required header.
	AcpX402V2PaymentRequiredHeader = "PAYMENT-REQUIRED"
)

// Request authorization keys and injected headers.
const (
	// AuthzenPcaActionKey is the AuthZEN context key that carries the PCActn.
	AuthzenPcaActionKey = "pca_action"
	// AuthzenPcaApprovalKey is the AuthZEN context key that carries an approval.
	AuthzenPcaApprovalKey = "pca_approval"
	// AuthzenPcaProvenanceKey is the AuthZEN context key that carries the provenance bundle.
	AuthzenPcaProvenanceKey = "pca_provenance"
)

// GatewayPcaInjectedHeaders are the verdict headers a gateway injects upstream (and strips from the incoming request).
var GatewayPcaInjectedHeaders = []string{"x-pca-verdict", "x-pca-verb", "x-pca-grant"}

// Web Bot Auth.
const (
	// WebbotauthDefaultExpiresSec is the default lifetime of a signed request.
	WebbotauthDefaultExpiresSec = 300
	// WebbotauthDirectoryContentType is the content type of a key directory.
	WebbotauthDirectoryContentType = "application/http-message-signatures-directory+json"
	// WebbotauthPcaProofComponent is the signed component that carries the PCA proof (the lowercase PCA-Action header).
	WebbotauthPcaProofComponent = "pca-action"
	// WebbotauthWellKnownDirectoryPath is the well-known path of the key directory.
	WebbotauthWellKnownDirectoryPath = "/.well-known/http-message-signatures-directory"
	// WebbotauthDefaultSignatureLabel is the default signature label.
	WebbotauthDefaultSignatureLabel = "sig1"
	// WebbotauthSignatureAgentHeader is the Signature-Agent header.
	WebbotauthSignatureAgentHeader = "Signature-Agent"
	// WebbotauthDirectorySignatureTag is the tag of a signed key directory response.
	WebbotauthDirectorySignatureTag = "http-message-signatures-directory"
)

// Attestation and EAT.
const (
	// EatDefaultPqCosignSuite is the default suite of a post-quantum attestation co-signature.
	EatDefaultPqCosignSuite = "ml-dsa-65"
	// EatPqcosignDomain is the signing domain of an attestation co-signature.
	EatPqcosignDomain = "atlas-pca/attest-cosign/v1"
	// EatAmdSevSnpSignedRegionEnd is the end offset of the signed region of an SEV-SNP report.
	EatAmdSevSnpSignedRegionEnd = 0x2a0
	// EatAmdSevSnpHardwareRootLabel labels the SEV-SNP hardware root in an appraisal.
	EatAmdSevSnpHardwareRootLabel = "amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)"
	// EatIntotoPayloadType is the in-toto payload type of a Sigstore bundle.
	EatIntotoPayloadType = "application/vnd.in-toto+json"
)

// EatPqCosignSuites are the suites an attestation co-signature may use.
var EatPqCosignSuites = []string{"ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-ml-dsa-65",
	"hybrid-nested-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s"}

// EatSigstoreBundleMediaTypes are the Sigstore bundle media types accepted.
var EatSigstoreBundleMediaTypes = []string{"application/vnd.dev.sigstore.bundle+json;version=0.2",
	"application/vnd.dev.sigstore.bundle+json;version=0.3", "application/vnd.dev.sigstore.bundle.v0.3+json"}

// Cryptographic building blocks.
const (
	// BbsCiphersuiteID is the BBS ciphersuite identifier.
	BbsCiphersuiteID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	// BbsAPIID is the BBS API identifier.
	BbsAPIID = BbsCiphersuiteID + "H2G_HM2S_"
	// BbsMaxMessages is the largest number of messages a BBS signature covers.
	BbsMaxMessages = 1024
	// AbeMaxPolicyDepth is the deepest attribute policy accepted.
	AbeMaxPolicyDepth = 10
	// AbeMaxPolicyNodes is the largest attribute policy accepted.
	AbeMaxPolicyNodes = 1024
	// OprfElementBytes is the size of an OPRF group element.
	OprfElementBytes = 32
	// OprfOutputBytes is the size of an OPRF output.
	OprfOutputBytes = 64
	// OprfScalarBytes is the size of an OPRF scalar.
	OprfScalarBytes = 32
	// MpcMinMacSoundnessBits is the least MAC soundness, in bits, an MPC session accepts.
	MpcMinMacSoundnessBits = 100
	// RatchetMaxRatchetDepth is the deepest ratchet accepted.
	RatchetMaxRatchetDepth = 20
	// VdfInsecureDevSetupDefaultBits is the modulus size of the insecure development setup.
	VdfInsecureDevSetupDefaultBits = 2048
	// FndsaNoFnDsaBackendMessage is the refusal text when no FN-DSA backend is registered.
	FndsaNoFnDsaBackendMessage = "no FN-DSA backend registered — install @atlasauth/pca-fndsa-wasm or supply a backend via setFalconBackend()"
	// HybridPqAlg is the post-quantum algorithm of the hybrid quorum.
	HybridPqAlg = PqQuorumAlg
)

// Tokens and presentations.
const (
	// SdjwtKbJwtTyp is the typ of a key-binding JWT.
	SdjwtKbJwtTyp = "kb+jwt"
	// TxnTokensMaxTokenChars is the longest transaction token accepted.
	TxnTokensMaxTokenChars = 16384
	// ActionIdempotencyParam is the parameter that carries an idempotency key.
	ActionIdempotencyParam = "idempotency_key"
	// ActionMaxAuthorBytes is the largest authored action document.
	ActionMaxAuthorBytes = 1 << 20
	// ActionMaxRuleApprovers is the most approvers a business rule names.
	ActionMaxRuleApprovers = 16
	// ActionMaxRuleCurrencies is the most currencies a business rule names.
	ActionMaxRuleCurrencies = 32
	// ActionMaxRuleExamples is the most examples a business rule carries.
	ActionMaxRuleExamples = 32
	// ActionMaxRuleList is the longest list in a business rule.
	ActionMaxRuleList = 64
	// ActionMaxDescriptionBytes is the longest action description.
	ActionMaxDescriptionBytes = 1024
	// ActionMaxTitleBytes is the longest action title.
	ActionMaxTitleBytes = 120
	// ActionMaxVerbBytes is the longest action verb.
	ActionMaxVerbBytes = 128
	// ActionMaxImportOps is the default operation cap of an import.
	ActionMaxImportOps = 20_000
	// ActionDefaultRulesVersion is the default business-rules version.
	ActionDefaultRulesVersion = "1.1.0"
	// ActionLintRulesDigestDomain is the domain of the lint-rules digest.
	ActionLintRulesDigestDomain = "atlas-pca/action-lint-rules/v1"
	// ActionPackSignDomain is the signing domain of an action pack.
	ActionPackSignDomain = "atlas-pca/action-pack/v1\x00"
	// ActionCoreNamespace is the namespace prefix of core traits.
	ActionCoreNamespace = "pca."
	// ActionRiskMax is the highest risk tier.
	ActionRiskMax = 3
)

// ActionAutoIdempotentEffects are the effects that get an idempotency key automatically.
var ActionAutoIdempotentEffects = []string{"send", "pay", "create", "provision", "publish"}

// ActionResourceScopes are the scopes an action's resource may have.
var ActionResourceScopes = []string{"one", "set", "tenant", "global"}

// Patterns of action definitions.
var (
	// ActionAliasRe matches an action alias.
	ActionAliasRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}$`)
	// ActionCustomRoleRe matches a custom parameter role.
	ActionCustomRoleRe = regexp.MustCompile(`^x\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}$`)
	// ActionIDFormatRe matches an identifier format.
	ActionIDFormatRe = regexp.MustCompile(`^id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$`)
	// ActionIDRoleRe matches an identifier role.
	ActionIDRoleRe = regexp.MustCompile(`^id\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$`)
	// ActionParamNameRe matches a parameter name.
	ActionParamNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$`)
	// ActionTraitIDRe matches a trait id.
	ActionTraitIDRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$`)
	// ActionVerbRe matches an action verb.
	ActionVerbRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}$`)
)

// Intent and wallet.
const (
	// IntentProfileKind is the kind of a signed intent profile.
	IntentProfileKind = "pca-intent-profile"
	// IntentProfileRefDomain is the domain of an intent profile reference.
	IntentProfileRefDomain = "atlas-pca/intent-profile-ref/v1"
	// IntentProfileSigDomain is the signing domain of an intent profile.
	IntentProfileSigDomain = "atlas-pca/intent-profile/v1\x00"
	// IntentMaxProfileObservations is the most observations an intent profile carries.
	IntentMaxProfileObservations = 2000
	// IntentHarmQuadraturePieces is the number of pieces of the harm quadrature.
	IntentHarmQuadraturePieces = 1024
	// WalletIntentAnswerRefDomain is the domain of an intent answer reference.
	WalletIntentAnswerRefDomain = "atlas-pca/intent-answer-ref/v1"
	// WalletIntentAnswerSigDomain is the signing domain of an intent answer.
	WalletIntentAnswerSigDomain = "atlas-pca/intent-obs/v2\x00"
	// WalletIntentDeviceChallengeDomain is the domain of an intent device challenge.
	WalletIntentDeviceChallengeDomain = "atlas-pca/intent-device/v1"
	// WalletIntentTypedDomain is the domain of a typed intent answer.
	WalletIntentTypedDomain = "atlas-pca/intent-typed/v1"
)

// IntentCpTolerance is the tolerance of the compile-and-compare check (2^-44).
const IntentCpTolerance = 1.0 / (1 << 44)

// ReadSafeTraits are the traits whose read actions are safe to repeat.
var ReadSafeTraits = []string{"pca.financial_data_read", "pca.pii_access", "pca.regulated_data"}

// K1CaveatTypes are the caveat types of the caveat language.
var K1CaveatTypes = []string{CaveatNeedsDischarge, CaveatSealed, CaveatMaxUses, CaveatDerive, CaveatSpiffeBound}

// VerifiedCoreTaintLevels are the taint levels, most trusted first.
var VerifiedCoreTaintLevels = []string{"trusted", "first_party", "tool", "web", "agent"}

// PolicyCiDefaultDangerousVerbs are the verb substrings the over-broad check treats as dangerous by default.
var PolicyCiDefaultDangerousVerbs = []string{"delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin",
	"grant", "revoke", "deploy", "shutdown", "rotate"}

// MissingContextSuppliers are the parties that may supply a missing context path.
var MissingContextSuppliers = append([]string(nil), missingSuppliers...)

// ActionResourceTypeRe matches an action resource type.
var ActionResourceTypeRe = reAimResourceType

// ActionEscMax is the highest escalation tier.
const ActionEscMax = maxEscTier

// PolicyCiSeverityRank orders the severities of a policy lint finding.
var PolicyCiSeverityRank = map[string]int{"info": 1, "warn": 2, "error": 3}

// ValidReadGrantBody reports whether x is a structurally valid read-grant body.
func ValidReadGrantBody(x any) bool { return k5ValidReadGrantBody(x) }

// ValidWorkflowBody reports whether x is a structurally valid workflow body.
func ValidWorkflowBody(x any) bool { return k5ValidWorkflowBody(x) }

// WorkflowDagError is "" when the workflow's step graph is well formed, else the reason.
func WorkflowDagError(b map[string]any) string { return k5DagError(b) }
