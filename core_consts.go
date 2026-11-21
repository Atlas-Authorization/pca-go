package pca

// Public constants of the core package: wire versions, domains, limits and sizes. Each value is the one the verifier enforces.

// PCActn wire format.
const (
	// PcactnWireVersion is the PCActn wire format version.
	PcactnWireVersion = 2
	// PcactnVersion is the PCActn version (the wire version).
	PcactnVersion = PcactnWireVersion
)

// PcactnRequiredFields is the closed set of required top-level members of a version-2 PCActn.
var PcactnRequiredFields = append([]string(nil), requiredFields...)

// PcactnOptionalFields is the closed set of optional top-level members of a version-2 PCActn.
var PcactnOptionalFields = append([]string(nil), optionalFields...)

// Domains and kinds.
const (
	// ChainHopDomain is the domain of a chain-hop leaf.
	ChainHopDomain = "atlas-pca/chain-hop/v1"
	// EscalationPolicyDomain is the domain of an escalation policy digest.
	EscalationPolicyDomain = "atlas-pca/escalation-policy/v1"
	// EscalationActionDomain is the domain of an escalation action digest.
	EscalationActionDomain = "atlas-pca/escalation-action/v1"
	// EscalationHistoryDomain is the domain of an escalation history digest.
	EscalationHistoryDomain = "atlas-pca/escalation-history/v1"
	// AggregateDomain is the signing domain of an aggregate grant.
	AggregateDomain = "atlas-pca/aggregate-grant/v1\x00"
	// ReadGrantDomain is the signing domain of a read grant.
	ReadGrantDomain = "atlas-pca/read-grant/v1\x00"
	// ReadReceiptDomain is the signing domain of a read receipt.
	ReadReceiptDomain = "atlas-pca/read-receipt/v1\x00"
	// ForbidCertKind is the kind of a forbid-wins certificate.
	ForbidCertKind = "forbid-wins"
	// ForbidCertVersion is the version of a forbid-wins certificate.
	ForbidCertVersion = 1
	// TemplateKind is the kind of a signed policy template.
	TemplateKind = "pca-policy-template"
	// TemplateVersion is the version of a signed policy template.
	TemplateVersion = 1
	// TightenKind is the kind of a signed template tighten overlay.
	TightenKind = "pca-template-tighten"
	// AgentLeafShareBindingVersion is the threshold-share binding version.
	AgentLeafShareBindingVersion = "2.1"
	// ProvHeader is the HTTP header that carries a provenance bundle.
	ProvHeader = ProvenanceHeader
	// BudgetAllocCaveat is the caveat type of a budget allocation.
	BudgetAllocCaveat = "budget_alloc"
	// DefaultSigAlg is the default signature algorithm (classical Ed25519).
	DefaultSigAlg = "ed25519"
	// DefaultReversibilityClass is the reversibility class assumed when none is stated.
	DefaultReversibilityClass = "reversible"
)

// Limits.
const (
	// MaxPolicyClasses is the number of policy classes.
	MaxPolicyClasses = 5
	// MaxSlots is the maximum number of slots in a policy template.
	MaxSlots = 32
	// PcaNeedMaxEncoded is the maximum encoded length of a pca_need value.
	PcaNeedMaxEncoded = 2048
	// MaxJSONBytes is the maximum byte length of strictly parsed JSON.
	MaxJSONBytes = 1 << 20
	// MaxReplayComponentLen is the maximum length of one component of a replay key.
	MaxReplayComponentLen = 512
	// MaxRepeat is the largest bounded repeat count the safe-regex subset accepts.
	MaxRepeat = 64
	// MaxRegexEvaluationsPerDocument is the regex evaluation budget of one document.
	MaxRegexEvaluationsPerDocument = 64
	// MaxRegexSourceCharsPerDocument is the regex source-length budget of one document.
	MaxRegexSourceCharsPerDocument = 8192
	// MaxRegexStepsPerDocument is the regex step budget of one document.
	MaxRegexStepsPerDocument = 5_000_000
	// RegexRequestScale is the multiple of the per-document regex budget one request may spend.
	RegexRequestScale = 4
	// RegexCacheMaxEntries is the capacity of the compiled-regex cache.
	RegexCacheMaxEntries = 512
	// ChainMemoMaxTTLMs is the longest time a chain-memo entry may live.
	ChainMemoMaxTTLMs = 3_600_000
	// ChainMemoDefaultMaxEntries is the default chain-memo capacity.
	ChainMemoDefaultMaxEntries = 10_000
)

// ValidThresholds are the legal required thresholds (1 agent only, 2 plus guardian, 3 plus principal).
var ValidThresholds = [3]int{1, 2, 3}

// ModelEnvRoots are the decision-environment roots a model may derive.
var ModelEnvRoots = []string{"class", "prov", "judge", "detect"}

// DetectorVerdicts are the verdicts a detector receipt may carry.
var DetectorVerdicts = []string{"suspicious", "no_finding"}

// ObligationKinds are the obligation kinds an authorization may carry.
var ObligationKinds = []string{"log", "notify", "redact", "watermark", "require_receipt", "undo_window"}

// WorkflowLimits are the structural bounds of a workflow body.
var WorkflowLimits = struct{ Steps, Edges, Deps, Labels, Fields, Cost, ID int }{64, 256, 16, 16, 32, 8, 64}

// Post-quantum and signature sizes.
const (
	// MlDsa65PublicKeyBytes is the ML-DSA-65 public key size.
	MlDsa65PublicKeyBytes = 1952
	// MlDsa65SignatureBytes is the ML-DSA-65 signature size.
	MlDsa65SignatureBytes = 3309
	// Ed25519SignatureBytes is the Ed25519 signature size.
	Ed25519SignatureBytes = 64
	// LessCat1PublicKeyBytes is the LESS category-1 public key size.
	LessCat1PublicKeyBytes = 97484
	// LessCat1SecretKeyBytes is the LESS category-1 secret key (seed) size.
	LessCat1SecretKeyBytes = 32
	// LessCat1SignatureMaxBytes is the longest LESS category-1 signature.
	LessCat1SignatureMaxBytes = 1329
	// LessCat1SignatureMinBytes is the shortest LESS category-1 signature.
	LessCat1SignatureMinBytes = 1153
)

// EmptyParamsDigest is the digest of an action with no parameters.
var EmptyParamsDigest = func() string { d, _ := ParamsDigest(nil); return d }()
