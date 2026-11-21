package pca

import (
	"math"
	"math/big"
	"regexp"
	"strings"
)

// More public constants and small pure helpers of the core package, under the reference's names.

const (
	// DefaultLeaseSkewMs is the default clock-error allowance of a guardian lease.
	DefaultLeaseSkewMs = DefaultGuardianLeaseSkewMs
	// DefaultTimeoutMs is the default HTTP timeout of a QRNG fetch.
	DefaultTimeoutMs = DefaultQrngTimeoutMs
	// IrreversibleClass is the reversibility class that is never eligible for the optimistic fast path.
	IrreversibleClass = "irreversible"
	// PcaGrantMaxDetails is the most pca_grant authorization details one request may carry.
	PcaGrantMaxDetails = pcaGrantMaxDetail
	// PcaGrantMaxChainLen is the longest chain a pca_grant detail may name.
	PcaGrantMaxChainLen = pcaGrantMaxChain
	// PcactnDefaultTtlMs is the lifetime BuildPCActn stamps by default (20 minutes).
	PcactnDefaultTtlMs = DefaultTTLMs
	// ApprovalRenderKind is the kind of an approval render document.
	ApprovalRenderKind = "pca-approval-render"
	// PcaNeedDomain is the domain of a pca_need digest.
	PcaNeedDomain = "atlas-pca/need/v1"
	// ReplayMinRetentionMs is how long a replay store must remember a key: the longest lifetime plus both skews.
	ReplayMinRetentionMs = PcactnMaxLifetimeMs + 2*PcactnMaxSkewMs
)

// StatefulRequiredChecks are the checks a stateful verifier requires by default.
var StatefulRequiredChecks = []string{"counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"}

// ProvPathRe is the shape of a `prov` key: one action.params.<name> segment.
var ProvPathRe = regexp.MustCompile(`^action\.params\.[A-Za-z0-9_]{1,64}$`)

// IsProvPath is true for a well-formed `prov` key whose segment is not a prototype name.
func IsProvPath(k string) bool {
	if !ProvPathRe.MatchString(k) {
		return false
	}
	switch k[len("action.params."):] {
	case "__proto__", "constructor", "prototype":
		return false
	}
	return true
}

// ParseLabelRef parses `pca-labels:<receipt digest>#<field>`; ok is false when malformed.
func ParseLabelRef(ref string) (receipt, field string, ok bool) {
	if !strings.HasPrefix(ref, labelRefPrefix) {
		return "", "", false
	}
	rest := ref[len(labelRefPrefix):]
	i := strings.IndexByte(rest, '#')
	if i < 0 {
		return "", "", false
	}
	receipt, field = rest[:i], rest[i+1:]
	if !isDigestV(receipt) || len(field) == 0 {
		return "", "", false
	}
	return receipt, field, true
}

// ResolveWindow derives the authoritative window of a new claim: issued_at = serverNow, the window is requestedMs (nil: the policy
// default) clamped into the policy bounds, never below DefaultMinChallengeWindowMs nor the policy minimum, never above the maximum.
func ResolveWindow(p ChallengeWindowPolicy, serverNow float64, requestedMs *float64, defaultWindowMs float64) (issuedAt, challengeWindowMs float64, err error) {
	if math.IsNaN(serverNow) || math.IsInf(serverNow, 0) {
		return 0, 0, errNotFinite("resolveWindow: serverNow must be finite")
	}
	want := defaultWindowMs
	if requestedMs != nil && !math.IsNaN(*requestedMs) && !math.IsInf(*requestedMs, 0) {
		want = *requestedMs
	}
	floor := math.Max(p.MinWindowMs, DefaultMinChallengeWindowMs)
	return serverNow, math.Min(p.MaxWindowMs, math.Max(floor, want)), nil
}

type errNotFinite string

func (e errNotFinite) Error() string { return string(e) }

// PqBindingError is the F-2 / F-4 rule: a hop or leaf of a suite that carries a PQ key is accepted only when that pq_pk is the
// one the signer's holder committed to. committed is the signer's holder_pq commitment (nil when it has none); allowUnboundPq is
// never honoured (an unbound PQ key is always refused). It returns "" when the key is fine or the suite carries none.
func PqBindingError(alg any, algPresent bool, pqPk any, committed *string, label string) string {
	su, ok := resolveSigAlg(alg, algPresent)
	if !ok || !su.needsPqPk {
		return ""
	}
	if committed == nil {
		return label + ": suite '" + su.alg + "' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
	}
	if pk, isStr := pqPk.(string); !isStr || holderPqCommitment(pk) != *committed {
		return label + ": pq_pk does not match the signer's committed holder_pq (F-2)"
	}
	return ""
}

// ValidateRevocationStaleness reports a malformed staleness policy (a configuration error, raised at construction).
func ValidateRevocationStaleness(p RevocationStalenessPolicy) error { return p.Validate() }

// StalenessPolicyOn is true when the policy turns the staleness check on (any age option set).
func StalenessPolicyOn(p RevocationStalenessPolicy) bool { return p.On() }

// FrostContextString is the RFC 9591 context string of the Ed25519 / SHA-512 ciphersuite.
const FrostContextString = frostContext

// FrostScalarToBytes serialises a scalar as 32 little-endian bytes (reduced mod L first, so a negative or oversized integer is fine).
func FrostScalarToBytes(s *big.Int) []byte { return frostIntScalar(s).Bytes() }

// FrostH1 is RFC 9591 H1 (the binding-factor hash) as a reduced 32-byte scalar.
func FrostH1(m []byte) []byte { return frostH("H1", m) }

// FrostH2 is RFC 9591 H2 (the challenge hash) as a reduced 32-byte scalar.
func FrostH2(m []byte) []byte { return frostH("H2", m) }

// FrostH3 is RFC 9591 H3 (the nonce hash) as a reduced 32-byte scalar.
func FrostH3(m []byte) []byte { return frostH("H3", m) }

// FrostH4 is RFC 9591 H4 (the message hash), a 64-byte digest.
func FrostH4(m []byte) []byte { return frostH("H4", m) }

// FrostH5 is RFC 9591 H5 (the commitment-list hash), a 64-byte digest.
func FrostH5(m []byte) []byte { return frostH("H5", m) }
