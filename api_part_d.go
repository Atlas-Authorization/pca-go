package pca

import "fmt"

// Public forms of reference exports that were reachable only through unexported helpers.

// MeshCheckHeadAdvance reports why next is not a legitimate successor of prev ("" when it is): same domain, sizes never shrink, an
// equal log size means an identical root, a larger one needs a verifying consistency proof.
func MeshCheckHeadAdvance(prev, next, proof any) string {
	return meshCheckHeadAdvance(prev, next, proof)
}

// MeshCheckCosignedHead reports why a cosigned head is not acceptable for expectedDomain under trust ("" when it is). A malformed
// trust configuration is refused with its reason.
func MeshCheckCosignedHead(ch any, expectedDomain string, trust any, pinProof any) string {
	t, bad := meshValidTrust(trust)
	if bad != "" {
		return bad
	}
	return meshCheckCosignedHead(ch, expectedDomain, t, pinProof)
}

// LeafHash is the Merkle leaf hash of a plan or action leaf (SHA-256 over 0x00 and the canonical form).
func LeafHash(leaf any) ([]byte, error) { return leafHash(leaf) }

// FloorOf is the join of the floors of the trait closure of ids.
func (r Registry) FloorOf(ids []string) (Profile, error) { return r.floorOf(ids) }

// IntentStateDigest is the digest of a frame state value (lenient canonical form under the frame-state domain).
func IntentStateDigest(value any) (s string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return ixStateDigest(value), nil
}

// IntentFactRef is the reference of a signed oracle fact (the artifact reference under the fact-ref domain).
func IntentFactRef(fact any) (string, bool) { return artifactRef(factRefDomain, "f", fact) }

// AuditRound is the audit round on its own: the number of questions asked and whether the budget ran out.
func (l *IntentLearner) AuditRound(answer func(q map[string]any) float64, o map[string]any, asked *[]any) (int, bool) {
	return l.auditRound(answer, o, asked)
}

// AnalyzerResidual specialises policy to the known context; everything under opts.unknown stays symbolic. The result carries
// decision never | always | conditional, the residual policy and its digest.
func AnalyzerResidual(policy, known, opts any) map[string]any {
	return anlResidual(policy, known, opts)
}

// MpcEcQ is the prime of the Ed25519 base field.
var MpcEcQ = mpcEcQ

// OprfMode maps an OPRF mode name (oprf, voprf, poprf) to its context-string byte (the reference's MODE).
var OprfMode = oprfModeByte
