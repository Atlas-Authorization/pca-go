package pca

// Post-quantum agility for the FROST guardian co-sign (interim hybrid): after the quorum's Ed25519 FROST aggregate, the guardian key
// attaches an ML-DSA-65 co-signature over a representative that binds the group key, sha256(message), the signer set and the suite;
// verification needs BOTH halves. The aggregate is self-describing through groupAlg, defaulting to plain ed25519.

import (
	"errors"
	"fmt"
	"sort"
)

const (
	// FrostCosignDomain separates the co-sign representative from every other signed surface.
	FrostCosignDomain = "atlas-pca/frost-pq-cosign/v1\x00"
	// FrostSignerSetDomain separates the signer-set digest.
	FrostSignerSetDomain = "atlas-pca/frost-signer-set/v1\x00"
	// FrostHybridGroupAlg is the hybrid suite: the FROST Ed25519 aggregate plus a guardian ML-DSA-65 co-signature.
	FrostHybridGroupAlg = "hybrid-ed25519-ml-dsa-65"
)

func frostKnownGroupAlg(x any) bool { return x == DefaultFrostGroupAlg || x == FrostHybridGroupAlg }

// ResolveFrostGroupAlg resolves an artifact's groupAlg (absent is the default ed25519); ok is false for an unknown value.
func ResolveFrostGroupAlg(alg any, present bool) (string, bool) {
	if !present {
		return DefaultFrostGroupAlg, true
	}
	if frostKnownGroupAlg(alg) {
		return alg.(string), true
	}
	return "", false
}

// FrostSignerSetDigest is sha256(domain || canonical(sorted distinct ids)): order-insensitive and duplicate-free. An empty set or a
// non-positive identifier is an error.
func FrostSignerSetDigest(signerSet []int64) ([]byte, error) {
	if len(signerSet) == 0 {
		return nil, errors.New("frostSignerSetDigest: empty signer set")
	}
	seen := map[int64]bool{}
	ids := []int64{}
	for _, id := range signerSet {
		if !frostIsID(id) {
			return nil, errors.New("frostSignerSetDigest: participant identifiers must be positive safe integers")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	l := make([]any, len(ids))
	for i, id := range ids {
		l[i] = jsNumber(float64(id))
	}
	cb, err := CanonicalBytes(l)
	if err != nil {
		return nil, err
	}
	return sha(append([]byte(FrostSignerSetDomain), cb...)), nil
}

// FrostCosignRepresentative is the exact bytes the guardian ML-DSA-65 co-signature covers:
// domain || groupAlg || 0x00 || groupPublicKey (32) || sha256(message) || signerSetDigest.
func FrostCosignRepresentative(groupPublicKeyB64u string, message []byte, signerSet []int64, groupAlg string) ([]byte, error) {
	gpk, ok := DecodeB64uStrict(groupPublicKeyB64u, 32)
	if !ok {
		return nil, errors.New("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point")
	}
	set, err := FrostSignerSetDigest(signerSet)
	if err != nil {
		return nil, err
	}
	out := append([]byte(FrostCosignDomain), groupAlg...)
	out = append(out, 0)
	out = append(out, gpk...)
	out = append(out, sha(message)...)
	return append(out, set...), nil
}

// HybridFrostCosignOptions are the options of SignHybridFrostCosign: the suite (empty is ed25519), the guardian's ML-DSA-65 key pair
// (required for the hybrid suite) and the threshold the quorum must reach.
type HybridFrostCosignOptions struct {
	GroupAlg      string
	GuardianMlDsa *PqKeyPair
	Threshold     *int
}

// SignHybridFrostCosign produces the guardian co-sign over message: the classical FROST aggregate (every safety check on) as
// {sig}, and for the hybrid suite also {groupAlg, pq_sig, pq_pk}. A hybrid suite without a guardian key is an error.
func SignHybridFrostCosign(groupPublicKey []byte, quorum []FrostParticipantShare, message []byte, o HybridFrostCosignOptions) (map[string]any, error) {
	alg := o.GroupAlg
	if alg == "" {
		alg = DefaultFrostGroupAlg
	}
	if !frostKnownGroupAlg(alg) {
		return nil, fmt.Errorf("signHybridFrostCosign: unknown groupAlg '%s'", alg)
	}
	agg, err := FrostCosign(groupPublicKey, quorum, message, o.Threshold)
	if err != nil {
		return nil, err
	}
	sig := b64.EncodeToString(agg)
	if alg == DefaultFrostGroupAlg {
		return map[string]any{"sig": sig}, nil
	}
	if o.GuardianMlDsa == nil {
		return nil, fmt.Errorf("signHybridFrostCosign: '%s' requires a guardian ML-DSA-65 key pair", alg)
	}
	ids := make([]int64, len(quorum))
	for i, p := range quorum {
		ids[i] = p.Identifier
	}
	rep, err := FrostCosignRepresentative(b64.EncodeToString(groupPublicKey), message, ids, alg)
	if err != nil {
		return nil, err
	}
	pq, _, err := signWithSuite(&SuiteOpts{Alg: "ml-dsa-65", Pq: o.GuardianMlDsa}, nil, rep)
	if err != nil {
		return nil, err
	}
	return map[string]any{"sig": sig, "groupAlg": alg, "pq_sig": pq, "pq_pk": o.GuardianMlDsa.Public}, nil
}

// FrostHybridVerdict is the outcome of VerifyHybridFrostCosign: GroupAlg is the resolved suite (empty when none resolved), EdOK
// whether the FROST group signature verified, PqOK whether the ML-DSA co-signature did (always false for plain ed25519).
type FrostHybridVerdict struct {
	OK, EdOK, PqOK bool
	GroupAlg       string
	Reason         string
}

// VerifyHybridFrostOptions are the options of VerifyHybridFrostCosign: the guardian's REGISTERED ML-DSA-65 public key (base64url;
// required for the hybrid suite, and verification binds to it, never to the artifact's own pq_pk) and the suite the verifier pins
// (when HasExpectGroupAlg: an artifact of another suite is denied, there is no downgrade).
type VerifyHybridFrostOptions struct {
	GuardianPqPublicKey any
	ExpectGroupAlg      any
	HasExpectGroupAlg   bool
}

// VerifyHybridFrostCosign verifies a guardian co-sign artifact over message under the group key. For the hybrid suite BOTH the FROST
// Ed25519 group signature and the ML-DSA-65 co-signature over the representative (under the registered guardian key) must verify.
// It never panics.
func VerifyHybridFrostCosign(artifact any, message []byte, groupPublicKeyB64u any, signerSet []int64, o VerifyHybridFrostOptions) (v FrostHybridVerdict) {
	deny := func(reason, alg string) FrostHybridVerdict { return FrostHybridVerdict{GroupAlg: alg, Reason: reason} }
	defer func() {
		if recover() != nil {
			v = deny("malformed artifact", "")
		}
	}()
	art, isMap := artifact.(map[string]any)
	sigS, sigIsStr := art["sig"].(string)
	if !isMap || !sigIsStr {
		return deny("malformed artifact", "")
	}
	gpkS, gIsStr := groupPublicKeyB64u.(string)
	if _, ok := DecodeB64uStrict(gpkS, 32); !gIsStr || !ok {
		return deny("malformed group public key", "")
	}
	galg, present := art["groupAlg"]
	alg, known := ResolveFrostGroupAlg(galg, present)
	if !known {
		return deny(fmt.Sprintf("unknown groupAlg '%s'", jsValueString(galg)), "")
	}
	if o.HasExpectGroupAlg {
		if !frostKnownGroupAlg(o.ExpectGroupAlg) {
			return deny(fmt.Sprintf("unknown expected groupAlg '%s'", jsValueString(o.ExpectGroupAlg)), "")
		}
		if o.ExpectGroupAlg != alg {
			return deny(fmt.Sprintf("groupAlg '%s' does not match the required '%s'", alg, o.ExpectGroupAlg), alg)
		}
	}
	edOk := VerifyB64u(gpkS, message, sigS)
	if alg == DefaultFrostGroupAlg {
		if !edOk {
			return deny("FROST Ed25519 group signature did not verify", alg)
		}
		return FrostHybridVerdict{OK: true, EdOK: true, GroupAlg: alg}
	}
	reg, regIsStr := o.GuardianPqPublicKey.(string)
	if _, ok := DecodeB64uStrict(reg, MlDsa65PublicKeyBytes); !regIsStr || !ok {
		return deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key", alg)
	}
	if pk, has := art["pq_pk"]; has && pk != reg {
		return deny("artifact pq_pk does not match the registered guardian ML-DSA key", alg)
	}
	pqSig, isStr := art["pq_sig"].(string)
	if !isStr {
		return deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing", alg)
	}
	pqOk := false
	if rep, err := FrostCosignRepresentative(gpkS, message, signerSet, alg); err == nil {
		pqOk = verifyLeafSuite("ml-dsa-65", true, "", callerVouchedPqKey(reg), rep, pqSig, nil)
	}
	if !edOk || !pqOk {
		why := "guardian ML-DSA-65 co-signature did not verify"
		if !edOk {
			why = "FROST Ed25519 group signature did not verify"
		}
		return FrostHybridVerdict{EdOK: edOk, PqOK: pqOk, GroupAlg: alg, Reason: why}
	}
	return FrostHybridVerdict{OK: true, EdOK: true, PqOK: true, GroupAlg: alg}
}
