package pca

import (
	"errors"
	"fmt"
)

// ActionPinOnNew are the values a grant's `on_new_action` may take: an unpinned verb is denied or escalated.
var ActionPinOnNew = []string{"deny", "escalate"}

func registryAlg(suite *SuiteOpts) (string, error) {
	su, ok := resolveSigAlg(suite.alg(), true)
	if !ok {
		return "", fmt.Errorf("signWithSuite: unknown signature alg %q", suite.alg())
	}
	return su.alg, nil
}

// SignRegistryDoc signs domain followed by the strict canonical form of body as the registry key kid, under the suite (nil:
// Ed25519), and returns {alg, kid, value, pq_value?}: for a post-quantum suite `value` is the post-quantum signature and, for a
// hybrid, `pq_value` is the second half. A body with no canonical form (-0, a non-finite number, an unsafe integer) is an error.
func SignRegistryDoc(domain string, body any, kid string, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	alg, err := registryAlg(suite)
	if err != nil {
		return nil, err
	}
	msg, ok := domainMessage(domain, body)
	if !ok {
		_, cerr := canonBytes(body)
		return nil, cerr
	}
	sig, pqSig, err := signWithSuite(suite, key, msg)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"alg": alg, "kid": kid, "value": sig}
	if pqSig != "" {
		out["pq_value"] = pqSig
	}
	return out, nil
}

// SignEvolutionRecord signs an unsigned evolution record as the registry key kid: the record plus its `sig`. An invalid unsigned
// record is an error and is never signed.
func SignEvolutionRecord(rec map[string]any, kid string, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if bad := evolutionRecordError(rec, false); bad != "" {
		return nil, errors.New("signEvolutionRecord: " + bad)
	}
	sig, err := SignRegistryDoc(evolutionDomain, rec, kid, key, suite)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(rec)+1)
	for k, v := range rec {
		out[k] = v
	}
	out["sig"] = sig
	return out, nil
}

// RegistryKeyOf is the registry key entry {kid, alg, pk, pq_pk?} that verifies what SignRegistryDoc signs with this key and suite
// (pq_pk only for a post-quantum suite).
func RegistryKeyOf(kid string, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	alg, err := registryAlg(suite)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"kid": kid, "alg": alg, "pk": key.Public}
	if pq, ok := SuitePqPublicKey(suite); ok {
		out["pq_pk"] = pq
	}
	return out, nil
}

// SignReapproval is the principal's re-approval of a widening evolution step: Ed25519 only, bound to the grant id and to the digest of
// the record's diff. The record may be signed or unsigned.
func SignReapproval(grantID string, record map[string]any, principal *KeyPair) (map[string]any, error) {
	diff, ok := evolutionDiffDigest(record)
	if !ok {
		return nil, errors.New("signReapproval: the record has no diff digest")
	}
	body := map[string]any{"v": jsNumber(1), "kind": reapprovalKind, "grant": grantID, "verb": record["verb"], "diff": diff}
	msg, ok := domainMessage(reapprovalDomain, body)
	if !ok {
		_, cerr := canonBytes(body)
		return nil, cerr
	}
	body["sig"] = map[string]any{"alg": "ed25519", "value": B64u(principal.Sign(msg))}
	return body, nil
}
