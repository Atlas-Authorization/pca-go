package pca

// B4 — post-quantum crypto-agility, mirroring packages/pca/src/pq.ts. An ADDITIVE, backward-compatible
// algorithm-agility slot for the PCActn leaf signature. Absent `alg` (or `alg == "ed25519"`) is
// BYTE-IDENTICAL to the pre-B4 wire. B4 adds optional post-quantum suites:
//   - "ed25519"                    classical 64-byte Ed25519 `sig` (unchanged).
//   - "ml-dsa-65"                  pure PQ: `sig` is an ML-DSA-65 (FIPS-204) signature verified under `pq_pk`.
//   - "hybrid-ed25519-ml-dsa-65"   BOTH Ed25519 `sig` (under the leaf holder) AND ML-DSA-65 `pq_sig`
//                                  (under `pq_pk`) over the same canonical message; both must verify.
//
// `alg` and `pq_pk` are SIGNED (part of the canonical body); `sig` and `pq_sig` are the signatures and are
// stripped from the signed body (like `sig`/`threshold`). The ML-DSA primitive is cloudflare/circl's
// mldsa65 (FIPS-204, category 3): public key 1952 bytes, signature 3309 bytes, empty context.

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	mlDsaPublicKeyBytes = 1952
	mlDsaSignatureBytes = 3309
)

type sigSuite struct {
	alg        string
	sigBytes   int
	hasEd25519 bool
	hasMlDsa   bool
	needsPqPk  bool
	needsPqSig bool
}

// The closed algorithm registry.
var sigSuites = map[string]sigSuite{
	"ed25519":                  {"ed25519", sigLen, true, false, false, false},
	"ml-dsa-65":                {"ml-dsa-65", mlDsaSignatureBytes, false, true, true, false},
	"hybrid-ed25519-ml-dsa-65": {"hybrid-ed25519-ml-dsa-65", sigLen, true, true, true, true},
}

// resolveSigAlg resolves the suite for a PCActn `alg` value. `present` is false when the field is absent
// (=> default ed25519). Returns (suite, true) for the default or a known suite; (_, false) fails closed.
func resolveSigAlg(alg any, present bool) (sigSuite, bool) {
	if !present {
		return sigSuites["ed25519"], true
	}
	s, ok := alg.(string)
	if !ok {
		return sigSuite{}, false
	}
	su, known := sigSuites[s]
	return su, known
}

// ---- the PQ key choke point (R3-01 / R4-01) -------------------------------------------

// pqVerifyKey is the ONLY key type the suite verifier accepts for the ML-DSA half of a signature. Its field is
// unexported and it is minted in exactly two places: resolvePqVerifyKey (the key is authorised by a verifier-side
// source: the signer's committed holder_pq, a root PQ pin, or the verifier's stored grant) and
// callerVouchedPqKey (explicitly named: the caller authorised the key elsewhere). The artifact's own pq_pk can
// therefore never reach the PQ verify directly. (Go cannot make a same-package struct unconstructible; the rule is
// that nothing outside this block builds a pqVerifyKey literal.)
type pqVerifyKey struct{ pk any }

// pqAuthority is where a PQ key gets its authority from. Exactly one of the two sources is used: when hasTrusted
// the artifact key must equal trustedPk (a root pin or the verifier's stored grant); otherwise the key must hash
// to the signer's committed holder_pq.
type pqAuthority struct {
	holderPq    any
	hasHolderPq bool
	trustedPk   string
	hasTrusted  bool
}

// resolvePqVerifyKey mirrors resolvePqVerifyKey in pq.ts (strict, no allowUnboundPq). For a suite without a PQ
// key it returns (zero key, true). For a suite that carries one it returns the key only if the artifact's pq_pk
// is authorised by `auth`; otherwise (_, false).
func resolvePqVerifyKey(alg any, present bool, artifactPk any, auth pqAuthority) (pqVerifyKey, bool) {
	su, ok := resolveSigAlg(alg, present)
	if !ok || !su.needsPqPk {
		return pqVerifyKey{}, true
	}
	pk, isStr := artifactPk.(string)
	if !isStr {
		return pqVerifyKey{}, false
	}
	if auth.hasTrusted {
		if pk != auth.trustedPk {
			return pqVerifyKey{}, false
		}
		return pqVerifyKey{pk}, true
	}
	cs, ok := auth.holderPq.(string)
	if !auth.hasHolderPq || !ok || holderPqCommitment(pk) != cs {
		return pqVerifyKey{}, false
	}
	return pqVerifyKey{pk}, true
}

// callerVouchedPqKey wraps a key whose authority the CALLER established elsewhere (threshold shares carry their
// own publicKey set, pq_artifact conformance primitives are checked against a stated key). Never use it on a
// chain hop or the PCActn leaf: those go through resolvePqVerifyKey.
func callerVouchedPqKey(pk any) pqVerifyKey { return pqVerifyKey{pk} }

// ---- ML-DSA-65 verification -----------------------------------------------------------

func mlDsa65VerifyRaw(pk, msg, sig []byte) bool {
	if len(pk) != mlDsaPublicKeyBytes || len(sig) != mlDsaSignatureBytes {
		return false
	}
	var p mldsa65.PublicKey
	if err := p.UnmarshalBinary(pk); err != nil {
		return false
	}
	return mldsa65.Verify(&p, msg, nil, sig) // nil context == empty, matching @noble/post-quantum
}

func mlDsa65VerifyB64u(key pqVerifyKey, msg []byte, sigB64u any) bool {
	pks, ok := key.pk.(string)
	if !ok {
		return false
	}
	sgs, ok := sigB64u.(string)
	if !ok {
		return false
	}
	pk, ok := DecodeB64uStrict(pks, mlDsaPublicKeyBytes)
	if !ok {
		return false
	}
	sg, ok := DecodeB64uStrict(sgs, mlDsaSignatureBytes)
	if !ok {
		return false
	}
	return mlDsa65VerifyRaw(pk, msg, sg)
}

// ---- wire-shape validation of the signature fields ------------------------------------

// validateSignatureWire validates `alg`/`sig`/`pq_pk`/`pq_sig` per suite. Returns "" when well-formed,
// else a short reason. Strict + fail-closed: unknown alg, wrong sizes, or a field not used by the suite
// being present, all fail.
func validateSignatureWire(p map[string]any) string {
	algV, algPresent := p["alg"]
	suite, ok := resolveSigAlg(algV, algPresent)
	if !ok {
		if _, isStr := algV.(string); !isStr && algPresent {
			return "'alg' must be a string"
		}
		return fmt.Sprintf("unknown signature alg '%v'", algV)
	}
	if !b64uOK(p["sig"], suite.sigBytes) {
		return fmt.Sprintf("'sig' is not canonical base64url (%d bytes) for alg '%s'", suite.sigBytes, suite.alg)
	}
	if _, present := p["pq_pk"]; suite.needsPqPk {
		if !b64uOK(p["pq_pk"], mlDsaPublicKeyBytes) {
			return fmt.Sprintf("'pq_pk' is not canonical base64url (%d bytes)", mlDsaPublicKeyBytes)
		}
	} else if present {
		return "'pq_pk' must be absent for alg '" + suite.alg + "'"
	}
	if _, present := p["pq_sig"]; suite.needsPqSig {
		if !b64uOK(p["pq_sig"], mlDsaSignatureBytes) {
			return fmt.Sprintf("'pq_sig' is not canonical base64url (%d bytes)", mlDsaSignatureBytes)
		}
	} else if present {
		return "'pq_sig' must be absent for alg '" + suite.alg + "'"
	}
	return ""
}

// ---- the leaf signature SEAM ----------------------------------------------------------

// verifyLeafSuite verifies the leaf signature under the PCActn's suite. FAIL-CLOSED: unknown alg, a missing
// component, or any invalid component returns false.
//
//   - ed25519:    Ed25519 `sig` under `holder`.
//   - ml-dsa-65:  ML-DSA-65 `sig` under `pq_pk`.
//   - hybrid:     Ed25519 `sig` under `holder` AND ML-DSA-65 `pq_sig` under `pq_pk`; BOTH must verify.
func verifyLeafSuite(alg any, algPresent bool, holder string, key pqVerifyKey, msg []byte, sig any, pqSig any) bool {
	suite, ok := resolveSigAlg(alg, algPresent)
	if !ok {
		return false
	}
	sigStr, ok := sig.(string)
	if !ok {
		return false
	}
	switch suite.alg {
	case "ed25519":
		return verifyB64u(holder, msg, sigStr)
	case "ml-dsa-65":
		return mlDsa65VerifyB64u(key, msg, sigStr)
	case "hybrid-ed25519-ml-dsa-65":
		pqSigStr, ok := pqSig.(string)
		if !ok {
			return false
		}
		return verifyB64u(holder, msg, sigStr) && mlDsa65VerifyB64u(key, msg, pqSigStr)
	}
	return false
}
