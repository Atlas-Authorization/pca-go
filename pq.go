package pca

// B4 — post-quantum crypto-agility, mirroring packages/pca/src/pq.ts. An ADDITIVE, backward-compatible
// algorithm-agility slot for the PCActn leaf signature. Absent `alg` (or `alg == "ed25519"`) is
// BYTE-IDENTICAL to the pre-B4 wire.
//
// Suite capability (packages/pca/conformance/SUITES.md): this verifier implements every registered suite Go has a
// trustworthy primitive for, all through cloudflare/circl (FIPS 204 ML-DSA, FIPS 205 SLH-DSA; pure mode, EMPTY context,
// exactly @noble/post-quantum's defaults):
//   - "ed25519"                                  classical 64-byte Ed25519 `sig`.
//   - "ml-dsa-65" / "ml-dsa-87"                  pure PQ: `sig` is the ML-DSA signature under the resolved `pq_pk`.
//   - "slh-dsa-sha2-128f" / "slh-dsa-sha2-256s"  pure hash-based PQ: `sig` is the SLH-DSA signature under `pq_pk`.
//   - "hybrid-ed25519-<pq>"                      Ed25519 `sig` under the holder AND the PQ `pq_sig` under `pq_pk`, over
//                                                the same message; the Ed25519 half is checked first; both must verify.
//   - "hybrid-nested-ed25519-ml-dsa-65"          SUF-CMA nested hybrid: Ed25519 `sig` over msg, then ML-DSA-65 `pq_sig`
//                                                over msg || the 64 decoded Ed25519 signature bytes.
//   - "less-cat1" / "hybrid-ed25519-less-cat1"  LESS (a NIST round-2 candidate, not a standard), ONLY in a build with the
//                                                `less` tag and cgo: the patched reference C of sdks/pca-less-c through cgo
//                                                (less_cgo.go); the LESS signature is variable-length (1,153..1,329 bytes
//                                                in steps of 16). A pure-Go build refuses both as unsupported.
// The remaining registered suites (fn-dsa-512 / fn-dsa-1024: no FIPS 206 implementation in Go worth trusting; LESS in a
// pure-Go build) are REFUSED with the distinct reason `unsupported_suite: <alg>` (never a silent bad signature). An `alg`
// that is not registered at all keeps the plain "unknown signature alg" refusal.
//
// `alg` and `pq_pk` are SIGNED (part of the canonical body); `sig` and `pq_sig` are the signatures and are
// stripped from the signed body (like `sig`/`threshold`).

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

const (
	mlDsaPublicKeyBytes   = mldsa65.PublicKeySize // 1952
	mlDsaSignatureBytes   = mldsa65.SignatureSize // 3309
	mlDsa87PublicKeyBytes = mldsa87.PublicKeySize // 2592
	mlDsa87SignatureBytes = mldsa87.SignatureSize // 4627
	slh128fPublicKeyBytes = 32
	slh128fSignatureBytes = 17088
	slh256sPublicKeyBytes = 64
	slh256sSignatureBytes = 29792
	lessPublicKeyBytes    = 97484
	lessSignatureMinBytes = 1153
	lessSignatureMaxBytes = 1329
	lessSignatureStep     = 16
)

// lessCat1Verify is the LESS (less-252-45) detached-signature verifier; nil unless the build links the C reference
// (tag `less` with cgo, less_cgo.go), which also registers the two LESS suites.
var lessCat1Verify func(pk, msg, sig []byte) bool

// UnsupportedSuite is the reason token of a REGISTERED suite this verifier does not implement (shared by every PCA
// verifier; the full reason is "unsupported_suite: <alg>").
const UnsupportedSuite = "unsupported_suite"

// RegisteredSuites is the closed TS suite registry (SIG_SUITES in packages/pca/src/pq.ts), in registry order.
var RegisteredSuites = []string{
	"ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65",
	"slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87",
	"slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "fn-dsa-1024",
	"less-cat1", "hybrid-ed25519-less-cat1",
}

// SupportedSuites returns the registered suites this verifier implements, in registry order (the capability
// manifest the conformance gate compares against).
func SupportedSuites() []string {
	out := make([]string, 0, len(sigSuites))
	for _, a := range RegisteredSuites {
		if _, ok := sigSuites[a]; ok {
			out = append(out, a)
		}
	}
	return out
}

// isRegisteredSuite: `alg` names a suite of the TS registry (implemented here or not).
func isRegisteredSuite(alg any) bool {
	s, ok := alg.(string)
	if !ok {
		return false
	}
	for _, a := range RegisteredSuites {
		if a == s {
			return true
		}
	}
	return false
}

// unsupportedSuiteReason is the refusal of a registered suite this verifier does not implement.
func unsupportedSuiteReason(alg any) string { return fmt.Sprintf("%s: %v", UnsupportedSuite, alg) }

// pqPrim is the post-quantum primitive of a suite.
type pqPrim int

const (
	pqNone pqPrim = iota
	pqMlDsa65
	pqMlDsa87
	pqSlh128f
	pqSlh256s
	pqLessCat1
)

// lens returns the (public key, signature) byte lengths of a PQ primitive.
func (p pqPrim) lens() (int, int) {
	switch p {
	case pqMlDsa65:
		return mlDsaPublicKeyBytes, mlDsaSignatureBytes
	case pqMlDsa87:
		return mlDsa87PublicKeyBytes, mlDsa87SignatureBytes
	case pqSlh128f:
		return slh128fPublicKeyBytes, slh128fSignatureBytes
	case pqSlh256s:
		return slh256sPublicKeyBytes, slh256sSignatureBytes
	case pqLessCat1:
		return lessPublicKeyBytes, lessSignatureMaxBytes
	}
	return 0, 0
}

// sigLenOK: n is a signature length of the primitive (its fixed length; LESS: 1,153..1,329 in steps of 16).
func (p pqPrim) sigLenOK(n int) bool {
	if p == pqLessCat1 {
		return n >= lessSignatureMinBytes && n <= lessSignatureMaxBytes && (lessSignatureMaxBytes-n)%lessSignatureStep == 0
	}
	_, sl := p.lens()
	return sl != 0 && n == sl
}

// b64uSigOK: canonical base64url whose decoded length is a signature length of p.
func b64uSigOK(v any, p pqPrim) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	b, ok := DecodeB64uStrict(s, -1)
	return ok && p.sigLenOK(len(b))
}

type sigSuite struct {
	alg        string
	sigBytes   int
	hasEd25519 bool
	pq         pqPrim
	needsPqPk  bool
	needsPqSig bool
	nested     bool // the PQ half signs msg || ed25519 sig bytes (SUF-CMA)
}

func pureSuite(alg string, p pqPrim) sigSuite {
	_, sl := p.lens()
	return sigSuite{alg: alg, sigBytes: sl, pq: p, needsPqPk: true}
}

func hybridSuite(alg string, p pqPrim, nested bool) sigSuite {
	return sigSuite{alg: alg, sigBytes: sigLen, hasEd25519: true, pq: p, needsPqPk: true, needsPqSig: true, nested: nested}
}

// The suites this verifier implements (a subset of RegisteredSuites).
var sigSuites = map[string]sigSuite{
	"ed25519":                          {alg: "ed25519", sigBytes: sigLen, hasEd25519: true},
	"ml-dsa-65":                        pureSuite("ml-dsa-65", pqMlDsa65),
	"hybrid-ed25519-ml-dsa-65":         hybridSuite("hybrid-ed25519-ml-dsa-65", pqMlDsa65, false),
	"hybrid-nested-ed25519-ml-dsa-65":  hybridSuite("hybrid-nested-ed25519-ml-dsa-65", pqMlDsa65, true),
	"slh-dsa-sha2-128f":                pureSuite("slh-dsa-sha2-128f", pqSlh128f),
	"hybrid-ed25519-slh-dsa-sha2-128f": hybridSuite("hybrid-ed25519-slh-dsa-sha2-128f", pqSlh128f, false),
	"ml-dsa-87":                        pureSuite("ml-dsa-87", pqMlDsa87),
	"hybrid-ed25519-ml-dsa-87":         hybridSuite("hybrid-ed25519-ml-dsa-87", pqMlDsa87, false),
	"slh-dsa-sha2-256s":                pureSuite("slh-dsa-sha2-256s", pqSlh256s),
	"hybrid-ed25519-slh-dsa-sha2-256s": hybridSuite("hybrid-ed25519-slh-dsa-sha2-256s", pqSlh256s, false),
}

// resolveSigAlg resolves the suite for a PCActn `alg` value. `present` is false when the field is absent
// (=> default ed25519). Returns (suite, true) for the default or an IMPLEMENTED suite; (_, false) fails closed
// (callers that report a reason distinguish a registered-but-unimplemented suite with isRegisteredSuite).
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

// ---- PQ primitive verification (circl; pure mode, empty context == @noble/post-quantum) ----------

func pqVerifyRaw(p pqPrim, pk, msg, sig []byte) bool {
	pkLen, _ := p.lens()
	if pkLen == 0 || len(pk) != pkLen || !p.sigLenOK(len(sig)) {
		return false
	}
	switch p {
	case pqMlDsa65:
		var k mldsa65.PublicKey
		if err := k.UnmarshalBinary(pk); err != nil {
			return false
		}
		return mldsa65.Verify(&k, msg, nil, sig)
	case pqMlDsa87:
		var k mldsa87.PublicKey
		if err := k.UnmarshalBinary(pk); err != nil {
			return false
		}
		return mldsa87.Verify(&k, msg, nil, sig)
	case pqSlh128f, pqSlh256s:
		id := slhdsa.SHA2_128f
		if p == pqSlh256s {
			id = slhdsa.SHA2_256s
		}
		k := slhdsa.PublicKey{ID: id}
		if err := k.UnmarshalBinary(pk); err != nil {
			return false
		}
		return slhdsa.Verify(&k, slhdsa.NewMessage(msg), sig, nil)
	case pqLessCat1:
		return lessCat1Verify != nil && lessCat1Verify(pk, msg, sig)
	}
	return false
}

func mlDsa65VerifyRaw(pk, msg, sig []byte) bool { return pqVerifyRaw(pqMlDsa65, pk, msg, sig) }

func pqVerifyB64u(p pqPrim, key pqVerifyKey, msg []byte, sigB64u any) bool {
	pks, ok := key.pk.(string)
	if !ok {
		return false
	}
	sgs, ok := sigB64u.(string)
	if !ok {
		return false
	}
	pkLen, _ := p.lens()
	pk, ok := DecodeB64uStrict(pks, pkLen)
	if !ok {
		return false
	}
	sg, ok := DecodeB64uStrict(sgs, -1)
	if !ok || !p.sigLenOK(len(sg)) {
		return false
	}
	return pqVerifyRaw(p, pk, msg, sg)
}

func mlDsa65VerifyB64u(key pqVerifyKey, msg []byte, sigB64u any) bool {
	return pqVerifyB64u(pqMlDsa65, key, msg, sigB64u)
}

// ---- wire-shape validation of the signature fields ------------------------------------

// validateSignatureWire validates `alg`/`sig`/`pq_pk`/`pq_sig` per suite. Returns "" when well-formed,
// else a short reason. Strict + fail-closed: unknown alg, an unimplemented registered suite (unsupported_suite),
// wrong sizes, or a field not used by the suite being present, all fail.
func validateSignatureWire(p map[string]any) string { return validateSuiteFields(p, true) }

// validateShareSignatureWire (0.4.1) applies the same per-suite rules to a threshold share: `alg` absent ==
// ed25519 (64-byte `sig`, no `pq_sig`), else a registered suite's lengths. A share's `pq_pk` is NOT judged here: it
// is an optional echo checked by the threshold verifier against the signer set. Mirrors validateShareSignatureWire in
// packages/pca/src/pq.ts.
func validateShareSignatureWire(s map[string]any) string { return validateSuiteFields(s, false) }

func validateSuiteFields(p map[string]any, checkPqPk bool) string {
	algV, algPresent := p["alg"]
	suite, ok := resolveSigAlg(algV, algPresent)
	if !ok {
		if _, isStr := algV.(string); !isStr && algPresent {
			return "'alg' must be a string"
		}
		if isRegisteredSuite(algV) {
			return unsupportedSuiteReason(algV)
		}
		return fmt.Sprintf("unknown signature alg '%v'", algV)
	}
	// the PQ signature is `sig` for a pure suite and `pq_sig` for a hybrid; its length rule is the primitive's
	sigOK := b64uOK(p["sig"], suite.sigBytes)
	if !suite.hasEd25519 {
		sigOK = b64uSigOK(p["sig"], suite.pq)
	}
	if !sigOK {
		return fmt.Sprintf("'sig' is not canonical base64url (%d bytes) for alg '%s'", suite.sigBytes, suite.alg)
	}
	pkLen, pqSigLen := suite.pq.lens()
	if !checkPqPk {
		// share: `pq_pk` is an optional echo, judged by the threshold check against the signer set
	} else if _, present := p["pq_pk"]; suite.needsPqPk {
		if !b64uOK(p["pq_pk"], pkLen) {
			return fmt.Sprintf("'pq_pk' is not canonical base64url (%d bytes)", pkLen)
		}
	} else if present {
		return "'pq_pk' must be absent for alg '" + suite.alg + "'"
	}
	if _, present := p["pq_sig"]; suite.needsPqSig {
		if !b64uSigOK(p["pq_sig"], suite.pq) {
			return fmt.Sprintf("'pq_sig' is not canonical base64url (%d bytes)", pqSigLen)
		}
	} else if present {
		return "'pq_sig' must be absent for alg '" + suite.alg + "'"
	}
	return ""
}

// ---- the leaf signature SEAM ----------------------------------------------------------

// verifyLeafSuite verifies a signature under the artifact's suite (the ONE suite dispatch every surface uses).
// FAIL-CLOSED: unknown / unimplemented alg, a missing component, or any invalid component returns false (callers that
// report a reason refuse an unimplemented registered suite earlier, with unsupported_suite).
//
//   - ed25519:          Ed25519 `sig` under `holder`.
//   - pure PQ:          the PQ `sig` under the resolved key.
//   - hybrid:           Ed25519 `sig` under `holder` (first) AND the PQ `pq_sig` under the resolved key, same msg.
//   - nested hybrid:    as hybrid, but the PQ half is over msg || the decoded Ed25519 signature bytes.
func verifyLeafSuite(alg any, algPresent bool, holder string, key pqVerifyKey, msg []byte, sig any, pqSig any) bool {
	suite, ok := resolveSigAlg(alg, algPresent)
	if !ok {
		return false
	}
	sigStr, ok := sig.(string)
	if !ok {
		return false
	}
	if !suite.hasEd25519 {
		return pqVerifyB64u(suite.pq, key, msg, sigStr)
	}
	// R6-API-04: the cheap Ed25519 half first; never pay for the PQ half of a forged hybrid.
	if !verifyB64u(holder, msg, sigStr) {
		return false
	}
	if suite.pq == pqNone {
		return true
	}
	pqSigStr, ok := pqSig.(string)
	if !ok {
		return false
	}
	pqMsg := msg
	if suite.nested {
		edSig, ok := DecodeB64uStrict(sigStr, sigLen)
		if !ok {
			return false
		}
		pqMsg = append(append(make([]byte, 0, len(msg)+len(edSig)), msg...), edSig...)
	}
	return pqVerifyB64u(suite.pq, key, pqMsg, pqSigStr)
}
