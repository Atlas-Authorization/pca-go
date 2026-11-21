package pca

// The seeded key generation, encoders, size constants, per-primitive verify wrappers, the LESS availability probe, the
// artifact-level suite signer and the LAMPS composite signature of the reference's pq module, over the same primitives
// as pq.go (cloudflare/circl for ML-DSA and SLH-DSA, the registered backend for FN-DSA, the optional C build for LESS).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// ErrLessUnavailable is returned by the LESS key and signing functions in a build without the `less` tag and cgo.
var ErrLessUnavailable = errors.New("LESS is not built in (needs the less build tag and cgo)")

// Sizes of the post-quantum primitives (seeds are the deterministic keygen input; secret keys the signing input).
const (
	// MlDsa65SeedBytes is the FIPS 204 xi seed of an ML-DSA-65 key.
	MlDsa65SeedBytes = 32
	// MlDsa87SeedBytes is the FIPS 204 xi seed of an ML-DSA-87 key.
	MlDsa87SeedBytes = 32
	// SlhDsaSha2128fPublicKeyBytes is the SLH-DSA-SHA2-128f public key size.
	SlhDsaSha2128fPublicKeyBytes = 32
	// SlhDsaSha2128fSecretKeyBytes is the SLH-DSA-SHA2-128f secret key size.
	SlhDsaSha2128fSecretKeyBytes = 64
	// SlhDsaSha2128fSignatureBytes is the SLH-DSA-SHA2-128f signature size.
	SlhDsaSha2128fSignatureBytes = 17088
	// SlhDsaSha2128fSeedBytes is the SK.seed || SK.prf || PK.seed keygen seed of SLH-DSA-SHA2-128f.
	SlhDsaSha2128fSeedBytes = 48
	// SlhDsaSha2256sPublicKeyBytes is the SLH-DSA-SHA2-256s public key size.
	SlhDsaSha2256sPublicKeyBytes = 64
	// SlhDsaSha2256sSecretKeyBytes is the SLH-DSA-SHA2-256s secret key size.
	SlhDsaSha2256sSecretKeyBytes = 128
	// SlhDsaSha2256sSignatureBytes is the SLH-DSA-SHA2-256s signature size.
	SlhDsaSha2256sSignatureBytes = 29792
	// SlhDsaSha2256sSeedBytes is the SK.seed || SK.prf || PK.seed keygen seed of SLH-DSA-SHA2-256s.
	SlhDsaSha2256sSeedBytes = 96
	// FnDsa512SecretKeyBytes is the FN-DSA-512 signing key size.
	FnDsa512SecretKeyBytes = 1345
	// FnDsa1024SecretKeyBytes is the FN-DSA-1024 signing key size.
	FnDsa1024SecretKeyBytes = 2369
	// FnDsaSeedBytes is the keygen / signing seed size of FN-DSA.
	FnDsaSeedBytes = 32
	// LessCat1SignatureStepBytes is the step between the possible LESS category-1 signature lengths.
	LessCat1SignatureStepBytes = 16
	// LessSeedBytes is the keygen / signing seed size of LESS.
	LessSeedBytes = 32
)

// MlDsaKeyPair is an ML-DSA key pair as raw bytes (the 4032 / 4896 byte secret key is the expanded FIPS 204 form).
type MlDsaKeyPair struct{ PublicKey, SecretKey []byte }

// SlhDsaKeyPair is an SLH-DSA key pair as raw bytes (the secret key is SK.seed || SK.prf || PK.seed || PK.root).
type SlhDsaKeyPair struct{ PublicKey, SecretKey []byte }

// FnDsaKeyPair is an FN-DSA key pair as raw bytes; VerifyingKey becomes `pq_pk`.
type FnDsaKeyPair struct{ VerifyingKey, SigningKey []byte }

// LessKeyPair is a LESS key pair; the secret key is the 32-byte seed the public key is expanded from.
type LessKeyPair struct{ PublicKey, SecretKey []byte }

// IsKnownSigAlg reports whether x names a suite of the registry (implemented in this build or not).
func IsKnownSigAlg(x any) bool { return isRegisteredSuite(x) }

// MlDsa65Keygen derives the ML-DSA-65 key pair of a 32-byte seed (FIPS 204 KeyGen_internal, deterministic).
func MlDsa65Keygen(seed []byte) (MlDsaKeyPair, error) {
	if len(seed) != MlDsa65SeedBytes {
		return MlDsaKeyPair{}, fmt.Errorf("mlDsa65Keygen: seed must be %d bytes", MlDsa65SeedBytes)
	}
	var xi [mldsa65.SeedSize]byte
	copy(xi[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&xi)
	clear(xi[:])
	return MlDsaKeyPair{PublicKey: pk.Bytes(), SecretKey: sk.Bytes()}, nil
}

// MlDsa87Keygen derives the ML-DSA-87 key pair of a 32-byte seed (FIPS 204 KeyGen_internal, deterministic).
func MlDsa87Keygen(seed []byte) (MlDsaKeyPair, error) {
	if len(seed) != MlDsa87SeedBytes {
		return MlDsaKeyPair{}, fmt.Errorf("mlDsa87Keygen: seed must be %d bytes", MlDsa87SeedBytes)
	}
	var xi [mldsa87.SeedSize]byte
	copy(xi[:], seed)
	pk, sk := mldsa87.NewKeyFromSeed(&xi)
	clear(xi[:])
	return MlDsaKeyPair{PublicKey: pk.Bytes(), SecretKey: sk.Bytes()}, nil
}

func slhKeygen(id slhdsa.ID, seedLen int, name string, seed []byte) (SlhDsaKeyPair, error) {
	if len(seed) != seedLen {
		return SlhDsaKeyPair{}, fmt.Errorf("%s: seed must be %d bytes", name, seedLen)
	}
	// GenerateKey reads SK.seed, SK.prf, PK.seed in that order: a reader over the seed replays it exactly.
	pk, sk, err := slhdsa.GenerateKey(bytes.NewReader(seed), id)
	if err != nil {
		return SlhDsaKeyPair{}, err
	}
	pb, err := pk.MarshalBinary()
	if err != nil {
		return SlhDsaKeyPair{}, err
	}
	sb, err := sk.MarshalBinary()
	if err != nil {
		return SlhDsaKeyPair{}, err
	}
	return SlhDsaKeyPair{PublicKey: pb, SecretKey: sb}, nil
}

func slhSign(id slhdsa.ID, name string, secretKey, msg []byte) ([]byte, error) {
	sk := slhdsa.PrivateKey{ID: id}
	if err := sk.UnmarshalBinary(secretKey); err != nil {
		return nil, errors.New(name + ": malformed secret key")
	}
	return slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(msg), nil)
}

// SlhDsa128fKeygen derives the SLH-DSA-SHA2-128f key pair of a 48-byte seed (SK.seed || SK.prf || PK.seed).
func SlhDsa128fKeygen(seed []byte) (SlhDsaKeyPair, error) {
	return slhKeygen(slhdsa.SHA2_128f, SlhDsaSha2128fSeedBytes, "slhDsa128fKeygen", seed)
}

// SlhDsa128fSign signs msg with a 64-byte SLH-DSA-SHA2-128f secret key (pure mode, empty context, deterministic opt_rand = PK.seed).
func SlhDsa128fSign(secretKey, msg []byte) ([]byte, error) {
	return slhSign(slhdsa.SHA2_128f, "slhDsa128fSign", secretKey, msg)
}

// SlhDsa128fVerify verifies an SLH-DSA-SHA2-128f signature over raw bytes; a wrong length or malformed key is false.
func SlhDsa128fVerify(publicKey, msg, sig []byte) bool {
	return pqVerifyRaw(pqSlh128f, publicKey, msg, sig)
}

// SlhDsa256sKeygen derives the SLH-DSA-SHA2-256s key pair of a 96-byte seed (SK.seed || SK.prf || PK.seed).
func SlhDsa256sKeygen(seed []byte) (SlhDsaKeyPair, error) {
	return slhKeygen(slhdsa.SHA2_256s, SlhDsaSha2256sSeedBytes, "slhDsa256sKeygen", seed)
}

// SlhDsa256sSign signs msg with a 128-byte SLH-DSA-SHA2-256s secret key (pure mode, empty context, deterministic).
func SlhDsa256sSign(secretKey, msg []byte) ([]byte, error) {
	return slhSign(slhdsa.SHA2_256s, "slhDsa256sSign", secretKey, msg)
}

// SlhDsa256sVerify verifies an SLH-DSA-SHA2-256s signature over raw bytes; a wrong length or malformed key is false.
func SlhDsa256sVerify(publicKey, msg, sig []byte) bool {
	return pqVerifyRaw(pqSlh256s, publicKey, msg, sig)
}

// b64uPair verifies over base64url-encoded key and signature of one primitive; any decoding error is false.
func b64uPair(p pqPrim, pkB64u any, msg []byte, sigB64u any) bool {
	return pqVerifyB64u(p, callerVouchedPqKey(pkB64u), msg, sigB64u)
}

// SlhDsa128fVerifyB64u is SlhDsa128fVerify over base64url-encoded key and signature; false on any decoding error.
func SlhDsa128fVerifyB64u(publicKeyB64u any, msg []byte, sigB64u any) bool {
	return b64uPair(pqSlh128f, publicKeyB64u, msg, sigB64u)
}

// SlhDsa256sVerifyB64u is SlhDsa256sVerify over base64url-encoded key and signature; false on any decoding error.
func SlhDsa256sVerifyB64u(publicKeyB64u any, msg []byte, sigB64u any) bool {
	return b64uPair(pqSlh256s, publicKeyB64u, msg, sigB64u)
}

// MlDsa87VerifyB64u is MlDsa87Verify over base64url-encoded key and signature; false on any decoding error.
func MlDsa87VerifyB64u(publicKeyB64u any, msg []byte, sigB64u any) bool {
	return b64uPair(pqMlDsa87, publicKeyB64u, msg, sigB64u)
}

// FnDsa512VerifyB64u is the FN-DSA-512 verify over base64url-encoded key and signature; false on any decoding error or with no backend.
func FnDsa512VerifyB64u(publicKeyB64u any, msg []byte, sigB64u any) bool {
	return b64uPair(pqFnDsa512, publicKeyB64u, msg, sigB64u)
}

// FnDsa1024VerifyB64u is the FN-DSA-1024 verify over base64url-encoded key and signature; false on any decoding error or with no backend.
func FnDsa1024VerifyB64u(publicKeyB64u any, msg []byte, sigB64u any) bool {
	return b64uPair(pqFnDsa1024, publicKeyB64u, msg, sigB64u)
}

// LessCat1VerifyB64u is the LESS verify over base64url-encoded key and signature; false on any decoding error or without the less build.
func LessCat1VerifyB64u(publicKeyB64u any, msg []byte, sigB64u any) bool {
	return b64uPair(pqLessCat1, publicKeyB64u, msg, sigB64u)
}

// FnDsa512Verify is the FN-DSA-512 verify over raw bytes: false on any length violation, a backend error, or no backend (fail closed).
func FnDsa512Verify(publicKey, msg, sig []byte) bool {
	return pqVerifyRaw(pqFnDsa512, publicKey, msg, sig)
}

// FnDsa1024Verify is the FN-DSA-1024 verify over raw bytes: false on any length violation, a backend error, or no backend (fail closed).
func FnDsa1024Verify(publicKey, msg, sig []byte) bool {
	return pqVerifyRaw(pqFnDsa1024, publicKey, msg, sig)
}

// IsFnDsaBackendActive reports whether an FN-DSA backend is registered (else every FN-DSA suite verify fails closed).
func IsFnDsaBackendActive() bool { return fnDsaBackendRegistered() }

func fnDsaKeygenOf(variant string, seed []byte) (FnDsaKeyPair, error) {
	if !fnDsaBackendRegistered() {
		return FnDsaKeyPair{}, ErrFnDsaBackendMissing
	}
	be := GetFalconBackend()
	if be.KeygenSeeded == nil {
		return FnDsaKeyPair{}, errors.New("FN-DSA backend cannot derive keys from a seed (no KeygenSeeded)")
	}
	if len(seed) != FnDsaSeedBytes {
		return FnDsaKeyPair{}, fmt.Errorf("fnDsaKeygen: seed must be %d bytes", FnDsaSeedBytes)
	}
	vk, sk, err := be.KeygenSeeded(variant, append([]byte(nil), seed...))
	if err != nil {
		return FnDsaKeyPair{}, err
	}
	return FnDsaKeyPair{VerifyingKey: vk, SigningKey: sk}, nil
}

// FnDsa512Keygen derives the FN-DSA-512 key pair of a 32-byte seed through the registered backend; ErrFnDsaBackendMissing without one.
func FnDsa512Keygen(seed []byte) (FnDsaKeyPair, error) { return fnDsaKeygenOf("fn-dsa-512", seed) }

// FnDsa1024Keygen derives the FN-DSA-1024 key pair of a 32-byte seed through the registered backend; ErrFnDsaBackendMissing without one.
func FnDsa1024Keygen(seed []byte) (FnDsaKeyPair, error) { return fnDsaKeygenOf("fn-dsa-1024", seed) }

// FnDsa512Sign signs msg (raw, no pre-hash) with the FN-DSA-512 signing key and a 32-byte signing seed through the registered backend.
func FnDsa512Sign(signingKey, msg, seed []byte) ([]byte, error) {
	return fnDsaSignChecked("fn-dsa-512", signingKey, msg, seed)
}

// FnDsa1024Sign signs msg (raw, no pre-hash) with the FN-DSA-1024 signing key and a 32-byte signing seed through the registered backend.
func FnDsa1024Sign(signingKey, msg, seed []byte) ([]byte, error) {
	return fnDsaSignChecked("fn-dsa-1024", signingKey, msg, seed)
}

func fnDsaSignChecked(variant string, sk, msg, seed []byte) ([]byte, error) {
	if !fnDsaBackendRegistered() {
		return nil, ErrFnDsaBackendMissing
	}
	if len(seed) != FnDsaSeedBytes {
		return nil, fmt.Errorf("fnDsaSign: seed must be %d bytes", FnDsaSeedBytes)
	}
	return fnDsaSignSeeded(variant, sk, msg, seed)
}

// EncodeMlDsaPublicKey is the base64url of an ML-DSA-65 public key, ready to be a `pq_pk`.
func EncodeMlDsaPublicKey(publicKey []byte) string { return b64.EncodeToString(publicKey) }

// EncodeMlDsa87PublicKey is the base64url of an ML-DSA-87 public key, ready to be a `pq_pk`.
func EncodeMlDsa87PublicKey(publicKey []byte) string { return b64.EncodeToString(publicKey) }

// EncodeSlhDsaPublicKey is the base64url of an SLH-DSA-SHA2-128f public key, ready to be a `pq_pk`.
func EncodeSlhDsaPublicKey(publicKey []byte) string { return b64.EncodeToString(publicKey) }

// EncodeSlhDsa256sPublicKey is the base64url of an SLH-DSA-SHA2-256s public key, ready to be a `pq_pk`.
func EncodeSlhDsa256sPublicKey(publicKey []byte) string { return b64.EncodeToString(publicKey) }

// EncodeFnDsaPublicKey is the base64url of an FN-DSA verifying key (either variant), ready to be a `pq_pk`.
func EncodeFnDsaPublicKey(publicKey []byte) string { return b64.EncodeToString(publicKey) }

// EncodeLessPublicKey is the base64url of a LESS public key, ready to be a `pq_pk`.
func EncodeLessPublicKey(publicKey []byte) string { return b64.EncodeToString(publicKey) }

// LessBackendStatus is the availability of the LESS backend; Reason is set exactly when it is unavailable.
type LessBackendStatus struct {
	Available bool
	Reason    string
}

// IsLessBackendActive reports whether this build verifies LESS (the `less` build tag with cgo).
func IsLessBackendActive() bool { return lessCat1Verify != nil }

// GetLessBackendStatus reports the availability of the LESS backend and, when absent, why every LESS suite is refused.
func GetLessBackendStatus() LessBackendStatus {
	if IsLessBackendActive() {
		return LessBackendStatus{Available: true}
	}
	return LessBackendStatus{Reason: "LESS needs a build with the less tag and cgo (" + ErrLessUnavailable.Error() + ")"}
}

// SuiteKeys is the signing material of one suite: the identity's Ed25519 key plus the suite options carrying the PQ key pair.
type SuiteKeys struct {
	Ed   *KeyPair
	Opts *SuiteOpts
}

// SuiteKeysOf pairs an identity's Ed25519 key with the caller's suite options, the full material for signing a surface artifact.
func SuiteKeysOf(ed *KeyPair, s *SuiteOpts) SuiteKeys { return SuiteKeys{Ed: ed, Opts: s} }

// SuitePqPublicKey is the base64url `pq_pk` the suite selects from its key pair; ok is false for ed25519, an unknown suite or a
// missing or mismatching key pair (signing then fails closed).
func SuitePqPublicKey(s *SuiteOpts) (pq string, ok bool) {
	su, known := resolveSigAlg(s.alg(), true)
	if !known || !su.needsPqPk || s == nil || s.Pq == nil || s.Pq.prim != su.pq {
		return "", false
	}
	return s.Pq.Public, true
}

// SignSuiteArtifact signs msg and returns every wire field an artifact carries for its suite: only `sig` for ed25519 (byte-identical
// to the pre-agility wire), and additionally `alg`, `pq_pk` and (hybrid suites) `pq_sig` for any other. Unknown suite or missing
// key material is an error.
func SignSuiteArtifact(s *SuiteOpts, ed *KeyPair, msg []byte) (map[string]any, error) {
	sig, pqSig, err := signWithSuite(s, ed, msg)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"sig": sig}
	if s.alg() == DefaultSigAlg {
		return out, nil
	}
	out["alg"] = s.alg()
	if pk, ok := SuitePqPublicKey(s); ok {
		out["pq_pk"] = pk
	}
	if pqSig != "" {
		out["pq_sig"] = pqSig
	}
	return out, nil
}

// IsPinnedPqKey reports whether x is a key minted by ResolvePqVerifyKey (a PinnedPqKey), as opposed to an arbitrary value.
func IsPinnedPqKey(x any) bool {
	switch x.(type) {
	case PinnedPqKey, *PinnedPqKey:
		return true
	}
	return false
}

// PqSuiteKeyOf returns the PQ half of a SuiteOpts, or nil.
func PqSuiteKeyOf(s *SuiteOpts) *PqKeyPair {
	if s == nil {
		return nil
	}
	return s.Pq
}

// ---- LAMPS composite signature (draft-ietf-lamps-pq-composite-sigs, ML-DSA-65 + Ed25519, SHA-512) -------------------

const (
	// CompositePrefix is the composite-signature Prefix: ASCII "CompositeAlgorithmSignatures2025".
	CompositePrefix = "CompositeAlgorithmSignatures2025"
	// CompositeLabel is the Label of id-MLDSA65-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.48).
	CompositeLabel = "COMPSIG-MLDSA65-Ed25519-SHA512"
	// CompositeSignatureBytes is the length of a composite signature: ML-DSA-65 (3309) then Ed25519 (64).
	CompositeSignatureBytes = MlDsa65SignatureBytes + Ed25519SignatureBytes
)

// CompositeRepresentative builds M' = Prefix || Label || len(ctx) || ctx || SHA-512(message). A ctx over 255 bytes is an error.
func CompositeRepresentative(message, ctx []byte) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, errors.New("compositeRepresentative: ctx exceeds 255 bytes")
	}
	h := sha512.Sum512(message)
	m := make([]byte, 0, len(CompositePrefix)+len(CompositeLabel)+1+len(ctx)+len(h))
	m = append(m, CompositePrefix...)
	m = append(m, CompositeLabel...)
	m = append(m, byte(len(ctx)))
	m = append(m, ctx...)
	return append(m, h[:]...), nil
}

// CompositeSign produces the composite signature (ML-DSA-65 signature || Ed25519 signature, 3373 bytes) over message, both halves
// signing the representative M'. ed25519Seed is the 32-byte Ed25519 seed, mlDsaSecretKey the 4032-byte ML-DSA-65 secret key.
func CompositeSign(ed25519Seed, mlDsaSecretKey, message, ctx []byte) ([]byte, error) {
	if len(ed25519Seed) != ed25519.SeedSize {
		return nil, errors.New("compositeSign: ed25519Seed must be 32 bytes")
	}
	m, err := CompositeRepresentative(message, ctx)
	if err != nil {
		return nil, err
	}
	ml, err := MlDsa65Sign(mlDsaSecretKey, m)
	if err != nil {
		return nil, err
	}
	return append(ml, ed25519.Sign(ed25519.NewKeyFromSeed(ed25519Seed), m)...), nil
}

// CompositeVerify verifies a composite signature: a wrong total length, a ctx over 255 bytes or either half failing is false; both
// the ML-DSA-65 half and the Ed25519 half must verify over the same M'. It never panics.
func CompositeVerify(ed25519Pub, mlDsaPub, message, signature, ctx []byte) bool {
	if len(signature) != CompositeSignatureBytes || len(ed25519Pub) != ed25519.PublicKeySize {
		return false
	}
	m, err := CompositeRepresentative(message, ctx)
	if err != nil {
		return false
	}
	return MlDsa65Verify(mlDsaPub, m, signature[:MlDsa65SignatureBytes]) &&
		ed25519.Verify(ed25519Pub, m, signature[MlDsa65SignatureBytes:])
}
