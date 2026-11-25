package pca

// FN-DSA (Falcon) suite registry, wire framing and the Ed25519+FN-DSA hybrid leaf composition (the TypeScript reference,
// @atlasauth/pca-fndsa). Like the reference this file carries NO Falcon arithmetic: the primitive is a pluggable FalconBackend
// (SetFalconBackend), so framing, lengths and the hybrid's fail-closed rules are testable without one, and verification refuses
// until a backend is installed. The real primitive is the separate cgo module fndsakit (Pornin's fn-dsa 0.4.0 through a small C
// library), which keeps this module cgo-free. FIPS 206 is not final: the primitive is a draft best guess pinned in lockstep with
// the TypeScript reference. Round-3 Falcon (liboqs, circl) shares the signature lengths but is a different scheme and does not
// interoperate. The registered suites in pq.go keep refusing fn-dsa-* as unsupported; this API is the opt-in route.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"
)

const (
	FnDsa512PublicKeyBytes  = 897
	FnDsa512SignatureBytes  = 666
	FnDsa1024PublicKeyBytes = 1793
	FnDsa1024SignatureBytes = 1280
)

// FnDsaLeafDomain separates the FN-DSA leaf message from every other signed message.
const FnDsaLeafDomain = "atlas-pca/fn-dsa/leaf/v1\x00"

// FnDsaSuite is one registered FN-DSA suite: sizes of the halves it frames.
type FnDsaSuite struct {
	Alg, Variant           string
	HasEd25519             bool
	SigBytes               int // the `sig` member: the Ed25519 signature for a hybrid, else the FN-DSA one
	NeedsPqPk              bool
	PqPkBytes              int
	NeedsPqSig             bool
	PqSigBytes, FnSigBytes int
}

var fnDsaVariantPk = map[string]int{"fn-dsa-512": FnDsa512PublicKeyBytes, "fn-dsa-1024": FnDsa1024PublicKeyBytes}
var fnDsaVariantSig = map[string]int{"fn-dsa-512": FnDsa512SignatureBytes, "fn-dsa-1024": FnDsa1024SignatureBytes}

func fnDsaSuiteOf(alg, variant string, hybrid bool) FnDsaSuite {
	pk, sig := fnDsaVariantPk[variant], fnDsaVariantSig[variant]
	if hybrid {
		return FnDsaSuite{alg, variant, true, ed25519.SignatureSize, true, pk, true, sig, sig}
	}
	return FnDsaSuite{alg, variant, false, sig, true, pk, false, 0, sig}
}

var fnDsaSuites = map[string]FnDsaSuite{
	"fn-dsa-512":                 fnDsaSuiteOf("fn-dsa-512", "fn-dsa-512", false),
	"fn-dsa-1024":                fnDsaSuiteOf("fn-dsa-1024", "fn-dsa-1024", false),
	"hybrid-ed25519-fn-dsa-512":  fnDsaSuiteOf("hybrid-ed25519-fn-dsa-512", "fn-dsa-512", true),
	"hybrid-ed25519-fn-dsa-1024": fnDsaSuiteOf("hybrid-ed25519-fn-dsa-1024", "fn-dsa-1024", true),
}

var fnDsaFamilies = map[string]string{"FN-DSA-512": "fn-dsa-512", "FN-DSA-1024": "fn-dsa-1024"}

func IsKnownFnDsaAlg(alg string) bool { _, ok := fnDsaSuites[alg]; return ok }

func ResolveFnDsaAlg(alg string) (FnDsaSuite, bool) { s, ok := fnDsaSuites[alg]; return s, ok }

func IsFnDsaVariant(v string) bool { _, ok := fnDsaVariantPk[v]; return ok }

// ---- backend seam

// FalconBackend: Verify is required; Sign (nil = verify-only) and Keygen are optional. A backend error propagates to the caller.
type FalconBackend struct {
	Verify func(pk, msg, sig []byte) (bool, error)
	Sign   func(sk, msg []byte) ([]byte, error)
	Keygen func() (pk, sk []byte, err error)
	// SignSeeded signs with a caller-supplied 32-byte sign seed (deterministic; known-answer replays). KeygenSeeded derives the key pair
	// of a 32-byte seed for the named variant. Both optional: the agent-side signer needs them only for a fixed seed.
	SignSeeded   func(sk, msg, seed []byte) ([]byte, error)
	KeygenSeeded func(variant string, seed []byte) (pk, sk []byte, err error)
}

// ErrFnDsaBackendMissing: no FN-DSA backend is installed.
var ErrFnDsaBackendMissing = errors.New("no FN-DSA backend registered: supply one via SetFalconBackend() (for example the fndsakit module's backend)")

var (
	fnDsaMu     sync.RWMutex
	fnDsaNoneBe = &FalconBackend{
		Verify: func(_, _, _ []byte) (bool, error) { return false, ErrFnDsaBackendMissing },
		Sign:   func(_, _ []byte) ([]byte, error) { return nil, ErrFnDsaBackendMissing },
		Keygen: func() ([]byte, []byte, error) { return nil, nil, ErrFnDsaBackendMissing },
	}
	fnDsaCurrent = fnDsaNoneBe
)

// SetFalconBackend installs b process-wide; nil or a backend without Verify is refused (the default stays).
func SetFalconBackend(b *FalconBackend) error {
	if b == nil || b.Verify == nil {
		return errors.New("SetFalconBackend: a backend needs a Verify function")
	}
	fnDsaMu.Lock()
	fnDsaCurrent = b
	fnDsaMu.Unlock()
	return nil
}

func GetFalconBackend() *FalconBackend {
	fnDsaMu.RLock()
	defer fnDsaMu.RUnlock()
	return fnDsaCurrent
}

// fnDsaBackendRegistered: a backend has been installed (the core suites fn-dsa-512/1024 are implemented only then).
func fnDsaBackendRegistered() bool {
	fnDsaMu.RLock()
	defer fnDsaMu.RUnlock()
	return fnDsaCurrent != fnDsaNoneBe
}

func ResetFalconBackend() {
	fnDsaMu.Lock()
	fnDsaCurrent = fnDsaNoneBe
	fnDsaMu.Unlock()
}

// FnDsaSign signs msg with the installed backend. The backend's answer must be exactly the variant's padded signature length.
func FnDsaSign(variant string, sk, msg []byte) ([]byte, error) {
	return fnDsaSignSeeded(variant, sk, msg, nil)
}

// fnDsaSignSeeded: a nil seed uses the backend's own CSPRNG signing; a given seed needs SignSeeded.
func fnDsaSignSeeded(variant string, sk, msg, seed []byte) ([]byte, error) {
	if !IsFnDsaVariant(variant) {
		return nil, fmt.Errorf("fndsaSign: unknown FN-DSA variant %q", variant)
	}
	if len(sk) == 0 {
		return nil, errors.New("fndsaSign: secret key must be a non-empty byte string")
	}
	be := GetFalconBackend()
	var sig []byte
	var err error
	if seed != nil {
		if be.SignSeeded == nil {
			return nil, errors.New("fndsaSign: FN-DSA backend cannot sign with a fixed seed (no SignSeeded)")
		}
		sig, err = be.SignSeeded(append([]byte(nil), sk...), append([]byte{}, msg...), append([]byte(nil), seed...))
	} else {
		if be.Sign == nil {
			return nil, errors.New("fndsaSign: FN-DSA backend is verify-only (no Sign)")
		}
		sig, err = be.Sign(append([]byte(nil), sk...), append([]byte{}, msg...))
	}
	if err != nil {
		return nil, err
	}
	if want := fnDsaVariantSig[variant]; len(sig) != want {
		return nil, fmt.Errorf("fndsaSign: FN-DSA backend returned a bad signature; expected padded %d bytes for %q", want, variant)
	}
	return append([]byte(nil), sig...), nil
}

// NewFnDsaKeyPair wraps an FN-DSA key bundle {vk, sk, signSeed} as a PqKeyPair, so every agent-side signer (SignPCActn, MintRoot, delegate,
// SignEscalationAnswer, SignRevocationEpoch ...) signs the pure suites fn-dsa-512/1024 through SuiteOpts. A nil signSeed signs with the
// backend's fresh CSPRNG seed each time (production); a 32-byte one is deterministic. Refused with ErrUnsupportedSigner while no backend
// is registered, exactly as the other suites are refused today.
func NewFnDsaKeyPair(variant string, vk, sk, signSeed []byte) (*PqKeyPair, error) {
	if !IsFnDsaVariant(variant) || !fnDsaBackendRegistered() {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSigner, variant)
	}
	if len(vk) != fnDsaVariantPk[variant] || len(sk) == 0 {
		return nil, fmt.Errorf("%s needs a %d-byte public key and a secret key", variant, fnDsaVariantPk[variant])
	}
	if len(signSeed) != 0 && len(signSeed) != 32 {
		return nil, errors.New("an FN-DSA sign seed is 32 bytes")
	}
	prim := pqFnDsa512
	if variant == "fn-dsa-1024" {
		prim = pqFnDsa1024
	}
	sk = append([]byte(nil), sk...)
	var seed []byte // nil = fresh CSPRNG seed per signature
	if len(signSeed) == 32 {
		seed = append([]byte(nil), signSeed...)
	}
	return &PqKeyPair{prim: prim, Public: b64.EncodeToString(vk), sign: func(m []byte) ([]byte, error) {
		return fnDsaSignSeeded(variant, sk, m, seed)
	}}, nil
}

// FnDsaKeyPairFromSeed derives the key pair of a 32-byte keygen seed through the backend (KeygenSeeded). signSeed as in NewFnDsaKeyPair.
func FnDsaKeyPairFromSeed(variant string, seed, signSeed []byte) (*PqKeyPair, error) {
	if !IsFnDsaVariant(variant) || !fnDsaBackendRegistered() {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSigner, variant)
	}
	be := GetFalconBackend()
	if be.KeygenSeeded == nil {
		return nil, errors.New("FN-DSA backend cannot derive keys from a seed (no KeygenSeeded)")
	}
	if len(seed) != 32 {
		return nil, errors.New("an FN-DSA keygen seed is 32 bytes")
	}
	vk, sk, err := be.KeygenSeeded(variant, append([]byte(nil), seed...))
	if err != nil {
		return nil, err
	}
	return NewFnDsaKeyPair(variant, vk, sk, signSeed)
}

// FnDsaVerify is false for any length violation (before the backend is consulted); a backend error propagates.
func FnDsaVerify(variant string, pk, msg, sig []byte) (bool, error) {
	if !IsFnDsaVariant(variant) || len(pk) != fnDsaVariantPk[variant] || len(sig) != fnDsaVariantSig[variant] {
		return false, nil
	}
	return GetFalconBackend().Verify(append([]byte(nil), pk...), append([]byte{}, msg...), append([]byte(nil), sig...))
}

// ---- hybrid leaf composition

// fnDsaUTF8 encodes like a JavaScript TextEncoder: every lone surrogate (kept as 3-byte WTF-8) and every invalid byte becomes U+FFFD.
func fnDsaUTF8(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			out, i = append(out, c), i+1
			continue
		}
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out, i = append(out, 0xEF, 0xBF, 0xBD), i+3
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == 0xFFFD && n == 1 {
			out, i = append(out, 0xEF, 0xBF, 0xBD), i+1
			continue
		}
		out, i = append(out, s[i:i+n]...), i+n
	}
	return out
}

// FnDsaLeafMessage = ThresholdMessage(leaf) || domain || alg || 0x00 || the base64url FN-DSA public key text (alg and key are bound).
func FnDsaLeafMessage(leaf map[string]any, alg, pqPkB64u string) ([]byte, error) {
	tm, err := ThresholdMessage(leaf)
	if err != nil {
		return nil, err
	}
	out := append(tm, FnDsaLeafDomain...)
	out = append(out, fnDsaUTF8(alg)...)
	out = append(out, 0)
	return append(out, fnDsaUTF8(pqPkB64u)...), nil
}

// SignPcaWithFndsa returns {"sig","alg","pq_pk"[,"pq_sig"]}. pk/sk are the FN-DSA key pair; a hybrid suite also needs the 32-byte Ed25519 seed.
func SignPcaWithFndsa(alg string, leaf map[string]any, pk, sk, edSecret []byte) (map[string]string, error) {
	suite, ok := ResolveFnDsaAlg(alg)
	if !ok {
		return nil, fmt.Errorf("signPcaWithFndsa: unknown FN-DSA alg %q", alg)
	}
	if len(pk) != suite.PqPkBytes {
		return nil, fmt.Errorf("signPcaWithFndsa: %q requires a %d-byte FN-DSA public key", suite.Alg, suite.PqPkBytes)
	}
	if len(sk) == 0 {
		return nil, fmt.Errorf("signPcaWithFndsa: %q requires FN-DSA secret-key material", suite.Alg)
	}
	if suite.HasEd25519 && len(edSecret) != ed25519.SeedSize {
		return nil, fmt.Errorf("signPcaWithFndsa: %q requires edSecret (the %d-byte Ed25519 leaf-holder seed)", suite.Alg, ed25519.SeedSize)
	}
	pqPk := b64.EncodeToString(pk)
	msg, err := FnDsaLeafMessage(leaf, suite.Alg, pqPk)
	if err != nil {
		return nil, err
	}
	fnSig, err := FnDsaSign(suite.Variant, sk, msg)
	if err != nil {
		return nil, err
	}
	if !suite.HasEd25519 {
		return map[string]string{"sig": b64.EncodeToString(fnSig), "alg": suite.Alg, "pq_pk": pqPk}, nil
	}
	edSig := ed25519.Sign(ed25519.NewKeyFromSeed(edSecret), msg)
	return map[string]string{"sig": b64.EncodeToString(edSig), "alg": suite.Alg, "pq_pk": pqPk, "pq_sig": b64.EncodeToString(fnSig)}, nil
}

// VerifyPcaFndsa fails closed (an absent member is ""). A hybrid needs BOTH halves; every length and encoding check runs before the
// backend. An error is returned only when the backend (or the leaf canonicalisation) fails.
func VerifyPcaFndsa(alg string, leaf map[string]any, holder, pqPk, sig, pqSig string) (bool, error) {
	suite, ok := ResolveFnDsaAlg(alg)
	if !ok {
		return false, nil
	}
	pk, ok := DecodeB64uStrict(pqPk, suite.PqPkBytes)
	if !ok {
		return false, nil
	}
	msg, err := FnDsaLeafMessage(leaf, suite.Alg, pqPk)
	if err != nil {
		return false, err
	}
	if !suite.HasEd25519 {
		fnSig, ok := DecodeB64uStrict(sig, suite.SigBytes)
		if !ok {
			return false, nil
		}
		return FnDsaVerify(suite.Variant, pk, msg, fnSig)
	}
	if _, ok := DecodeB64uStrict(sig, suite.SigBytes); !ok {
		return false, nil
	}
	edOK := verifyB64u(holder, msg, sig)
	fnSig, ok := DecodeB64uStrict(pqSig, suite.PqSigBytes)
	if !ok {
		return false, nil
	}
	pqOK, err := FnDsaVerify(suite.Variant, pk, msg, fnSig)
	return edOK && pqOK, err
}
