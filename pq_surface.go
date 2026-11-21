package pca

import (
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PinnedPqKey is the only key type the suite verifier accepts for the post-quantum half of a signature: a key that was
// authorised by a verifier-side source (see ResolvePqVerifyKey). It cannot be built from an artifact's own pq_pk.
type PinnedPqKey = pqVerifyKey

// MlDsa65Sign signs msg with a 4032-byte ML-DSA-65 secret key (FIPS 204, pure mode, empty context, deterministic).
func MlDsa65Sign(secretKey, msg []byte) ([]byte, error) {
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(secretKey); err != nil {
		return nil, errors.New("mlDsa65Sign: malformed secret key")
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&sk, msg, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// MlDsa87Sign signs msg with an ML-DSA-87 secret key (FIPS 204, pure mode, empty context, deterministic).
func MlDsa87Sign(secretKey, msg []byte) ([]byte, error) {
	var sk mldsa87.PrivateKey
	if err := sk.UnmarshalBinary(secretKey); err != nil {
		return nil, errors.New("mlDsa87Sign: malformed secret key")
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(&sk, msg, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// MlDsa65Verify verifies an ML-DSA-65 signature over raw bytes. A wrong length or a malformed key is false, never a panic.
func MlDsa65Verify(publicKey, msg, sig []byte) bool {
	return pqVerifyRaw(pqMlDsa65, publicKey, msg, sig)
}

// MlDsa87Verify verifies an ML-DSA-87 signature over raw bytes. A wrong length or a malformed key is false, never a panic.
func MlDsa87Verify(publicKey, msg, sig []byte) bool {
	return pqVerifyRaw(pqMlDsa87, publicKey, msg, sig)
}

// VerifyWithSuite verifies a signature under the named suite. edPub is the Ed25519 identity (base64url); pq is the pinned PQ
// key for a suite that has one; sig and pqSig are the base64url classical and post-quantum parts. An unknown suite, a missing
// part or a missing key is false; a hybrid needs both halves, the cheap Ed25519 half first. algPresent false means ed25519.
func VerifyWithSuite(alg any, algPresent bool, edPub string, pq PinnedPqKey, msg []byte, sig, pqSig any) bool {
	return verifyLeafSuite(alg, algPresent, edPub, pq, msg, sig, pqSig)
}

// IsWellFormedPqPublicKey reports whether pq is a strict base64url string whose decoded length is one of the registered PQ
// public key sizes.
func IsWellFormedPqPublicKey(pq any) bool {
	s, ok := pq.(string)
	if !ok {
		return false
	}
	b, ok := DecodeB64uStrict(s, -1)
	return ok && pqPkLengths[len(b)]
}

// PqPinFor verifies a PQ key binding (see SignPqBinding) and returns the one-entry pin {ed identity: pq key}. It is nil when
// the binding does not verify, is for another audience, carries a malformed PQ key or has an epoch below 1. aud is required.
func PqPinFor(binding map[string]any, aud string) map[string]string {
	ed, ok1 := binding["ed"].(string)
	sig, ok2 := binding["sig"].(string)
	pq, ok3 := binding["pq"].(string)
	bAud, ok4 := binding["aud"].(string)
	if !ok1 || !ok2 || !ok3 || !ok4 || aud == "" || bAud != aud {
		return nil
	}
	ep, ok := jsNum(binding["epoch"])
	if !ok || ep != float64(int64(ep)) || ep < 1 || ep > maxSafeInt || !IsWellFormedPqPublicKey(pq) {
		return nil
	}
	msg := pqBindDomain + ed + "\x00" + pq + "\x00" + jsNumberString(ep) + "\x00" + bAud
	if !verifyB64u(ed, []byte(msg), sig) {
		return nil
	}
	return map[string]string{ed: pq}
}
