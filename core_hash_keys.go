package pca

import (
	"errors"
	"math"
	"strings"
)

// HashLen is the digest length in bytes of each hash suite.
var HashLen = map[string]int{"sha256": 32, "sha384": 48}

// DefaultHashSuite is the suite an absent hash_suite means (back-compat).
const DefaultHashSuite = "sha256"

// Sha256 is the SHA-256 digest of b.
func Sha256(b []byte) []byte { return sha(b) }

// Sha384 is the SHA-384 digest of b.
func Sha384(b []byte) []byte { return sha384Sum(b) }

// HashWithSuite dispatches a raw-byte hash over a suite; an empty suite is the default (sha256). An unknown suite is an error
// (the reference would silently take sha256: refused here so a typo cannot weaken the digest).
func HashWithSuite(b []byte, suite string) ([]byte, error) {
	switch suite {
	case "", DefaultHashSuite:
		return sha(b), nil
	case "sha384":
		return sha384Sum(b), nil
	}
	return nil, errors.New("hashWithSuite: unknown hash suite")
}

// Utf8 is the UTF-8 encoding of s (a Go string already is UTF-8; this is the []byte form).
func Utf8(s string) []byte { return []byte(s) }

// B64u is the unpadded base64url encoding of b.
func B64u(b []byte) string { return b64.EncodeToString(b) }

// Unb64u decodes unpadded base64url; any deviation (padding, a foreign character, bad length) is an error.
func Unb64u(s string) ([]byte, error) {
	b, ok := DecodeB64uStrict(s, -1)
	if !ok {
		return nil, errors.New("invalid base64url")
	}
	return b, nil
}

// EncodeKey is the wire form (base64url) of a public or secret key.
func EncodeKey(b []byte) string { return B64u(b) }

// DecodeKey decodes a wire-form key.
func DecodeKey(s string) ([]byte, error) { return Unb64u(s) }

// EncodeSig is the wire form (base64url) of a signature.
func EncodeSig(b []byte) string { return B64u(b) }

// DecodeSig decodes a wire-form signature.
func DecodeSig(s string) ([]byte, error) { return Unb64u(s) }

// GenerateKeyPair generates a fresh Ed25519 identity key pair.
func GenerateKeyPair() (*KeyPair, error) { return NewKeyPair() }

// CanonicalizeStrict is the strict, language-portable canonical text of v (the form every protocol digest uses); it errors on
// a lone surrogate, nesting past MaxJSONDepth and any number outside the canonical wire profile.
func CanonicalizeStrict(v any) (string, error) { return Canonicalize(v) }

// CanonicalBytes is the strict canonical form of v as bytes.
func CanonicalBytes(v any) ([]byte, error) { return canonBytes(v) }

// CanonicalBytesStrict is CanonicalBytes (both are strict).
func CanonicalBytesStrict(v any) ([]byte, error) { return canonBytes(v) }

// CanonicalizeLenientServerOnly is the lenient canonical text of v (any finite number, no depth limit). It is NOT portable and
// must never feed a protocol digest; ok is false for a value with no stable encoding.
func CanonicalizeLenientServerOnly(v any) (string, bool) { return canonicalLenient(v) }

// CanonicalBytesLenient is CanonicalizeLenientServerOnly as bytes (server-only digests).
func CanonicalBytesLenient(v any) ([]byte, bool) {
	s, ok := canonicalLenient(v)
	return []byte(s), ok
}

// HashCanonicalLenient is base64url(sha256(lenient canonical form)); server-only digests, never a protocol hash.
func HashCanonicalLenient(v any) (string, error) {
	b, ok := CanonicalBytesLenient(v)
	if !ok {
		return "", errors.New("canonicalize: value has no stable encoding")
	}
	return b64.EncodeToString(sha(b)), nil
}

// StrictNumberError is the strict-profile check of one number: "" when v is in the canonical wire profile, else the reason.
func StrictNumberError(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "non-finite number"
	}
	if v == 0 && math.Signbit(v) {
		return "negative zero"
	}
	if v == math.Trunc(v) {
		if math.Abs(v) > maxSafeInt {
			return "integer outside the safe range (|n| > 2^53-1)"
		}
		return ""
	}
	if math.Abs(v) < 1e-6 {
		return "non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)"
	}
	s := jsNumberString(v)
	if strings.ContainsAny(s, "eE") {
		return "non-integer number needs an exponent form (not representable in the canonical decimal form)"
	}
	digits := strings.TrimLeft(strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), ".", ""), "0")
	if len(digits) > MaxDecimalDigits {
		return "non-integer number has more than 15 significant digits"
	}
	return ""
}
