package pca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
)

// EatGenerateKeyPair generates a signing key for an EAT: alg EdDSA (the default when empty) or ES256. signKey is what EatBuild
// signs with (the 32-byte Ed25519 seed, or the *ecdsa.PrivateKey) and verifyKey is what EatVerify checks under.
func EatGenerateKeyPair(alg string) (signKey any, verifyKey *JOSEKey, err error) {
	switch alg {
	case "", EatDefaultAlg:
		seed := make([]byte, ed25519.SeedSize)
		if _, err = io.ReadFull(rand.Reader, seed); err != nil {
			return nil, nil, err
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		return seed, &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: pub}, nil
	case "ES256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, &JOSEKey{Kty: "EC", Crv: "P-256", EC: &k.PublicKey}, nil
	}
	return nil, nil, errors.New("generateEatKeyPair: alg must be EdDSA or ES256")
}
