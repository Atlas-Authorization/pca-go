package fndsakit

import (
	"crypto/ed25519"
	"encoding/base64"
)

// edHolder is the base64url Ed25519 public key of a seed (the leaf holder member).
func edHolder(seed []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}
