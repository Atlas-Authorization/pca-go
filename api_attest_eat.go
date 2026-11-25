package pca

import (
	"crypto/rsa"
)

// EatRsaKeyOk is the public form of the pca-attest-eat export rsaKeyOk.
func EatRsaKeyOk(pk *rsa.PublicKey) bool {
	return rsaKeyOK(pk)
}
