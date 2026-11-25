package pca

import (
	"math/big"
)

// VdfVerify is the public form of the pca-vdf export vdfVerify.
func VdfVerify(x *big.Int, y *big.Int, pi *big.Int, t float64, n *big.Int, canonical bool) (v VdfVerdict) {
	return vdfVerify(x, y, pi, t, n, canonical)
}
