package pcasigstore

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

// The usable-key rule of every RSA verification: modulus 512..16384 bits, odd exponent >= 3, at most 32 bits.
func TestGoCRsaKeyOKBounds(t *testing.T) {
	n2048 := new(big.Int).Lsh(big.NewInt(1), 2047)
	n2048.Add(n2048, big.NewInt(1))
	mod := func(b int) *big.Int { m := new(big.Int).Lsh(big.NewInt(1), uint(b-1)); return m.Add(m, big.NewInt(1)) }
	for name, c := range map[string]struct {
		pk   *rsa.PublicKey
		want bool
	}{
		"2048 e 65537":       {&rsa.PublicKey{N: n2048, E: 65537}, true},
		"e 3":                {&rsa.PublicKey{N: n2048, E: 3}, true},
		"e 1":                {&rsa.PublicKey{N: n2048, E: 1}, false},
		"e 0":                {&rsa.PublicKey{N: n2048, E: 0}, false},
		"e negative":         {&rsa.PublicKey{N: n2048, E: -3}, false},
		"e 2":                {&rsa.PublicKey{N: n2048, E: 2}, false},
		"e 4 (even)":         {&rsa.PublicKey{N: n2048, E: 4}, false},
		"e 65538 (even)":     {&rsa.PublicKey{N: n2048, E: 65538}, false},
		"e 2^32-1 (32 bits)": {&rsa.PublicKey{N: n2048, E: 1<<32 - 1}, true},
		"e 2^32+1 (33 bits)": {&rsa.PublicKey{N: n2048, E: 1<<32 + 1}, false},
		"e 2^33+1":           {&rsa.PublicKey{N: n2048, E: 1<<33 + 1}, false},
		"modulus 511 bits":   {&rsa.PublicKey{N: mod(511), E: 65537}, false},
		"modulus 512 bits":   {&rsa.PublicKey{N: mod(512), E: 65537}, true},
		"modulus 256 bits":   {&rsa.PublicKey{N: mod(256), E: 65537}, false},
		"modulus 16384 bits": {&rsa.PublicKey{N: mod(16384), E: 65537}, true},
		"modulus 16385 bits": {&rsa.PublicKey{N: mod(16385), E: 65537}, false},
		"modulus 17000 bits": {&rsa.PublicKey{N: mod(17000), E: 65537}, false},
		"modulus zero":       {&rsa.PublicKey{N: big.NewInt(0), E: 65537}, false},
		"modulus negative":   {&rsa.PublicKey{N: new(big.Int).Neg(mod(2048)), E: 65537}, false},
		"nil modulus":        {&rsa.PublicKey{E: 65537}, false},
		"nil key":            {nil, false},
	} {
		if got := rsaKeyOK(c.pk); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
