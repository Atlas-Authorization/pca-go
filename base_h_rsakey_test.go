package pca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// H1: the RSA public-key rule (modulus 512..16384 bits, odd e >= 3, at most 32 bits) holds at every RSA verification.

func h1Key(t *testing.T, bitsN int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bitsN)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestH1_RsaKeyOKBounds(t *testing.T) {
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

// A signature by a real key verifies; the same signature under a key the rule refuses does not, and an oversized modulus is
// refused without any modular exponentiation.
func TestH1_JwsRS256UnderTheRule(t *testing.T) {
	k := h1Key(t, 2048)
	input := []byte("header.payload")
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if !jwsRS256OK(sig, input, certKey{pub: &k.PublicKey}) {
		t.Fatal("a genuine RS256 signature must verify")
	}
	for name, pk := range map[string]*rsa.PublicKey{
		"e 1":    {N: k.N, E: 1},
		"e 4":    {N: k.N, E: 4},
		"e 2^33": {N: k.N, E: 1<<33 + 1},
	} {
		if jwsRS256OK(sig, input, certKey{pub: pk}) {
			t.Errorf("%s verified", name)
		}
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 16999)
	huge.Add(huge, big.NewInt(1))
	start := time.Now()
	if jwsRS256OK(make([]byte, 2125), input, certKey{pub: &rsa.PublicKey{N: huge, E: 65537}}) {
		t.Error("a 17000-bit modulus verified")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("a 17000-bit modulus took %v: the rule must refuse before any exponentiation", d)
	}
}

func TestH1_JwkRsaKeyUnderTheRule(t *testing.T) {
	k := h1Key(t, 2048)
	enc := base64.RawURLEncoding.EncodeToString
	n := enc(k.N.Bytes())
	if _, err := jwkRSAKey(n, enc(big.NewInt(65537).Bytes())); err != nil {
		t.Fatalf("a genuine key: %v", err)
	}
	for name, e := range map[string]*big.Int{"e 4": big.NewInt(4), "e 65538": big.NewInt(65538), "e 2^31": big.NewInt(1 << 31), "e 1": big.NewInt(1)} {
		if _, err := jwkRSAKey(n, enc(e.Bytes())); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	short := new(big.Int).Lsh(big.NewInt(1), 255)
	if _, err := jwkRSAKey(enc(short.Bytes()), enc(big.NewInt(65537).Bytes())); err == nil {
		t.Error("a 256-bit modulus accepted")
	}
	big17k := new(big.Int).Lsh(big.NewInt(1), 16999)
	if _, err := jwkRSAKey(enc(big17k.Bytes()), enc(big.NewInt(65537).Bytes())); err == nil {
		t.Error("a 17000-bit modulus accepted")
	}
}
