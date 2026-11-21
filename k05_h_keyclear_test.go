package pca

import (
	"bytes"
	"testing"
)

// O2: private key material that Go code holds is cleared when it is no longer needed.
func TestO2_KeyPairZero(t *testing.T) {
	k, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Seed()) != 32 || bytes.Equal(k.Seed(), make([]byte, 32)) {
		t.Fatal("a fresh key pair has a seed")
	}
	k.Zero()
	if !bytes.Equal(k.priv, make([]byte, len(k.priv))) || len(k.priv) != 64 {
		t.Error("the private key was not cleared")
	}
}

func TestO2_FromSeedKeepsItsOwnCopy(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	k, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	clear(seed) // the caller wipes its buffer: the key pair must not be affected
	if !bytes.Equal(k.Seed(), bytes.Repeat([]byte{7}, 32)) {
		t.Error("the key pair shares the caller's seed buffer")
	}
	if len(k.Sign([]byte("m"))) != 64 {
		t.Error("sign")
	}
}
