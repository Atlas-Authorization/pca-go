package pca

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// H19: the Ed25519 equation runs first; the torsion (subgroup) checks run only for a signature that verifies.
func TestH19_ForgedSignatureSkipsTheSubgroupChecks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("m")
	edPointMemo.Lock()
	before := len(edPointMemo.m)
	edPointMemo.Unlock()
	for i := 0; i < 20; i++ {
		forged := make([]byte, 64)
		_, _ = rand.Read(forged[:32])
		forged[63] &= 0x0f // a canonical S, so only the equation can refuse it
		if VerifyStrict(pub, msg, forged) {
			t.Fatal("a forged signature verified")
		}
	}
	edPointMemo.Lock()
	after := len(edPointMemo.m)
	edPointMemo.Unlock()
	if after != before {
		t.Errorf("%d subgroup checks ran for forged signatures", after-before)
	}
	// a genuine signature still passes through every gate
	if !VerifyStrict(pub, msg, ed25519.Sign(priv, msg)) {
		t.Error("a genuine signature was refused")
	}
	edPointMemo.Lock()
	ran := len(edPointMemo.m)
	edPointMemo.Unlock()
	if ran <= before {
		t.Error("the subgroup checks did not run for a verifying signature")
	}
}
