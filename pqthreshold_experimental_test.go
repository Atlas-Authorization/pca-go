package pca

import (
	"math/big"
	"strings"
	"testing"
)

func TestExperimentalLatticeToy(t *testing.T) {
	opt := ExperimentalOptIn{IUnderstandThisIsNotProduction: true}
	d := RaccoonDesign()
	if d.ProductionReady || d.Status != "research-prototype" || !strings.Contains(d.Banner, "NOT PRODUCTION") || !strings.Contains(d.ShippableAlternative, "HYBRID") || len(d.Construction) == 0 {
		t.Fatal("design")
	}
	d.Construction[0] = "edited"
	if RaccoonDesign().Construction[0] == "edited" {
		t.Fatal("the design is shared")
	}
	p := ToyDefaultParams()
	key := []*big.Int{big.NewInt(123), big.NewInt(8380416), big.NewInt(0), big.NewInt(-42)}
	if _, err := AdditiveShareLatticeKey(key, 3, ExperimentalOptIn{}, p, nil); err == nil || !strings.Contains(err.Error(), "NOT PRODUCTION") {
		t.Fatal("no opt-in must throw the banner")
	}
	state := big.NewInt(0x12345678)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	sampler := func(q *big.Int) *big.Int {
		state = new(big.Int).And(new(big.Int).Add(new(big.Int).Mul(state, new(big.Int).SetUint64(6364136223846793005)), new(big.Int).SetUint64(1442695040888963407)), mask)
		return new(big.Int).Mod(state, q)
	}
	shares, err := AdditiveShareLatticeKey(key, 4, opt, p, sampler)
	if err != nil || len(shares) != 4 {
		t.Fatal(err)
	}
	got, err := ReconstructLatticeKey(shares, opt, p)
	if err != nil {
		t.Fatal(err)
	}
	for c := range key {
		if got[c].Cmp(new(big.Int).Mod(key[c], p.Q)) != 0 {
			t.Fatalf("coefficient %d: %v", c, got[c])
		}
	}
	if miss, _ := ReconstructLatticeKey(shares[:3], opt, p); miss[0].Cmp(got[0]) == 0 && miss[1].Cmp(got[1]) == 0 && miss[2].Cmp(got[2]) == 0 {
		t.Fatal("a missing share reconstructed the key")
	}
	if _, err := ReconstructLatticeKey(append(shares[:1:1], shares[0]), opt, p); err == nil {
		t.Fatal("duplicate index")
	}
	if _, err := ReconstructLatticeKey(nil, opt, p); err == nil {
		t.Fatal("no shares")
	}
	if _, err := ReconstructLatticeKey(shares, ExperimentalOptIn{}, p); err == nil {
		t.Fatal("reconstruct without opt-in")
	}
	if _, err := AdditiveShareLatticeKey(key, 0, opt, p, nil); err == nil {
		t.Fatal("n = 0")
	}
	if _, err := AdditiveShareLatticeKey(key[:2], 2, opt, p, nil); err == nil {
		t.Fatal("wrong dimension")
	}
	if s, err := AdditiveShareLatticeKey(key, 2, opt, p, nil); err != nil || len(s) != 2 { // crypto/rand sampler
		t.Fatal("default sampler")
	}
}
