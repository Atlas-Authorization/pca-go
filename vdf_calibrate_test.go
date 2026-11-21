package pca

import (
	"math/big"
	"testing"
)

func TestVdfCalibrateSteps(t *testing.T) {
	n := big.NewInt(1000003)
	tick := 0.0
	clock := func() float64 { tick += 10; return tick } // 10 ms per reading
	r, err := VdfCalibrateSteps(n, 2, 1000, 10, clock)
	if err != nil {
		t.Fatal(err)
	}
	// 1000 squarings in 10 ms = 100000/s, x10 = 1e6/s, 2 s = 2e6 steps
	if r.MeasuredSquaringsPerSecond != 100000 || r.AssumedAdversarySquaringsPerSecond != 1e6 || r.Steps != 2e6 {
		t.Fatalf("%+v", r)
	}
	for _, bad := range []func() error{
		func() error { _, e := VdfCalibrateSteps(big.NewInt(3), 1, 1, 1, clock); return e },
		func() error { _, e := VdfCalibrateSteps(n, 0, 1, 1, clock); return e },
		func() error { _, e := VdfCalibrateSteps(n, 1, -1, 1, clock); return e },
		func() error { _, e := VdfCalibrateSteps(n, 1, 1, 0.5, clock); return e },
		func() error { _, e := VdfCalibrateSteps(nil, 1, 1, 1, clock); return e },
	} {
		if bad() == nil {
			t.Fatal("accepted a bad argument")
		}
	}
	if VdfDefaultModulus.Cmp(VdfRSA2048ChallengeModulus) != 0 {
		t.Fatal("default modulus")
	}
}
