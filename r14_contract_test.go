package pca

import (
	"math"
	"testing"
)

func TestImmuneDecayIsPlatformDeterministic(t *testing.T) {
	h := DefaultImmuneConfig.HalfLifeMs
	for n, want := range map[float64]float64{1: 4, 2: 2, 3: 1} {
		if got := immuneDecay(8, n*h, h); got != want {
			t.Errorf("%v half-lives: %v, want %v", n, got, want)
		}
	}
	if got := immuneDecay(8, h/1024, h); got != 8*0.9993233275026507 {
		t.Errorf("one step: %v", got)
	}
	if got := immuneDecay(8, h/1024*0.999, h); got != 8 {
		t.Errorf("below one step: %v", got)
	}
	if got := immuneDecay(8, h/2, h); math.Abs(got-8*math.Sqrt2/2) > 1e-9 {
		t.Errorf("half a half-life: %v", got)
	}
	if !math.IsNaN(immuneDecay(8, h, math.NaN())) || !math.IsNaN(immuneDecay(8, math.NaN(), h)) {
		t.Error("a NaN operand stays NaN")
	}
	if immuneDecay(8, 2000*h, h) != 0 {
		t.Error("an underflowing factor is zero")
	}
}

func TestNoWidenRefusesNonNumbers(t *testing.T) {
	base := map[string]any{"kappa": 1.0, "theta1": 0.5, "theta2": 0.8, "lambda": 1.0, "rho": 1.0, "bMax": 1.0, "weights": map[string]any{"a": 1.0}}
	for _, bad := range []any{nil, true, false, "1"} {
		for _, k := range []string{"kappa", "theta1", "theta2"} {
			ad := map[string]any{}
			for kk, v := range base {
				ad[kk] = v
			}
			ad[k] = bad
			if got, err := ImmuneNoWidenViolation(base, ad); err != nil || got != "kappa and theta must be numbers" {
				t.Errorf("%s=%v: %q %v", k, bad, got, err)
			}
		}
	}
}

func TestStalenessChecksFailClosedOnNaN(t *testing.T) {
	nan := math.NaN()
	issued := 1000.0
	if nonceAgeReason(&issued, nan, 0, 10) == "" || nonceAgeReason(&issued, 1000, nan, 10) == "" || nonceAgeReason(&issued, 1000, 0, nan) == "" {
		t.Error("a NaN clock, skew or window must refuse the nonce")
	}
	if nonceAgeReason(&issued, 1005, 0, 10) != "" {
		t.Error("a fresh nonce must pass")
	}
}

func TestUnrepresentableTimeIsRefused(t *testing.T) {
	for _, bad := range []float64{9e15, -9e15} {
		now := bad
		if r := VerifyPcaSdJwt("x", SdJwtVerifyOptions{NowMs: &now}); r.Reason != "now is not a representable time" {
			t.Errorf("sd-jwt now %v: %q", bad, r.Reason)
		}
	}
	key := sigK1Seed
	set, err := BuildSET(BuildSETArgs{Events: map[string]any{SetEventTypes["grantRevoked"]: map[string]any{"grant_ref": "g", "event_timestamp": 1.0}},
		Issuer: "iss", Audience: "aud", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []float64{1e13, -1e13, math.NaN(), math.Inf(1)} {
		now := bad
		store, serr := NewInMemorySetReplayStore(nil)
		if serr != nil {
			t.Fatal(serr)
		}
		r := ReceiveSET(set, sigK1Pub, &ReceiveSETOptions{Issuer: []string{"iss"}, Audience: []string{"aud"}, ReplayStore: store, State: NewRevocationState(), NowSec: &now, MaxAgeSec: 300})
		if r.OK || r.Code != "verify_failed" || r.Reason != "nowSec is not a representable time" {
			t.Errorf("receiveSET nowSec %v: %+v", bad, r)
		}
	}
}

func TestBondPowerCurveIsExactEighths(t *testing.T) {
	for _, c := range []struct{ e, g, want float64 }{{3, 1, 3}, {4, 1.5, 8}, {3, 2, 9}, {16, 2.25, 256 * 2}, {1e12, 1.5, 1e18}, {2, 64, 18446744073709551616}} {
		got, err := bsPowEighths(c.e, c.g)
		if err != nil || got != c.want {
			t.Fatalf("e=%v gamma=%v: got %v err %v want %v", c.e, c.g, got, err, c.want)
		}
	}
	for _, g := range []float64{1.1, 64.125, 65, 1.0625} {
		if _, err := bsPowEighths(2, g); err == nil || err.Error() != "bondAmount: power curve gamma must be a multiple of 1/8 and at most 64" {
			t.Fatalf("gamma %v: %v", g, err)
		}
	}
	if _, err := bsCurve(&BondCurve{Kind: "power", Gamma: 1.1}, 1, 2); err == nil {
		t.Fatal("non-eighth gamma must be refused through bsCurve")
	}
}
