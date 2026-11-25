package pca

import (
	"errors"
	"math"
	"math/big"
	"time"
)

// VdfDefaultModulus is the RSA-2048 challenge modulus (unknown factorisation): the default timelock modulus. Pass your own N (or a
// class-group VDF) when the provenance of this value matters.
var VdfDefaultModulus = VdfRSA2048ChallengeModulus

// VdfCalibration is what VdfCalibrateSteps measured and derived.
type VdfCalibration struct {
	Steps                              float64
	MeasuredSquaringsPerSecond         float64
	AssumedAdversarySquaringsPerSecond float64
}

// VdfCalibrateSteps sizes a timelock: it measures sequential squarings per second against the modulus n and returns the step count
// for desiredSeconds against an assumed adversary advantage (default 10x faster hardware), so the real delay can only be LONGER.
// Treat the wall-clock as a FLOOR, never an exact timer. sampleSquarings 0 is 50,000, adversaryAdvantage 0 is 10; now is a
// millisecond clock (nil: the wall clock; tests pass their own).
func VdfCalibrateSteps(n *big.Int, desiredSeconds float64, sampleSquarings int, adversaryAdvantage float64, now func() float64) (VdfCalibration, error) {
	if n == nil || n.Cmp(big.NewInt(3)) <= 0 {
		return VdfCalibration{}, errors.New("calibrateSteps: modulus N must be a bigint > 3")
	}
	if math.IsNaN(desiredSeconds) || math.IsInf(desiredSeconds, 0) || desiredSeconds <= 0 {
		return VdfCalibration{}, errors.New("calibrateSteps: desiredSeconds must be > 0")
	}
	if sampleSquarings == 0 {
		sampleSquarings = 50000
	}
	if adversaryAdvantage == 0 {
		adversaryAdvantage = 10
	}
	if sampleSquarings < 1 {
		return VdfCalibration{}, errors.New("calibrateSteps: sampleSquarings must be a safe integer >= 1")
	}
	if math.IsNaN(adversaryAdvantage) || math.IsInf(adversaryAdvantage, 0) || adversaryAdvantage < 1 {
		return VdfCalibration{}, errors.New("calibrateSteps: adversaryAdvantage must be >= 1")
	}
	if now == nil {
		now = func() float64 { return float64(time.Now().UnixNano()) / 1e6 }
	}
	y := new(big.Int).Mod(big.NewInt(2), n)
	t0 := now()
	for i := 0; i < sampleSquarings; i++ {
		y.Mul(y, y).Mod(y, n)
	}
	t1 := now()
	if !finite(t0) || !finite(t1) { // a non-finite reading gives NaN steps, or one step from an infinite elapsed time
		return VdfCalibration{}, errors.New("calibrateSteps: the clock must return finite times")
	}
	elapsedMs := math.Max(t1-t0, 2.220446049250313e-16)
	measured := float64(sampleSquarings) / elapsedMs * 1000
	assumed := measured * adversaryAdvantage
	return VdfCalibration{Steps: math.Max(1, math.Ceil(assumed*desiredSeconds)), MeasuredSquaringsPerSecond: measured, AssumedAdversarySquaringsPerSecond: assumed}, nil
}
