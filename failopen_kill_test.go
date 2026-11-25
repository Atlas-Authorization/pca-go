package pca

import (
	"math"
	"testing"
)

// Closeness and tolerance tests read as the positive condition, so a NaN, a missing value or a wrong type is a mismatch and never
// passes (`|a-b| > tol` is false for NaN).
func TestFailOpenIntentMapClaimMismatch(t *testing.T) {
	for name, claimed := range map[string]any{"NaN": math.NaN(), "missing": nil, "string": "5", "bool": true, "far": 9.0} {
		if !ixMkDiffers2(5.0, claimed) {
			t.Errorf("a %s claim must be a mismatch", name)
		}
	}
	for _, claimed := range []float64{5, 6.5, 3, 7} {
		if ixMkDiffers2(5.0, claimed) {
			t.Errorf("%v is within 2 of 5", claimed)
		}
	}
	if !ixMkDiffers2(math.NaN(), 5.0) {
		t.Error("a NaN replayed value must be a mismatch")
	}
}

func TestFailOpenFraudProofRiskMatch(t *testing.T) {
	for name, asserted := range map[string]any{"NaN": math.NaN(), "missing": nil, "string": "0.5", "far": 0.6} {
		if oaRMatches(0.5, asserted) {
			t.Errorf("a %s asserted r must not match", name)
		}
	}
	if !oaRMatches(0.5, 0.5) || !oaRMatches(0.5, 0.5+5e-10) {
		t.Error("an equal r must match")
	}
	if oaRMatches(math.NaN(), 0.5) {
		t.Error("a NaN recomputed r must not match")
	}
}

func TestFailOpenHeartbeatSkew(t *testing.T) {
	if heartbeatInSkew(math.NaN(), 1000) || heartbeatInSkew(1000, math.NaN()) || heartbeatInSkew(1000, math.Inf(1)) {
		t.Error("a NaN or infinite time is outside the skew window")
	}
	if !heartbeatInSkew(1000, 1000) || heartbeatInSkew(1000, 1000+HeartbeatSkewMs+1) {
		t.Error("the window itself must hold")
	}
}
