package pca

import (
	"math"
	"strings"
	"testing"
)

func TestBuildPaymentMandateRefusesNegativeZero(t *testing.T) {
	negZero := math.Copysign(0, -1)
	for _, k := range []string{"autoApproveThreshold", "replenishPerCosign", "periodStart"} {
		_, err := BuildPaymentMandate(map[string]any{"merchants": []any{"m"}, "currency": "USD", "perTransactionCap": 100.0,
			"autoApproveThreshold": 10.0, "cumulativeCap": 1000.0, k: negZero})
		if err == nil || !strings.Contains(err.Error(), "negative zero") {
			t.Errorf("%s = -0: %v", k, err)
		}
	}
}

func TestLeakFailsClosedOnNonFiniteStamps(t *testing.T) {
	if got := (TrustBudget{B: 1, Tau: 0, AsOf: math.NaN(), HasAsOf: true}).Leak(1000, 1); got.B != 0 {
		t.Errorf("NaN asOf: %+v", got)
	}
	if got := (TrustBudget{B: 1, Tau: 0}).Leak(math.Inf(1), 1); got.B != 0 {
		t.Errorf("infinite now: %+v", got)
	}
	if got := (TrustBudget{B: 1, Tau: 0}).Leak(1000, 0); got.B != 1 || !got.HasAsOf || got.AsOf != 1000 {
		t.Errorf("finite stamps unchanged: %+v", got)
	}
}
