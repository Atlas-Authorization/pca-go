package pca

import (
	"strings"
	"testing"
)

func TestEatFreshnessRefusesANullSkew(t *testing.T) {
	r, _ := EatVerifyFreshness(map[string]any{}, map[string]any{"clockSkewMs": nil, "expectedNonce": "n", "maxAgeMs": 1.0})
	if r["ok"] != false || r["reason"] != "invalid clockSkewMs (must be a finite number)" {
		t.Errorf("null skew: %v", r)
	}
}

func TestEatAmdPinIsCheckedBeforeTheReport(t *testing.T) {
	for _, raw := range []any{"not bytes", nil, []byte{1}} {
		r := eatVerifyAmd(raw, map[string]any{})
		if r["ok"] != false || !strings.HasPrefix(r["reason"].(string), "exactly one of family or trustAnchorArkSpkiSha384") {
			t.Errorf("%v: %v", raw, r)
		}
	}
}

func TestEatCosignNullExpectedSignerFailsClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != "Cannot read properties of null (reading 'pq')" {
			t.Errorf("recovered %v", r)
		}
	}()
	eatSignerMatches(nil, map[string]any{"pq": "x"})
}

func TestEatErrorNames(t *testing.T) {
	if eatJSErrorName("Cannot read properties of undefined (reading 'referenceValues')") != "TypeError" || eatJSErrorName("boom") != "Error" {
		t.Error("error names")
	}
}

func TestEatRuntimeDigestRefusesNonArrayMeasurements(t *testing.T) {
	v := func(m any) map[string]any { return map[string]any{"ok": true, "claims": map[string]any{"measurements": m}} }
	if _, err := EatRuntimeDigestFromEat(v("x"), "", ""); err == nil || !strings.Contains(err.Error(), "filter is not a function") {
		t.Errorf("string measurements: %v", err)
	}
	if r, err := EatRuntimeDigestFromEat(v(nil), "", ""); r != nil || err != nil {
		t.Errorf("null measurements: %v %v", r, err)
	}
}
