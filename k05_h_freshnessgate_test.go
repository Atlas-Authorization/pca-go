package pca

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// F3 enforce.freshness: the signed freshness anchor gate (check `freshness_anchor`).
func TestF3_FreshnessGateReasons(t *testing.T) {
	anchor := func(epoch int64) map[string]any {
		return map[string]any{"beacon_ref": "b", "epoch": json.Number(jsNumberString(float64(epoch)))}
	}
	const epoch = 1000
	at := int64(epoch * DefaultFreshnessEpochMs)
	gate := func(mut func(g *FreshnessGate)) *FreshnessGate {
		g := &FreshnessGate{MaxAgeMs: 5000}
		mut(g)
		return g
	}
	for name, c := range map[string]struct {
		g    *FreshnessGate
		fr   map[string]any
		now  int64
		want string
	}{
		"fresh":                 {gate(func(*FreshnessGate) {}), anchor(epoch), at + 1000, ""},
		"exactly max age":       {gate(func(*FreshnessGate) {}), anchor(epoch), at + 5000, ""},
		"one past max age":      {gate(func(*FreshnessGate) {}), anchor(epoch), at + 5001, "freshness anchor is stale (older than 5000 ms)"},
		"in the future":         {gate(func(*FreshnessGate) {}), anchor(epoch), at - 1, "freshness anchor is in the future"},
		"future within skew":    {gate(func(g *FreshnessGate) { g.ClockSkewMs = 100 }), anchor(epoch), at - 100, ""},
		"future past skew":      {gate(func(g *FreshnessGate) { g.ClockSkewMs = 100 }), anchor(epoch), at - 101, "freshness anchor is in the future"},
		"negative skew is zero": {gate(func(g *FreshnessGate) { g.ClockSkewMs = -50 }), anchor(epoch), at - 1, "freshness anchor is in the future"},
		"custom epoch length":   {gate(func(g *FreshnessGate) { g.EpochMs = 1000 }), anchor(epoch), 1_000_000 + 10, ""},
		"missing anchor":        {gate(func(*FreshnessGate) {}), nil, at, "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"},
		"empty beacon_ref":      {gate(func(*FreshnessGate) {}), map[string]any{"beacon_ref": "", "epoch": json.Number("5")}, at, "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"},
		"epoch zero":            {gate(func(*FreshnessGate) {}), anchor(0), at, "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"},
		"negative max age":      {gate(func(g *FreshnessGate) { g.MaxAgeMs = -1 }), anchor(epoch), at, "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"},
		"NaN max age":           {gate(func(g *FreshnessGate) { g.MaxAgeMs = math.NaN() }), anchor(epoch), at, "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"},
		"negative epoch length": {gate(func(g *FreshnessGate) { g.EpochMs = -1 }), anchor(epoch), at, "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"},
	} {
		if got := freshnessGateReason(c.g, c.fr, c.now); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	// the gate's own clock overrides the verifier's
	now := at + 1000
	if got := freshnessGateReason(&FreshnessGate{MaxAgeMs: 5000, Now: &now}, anchor(epoch), at+999_999); got != "" {
		t.Errorf("gate Now: %q", got)
	}
}

func TestF3_FreshnessGateInTheCore(t *testing.T) {
	core := load(t, "vectors.json")
	var v map[string]any
	for _, x := range core["vectors"].([]any) {
		if m := x.(map[string]any); m["name"] == "valid-in-plan-action" {
			v = m
		}
	}
	ctx := v["context"].(map[string]any)
	run := func(g *FreshnessGate) Verdict {
		got, err := VerifyPCActnCoreWith(v["pcactn"].(map[string]any), v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string),
			VerifyOptions{InsecureSkipPlanRootCheck: true, EnforceFreshness: g})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// gate off: nothing reported, the vector's stub anchor is fine
	if got := run(nil); !got.Allow {
		t.Fatalf("gate off: %+v", got)
	} else if _, has := got.Checks["freshness_anchor"]; has {
		t.Error("gate off still reports freshness_anchor")
	}
	// gate on: the vector carries the stub anchor (empty beacon_ref, epoch 0), which the gate refuses
	got := run(&FreshnessGate{MaxAgeMs: 1000})
	if got.Allow || got.Checks["freshness_anchor"] || !strings.Contains(got.Reason, "freshness_anchor: freshness anchor is missing") {
		t.Errorf("stub anchor: %+v", got)
	}
}
