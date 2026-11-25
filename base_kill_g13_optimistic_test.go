package pca

import (
	"encoding/json"
	"math"
	"testing"
)

// Mutation kills for optimistic.go.

func TestG13OptDefaultsAndHelpers(t *testing.T) {
	if DefaultChallengeWindowPolicy != (ChallengeWindowPolicy{MinWindowMs: 1000, MaxWindowMs: 86_400_000, MaxSkewMs: 5000}) {
		t.Fatalf("default policy %+v", DefaultChallengeWindowPolicy)
	}
	if _, ok := extFinite(math.Inf(-1)); ok {
		t.Fatal("-Infinity is finite")
	}
	if _, ok := extFinite(json.Number("2")); !ok {
		t.Fatal("2 is not finite")
	}
	if m, ok := extObject([]any{}); !ok || m == nil || len(m) != 0 {
		t.Fatalf("an array is an (empty) object: %v %v", m, ok)
	}
	if _, ok := extObject("x"); ok {
		t.Fatal("a string is an object")
	}
	if good, canon := extSignedLenient("k", claimDomain, map[string]any{"x": math.NaN()}, "s"); good || canon {
		t.Fatalf("a NaN body: %v %v", good, canon)
	}
	if WithinChallengeWindow(0, 10, math.Inf(-1)) {
		t.Fatal("-Infinity is within the window")
	}
	if !WithinChallengeWindow(0, 10, 10) || WithinChallengeWindow(0, 10, 11) {
		t.Fatal("inclusive window end")
	}
	one := map[string]any{"a": json.Number("1")}
	if extNumEq(one, map[string]any{}, "a") || extNumEq(map[string]any{}, one, "a") {
		t.Fatal("present vs absent")
	}
	if !extNumEq(map[string]any{}, map[string]any{}, "a") || !extNumEq(one, map[string]any{"a": json.Number("1.0")}, "a") {
		t.Fatal("equal members")
	}
}

func TestG13OptClaimWindow(t *testing.T) {
	claim := func(drop string, set map[string]any) map[string]any {
		c := map[string]any{"pcactn_digest": "D", "claimed_r": json.Number("0.5"), "issued_at": json.Number("1000"),
			"challenge_window_ms": json.Number("2000"), "sig": "x"}
		delete(c, drop)
		for k, v := range set {
			c[k] = v
		}
		return c
	}
	def := DefaultChallengeWindowPolicy
	wide := ChallengeWindowPolicy{MinWindowMs: 0, MaxWindowMs: 1e9, MaxSkewMs: 5000}
	infSkew := ChallengeWindowPolicy{MinWindowMs: 0, MaxWindowMs: 1e9, MaxSkewMs: math.Inf(1)}
	for _, c := range []struct {
		name  string
		claim map[string]any
		now   float64
		p     ChallengeWindowPolicy
		want  string
	}{
		{"well formed (unsigned)", claim("", nil), 1000, def, "signature"},
		{"issued_at missing", claim("issued_at", nil), 1000, def, "window"},
		{"window missing", claim("challenge_window_ms", nil), 1000, wide, "window"},
		{"now NaN", claim("", nil), math.NaN(), def, "window"},
		{"now +Infinity", claim("", nil), math.Inf(1), infSkew, "window"},
		{"now -Infinity", claim("", nil), math.Inf(-1), infSkew, "window"},
		{"skew exceeded", claim("", nil), 7000, def, "window"},
		{"window below minimum", claim("", map[string]any{"challenge_window_ms": json.Number("999")}), 1000, def, "window"},
		{"window above maximum", claim("", map[string]any{"challenge_window_ms": json.Number("86400001")}), 1000, def, "window"},
	} {
		if got := ClaimCheck(c.claim, "D", "k", c.now, c.p); got != c.want {
			t.Fatalf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestG13OptRiskUnderstatedMargin(t *testing.T) {
	claim := map[string]any{"pcactn_digest": "D", "bond_ref": "B", "claimed_r": json.Number("0.5")}
	proof := func(r string) map[string]any {
		return map[string]any{"pcactn_digest": "D", "bond_ref": "B", "claimed_r": json.Number("0.5"), "reason": "x",
			"kind": "risk-understated", "r_margin": json.Number("0"),
			"decision": map[string]any{"releaseGuardianShare": true, "optimisticAllowed": true, "r": json.Number(r)}}
	}
	if got := FraudProofWireCheck(claim, proof("0.5")); got != "consistency" {
		t.Fatalf("r == claimed_r + margin: %q", got)
	}
	if got := FraudProofWireCheck(claim, proof("0.6")); got != "ok" {
		t.Fatalf("r > claimed_r + margin: %q", got)
	}
}

func TestG13OptSettlementShapeAndSplit(t *testing.T) {
	open := map[string]any{"claimId": "c", "action": "open", "amount": json.Number("0.5"), "from": "f", "to": "t",
		"at": json.Number("1"), "evidenceDigest": "", "sig": "x"}
	if got := SettlementWireCheck(open, "k"); got != "signature" {
		t.Fatalf("a fractional positive amount is well formed: %q", got)
	}
	slash := func(withChallenger bool) map[string]any {
		sp := map[string]any{"amount": json.Number("10"), "challengerReward": json.Number("0"), "victimCompensation": json.Number("0"),
			"treasuryRemainder": json.Number("10"), "victimAccount": "v", "treasuryAccount": "t"}
		if withChallenger {
			sp["challengerAccount"] = nil
		}
		return map[string]any{"claimId": "c", "action": "slash", "amount": json.Number("10"), "from": "f", "to": "t",
			"at": json.Number("1"), "evidenceDigest": "e", "sig": "x", "split": sp}
	}
	if got := SettlementWireCheck(slash(true), "k"); got != "signature" {
		t.Fatalf("all-treasury split with a null challenger: %q", got)
	}
	if got := SettlementWireCheck(slash(false), "k"); got != "split" {
		t.Fatalf("all-treasury split with the challenger account absent: %q", got)
	}
}
