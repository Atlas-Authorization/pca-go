package pca

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestR5N3PricingConfigWithAnUndecodableKeyIsMalformed(t *testing.T) {
	// the signature is well formed base64url but the principal key is not: nothing can be verified
	if got := PricingConfigError(g11K4Cfg("", map[string]any{"principal": "!!not-b64!!"})); got != "config_malformed" {
		t.Errorf("undecodable principal: %q", got)
	}
	if got := PricingConfigError("x"); got != "config_malformed" {
		t.Errorf("non-object: %q", got)
	}
	if k4AnswerOK("x", "p") || k4AnswerOK(nil, "p") {
		t.Error("non-object answer accepted")
	}
}

func TestR5N3UpdateCalibrationKeepsReadingAfterASkippedAnswer(t *testing.T) {
	cfg := g11K4Cfg("", nil)
	risks := map[string]any{"ad1": map[string]any{"currency": "USD", "loss": json.Number("1"), "pBadUpperPpm": json.Number("1")}}
	cal := func(seen ...any) map[string]any {
		m := map[string]any{"multiplierPpm": json.Number("1000000")}
		if seen != nil {
			m["seen"] = seen
		}
		return m
	}
	deny := func(nonce, digest string) any {
		return g11K4Answer("", map[string]any{"answer": "deny", "nonce": nonce, "action_digest": digest})
	}
	// an invalid answer, then a valid deny
	bogus := g11K4Answer("", map[string]any{"answer": "bogus", "nonce": "nonce-0000"})
	mult, order := UpdateCalibration(cfg, cal(), []any{bogus, deny("nonce-0001", "ad1")}, risks)
	if mult != 1_100_000 || !reflect.DeepEqual(order, []string{"nonce-0001"}) {
		t.Errorf("after an invalid answer: %d %v", mult, order)
	}
	// an already seen nonce, then a valid deny
	mult, order = UpdateCalibration(cfg, cal("nonce-0001"), []any{deny("nonce-0001", "ad1"), deny("nonce-0002", "ad1")}, risks)
	if mult != 1_100_000 || !reflect.DeepEqual(order, []string{"nonce-0001", "nonce-0002"}) {
		t.Errorf("after a replayed nonce: %d %v", mult, order)
	}
	// an approval, a deny of an unknown action, then a valid deny
	approve := g11K4Answer("", map[string]any{"answer": "approve", "nonce": "nonce-0003"})
	mult, order = UpdateCalibration(cfg, cal(), []any{approve, deny("nonce-0004", "unknown"), deny("nonce-0005", "ad1")}, risks)
	if mult != 1_100_000 || !reflect.DeepEqual(order, []string{"nonce-0003", "nonce-0004", "nonce-0005"}) {
		t.Errorf("after an approval and an unknown action: %d %v", mult, order)
	}
}

func TestR5N3GrantedPermissionNonStringChainIsNotAnEmptyString(t *testing.T) {
	g, s, r := g11Perm(nil, false)
	s["chainId"] = ""
	r["chainId"] = json.Number("1") // not a string: it never equals even the empty chain id
	if got := VerifyGrantedPermission(g, s, r, []string{g11Mgr}, nil); got != "chain_mismatch" {
		t.Errorf("non-string chain: %q", got)
	}
	g, s, r = g11Perm(nil, false)
	r["rules"] = "x" // not a list: there is no expiry rule
	if got := VerifyGrantedPermission(g, s, r, []string{g11Mgr}, nil); got != "expiry_missing" {
		t.Errorf("rules not a list: %q", got)
	}
}
