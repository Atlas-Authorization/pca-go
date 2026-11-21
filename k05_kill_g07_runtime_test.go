package pca

import (
	"encoding/json"
	"strings"
	"testing"
)

// g07rcClaim builds a runtime-class claim signed by k, after applying mut to the unsigned body.
func g07rcClaim(t *testing.T, k fxKey, mut func(m map[string]any)) map[string]any {
	t.Helper()
	m := map[string]any{"v": json.Number("1"), "class": "os_confined", "passport_digest": "pd", "evidence_digest": "ed",
		"iat": json.Number("100"), "exp": json.Number("200"), "attestor": k.id}
	if mut != nil {
		mut(m)
	}
	return signArt(t, k, runtimeClaimDomain, m)
}

func TestG07RuntimeClaimEveryGate(t *testing.T) {
	k := newKey(t)
	pinned := []string{k.id}
	long128 := strings.Repeat("d", 128)
	long129 := strings.Repeat("d", 129)
	cases := []struct {
		name     string
		mut      func(m map[string]any)
		passport string
		evidence string
		now      any
		want     string
	}{
		{"baseline", nil, "pd", "ed", json.Number("150"), "os_confined"},
		{"v is 2", func(m map[string]any) { m["v"] = json.Number("2") }, "pd", "ed", json.Number("150"), "none"},
		{"unknown class", func(m map[string]any) { m["class"] = "bogus" }, "pd", "ed", json.Number("150"), "none"},
		{"passport 128", func(m map[string]any) { m["passport_digest"] = long128 }, long128, "ed", json.Number("150"), "os_confined"},
		{"passport 129", func(m map[string]any) { m["passport_digest"] = long129 }, long129, "ed", json.Number("150"), "none"},
		{"evidence 128", func(m map[string]any) { m["evidence_digest"] = long128 }, "pd", long128, json.Number("150"), "os_confined"},
		{"evidence 129", func(m map[string]any) { m["evidence_digest"] = long129 }, "pd", long129, json.Number("150"), "none"},
		{"iat not int", func(m map[string]any) { m["iat"] = json.Number("0.5") }, "pd", "ed", json.Number("150"), "none"},
		{"exp not int", func(m map[string]any) { m["exp"] = json.Number("200.5") }, "pd", "ed", json.Number("150"), "none"},
		{"now not int", func(m map[string]any) { m["iat"] = json.Number("0") }, "pd", "ed", json.Number("0.5"), "none"},
		{"now == iat", nil, "pd", "ed", json.Number("100"), "os_confined"},
		{"now == exp", nil, "pd", "ed", json.Number("200"), "none"},
	}
	for _, c := range cases {
		claim := g07rcClaim(t, k, c.mut)
		if got := VerifiedRuntimeClass(claim, pinned, c.passport, []string{c.evidence}, c.now); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestG07ExplainRefusalHeadScan(t *testing.T) {
	if h := ExplainRefusal("plan_state x"); h.Check != "plan_state" {
		t.Errorf("plan_state x -> %q", h.Check)
	}
	if h := ExplainRefusal("plan_state"); h.Check != "plan_state" {
		t.Errorf("plan_state -> %q", h.Check)
	}
	if h := ExplainRefusal("authorize"); h.Check != "authorize" {
		t.Errorf("authorize -> %q", h.Check)
	}
}
