package pca

import "testing"

// Replays packages/pca/conformance/k4-vectors.json: escalation pricing, network-token binding, ERC-7715 permission check.
func TestK4Vectors(t *testing.T) {
	doc := load(t, "k4-vectors.json")
	esc := doc["escalation"].(map[string]any)
	cc := esc["config_cases"].([]any)
	if len(cc) < 6 {
		t.Fatal("too few config cases")
	}
	for _, x := range cc {
		c := x.(map[string]any)
		want, _ := c["expect"].(string)
		if got := PricingConfigError(c["config"]); got != want {
			t.Errorf("config %v: %q, want %q", c["name"], got, want)
		}
	}
	ds := esc["decisions"].([]any)
	if len(ds) < 14 {
		t.Fatal("too few decisions")
	}
	for _, x := range ds {
		c := x.(map[string]any)
		exp := c["expect"].(map[string]any)
		got := DecideEscalation(esc["config"], c["calibration"], c["risk"])
		if got.Ask != exp["ask"].(bool) || got.Reason != exp["reason"] {
			t.Errorf("decision %v: %+v, want %v", c["risk"], got, exp)
		}
	}
	for _, x := range esc["calibration"].([]any) {
		c := x.(map[string]any)
		risks := map[string]any{}
		for k, v := range c["risks"].(map[string]any) {
			risks[k] = v
		}
		mult, seen := UpdateCalibration(c["config"], c["start"].(map[string]any), c["answers"].([]any), risks)
		exp := c["expect"].(map[string]any)
		want := exp["seen"].([]any)
		if mult != num(exp["multiplierPpm"]) || len(seen) != len(want) {
			t.Errorf("calibration %v: %d %v, want %v", c["name"], mult, seen, exp)
			continue
		}
		for i := range seen {
			if seen[i] != want[i] {
				t.Errorf("calibration %v: seen %v, want %v", c["name"], seen, want)
			}
		}
	}
	bs := doc["network_binding"].(map[string]any)["cases"].([]any)
	if len(bs) < 15 {
		t.Fatal("too few binding cases")
	}
	for _, x := range bs {
		c := x.(map[string]any)
		e := c["expect_in"].(map[string]any)
		prov, _ := e["provider"].(string)
		want, _ := c["expect"].(string)
		if got := VerifyNetworkTokenBinding(c["binding"], e["grant"], e["holder"].(string), e["issuer_nonce"].(string), prov); got != want {
			t.Errorf("binding %v: %q, want %q", c["name"], got, want)
		}
	}
	es := doc["erc7715"].(map[string]any)["cases"].([]any)
	if len(es) < 24 {
		t.Fatal("too few erc7715 cases")
	}
	for _, x := range es {
		c := x.(map[string]any)
		o := c["opts"].(map[string]any)
		var mgrs []string
		for _, m := range o["allowedManagers"].([]any) {
			mgrs = append(mgrs, m.(string))
		}
		ctxs, _ := o["contexts"].(map[string]any)
		owner := func(k string) (string, bool) { v, ok := ctxs[k].(string); return v, ok }
		want, _ := c["expect"].(string)
		if got := VerifyGrantedPermission(c["envelope"], c["sent"], c["got"], mgrs, owner); got != want {
			t.Errorf("erc7715 %v: %q, want %q", c["name"], got, want)
		}
	}
}
