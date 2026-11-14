package pca

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// F3 pqPins: the server-side post-quantum pins (conformance/pq-pin-vectors.json).
func TestF3_PqPinVectors(t *testing.T) {
	var doc struct {
		Cases []struct {
			Name   string             `json:"name"`
			Vector string             `json:"vector"`
			Pins   map[string]*string `json:"pq_pins"`
			Expect struct {
				Check  string `json:"check"`
				Reason string `json:"reason"`
			} `json:"expect"`
		} `json:"pq_pin"`
	}
	raw, err := os.ReadFile(dir + "pq-pin-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Cases) == 0 {
		t.Fatalf("pq-pin-vectors.json: %v (%d cases)", err, len(doc.Cases))
	}
	byName := map[string]map[string]any{}
	for _, x := range load(t, "vectors.json")["vectors"].([]any) {
		v := x.(map[string]any)
		byName[v["name"].(string)] = v
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, ok := byName[c.Vector]
			if !ok {
				t.Fatalf("vector %q is not in vectors.json", c.Vector)
			}
			grant := v["grant"].(map[string]any)
			issuer, _ := grant["issuer"].(string)
			pk, _ := grant["pq_pk"].(string)
			expand := func(s string) string {
				s = strings.ReplaceAll(s, "$grant.pq_pk[0:20]", pk[:min(20, len(pk))])
				s = strings.ReplaceAll(s, "$grant.pq_pk", pk)
				return strings.ReplaceAll(s, "$grant.issuer", issuer)
			}
			opts := VerifyOptions{InsecureSkipPlanRootCheck: true}
			if c.Pins != nil {
				opts.PQPins = map[string]string{}
				for k, val := range c.Pins {
					opts.PQPins[expand(k)] = expand(*val)
				}
			}
			ctx := v["context"].(map[string]any)
			got, err := VerifyPCActnCoreWith(v["pcactn"].(map[string]any), grant, num(ctx["now"]), ctx["aud"].(string), opts)
			if err != nil {
				t.Fatal(err)
			}
			pass, has := got.Checks["pq_pin"]
			switch c.Expect.Check {
			case "pass":
				if !has || !pass {
					t.Errorf("check %v %v (%s)", pass, has, got.Reason)
				}
			case "fail":
				if !has || pass {
					t.Errorf("check %v %v", pass, has)
				}
				found := false
				for _, r := range append([]string{got.Reason}, got.Reasons...) {
					found = found || r == c.Expect.Reason
				}
				if !found {
					t.Errorf("reason %q not among %q / %v", c.Expect.Reason, got.Reason, got.Reasons)
				}
			case "absent":
				if has {
					t.Errorf("pq_pin reported without pins: %v", pass)
				}
			}
		})
	}
}

// The same pins end to end through Authorize (conformance/authorize-pq-pin-fixtures.json): a classical grant from a pinned issuer is
// refused, an unpinned issuer, empty pins and unset pins are not.
func TestF3_AuthorizePqPinFixtures(t *testing.T) {
	doc := load(t, "authorize-pq-pin-fixtures.json")
	op := doc["operation"].(map[string]any)
	params, _ := op["params"].(map[string]any)
	cases := doc["cases"].([]any)
	if len(cases) < 9 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, cv := range cases {
		c := cv.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			grant := c["grant"].(map[string]any)
			in := AuthorizeInput{
				Audience: doc["audience"].(string), Now: num(doc["now"]), Plan: PlanSingleStep, Risk: InsecureCalmRisk,
				Operation:    &Operation{Verb: op["verb"].(string), Resource: op["resource"].(string), Params: params},
				ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
				IsRevoked:    func(_, _ map[string]any) (bool, error) { return false, nil },
				StateStore:   NewMemoryStateStore(),
			}
			if pins, ok := c["pq_pins"].(map[string]any); ok {
				in.PqPins = map[string]string{}
				for k, v := range pins {
					in.PqPins[k] = v.(string)
				}
			}
			got := Authorize(c["pcactn"].(map[string]any), in)
			e := c["expect"].(map[string]any)
			if got.Allow != (e["allow"] == true) {
				t.Fatalf("allow %v, want %v: %q", got.Allow, e["allow"], got.Reasons)
			}
			if !got.Allow && got.Status != int(num(e["status"])) { // a pq_pin denial is an authentication failure (401)
				t.Errorf("status %d, want %v", got.Status, e["status"])
			}
			want := e["checks"].(map[string]any)["pq_pin"].(string)
			st, has := got.Checks["pq_pin"]
			if (want == "absent") == has || (has && st != want) {
				t.Errorf("pq_pin %q (present %v), want %s", st, has, want)
			}
			failed := map[string]bool{}
			for n, s := range got.Checks {
				if s == "fail" {
					failed[n] = true
				}
			}
			for _, n := range e["failed_includes"].([]any) {
				if !failed[n.(string)] {
					t.Errorf("%s is not among the failing checks %v", n, failed)
				}
			}
			if r, ok := e["reason"].(string); ok && !strings.Contains(strings.Join(got.Reasons, " | "), r) {
				t.Errorf("reason %q not in %q", r, got.Reasons)
			}
		})
	}
}
