package pca

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// F1: the core `plan_root_authorized` check. The shared vectors (conformance/plan-root-vectors.json) run each case through the core
// verifier with the stated options.

func verifyCoreSkipPlan(p, g map[string]any, now int64, aud string) (Verdict, error) {
	return VerifyPCActnCoreWith(p, g, now, aud, VerifyOptions{InsecureSkipPlanRootCheck: true})
}

func verifyCorePolicySkipPlan(p, g map[string]any, now int64, aud string, allowed []string) (Verdict, error) {
	return VerifyPCActnCoreWith(p, g, now, aud, VerifyOptions{AllowedSuites: allowed, InsecureSkipPlanRootCheck: true})
}

func TestF1_PlanRootVectors(t *testing.T) {
	var doc struct {
		Cases []struct {
			Name    string         `json:"name"`
			Vector  string         `json:"vector"`
			Options map[string]any `json:"options"`
			Expect  struct {
				Allow  bool   `json:"allow"`
				Check  string `json:"check"`
				Reason string `json:"reason"`
			} `json:"expect"`
		} `json:"plan_root_authorized"`
	}
	raw, err := os.ReadFile(dir + "plan-root-vectors.json")
	if err != nil {
		t.Fatalf("plan-root-vectors.json is missing: %v", err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Cases) == 0 {
		t.Fatalf("plan-root-vectors.json: %v (%d cases)", err, len(doc.Cases))
	}
	core := load(t, "vectors.json")
	byName := map[string]map[string]any{}
	for _, x := range core["vectors"].([]any) {
		v := x.(map[string]any)
		byName[v["name"].(string)] = v
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, ok := byName[c.Vector]
			if !ok {
				t.Fatalf("vector %q is not in vectors.json", c.Vector)
			}
			ctx := v["context"].(map[string]any)
			p := v["pcactn"].(map[string]any)
			root, _ := p["plan"].(map[string]any)["root"].(string)
			opts := VerifyOptions{}
			if list, has := c.Options["authorizedPlanRoots"]; has {
				opts.AuthorizedPlanRoots = []string{}
				for _, x := range list.([]any) {
					s := x.(string)
					if s == "$plan_root" {
						s = root
					}
					opts.AuthorizedPlanRoots = append(opts.AuthorizedPlanRoots, s)
				}
			}
			opts.InsecureSkipPlanRootCheck = c.Options["insecureSkipPlanRootCheck"] == true
			got, err := VerifyPCActnCoreWith(p, v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string), opts)
			if err != nil {
				t.Fatal(err)
			}
			if got.Allow != c.Expect.Allow {
				t.Errorf("allow %v, want %v (%s)", got.Allow, c.Expect.Allow, got.Reason)
			}
			switch c.Expect.Check {
			case "pass":
				if pass, has := got.Checks["plan_root_authorized"]; !has || !pass {
					t.Errorf("check: %v %v", pass, has)
				}
			case "fail":
				if pass, has := got.Checks["plan_root_authorized"]; !has || pass {
					t.Errorf("check: %v %v", pass, has)
				}
			case "not-enforced":
				if _, has := got.Checks["plan_root_authorized"]; has || !got.NotEnforced["plan_root_authorized"] {
					t.Errorf("not-enforced: checks %v notEnforced %v", got.Checks, got.NotEnforced)
				}
			}
			if c.Expect.Reason != "" && got.Reason != c.Expect.Reason {
				t.Errorf("reason %q, want %q", got.Reason, c.Expect.Reason)
			}
			if c.Expect.Reason == "" && c.Expect.Allow && strings.Contains(got.Reason, "plan_root_authorized") {
				t.Errorf("an allow carries a plan_root_authorized reason: %q", got.Reason)
			}
		})
	}
}

// End to end through the guard (not a helper): a plan root the principal has not authorized denies at the HTTP layer with the reference
// reason, and the listed root admits.
func TestF1_GuardDeniesAnUnauthorizedPlanRoot(t *testing.T) {
	d, grant, s := guardCase(t, "envelope-predicate-400-refused")
	pc := s["pcactn"].(map[string]any)
	root, _ := pc["plan"].(map[string]any)["root"].(string)
	opts := RequirePCAOptions{SignatureOnly: true, Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil }, AuthorizedPlanRoots: []string{"not-the-root"}}
	g := serve(t, opts, pc)
	if g.code != 403 || g.calls != 0 || g.body["checks"].(map[string]any)["plan_root_authorized"] != false ||
		!strings.Contains(fmt.Sprint(g.body), "the plan root has not been authorized by the principal") {
		t.Fatalf("an unauthorized plan root must deny: %+v", g)
	}
	opts.AuthorizedPlanRoots = []string{root}
	if g := serve(t, opts, pc); g.code != 204 || g.calls != 1 {
		t.Fatalf("the authorized plan root admits: %+v", g)
	}
}
